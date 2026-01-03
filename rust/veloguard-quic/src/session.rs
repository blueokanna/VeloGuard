//! Session resumption and 0-RTT ticket storage for VeloGuard QUIC

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Maximum number of session tickets to store per server
const MAX_TICKETS_PER_SERVER: usize = 4;

/// Session ticket lifetime
const TICKET_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days

/// Session ticket for 0-RTT resumption
#[derive(Clone, Debug)]
pub struct SessionTicket {
    /// The ticket data
    pub data: Vec<u8>,
    /// When the ticket was received
    pub received_at: Instant,
    /// Ticket lifetime hint from server
    pub lifetime_hint: Duration,
    /// Server name this ticket is for
    pub server_name: String,
}

impl SessionTicket {
    /// Create a new session ticket
    pub fn new(data: Vec<u8>, server_name: String, lifetime_hint: Duration) -> Self {
        Self {
            data,
            received_at: Instant::now(),
            lifetime_hint,
            server_name,
        }
    }

    /// Check if the ticket is still valid
    pub fn is_valid(&self) -> bool {
        let age = self.received_at.elapsed();
        age < self.lifetime_hint && age < TICKET_LIFETIME
    }

    /// Get the ticket age
    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

/// Session ticket store for managing 0-RTT tickets
#[derive(Debug)]
pub struct SessionStore {
    /// Tickets indexed by server name
    tickets: DashMap<String, VecDeque<SessionTicket>>,
    /// Maximum tickets per server
    max_tickets: usize,
}

impl SessionStore {
    /// Create a new session store
    pub fn new() -> Self {
        Self {
            tickets: DashMap::new(),
            max_tickets: MAX_TICKETS_PER_SERVER,
        }
    }

    /// Create with custom max tickets
    pub fn with_max_tickets(max_tickets: usize) -> Self {
        Self {
            tickets: DashMap::new(),
            max_tickets,
        }
    }

    /// Store a session ticket
    pub fn store(&self, ticket: SessionTicket) {
        let server_name = ticket.server_name.clone();

        self.tickets
            .entry(server_name.clone())
            .or_insert_with(VecDeque::new)
            .push_back(ticket);

        // Trim old tickets
        if let Some(mut tickets) = self.tickets.get_mut(&server_name) {
            while tickets.len() > self.max_tickets {
                tickets.pop_front();
            }
            // Remove expired tickets
            tickets.retain(|t| t.is_valid());
        }

        debug!("Stored session ticket for {}", server_name);
    }

    /// Get a valid session ticket for a server
    pub fn get(&self, server_name: &str) -> Option<SessionTicket> {
        if let Some(mut tickets) = self.tickets.get_mut(server_name) {
            // Remove expired tickets
            tickets.retain(|t| t.is_valid());

            // Return the newest valid ticket
            tickets.back().cloned()
        } else {
            None
        }
    }

    /// Take a session ticket (removes it from store)
    pub fn take(&self, server_name: &str) -> Option<SessionTicket> {
        if let Some(mut tickets) = self.tickets.get_mut(server_name) {
            // Remove expired tickets
            tickets.retain(|t| t.is_valid());

            // Take the newest valid ticket
            tickets.pop_back()
        } else {
            None
        }
    }

    /// Check if we have a valid ticket for a server
    pub fn has_ticket(&self, server_name: &str) -> bool {
        self.get(server_name).is_some()
    }

    /// Clear all tickets for a server
    pub fn clear(&self, server_name: &str) {
        self.tickets.remove(server_name);
    }

    /// Clear all tickets
    pub fn clear_all(&self) {
        self.tickets.clear();
    }

    /// Get the number of servers with tickets
    pub fn server_count(&self) -> usize {
        self.tickets.len()
    }

    /// Get the total number of tickets
    pub fn ticket_count(&self) -> usize {
        self.tickets.iter().map(|e| e.value().len()).sum()
    }

    /// Cleanup expired tickets
    pub fn cleanup(&self) {
        for mut entry in self.tickets.iter_mut() {
            entry.value_mut().retain(|t| t.is_valid());
        }
        // Remove empty entries
        self.tickets.retain(|_, v| !v.is_empty());
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Rustls session storage implementation
#[derive(Debug)]
#[allow(dead_code)]
pub struct RustlsSessionStore {
    inner: Arc<SessionStore>,
}

#[allow(dead_code)]
impl RustlsSessionStore {
    /// Create a new Rustls session store
    pub fn new(store: Arc<SessionStore>) -> Self {
        Self { inner: store }
    }
}

impl rustls::client::ClientSessionStore for RustlsSessionStore {
    fn set_kx_hint(&self, _server_name: rustls::pki_types::ServerName<'_>, _group: rustls::NamedGroup) {
        // We don't store key exchange hints
    }

    fn kx_hint(&self, _server_name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        None
    }

    fn set_tls12_session(
        &self,
        _server_name: rustls::pki_types::ServerName<'_>,
        _value: rustls::client::Tls12ClientSessionValue,
    ) {
        // We don't support TLS 1.2 session resumption
    }

    fn tls12_session(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &rustls::pki_types::ServerName<'_>) {
        // No-op
    }

    fn insert_tls13_ticket(
        &self,
        server_name: rustls::pki_types::ServerName<'_>,
        _value: rustls::client::Tls13ClientSessionValue,
    ) {
        let name = match &server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref().to_string(),
            _ => return,
        };

        // We store a placeholder since we can't access the internal ticket data
        // The actual 0-RTT is handled at the QUIC level
        let lifetime = Duration::from_secs(86400); // 24 hours default

        let ticket = SessionTicket::new(vec![], name, lifetime);
        self.inner.store(ticket);
    }

    fn take_tls13_ticket(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        // We return None here because we handle 0-RTT at the QUIC level
        // The tickets are stored for our own use
        None
    }
}

/// Connection state for tracking 0-RTT status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroRttState {
    /// 0-RTT not attempted
    NotAttempted,
    /// 0-RTT in progress
    InProgress,
    /// 0-RTT accepted by server
    Accepted,
    /// 0-RTT rejected by server
    Rejected,
    /// 0-RTT not available (no ticket)
    NotAvailable,
}

impl ZeroRttState {
    /// Check if 0-RTT was successful
    pub fn is_accepted(&self) -> bool {
        matches!(self, ZeroRttState::Accepted)
    }

    /// Check if 0-RTT is still pending
    pub fn is_pending(&self) -> bool {
        matches!(self, ZeroRttState::InProgress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_store() {
        let store = SessionStore::new();

        let ticket = SessionTicket::new(
            vec![1, 2, 3, 4],
            "example.com".to_string(),
            Duration::from_secs(3600),
        );

        store.store(ticket);
        assert!(store.has_ticket("example.com"));
        assert!(!store.has_ticket("other.com"));

        let retrieved = store.get("example.com").unwrap();
        assert_eq!(retrieved.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ticket_expiry() {
        let ticket = SessionTicket::new(
            vec![1, 2, 3],
            "test.com".to_string(),
            Duration::from_millis(1),
        );

        assert!(ticket.is_valid());
        std::thread::sleep(Duration::from_millis(10));
        assert!(!ticket.is_valid());
    }

    #[test]
    fn test_max_tickets() {
        let store = SessionStore::with_max_tickets(2);

        for i in 0..5 {
            let ticket = SessionTicket::new(
                vec![i],
                "server.com".to_string(),
                Duration::from_secs(3600),
            );
            store.store(ticket);
        }

        // Should only have 2 tickets
        let tickets = store.tickets.get("server.com").unwrap();
        assert_eq!(tickets.len(), 2);
        // Should have the newest tickets (3 and 4)
        assert_eq!(tickets[0].data, vec![3]);
        assert_eq!(tickets[1].data, vec![4]);
    }
}
