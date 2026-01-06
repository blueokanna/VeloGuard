use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

const MAX_TICKETS_PER_SERVER: usize = 4;
const TICKET_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Debug)]
pub struct SessionTicket {
    pub data: Vec<u8>,
    pub received_at: Instant,
    pub lifetime_hint: Duration,
    pub server_name: String,
}

impl SessionTicket {
    pub fn new(data: Vec<u8>, server_name: String, lifetime_hint: Duration) -> Self {
        Self {
            data,
            received_at: Instant::now(),
            lifetime_hint,
            server_name,
        }
    }

    pub fn is_valid(&self) -> bool {
        let age = self.received_at.elapsed();
        age < self.lifetime_hint && age < TICKET_LIFETIME
    }

    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

#[derive(Debug)]
pub struct SessionStore {
    tickets: DashMap<String, VecDeque<SessionTicket>>,
    max_tickets: usize,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            tickets: DashMap::new(),
            max_tickets: MAX_TICKETS_PER_SERVER,
        }
    }

    pub fn with_max_tickets(max_tickets: usize) -> Self {
        Self {
            tickets: DashMap::new(),
            max_tickets,
        }
    }

    pub fn store(&self, ticket: SessionTicket) {
        let server_name = ticket.server_name.clone();

        self.tickets
            .entry(server_name.clone())
            .or_default()
            .push_back(ticket);

        if let Some(mut tickets) = self.tickets.get_mut(&server_name) {
            while tickets.len() > self.max_tickets {
                tickets.pop_front();
            }
            tickets.retain(|t| t.is_valid());
        }

        debug!("Stored session ticket for {}", server_name);
    }

    pub fn get(&self, server_name: &str) -> Option<SessionTicket> {
        if let Some(mut tickets) = self.tickets.get_mut(server_name) {
            tickets.retain(|t| t.is_valid());
            tickets.back().cloned()
        } else {
            None
        }
    }

    pub fn take(&self, server_name: &str) -> Option<SessionTicket> {
        if let Some(mut tickets) = self.tickets.get_mut(server_name) {
            tickets.retain(|t| t.is_valid());
            tickets.pop_back()
        } else {
            None
        }
    }

    pub fn has_ticket(&self, server_name: &str) -> bool {
        self.get(server_name).is_some()
    }

    pub fn clear(&self, server_name: &str) {
        self.tickets.remove(server_name);
    }

    pub fn clear_all(&self) {
        self.tickets.clear();
    }

    pub fn server_count(&self) -> usize {
        self.tickets.len()
    }

    pub fn ticket_count(&self) -> usize {
        self.tickets.iter().map(|e| e.value().len()).sum()
    }

    pub fn cleanup(&self) {
        for mut entry in self.tickets.iter_mut() {
            entry.value_mut().retain(|t| t.is_valid());
        }
        self.tickets.retain(|_, v| !v.is_empty());
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RustlsSessionStore {
    inner: Arc<SessionStore>,
}

#[allow(dead_code)]
impl RustlsSessionStore {
    pub fn new(store: Arc<SessionStore>) -> Self {
        Self { inner: store }
    }
}

impl rustls::client::ClientSessionStore for RustlsSessionStore {
    fn set_kx_hint(&self, _server_name: rustls::pki_types::ServerName<'_>, _group: rustls::NamedGroup) {}

    fn kx_hint(&self, _server_name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        None
    }

    fn set_tls12_session(
        &self,
        _server_name: rustls::pki_types::ServerName<'_>,
        _value: rustls::client::Tls12ClientSessionValue,
    ) {}

    fn tls12_session(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &rustls::pki_types::ServerName<'_>) {}

    fn insert_tls13_ticket(
        &self,
        server_name: rustls::pki_types::ServerName<'_>,
        _value: rustls::client::Tls13ClientSessionValue,
    ) {
        let name = match &server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref().to_string(),
            _ => return,
        };

        let lifetime = Duration::from_secs(86400);
        let ticket = SessionTicket::new(vec![], name, lifetime);
        self.inner.store(ticket);
    }

    fn take_tls13_ticket(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroRttState {
    NotAttempted,
    InProgress,
    Accepted,
    Rejected,
    NotAvailable,
}

impl ZeroRttState {
    pub fn is_accepted(&self) -> bool {
        matches!(self, ZeroRttState::Accepted)
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, ZeroRttState::InProgress)
    }
}
