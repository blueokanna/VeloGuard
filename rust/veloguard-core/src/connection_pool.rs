use crate::error::{Error, Result};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Connection pool entry
#[derive(Debug)]
pub struct PooledConnection {
    /// Connection ID
    pub id: String,
    /// Target address
    pub target: String,
    /// Last used time
    pub last_used: Instant,
    /// Connection state
    pub state: ConnectionState,
}

/// Connection states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is available for use
    Available,
    /// Connection is currently in use
    InUse,
    /// Connection is being closed
    Closing,
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per target
    pub max_connections: usize,
    /// Maximum idle time before closing connection
    pub max_idle_time: Duration,
    /// Maximum connection lifetime
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            max_idle_time: Duration::from_secs(300), // 5 minutes
            max_lifetime: Duration::from_secs(3600),  // 1 hour
        }
    }
}

/// Connection pool manager
pub struct ConnectionPool {
    config: PoolConfig,
    pools: DashMap<String, Vec<Arc<Mutex<PooledConnection>>>>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            pools: DashMap::new(),
        }
    }

    /// Get a connection from the pool
    pub async fn get_connection(&self, target: &str) -> Result<Arc<Mutex<PooledConnection>>> {
        let mut pool = self.pools.entry(target.to_string()).or_default();

        // Clean up expired connections
        self.cleanup_expired_connections(&mut pool).await;

        // Find an available connection
        for conn_mutex in pool.iter() {
            let mut conn = conn_mutex.lock().await;
            if conn.state == ConnectionState::Available {
                conn.state = ConnectionState::InUse;
                conn.last_used = Instant::now();
                return Ok(Arc::clone(conn_mutex));
            }
        }

        // Check if we can create a new connection
        if pool.len() < self.config.max_connections {
            let conn = PooledConnection {
                id: format!("{}-{}", target, uuid::Uuid::new_v4()),
                target: target.to_string(),
                last_used: Instant::now(),
                state: ConnectionState::InUse,
            };
            let conn_arc = Arc::new(Mutex::new(conn));
            pool.push(Arc::clone(&conn_arc));
            return Ok(conn_arc);
        }

        Err(Error::ResourceExhausted {
            message: format!("Connection pool exhausted for target: {}", target),
            resource: Some("connection_pool".to_string()),
        })
    }

    /// Return a connection to the pool
    pub async fn return_connection(&self, connection: Arc<Mutex<PooledConnection>>) -> Result<()> {
        let mut conn = connection.lock().await;
        if conn.state == ConnectionState::InUse {
            conn.state = ConnectionState::Available;
            conn.last_used = Instant::now();
        }
        Ok(())
    }

    /// Remove a connection from the pool
    pub async fn remove_connection(&self, connection: Arc<Mutex<PooledConnection>>) -> Result<()> {
        let conn = connection.lock().await;
        let target = conn.target.clone();
        drop(conn);

        if let Some(mut pool) = self.pools.get_mut(&target) {
            pool.retain(|c| !Arc::ptr_eq(c, &connection));
        }
        Ok(())
    }

    /// Clean up expired connections
    async fn cleanup_expired_connections(&self, pool: &mut Vec<Arc<Mutex<PooledConnection>>>) {
        let now = Instant::now();
        pool.retain(|conn| {
            let conn_guard = conn.try_lock();
            if let Ok(conn) = conn_guard {
                let age = now.duration_since(conn.last_used);
                age < self.config.max_idle_time && conn.state != ConnectionState::Closing
            } else {
                true // Keep locked connections
            }
        });
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let mut total_connections = 0;
        let mut available_connections = 0;
        let mut in_use_connections = 0;

        for pool in self.pools.iter() {
            for conn in pool.value() {
                total_connections += 1;
                if let Ok(conn) = conn.try_lock() {
                    match conn.state {
                        ConnectionState::Available => available_connections += 1,
                        ConnectionState::InUse => in_use_connections += 1,
                        ConnectionState::Closing => {}
                    }
                }
            }
        }

        PoolStats {
            total_connections,
            available_connections,
            in_use_connections,
            pools_count: self.pools.len(),
        }
    }

    /// Shutdown the connection pool
    pub async fn shutdown(&self) -> Result<()> {
        for pool in self.pools.iter() {
            for conn in pool.value() {
                let mut conn = conn.lock().await;
                conn.state = ConnectionState::Closing;
            }
        }
        self.pools.clear();
        Ok(())
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub available_connections: usize,
    pub in_use_connections: usize,
    pub pools_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = ConnectionPool::new(PoolConfig::default());

        // Get a connection
        let conn1 = pool.get_connection("example.com:80").await.unwrap();
        {
            let conn = conn1.lock().await;
            assert_eq!(conn.target, "example.com:80");
            assert_eq!(conn.state, ConnectionState::InUse);
        }

        // Return the connection
        pool.return_connection(conn1.clone()).await.unwrap();
        {
            let conn = conn1.lock().await;
            assert_eq!(conn.state, ConnectionState::Available);
        }

        // Get another connection
        let conn2 = pool.get_connection("example.com:80").await.unwrap();
        assert!(Arc::ptr_eq(&conn1, &conn2));

        // Check stats
        let stats = pool.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.available_connections, 0);
        assert_eq!(stats.in_use_connections, 1);
    }
}
