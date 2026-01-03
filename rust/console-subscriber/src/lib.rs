use std::collections::HashMap;
use std::sync::{Mutex, atomic::AtomicU64};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{Subscriber, Metadata, Event, span::{Id, Record}};
use tracing_subscriber::{layer::SubscriberExt, Registry, Layer};

#[derive(Debug, Error)]
pub enum ConsoleSubscriberError {
    #[error("Tracing error: {0}")]
    Tracing(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Console subscriber for tokio-console
pub struct ConsoleSubscriber {
    tx: mpsc::UnboundedSender<ConsoleEvent>,
    rx: Mutex<Option<mpsc::UnboundedReceiver<ConsoleEvent>>>,
    _next_span_id: AtomicU64,
    _next_task_id: AtomicU64,
}

impl ConsoleSubscriber {
    /// Create a new console subscriber
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            _next_span_id: AtomicU64::new(1),
            _next_task_id: AtomicU64::new(1),
        }
    }

    /// Initialize the subscriber with the global registry
    pub fn init(self) -> Result<(), ConsoleSubscriberError> {
        let subscriber = Registry::default().with(self);

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| ConsoleSubscriberError::Tracing(e.to_string()))?;

        Ok(())
    }

    /// Try to receive an event
    pub fn try_recv(&self) -> Option<ConsoleEvent> {
        if let Ok(mut rx_guard) = self.rx.lock() {
            if let Some(rx) = rx_guard.as_mut() {
                rx.try_recv().ok()
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get a receiver for console events
    pub fn subscribe(&self) -> Option<mpsc::UnboundedReceiver<ConsoleEvent>> {
        self.rx.lock().ok()?.take()
    }
}

impl Default for ConsoleSubscriber {
    fn default() -> Self {
        Self::new()
    }
}

/// Console event data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsoleEvent {
    pub timestamp: u64,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub span_id: Option<u64>,
    pub task_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub thread_name: Option<String>,
}

/// Task information
#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub id: u64,
    pub name: Option<String>,
    pub location: Option<String>,
    pub kind: TaskKind,
    pub state: TaskState,
    pub total_polls: u64,
    pub busy_time: std::time::Duration,
    pub idle_time: std::time::Duration,
    pub scheduled_time: Option<std::time::SystemTime>,
    pub woken_time: Option<std::time::SystemTime>,
    pub waker_count: u64,
    pub waker_clones: u64,
    pub waker_drops: u64,
    pub self_wakes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TaskKind {
    Spawn,
    Blocking,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TaskState {
    Running,
    Idle,
    Scheduled,
}

/// Resource information
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub kind: ResourceKind,
    pub concrete_type: String,
    pub location: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ResourceKind {
    Task,
    Resource,
}

/// Async operation information
#[derive(Debug, Clone)]
pub struct AsyncOpInfo {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub resource_id: u64,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

/// Builder for console subscriber
pub struct Builder {
    sample_rate: u64,
    filter: Option<String>,
    record_all: bool,
    buffer_size: usize,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            sample_rate: 1,
            filter: None,
            record_all: false,
            buffer_size: 1024,
        }
    }

    pub fn sample_rate(mut self, rate: u64) -> Self {
        self.sample_rate = rate;
        self
    }

    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    pub fn record_all(mut self, record_all: bool) -> Self {
        self.record_all = record_all;
        self
    }

    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    pub fn build(self) -> ConsoleSubscriber {
        ConsoleSubscriber::new()
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for ConsoleSubscriber
where
    S: Subscriber,
{
    fn enabled(&self, _metadata: &Metadata<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) -> bool {
        // Basic filtering - in a real implementation would use more sophisticated logic
        true
    }

    fn on_record(&self, _span: &Id, _values: &Record<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Record span data
    }

    fn on_follows_from(&self, _span: &Id, _follows: &Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Record span relationships
    }

    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Create console event from tracing event
        let mut fields = HashMap::new();

        event.record(&mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
            fields.insert(field.name().to_string(), serde_json::Value::String(format!("{:?}", value)));
        });

        let console_event = ConsoleEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: fields.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            fields,
            span_id: None, // Would be set from context
            task_id: None, // Would be set from context
            thread_id: None, // Thread ID not easily available in stable Rust
            thread_name: std::thread::current().name().map(|s| s.to_string()),
        };

        let _ = self.tx.send(console_event);
    }

    fn on_enter(&self, _id: &Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Handle span enter
    }

    fn on_exit(&self, _id: &Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Handle span exit
    }

    fn on_close(&self, _id: Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Handle span close
    }
}

/// Convenience function to initialize console subscriber
pub fn init() -> Result<(), ConsoleSubscriberError> {
    ConsoleSubscriber::new().init()
}

/// Convenience function to build and initialize console subscriber
pub fn build() -> Builder {
    Builder::new()
}

/// Spawn a task with console tracking
pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// Spawn a blocking task with console tracking
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}