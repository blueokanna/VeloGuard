use thiserror::Error;

/// VeloGuard error types
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("DNS error: {message}")]
    Dns {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("TLS error: {message}")]
    Tls {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Protocol error: {message}")]
    Protocol {
        message: String,
        protocol: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {message}")]
    Parse {
        message: String,
        input: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authentication error: {message}")]
    Auth {
        message: String,
        username: Option<String>,
    },

    #[error("Timeout error: {message}")]
    Timeout {
        message: String,
        operation: Option<String>,
    },

    #[error("Resource exhausted: {message}")]
    ResourceExhausted {
        message: String,
        resource: Option<String>,
    },

    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Routing error: {message}")]
    Routing {
        message: String,
        rule_type: Option<String>,
        pattern: Option<String>,
    },

    #[error("Proxy error: {message}")]
    Proxy {
        message: String,
        proxy_type: Option<String>,
        target: Option<String>,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create a new configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new configuration error with source
    pub fn config_with_source<S: Into<String>, E: std::error::Error + Send + Sync + 'static>(
        message: S,
        source: E,
    ) -> Self {
        Self::Config {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new network error with source
    pub fn network_with_source<S: Into<String>, E: std::error::Error + Send + Sync + 'static>(
        message: S,
        source: E,
    ) -> Self {
        Self::Network {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new protocol error
    pub fn protocol<S: Into<String>>(message: S) -> Self {
        Self::Protocol {
            message: message.into(),
            protocol: None,
            source: None,
        }
    }

    /// Create a new protocol error with protocol info
    pub fn protocol_with_info<S: Into<String>, P: Into<String>>(message: S, protocol: P) -> Self {
        Self::Protocol {
            message: message.into(),
            protocol: Some(protocol.into()),
            source: None,
        }
    }

    /// Create a new parse error
    pub fn parse<S: Into<String>>(message: S) -> Self {
        Self::Parse {
            message: message.into(),
            input: None,
            source: None,
        }
    }

    /// Create a new parse error with input
    pub fn parse_with_input<S: Into<String>, I: Into<String>>(message: S, input: I) -> Self {
        Self::Parse {
            message: message.into(),
            input: Some(input.into()),
            source: None,
        }
    }

    /// Create a new routing error
    pub fn routing<S: Into<String>>(message: S) -> Self {
        Self::Routing {
            message: message.into(),
            rule_type: None,
            pattern: None,
        }
    }

    /// Create a new proxy error
    pub fn proxy<S: Into<String>>(message: S) -> Self {
        Self::Proxy {
            message: message.into(),
            proxy_type: None,
            target: None,
        }
    }

    /// Get error code/category for external use
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config { .. } => "CONFIG",
            Self::Network { .. } => "NETWORK",
            Self::Dns { .. } => "DNS",
            Self::Tls { .. } => "TLS",
            Self::Protocol { .. } => "PROTOCOL",
            Self::Io(_) => "IO",
            Self::Parse { .. } => "PARSE",
            Self::Auth { .. } => "AUTH",
            Self::Timeout { .. } => "TIMEOUT",
            Self::ResourceExhausted { .. } => "RESOURCE_EXHAUSTED",
            Self::Internal { .. } => "INTERNAL",
            Self::Routing { .. } => "ROUTING",
            Self::Proxy { .. } => "PROXY",
        }
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Network { .. } | Self::Timeout { .. } | Self::Io(_) => true,
            Self::Config { .. } | Self::Parse { .. } | Self::Protocol { .. } => false,
            _ => true,
        }
    }
}
