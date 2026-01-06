use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    pub enable_sni: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: false,
            enable_sni: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            certificate: String::new(),
            private_key: String::new(),
            alpn: vec!["h2".into(), "http/1.1".into()],
        }
    }
}
