use super::WireGuardError;

pub struct Device {
    pub listen_port: u16,
}

impl Device {
    pub fn new(listen_port: u16) -> Result<Self, WireGuardError> {
        Ok(Self { listen_port })
    }
}
