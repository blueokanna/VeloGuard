//! TLS error types

use std::fmt;

/// TLS operation result type
pub type Result<T> = std::result::Result<T, Error>;

/// TLS error types
#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(std::io::Error),

    /// Invalid certificate
    InvalidCertificate(String),

    /// Certificate verification failed
    CertificateVerification(String),

    /// Handshake failed
    HandshakeFailed(String),

    /// Protocol error
    Protocol(String),

    /// Alert received
    AlertReceived(AlertDescription),

    /// Unsupported feature
    Unsupported(String),

    /// Invalid record
    InvalidRecord(String),

    /// Decrypt error
    DecryptError(String),

    /// Encrypt error
    EncryptError(String),

    /// Key exchange error
    KeyExchange(String),

    /// Bad record MAC
    BadRecordMac,

    /// Unexpected message
    UnexpectedMessage(String),

    /// Corrupt message
    CorruptMessage(String),

    /// Invalid signature
    InvalidSignature,

    /// No certificates presented
    NoCertificatesPresented,

    /// Decoding error
    DecodingError(String),

    /// Encoding error
    EncodingError(String),
}

/// TLS alert descriptions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114,
    UnknownPskIdentity = 115,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::InvalidCertificate(s) => write!(f, "Invalid certificate: {}", s),
            Error::CertificateVerification(s) => write!(f, "Certificate verification failed: {}", s),
            Error::HandshakeFailed(s) => write!(f, "Handshake failed: {}", s),
            Error::Protocol(s) => write!(f, "Protocol error: {}", s),
            Error::AlertReceived(alert) => write!(f, "Alert received: {:?}", alert),
            Error::Unsupported(s) => write!(f, "Unsupported feature: {}", s),
            Error::InvalidRecord(s) => write!(f, "Invalid record: {}", s),
            Error::DecryptError(s) => write!(f, "Decrypt error: {}", s),
            Error::EncryptError(s) => write!(f, "Encrypt error: {}", s),
            Error::KeyExchange(s) => write!(f, "Key exchange error: {}", s),
            Error::BadRecordMac => write!(f, "Bad record MAC"),
            Error::UnexpectedMessage(s) => write!(f, "Unexpected message: {}", s),
            Error::CorruptMessage(s) => write!(f, "Corrupt message: {}", s),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::NoCertificatesPresented => write!(f, "No certificates presented"),
            Error::DecodingError(s) => write!(f, "Decoding error: {}", s),
            Error::EncodingError(s) => write!(f, "Encoding error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<AlertDescription> for Error {
    fn from(alert: AlertDescription) -> Self {
        Error::AlertReceived(alert)
    }
}
