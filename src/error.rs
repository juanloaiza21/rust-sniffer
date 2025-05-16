use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum CaptureError {
    NetworkError(String),
    ParseError(String),
    InputError(String),
    PcapError(String),           // Added for PCAP-related errors
    InterfaceNotFound(String),   // Added for interface not found errors
    Other(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CaptureError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            CaptureError::InputError(msg) => write!(f, "Input error: {}", msg),
            CaptureError::PcapError(msg) => write!(f, "PCAP error: {}", msg),
            CaptureError::InterfaceNotFound(msg) => write!(f, "Interface not found: {}", msg),
            CaptureError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl StdError for CaptureError {}

// Implement From<Box<dyn StdError>> for CaptureError
impl From<Box<dyn StdError>> for CaptureError {
    fn from(error: Box<dyn StdError>) -> Self {
        CaptureError::Other(error.to_string())
    }
}
