use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CaptureError {
    PcapError(String),
    InterfaceNotFound(String),
    ParseError(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CaptureError::PcapError(e) => write!(f, "PCap error: {}", e),
            CaptureError::InterfaceNotFound(name) => write!(f, "Interface not found: {}", name),
            CaptureError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl Error for CaptureError {}