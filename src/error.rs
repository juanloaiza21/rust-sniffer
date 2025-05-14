use thiserror::Error;
use pcap::Error as PcapError;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Pcap error: {0}")]
    PcapError(#[from] PcapError),
}
