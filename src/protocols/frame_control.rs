use std::fmt;

/// Represents frame control information extracted from various protocol headers
#[derive(Debug)]
pub struct FrameControlInfo {
    pub protocol_type: ProtocolType,
    pub control_fields: Vec<ControlField>,
}

/// Types of protocols that may contain frame control information
#[derive(Debug)]
pub enum ProtocolType {
    Ethernet,
    WiFi,
    IPv4,
    IPv6,
    TCP,
    UDP,
    Other(String),
}

/// Represents a single control field with name and value
#[derive(Debug)]
pub struct ControlField {
    pub name: String,
    pub value: String,
    pub description: String,
}

impl fmt::Display for FrameControlInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Protocol: {:?}", self.protocol_type)?;
        for field in &self.control_fields {
            writeln!(f, "  {}: {} ({})", field.name, field.value, field.description)?;
        }
        Ok(())
    }
}

impl fmt::Display for ControlField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}