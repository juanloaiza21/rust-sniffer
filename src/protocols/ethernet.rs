use super::frame_control::{FrameControlInfo, ProtocolType, ControlField};
use super::ipv4::IPv4Packet;
use super::ipv6::IPv6Packet;
use std::fmt;

/// Ethernet frame parser
pub struct EthernetFrame<'a> {
    data: &'a [u8],
}

#[derive(Debug)]
pub struct MacAddress([u8; 6]);

#[derive(Debug)]
pub struct EtherType(u16);

/// Error types for Ethernet frame parsing
#[derive(Debug)]
pub enum EthernetError {
    TooShort,
    InvalidFormat,
}

impl fmt::Display for EthernetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthernetError::TooShort => write!(f, "Packet too short for Ethernet frame"),
            EthernetError::InvalidFormat => write!(f, "Invalid Ethernet frame format"),
        }
    }
}

impl<'a> EthernetFrame<'a> {
    /// Parse raw bytes into an Ethernet frame
    pub fn parse(data: &'a [u8]) -> Result<Self, EthernetError> {
        if data.len() < 14 {
            return Err(EthernetError::TooShort);
        }
        
        // Simple validation that this looks like an Ethernet frame
        // In a full implementation, you might do more validation here
        
        Ok(EthernetFrame { data })
    }
    
    /// Get destination MAC address
    pub fn dest_mac(&self) -> MacAddress {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.data[0..6]);
        MacAddress(mac)
    }
    
    /// Get source MAC address
    pub fn src_mac(&self) -> MacAddress {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.data[6..12]);
        MacAddress(mac)
    }
    
    /// Get EtherType
    pub fn ether_type(&self) -> EtherType {
        let etype = ((self.data[12] as u16) << 8) | (self.data[13] as u16);
        EtherType(etype)
    }
    
    /// Get payload data
    pub fn payload(&self) -> &[u8] {
        &self.data[14..]
    }
    
    /// Get frame control information
    pub fn get_frame_control(&self) -> FrameControlInfo {
        let src_mac = self.src_mac();
        let dst_mac = self.dest_mac();
        let etype = self.ether_type();
        
        let mut control_fields = vec![
            ControlField {
                name: "Source MAC".to_string(),
                value: format!("{}", src_mac),
                description: "Source hardware address".to_string(),
            },
            ControlField {
                name: "Destination MAC".to_string(),
                value: format!("{}", dst_mac),
                description: "Destination hardware address".to_string(),
            },
            ControlField {
                name: "EtherType".to_string(),
                value: format!("{}", etype),
                description: etype.get_protocol_description(),
            },
        ];
        
        // Add deeper protocol inspection based on EtherType
        match etype.0 {
            0x0800 => {
                // IPv4
                if let Ok(ipv4) = IPv4Packet::parse(self.payload()) {
                    let ipv4_control = ipv4.get_control_fields();
                    control_fields.extend(ipv4_control);
                }
            },
            0x86DD => {
                // IPv6
                if let Ok(ipv6) = IPv6Packet::parse(self.payload()) {
                    let ipv6_control = ipv6.get_control_fields();
                    control_fields.extend(ipv6_control);
                }
            },
            // Other protocols can be added here
            _ => {}
        }
        
        FrameControlInfo {
            protocol_type: ProtocolType::Ethernet,
            control_fields,
        }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, 
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

impl EtherType {
    pub fn get_protocol_description(&self) -> String {
        match self.0 {
            0x0800 => "IPv4".to_string(),
            0x0806 => "ARP".to_string(),
            0x86DD => "IPv6".to_string(),
            0x8100 => "VLAN".to_string(),
            0x88CC => "LLDP".to_string(),
            _ => format!("Unknown (0x{:04x})", self.0),
        }
    }
}