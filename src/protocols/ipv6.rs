use super::frame_control::ControlField;
use std::fmt;
use std::net::Ipv6Addr;

pub struct IPv6Packet<'a> {
    data: &'a [u8],
}

#[derive(Debug)]
pub enum IPv6Error {
    TooShort,
    InvalidVersion,
}

impl fmt::Display for IPv6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IPv6Error::TooShort => write!(f, "Packet too short for IPv6 header"),
            IPv6Error::InvalidVersion => write!(f, "Invalid IP version"),
        }
    }
}

impl<'a> IPv6Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, IPv6Error> {
        if data.len() < 40 {
            return Err(IPv6Error::TooShort);
        }
        
        let version = (data[0] & 0xF0) >> 4;
        if version != 6 {
            return Err(IPv6Error::InvalidVersion);
        }
        
        Ok(IPv6Packet { data })
    }
    
    pub fn version(&self) -> u8 {
        (self.data[0] & 0xF0) >> 4
    }
    
    pub fn traffic_class(&self) -> u8 {
        ((self.data[0] & 0x0F) << 4) | ((self.data[1] & 0xF0) >> 4)
    }
    
    pub fn flow_label(&self) -> u32 {
        (((self.data[1] as u32) & 0x0F) << 16) |
        ((self.data[2] as u32) << 8) |
        (self.data[3] as u32)
    }
    
    pub fn payload_length(&self) -> u16 {
        ((self.data[4] as u16) << 8) | (self.data[5] as u16)
    }
    
    pub fn next_header(&self) -> u8 {
        self.data[6]
    }
    
    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }
    
    pub fn source_ip(&self) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[8..24]);
        Ipv6Addr::from(addr)
    }
    
    pub fn destination_ip(&self) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[24..40]);
        Ipv6Addr::from(addr)
    }
    
    pub fn get_next_header_name(&self) -> String {
        match self.next_header() {
            0 => "Hop-by-Hop Options".to_string(),
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            43 => "Routing".to_string(),
            44 => "Fragment".to_string(),
            50 => "ESP".to_string(),
            51 => "AH".to_string(),
            58 => "ICMPv6".to_string(),
            59 => "No Next Header".to_string(),
            60 => "Destination Options".to_string(),
            _ => format!("Unknown ({})", self.next_header()),
        }
    }
    
    pub fn get_control_fields(&self) -> Vec<ControlField> {
        vec![
            ControlField {
                name: "IP Version".to_string(),
                value: self.version().to_string(),
                description: "Internet Protocol version".to_string(),
            },
            ControlField {
                name: "Traffic Class".to_string(),
                value: format!("0x{:02x}", self.traffic_class()),
                description: "Traffic class field".to_string(),
            },
            ControlField {
                name: "Flow Label".to_string(),
                value: format!("0x{:05x}", self.flow_label()),
                description: "Flow label field".to_string(),
            },
            ControlField {
                name: "Payload Length".to_string(),
                value: self.payload_length().to_string(),
                description: "Length of the payload in bytes".to_string(),
            },
            ControlField {
                name: "Next Header".to_string(),
                value: self.next_header().to_string(),
                description: self.get_next_header_name(),
            },
            ControlField {
                name: "Hop Limit".to_string(),
                value: self.hop_limit().to_string(),
                description: "Hop limit (similar to IPv4 TTL)".to_string(),
            },
            ControlField {
                name: "Source IP".to_string(),
                value: self.source_ip().to_string(),
                description: "Source IPv6 address".to_string(),
            },
            ControlField {
                name: "Destination IP".to_string(),
                value: self.destination_ip().to_string(),
                description: "Destination IPv6 address".to_string(),
            },
        ]
    }
}