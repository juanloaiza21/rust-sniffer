use super::frame_control::ControlField;
use std::fmt;
use std::net::Ipv4Addr;

pub struct IPv4Packet<'a> {
    data: &'a [u8],
}

#[derive(Debug)]
pub enum IPv4Error {
    TooShort,
    InvalidVersion,
    InvalidHeaderLength,
}

impl fmt::Display for IPv4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IPv4Error::TooShort => write!(f, "Packet too short for IPv4 header"),
            IPv4Error::InvalidVersion => write!(f, "Invalid IP version"),
            IPv4Error::InvalidHeaderLength => write!(f, "Invalid IPv4 header length"),
        }
    }
}

impl<'a> IPv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, IPv4Error> {
        if data.len() < 20 {
            return Err(IPv4Error::TooShort);
        }
        
        let version = (data[0] & 0xF0) >> 4;
        if version != 4 {
            return Err(IPv4Error::InvalidVersion);
        }
        
        let ihl = data[0] & 0x0F;
        if ihl < 5 {
            return Err(IPv4Error::InvalidHeaderLength);
        }
        
        Ok(IPv4Packet { data })
    }
    
    pub fn version(&self) -> u8 {
        (self.data[0] & 0xF0) >> 4
    }
    
    pub fn header_length(&self) -> u8 {
        (self.data[0] & 0x0F) * 4  // In bytes
    }
    
    pub fn dscp(&self) -> u8 {
        (self.data[1] & 0xFC) >> 2
    }
    
    pub fn ecn(&self) -> u8 {
        self.data[1] & 0x03
    }
    
    pub fn total_length(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }
    
    pub fn identification(&self) -> u16 {
        ((self.data[4] as u16) << 8) | (self.data[5] as u16)
    }
    
    pub fn flags(&self) -> u8 {
        (self.data[6] & 0xE0) >> 5
    }
    
    pub fn fragment_offset(&self) -> u16 {
        (((self.data[6] as u16) & 0x1F) << 8) | (self.data[7] as u16)
    }
    
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }
    
    pub fn protocol(&self) -> u8 {
        self.data[9]
    }
    
    pub fn checksum(&self) -> u16 {
        ((self.data[10] as u16) << 8) | (self.data[11] as u16)
    }
    
    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15])
    }
    
    pub fn destination_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19])
    }
    
    pub fn get_protocol_name(&self) -> String {
        match self.protocol() {
            1 => "ICMP".to_string(),
            2 => "IGMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            _ => format!("Unknown ({})", self.protocol()),
        }
    }
    
    pub fn get_flags_description(&self) -> String {
        let flags = self.flags();
        let mut desc = Vec::new();
        
        if flags & 0x01 != 0 { desc.push("More Fragments"); }
        if flags & 0x02 != 0 { desc.push("Don't Fragment"); }
        if flags & 0x04 != 0 { desc.push("Reserved"); }
        
        if desc.is_empty() {
            "None".to_string()
        } else {
            desc.join(", ")
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
                name: "Header Length".to_string(),
                value: self.header_length().to_string(),
                description: "IP header length in bytes".to_string(),
            },
            ControlField {
                name: "DSCP".to_string(),
                value: self.dscp().to_string(),
                description: "Differentiated Services Code Point".to_string(),
            },
            ControlField {
                name: "ECN".to_string(),
                value: self.ecn().to_string(),
                description: "Explicit Congestion Notification".to_string(),
            },
            ControlField {
                name: "Total Length".to_string(),
                value: self.total_length().to_string(),
                description: "Total packet length in bytes".to_string(),
            },
            ControlField {
                name: "Identification".to_string(),
                value: format!("0x{:04x}", self.identification()),
                description: "Packet identification for fragmentation".to_string(),
            },
            ControlField {
                name: "Flags".to_string(),
                value: format!("0x{:02x}", self.flags()),
                description: self.get_flags_description(),
            },
            ControlField {
                name: "Fragment Offset".to_string(),
                value: self.fragment_offset().to_string(),
                description: "Fragment offset in 8-byte units".to_string(),
            },
            ControlField {
                name: "TTL".to_string(),
                value: self.ttl().to_string(),
                description: "Time to Live".to_string(),
            },
            ControlField {
                name: "Protocol".to_string(),
                value: self.protocol().to_string(),
                description: self.get_protocol_name(),
            },
            ControlField {
                name: "Checksum".to_string(),
                value: format!("0x{:04x}", self.checksum()),
                description: "Header checksum".to_string(),
            },
            ControlField {
                name: "Source IP".to_string(),
                value: self.source_ip().to_string(),
                description: "Source IP address".to_string(),
            },
            ControlField {
                name: "Destination IP".to_string(),
                value: self.destination_ip().to_string(),
                description: "Destination IP address".to_string(),
            },
        ]
    }
}