use tokio::net::UdpSocket;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bvlc::BVLCHeader;


const BIT7_MASK: u8 = 0b1000_0000;
const BIT5_MASK: u8 = 0b0010_0000;
pub const BVLC_HEADER_SIZE: usize = 4;

pub struct NPDUServer {
    socket: Arc<Mutex<UdpSocket>>,
}

#[derive(Debug, PartialEq)]
pub struct NPDU {
    protocol_version: u8,
    control: u8,
    message_type: Option<u8>,
    destination_network_address: Option<u16>,
    destination_mac_address_length: Option<u8>,
    hop_count: Option<u8>,
}

#[derive(PartialEq, Debug)]
enum MessageType {
    WhoIsRouterToNetwork,
    IAmRouterToNetwork,
    ICouldBeRouterToNetwork,
    RejectMessageToNetwork,
    RouterBusyToNetwork,
    RouterAvailableToNetwork,
    InitializeRoutingTable,
    InitializeRoutingTableAck,
    EstablishConnectionToNetwork,
    DisconnectConnectionToNetwork,
    WhatIsNetworkNumber,
    NetworkNumberIs,
    ReservedForAshrae(u8),
    VendorProprietary(u8),
}

impl MessageType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(MessageType::WhoIsRouterToNetwork),
            0x01 => Some(MessageType::IAmRouterToNetwork),
            0x02 => Some(MessageType::ICouldBeRouterToNetwork),
            0x03 => Some(MessageType::RejectMessageToNetwork),
            0x04 => Some(MessageType::RouterBusyToNetwork),
            0x05 => Some(MessageType::RouterAvailableToNetwork),
            0x06 => Some(MessageType::InitializeRoutingTable),
            0x07 => Some(MessageType::InitializeRoutingTableAck),
            0x08 => Some(MessageType::EstablishConnectionToNetwork),
            0x09 => Some(MessageType::DisconnectConnectionToNetwork),
            // range in between removed by ASHRAE
            0x12 => Some(MessageType::WhatIsNetworkNumber),
            0x13 => Some(MessageType::NetworkNumberIs),
            0x14..=0x7F => Some(MessageType::ReservedForAshrae(value)),
            0x80..=0xFF => Some(MessageType::VendorProprietary(value)),
            _ => None,

        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            MessageType::WhoIsRouterToNetwork => 0x00,
            MessageType::IAmRouterToNetwork => 0x01,
            MessageType::ICouldBeRouterToNetwork => 0x02,
            MessageType::RejectMessageToNetwork => 0x03,
            MessageType::RouterBusyToNetwork => 0x04,
            MessageType::RouterAvailableToNetwork => 0x05,
            MessageType::InitializeRoutingTable => 0x06,
            MessageType::InitializeRoutingTableAck => 0x07,
            MessageType::EstablishConnectionToNetwork => 0x08,
            MessageType::DisconnectConnectionToNetwork => 0x09,
            MessageType::WhatIsNetworkNumber => 0x12,
            MessageType::NetworkNumberIs => 0x13,
            MessageType::ReservedForAshrae(value) => *value,
            MessageType::VendorProprietary(value) => *value,
        }
    }
}

impl NPDU {

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.protocol_version);
        data.push(self.control);

        if let Some(dna) = self.destination_network_address {
            data.extend_from_slice(&dna.to_be_bytes()); // Add network address
        }

        if let Some(dmal) = self.destination_mac_address_length {
            data.push(dmal); // Add MAC address length
        }

        if let Some(mt) = self.message_type {
            data.push(mt);
        }

        if let Some(hc) = self.hop_count {
            data.push(hc);
        }

        data
    }

    pub fn decode(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        // First, check if there's enough data for protocol version and control fields
        if data.len() < 2 {
            return Err("Data too short to be an NPDU".into());
        }

        let protocol_version = data[0];
        if protocol_version != 1 {
            return Err(format!("Unexpected protocol version: {}", protocol_version).into());
        }

        let control = data[1];
        let mut offset = 2; // Start after protocol version and control

        // Initialize fields with None
        let mut message_type = None;
        let mut destination_network_address = None;
        let mut destination_mac_address_length = None;
        let mut hop_count = None;

        // Check for destination fields if control indicates their presence
        if control & BIT5_MASK != 0 {
            // Check if enough data for destination network address
            if data.len() < offset + 3 { // +3 because 2 bytes for address + 1 for MAC length
                return Err("Data too short for destination network address".into());
            }

            destination_network_address = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 2;

            destination_mac_address_length = Some(data[offset]);
            offset += 1;
        }

        // Check for message type field if control indicates its presence
        if control & BIT7_MASK != 0 {
            if data.len() <= offset {
                return Err("Data too short for message type".into());
            }
            message_type = Some(data[offset]);
            offset += 1;
        }

        // Check for hop count field if control indicates its presence
        if control & BIT5_MASK != 0 {
            if data.len() <= offset {
                return Err("Data too short for hop count".into());
            }
            hop_count = Some(data[offset]);
            if hop_count == Some(0) {
                return Err("Hop count cannot be zero".into());
            }
            offset += 1;
        }

        Ok(NPDU {
            protocol_version,
            control,
            message_type,
            destination_network_address,
            destination_mac_address_length,
            hop_count,
        })
    }
}
    
impl NPDUServer {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(NPDUServer {
            socket: Arc::new(Mutex::new(socket)),
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let mut buf = [0u8; 1024];
        loop {
            let (len, src) = self.socket.lock().await.recv_from(&mut buf).await?;
            println!("Received {} bytes from {}", len, src);

            // Handle BVLC
            if let Ok(bvlc_header) = BVLCHeader::parse(&buf[..len]) {
                println!("BVLC header parsed successfully.");

                // Assuming NPDU is immediately after BVLC
                match NPDU::decode(&buf[BVLC_HEADER_SIZE..len]) {
                    Ok(npdu) => {
                        println!("NPDU decoded successfully: {:?}", npdu);
                        // Further processing...
                    },
                    Err(e) => eprintln!("Failed to decode NPDU: {}", e),
                }
            } else {
                eprintln!("Failed to parse BVLC header.");
            }
        }
    }
}


pub fn handle_incoming_message(data: &[u8]) {
    if let Ok(bvlc_header) = BVLCHeader::parse(data) {
        // Process BVLC header, then NPDU
    }
    // ... handle errors or other cases ...
}



#[cfg(test)]
mod tests {
    use super::*; // Import everything from the outer module

    #[test]
    fn test_message_type_from_u8() {
        assert_eq!(MessageType::from_u8(0x00), Some(MessageType::WhoIsRouterToNetwork));
        assert_eq!(MessageType::from_u8(0x01), Some(MessageType::IAmRouterToNetwork));
        assert_eq!(MessageType::from_u8(0x02), Some(MessageType::ICouldBeRouterToNetwork));
        assert_eq!(MessageType::from_u8(0x03), Some(MessageType::RejectMessageToNetwork));
        assert_eq!(MessageType::from_u8(0x04), Some(MessageType::RouterBusyToNetwork));
        assert_eq!(MessageType::from_u8(0x05), Some(MessageType::RouterAvailableToNetwork));
        assert_eq!(MessageType::from_u8(0x06), Some(MessageType::InitializeRoutingTable));
        assert_eq!(MessageType::from_u8(0x07), Some(MessageType::InitializeRoutingTableAck));
        assert_eq!(MessageType::from_u8(0x08), Some(MessageType::EstablishConnectionToNetwork));
        assert_eq!(MessageType::from_u8(0x09), Some(MessageType::DisconnectConnectionToNetwork));
        assert_eq!(MessageType::from_u8(0x12), Some(MessageType::WhatIsNetworkNumber));
        assert_eq!(MessageType::from_u8(0x13), Some(MessageType::NetworkNumberIs));
        assert_eq!(MessageType::ReservedForAshrae(0x14).to_u8(), 0x14);
        assert_eq!(MessageType::ReservedForAshrae(0x7F).to_u8(), 0x7F);
    }

    #[test]
    fn test_message_type_to_u8() {
        assert_eq!(MessageType::WhoIsRouterToNetwork.to_u8(), 0x00);
        assert_eq!(MessageType::IAmRouterToNetwork.to_u8(), 0x01);
        assert_eq!(MessageType::ICouldBeRouterToNetwork.to_u8(), 0x02);
        assert_eq!(MessageType::RejectMessageToNetwork.to_u8(), 0x03);
        assert_eq!(MessageType::RouterBusyToNetwork.to_u8(), 0x04);
        assert_eq!(MessageType::RouterAvailableToNetwork.to_u8(), 0x05);
        assert_eq!(MessageType::InitializeRoutingTable.to_u8(), 0x06);
        assert_eq!(MessageType::InitializeRoutingTableAck.to_u8(), 0x07);
        assert_eq!(MessageType::EstablishConnectionToNetwork.to_u8(), 0x08);
        assert_eq!(MessageType::DisconnectConnectionToNetwork.to_u8(), 0x09);
        assert_eq!(MessageType::WhatIsNetworkNumber.to_u8(), 0x12);
        assert_eq!(MessageType::NetworkNumberIs.to_u8(), 0x13);
        assert_eq!(MessageType::VendorProprietary(0x80).to_u8(), 0x80);
        assert_eq!(MessageType::VendorProprietary(0xFF).to_u8(), 0xFF);

    }

    #[cfg(test)]
    mod tests {
        use super::*;
    
        #[test]
        fn test_from_whois_iam_pcap_num_8() {
            // NPDU data extracted from the pcap of BACnet router
            let real_data = [
                0x01, // Version
                0x20, // Control
                0xFF, 0xFF, // Destination Network Address (65535)
                0x00, // Destination MAC Layer Address Length (0 - broadcast)
                0xFF, // Hop Count (255)
                // ... (additional APDU data if needed)
            ];
    
            let decoded = NPDU::decode(&real_data).unwrap();
    
            // Assert specific values based on known real-world data
            assert_eq!(decoded.protocol_version, 1);
            assert_eq!(decoded.control, 0x20);
            assert_eq!(decoded.destination_network_address, Some(65535)); // 0xFFFF
            assert_eq!(decoded.destination_mac_address_length, Some(0)); // Broadcast
            assert_eq!(decoded.hop_count, Some(255)); // 0xFF
        }
    }
    
}
