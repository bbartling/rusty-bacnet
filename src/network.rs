use std::error::Error;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::bvlc::BVLCHeader;

const BIT7_MASK: u8 = 0b1000_0000;
const BIT5_MASK: u8 = 0b0010_0000;
const BIT3_MASK: u8 = 0b0000_1000;
const MAX_MAC_LEN: usize = 6;

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
    destination_mac_address: Option<Vec<u8>>, // Update decoding logic if needed
    hop_count: Option<u8>,
    source_network_address: Option<u16>,
    source_mac_address_length: Option<u8>,
    source_mac_address: Option<Vec<u8>>, // Update decoding logic if needed
    network_message_type: Option<u8>,    // Optional, based on Bit 7
    vendor_specific_parameters: Option<Vec<u8>>, // Update decoding logic if needed
    priority: NetworkPriority,           // Removed Option
    data_expecting_reply: bool,
}

#[derive(Debug, PartialEq)]
pub enum NetworkPriority {
    Normal,
    Urgent,
    CriticalEquipment,
    LifeSafety,
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

        // Handle Destination fields based on control bit
        if self.control & BIT5_MASK != 0 {
            if let Some(dna) = self.destination_network_address {
                data.extend_from_slice(&dna.to_be_bytes()); // Add network address

                if let Some(dmal) = self.destination_mac_address_length {
                    data.push(dmal); // Add MAC address length
                                     // Append the DADR field if needed (not shown here)
                }
            }
            if let Some(hc) = self.hop_count {
                data.push(hc);
            }
        }

        // Handle Source fields based on control bit
        // Similar logic as above for SNET, SLEN, SADR

        // Handle Message Type
        if self.control & BIT7_MASK != 0 {
            if let Some(mt) = self.message_type {
                data.push(mt);
            }
        }

        data
    }


    pub fn decode(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        println!("NPDU Data: {:?}", data);

        if data.len() < 2 {
            return Err("Data too short to be an NPDU".into());
        }

        let protocol_version = data[0];
        if protocol_version != 1 {
            return Err(format!("Unexpected protocol version: {}", protocol_version).into());
        }

        let control = data[1];

        let mut message_type = None;
        let mut destination_network_address = None;
        let mut destination_mac_address_length = None;
        let mut destination_mac_address = None;
        let mut hop_count = None;
        let mut source_network_address = None;
        let mut source_mac_address_length = None;
        let mut source_mac_address = None;

        let mut len = 2; // Start after protocol version and control

        if control & BIT5_MASK != 0 {
            if data.len() >= len + 3 {
                destination_network_address = Some(u16::from_be_bytes([data[len], data[len + 1]]));
                len += 2;

                let dlen = data[len] as usize;
                len += 1;

                if dlen > MAX_MAC_LEN || data.len() < len + dlen {
                    return Err("Invalid length for destination MAC address".into());
                }

                destination_mac_address_length = Some(dlen as u8);
                if dlen > 0 {
                    destination_mac_address = Some(data[len..len + dlen].to_vec());
                    len += dlen;
                }
            } else {
                return Err("Data too short for destination network address".into());
            }
        }

        if control & BIT3_MASK != 0 {
            if data.len() >= len + 3 {
                source_network_address = Some(u16::from_be_bytes([data[len], data[len + 1]]));
                len += 2;

                let slen = data[len] as usize;
                len += 1;

                if slen > MAX_MAC_LEN || data.len() < len + slen {
                    return Err("Invalid length for source MAC address".into());
                }

                source_mac_address_length = Some(slen as u8);
                if slen > 0 {
                    source_mac_address = Some(data[len..len + slen].to_vec());
                    len += slen;
                }
            } else {
                return Err("Data too short for source network address".into());
            }
        }

        if control & BIT7_MASK != 0 {
            if data.len() > len {
                message_type = Some(data[len]);
                len += 1;
            } else {
                return Err("Data too short for message type".into());
            }
        }

        if control & BIT5_MASK != 0 {
            if data.len() > len {
                hop_count = Some(data[len]);
                if hop_count == Some(0) {
                    return Err("Hop count cannot be zero".into());
                }
                len += 1;
            } else {
                hop_count = None;
            }
        }

        let priority = match control & 0b00000011 {
            0b00 => NetworkPriority::Normal,
            0b01 => NetworkPriority::Urgent,
            0b10 => NetworkPriority::CriticalEquipment,
            0b11 => NetworkPriority::LifeSafety,
            _ => return Err("Invalid priority bits".into()),
        };

        let data_expecting_reply = control & 0b00000100 != 0;

        Ok(NPDU {
            protocol_version,
            control,
            message_type,
            destination_network_address,
            destination_mac_address_length,
            destination_mac_address,
            hop_count,
            source_network_address,
            source_mac_address_length,
            source_mac_address,
            network_message_type: None, // Optional, based on Bit 7
            vendor_specific_parameters: None, // Optional, for vendor-specific implementations
            priority,
            data_expecting_reply,
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
            // if let Ok(bvlc_header) = BVLCHeader::parse(&buf[..len]) {
            if let Ok(_bvlc_header) = BVLCHeader::parse(&buf[..len]) {
                println!("BVLC header parsed successfully.");

                // Assuming NPDU is immediately after BVLC
                match NPDU::decode(&buf[BVLC_HEADER_SIZE..len]) {
                    Ok(npdu) => {
                        println!("NPDU decoded successfully: {:?}", npdu);
                        // Further processing...
                    }
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
        assert_eq!(
            MessageType::from_u8(0x00),
            Some(MessageType::WhoIsRouterToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x01),
            Some(MessageType::IAmRouterToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x02),
            Some(MessageType::ICouldBeRouterToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x03),
            Some(MessageType::RejectMessageToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x04),
            Some(MessageType::RouterBusyToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x05),
            Some(MessageType::RouterAvailableToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x06),
            Some(MessageType::InitializeRoutingTable)
        );
        assert_eq!(
            MessageType::from_u8(0x07),
            Some(MessageType::InitializeRoutingTableAck)
        );
        assert_eq!(
            MessageType::from_u8(0x08),
            Some(MessageType::EstablishConnectionToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x09),
            Some(MessageType::DisconnectConnectionToNetwork)
        );
        assert_eq!(
            MessageType::from_u8(0x12),
            Some(MessageType::WhatIsNetworkNumber)
        );
        assert_eq!(
            MessageType::from_u8(0x13),
            Some(MessageType::NetworkNumberIs)
        );
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

    #[test]
    fn test_from_whois_iam_pcap_packet_8() {
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

    #[test]
    fn test_from_whois_iam_pcap_packet_9() {
        // NPDU data extracted from the pcap of BACnet router
        let real_data = [
            0x01, // Version
            0x08, // Control (Source Specifier)
            0x30, 0x39, // Source Network Address (12345 in hexadecimal)
            0x01, // Source MAC Layer Address Length
            0x02, // SADR (2)
                  // ... (additional APDU data if needed)
        ];

        let decoded = NPDU::decode(&real_data).unwrap();

        // Assert specific values based on known real-world data
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.control, 0x08);
        assert_eq!(decoded.source_network_address, Some(12345)); // 0x3039
        assert_eq!(decoded.source_mac_address_length, Some(1));
        assert_eq!(decoded.source_mac_address, Some(vec![2])); // Assuming SADR is stored as Vec<u8>
                                                               // Remove or modify the hop_count assertion as appropriate
    }
}
