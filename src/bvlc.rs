// bvlc.rs
use std::error::Error;
use std::fmt;

pub struct BVLCHeader {
    pub bvlc_type: u8,
    pub function: u8,
    pub length: u16,
}

impl BVLCHeader {
    pub fn parse(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        if data.len() < 4 {
            return Err("Data too short for BVLC header".into());
        }

        let bvlc_type = data[0];
        let function = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]); // Big-endian byte order

        println!("Parsed BVLC Header - Type: 0x{:02X}, Function: 0x{:02X}, Length: {}", bvlc_type, function, length);

        Ok(BVLCHeader {
            bvlc_type,
            function,
            length,
        })
    }
}
