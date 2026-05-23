//! WebSocket framing helpers used by the upgrade-pathway in the listener.
//!
//! This module decodes the frame header so we can log message size, opcode,
//! and direction without needing to fully reassemble fragmented messages.

use bytes::{Buf, BytesMut};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved,
}

impl Opcode {
    fn from_u8(v: u8) -> Self {
        match v {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => Opcode::Reserved,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub fin: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub payload_len: usize,
    pub header_len: usize,
    pub mask_key: Option<[u8; 4]>,
}

impl FrameHeader {
    /// Try to parse the header in `buf`. Returns `Ok(None)` if more bytes are
    /// needed, `Err` on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Option<FrameHeader>, &'static str> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let b0 = buf[0];
        let fin = b0 & 0x80 != 0;
        let opcode = Opcode::from_u8(b0 & 0x0F);
        let b1 = buf[1];
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7F) as usize;
        let mut idx = 2;
        let payload_len = match len7 {
            126 => {
                if buf.len() < idx + 2 {
                    return Ok(None);
                }
                let v = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
                idx += 2;
                v
            }
            127 => {
                if buf.len() < idx + 8 {
                    return Ok(None);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[idx..idx + 8]);
                idx += 8;
                u64::from_be_bytes(arr) as usize
            }
            n => n,
        };
        let mask_key = if masked {
            if buf.len() < idx + 4 {
                return Ok(None);
            }
            let mut k = [0u8; 4];
            k.copy_from_slice(&buf[idx..idx + 4]);
            idx += 4;
            Some(k)
        } else {
            None
        };
        Ok(Some(FrameHeader {
            fin,
            opcode,
            masked,
            payload_len,
            header_len: idx,
            mask_key,
        }))
    }

    pub fn apply_mask(&self, payload: &mut [u8]) {
        if let Some(key) = self.mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= key[i % 4];
            }
        }
    }
}

/// Strip one frame from `buf` if a complete one is present.
pub fn drain_frame(buf: &mut BytesMut) -> Result<Option<(FrameHeader, Vec<u8>)>, &'static str> {
    let Some(header) = FrameHeader::parse(buf)? else {
        return Ok(None);
    };
    let total = header.header_len + header.payload_len;
    if buf.len() < total {
        return Ok(None);
    }
    buf.advance(header.header_len);
    let mut payload = buf.split_to(header.payload_len).to_vec();
    header.apply_mask(&mut payload);
    Ok(Some((header, payload)))
}
