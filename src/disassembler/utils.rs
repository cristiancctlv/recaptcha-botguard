use std::io;

#[derive(Debug, Clone)]
pub enum DisasmError {
    UnexpectedEof,
    InvalidUtf8,
    InvalidBase64,
    InvalidRegisterIndex,
    InvalidOpcode(u16),
    IoError(String),
}

impl From<io::Error> for DisasmError {
    fn from(e: io::Error) -> Self {
        DisasmError::IoError(e.to_string())
    }
}

impl std::fmt::Display for DisasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisasmError::UnexpectedEof => write!(f, "Unexpected end of input"),
            DisasmError::InvalidUtf8 => write!(f, "Invalid UTF-8 sequence"),
            DisasmError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            DisasmError::InvalidRegisterIndex => write!(f, "Invalid register index"),
            DisasmError::InvalidOpcode(op) => write!(f, "Invalid opcode: {}", op),
            DisasmError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for DisasmError {}

pub type Result<T> = std::result::Result<T, DisasmError>;

pub fn int_to_bytes_be(value: u32, num_bytes: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(num_bytes);
    for i in (0..num_bytes).rev() {
        result.push(((value >> (i * 8)) & 0xFF) as u8);
    }
    result
}

pub fn read_i32_be(data: &[u8], offset: usize) -> i32 {
    if offset + 4 > data.len() {
        return 0;
    }
    ((data[offset] as i32) << 24)
        | ((data[offset + 1] as i32) << 16)
        | ((data[offset + 2] as i32) << 8)
        | (data[offset + 3] as i32)
}

pub fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    ((data[offset] as u32) << 24)
        | ((data[offset + 1] as u32) << 16)
        | ((data[offset + 2] as u32) << 8)
        | (data[offset + 3] as u32)
}

pub fn read_u16_be(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    ((data[offset] as u16) << 8) | (data[offset + 1] as u16)
}

pub fn pack_three_i32s(data: &[u8]) -> [i32; 3] {
    [
        read_i32_be(data, 0),
        read_i32_be(data, 4),
        read_i32_be(data, 8),
    ]
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};

    let input = input.replace('-', "+").replace('_', "/");
    let padding = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding));

    general_purpose::STANDARD
        .decode(&padded)
        .map_err(|_| DisasmError::InvalidBase64)
}

pub fn base64_decode_simple(input: &str) -> Result<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        if chunk.len() < 4 {
            break;
        }

        let b0 = decode_char(chunk[0]).ok_or(DisasmError::InvalidBase64)?;
        let b1 = decode_char(chunk[1]).ok_or(DisasmError::InvalidBase64)?;
        let b2 = decode_char(chunk[2]).ok_or(DisasmError::InvalidBase64)?;
        let b3 = decode_char(chunk[3]).ok_or(DisasmError::InvalidBase64)?;

        result.push((b0 << 2) | (b1 >> 4));
        if chunk[2] != b'=' {
            result.push((b1 << 4) | (b2 >> 2));
        }
        if chunk[3] != b'=' {
            result.push((b2 << 6) | b3);
        }
    }

    Ok(result)
}


pub fn string_to_bytes(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for c in s.chars() {
        let code = c as u32;
        if code > 255 {
            result.push((code & 0xFF) as u8);
            result.push((code >> 8) as u8);
        } else {
            result.push(code as u8);
        }
    }
    result
}

pub fn encode_utf8(s: &str) -> Vec<u8> {
    s.replace("\r\n", "\n").into_bytes()
}

pub fn decode_utf8(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec()).map_err(|_| DisasmError::InvalidUtf8)
}

pub fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(DisasmError::InvalidBase64);
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| DisasmError::InvalidBase64))
        .collect()
}

pub fn get_type_name(value: &serde_json::Value) -> &'static str {
    use serde_json::Value;
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn write_to_buffer(buffer: &mut Vec<u8>, data: &[u8], tag: Option<u8>) {
    if let Some(t) = tag {
        buffer.push(t);
    }
    buffer.extend_from_slice(data);
}

pub fn write_length_prefixed(buffer: &mut Vec<u8>, data: &[u8], length_bytes: usize) {
    let len_bytes = int_to_bytes_be(data.len() as u32, length_bytes);
    buffer.extend_from_slice(&len_bytes);
    buffer.extend_from_slice(data);
}
