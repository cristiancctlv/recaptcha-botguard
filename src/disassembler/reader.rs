use super::cipher::CipherState;
use super::utils::{DisasmError, Result};

pub struct BytecodeReader<'a> {
    data: &'a [u8],
    pos: usize,
    size_bits: usize,
    cipher: CipherState,
}

impl<'a> BytecodeReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            size_bits: data.len() * 8,
            cipher: CipherState::new(),
        }
    }

    pub fn with_seed(data: &'a [u8], seed: &[i32; 3]) -> Self {
        let mut reader = Self::new(data);

        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[i] = reader.read_byte_raw().unwrap();
        }
        let cipher_key = i32::from_be_bytes(bytes);

        reader.cipher.set_cipher_key(cipher_key);
        reader.cipher.set_seed(seed);
        reader
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn byte_pos(&self) -> usize {
        self.pos >> 3
    }

    pub fn bit_offset(&self) -> usize {
        self.pos & 7
    }

    pub fn is_eof(&self) -> bool {
        self.pos >= self.size_bits
    }

    pub fn remaining_bits(&self) -> usize {
        if self.pos >= self.size_bits {
            0
        } else {
            self.size_bits - self.pos
        }
    }

    pub fn seek(&mut self, bit_pos: usize) {
        self.pos = bit_pos;
    }

    pub fn seek_byte(&mut self, byte_pos: usize) {
        self.pos = byte_pos * 8;
    }

    pub fn get_cipher_key(&self) -> i32 {
        self.cipher.get_cipher_key()
    }

    pub fn get_block_idx(&self) -> usize {
        self.cipher.get_block_idx()
    }

    pub fn get_seed(&self) -> [i32; 3] {
        self.cipher.get_seed()
    }

    pub fn set_seed(&mut self, seed: &[i32; 3]) {
        self.cipher.set_seed(seed);
    }

    pub fn update_seed(&mut self, value: i32, idx: usize) {
        self.cipher.update_seed(value, idx);
    }

    pub fn set_cipher_info(
        &mut self,
        info: crate::parser::cipher::CipherInfo,
        params: Vec<crate::parser::cipher::CipherParam>,
    ) {
        self.cipher.set_cipher_info(info, params);
    }

    pub fn reset_block_idx(&mut self) {
        self.cipher.reset_block_idx();
    }

    pub fn set_cipher_key(&mut self) {
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[i] = self.read_byte_raw().unwrap();
        }
        let cipher_key = i32::from_be_bytes(bytes);

        self.cipher.set_cipher_key(cipher_key);
    }

    pub fn set_cipher_enabled(&mut self, enabled: bool) {
        if enabled {
            self.cipher.enable();
        } else {
            self.cipher.disable();
        }
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        self.read_bits(8, true)
    }

    pub fn read_byte_raw(&mut self) -> Result<u8> {
        self.read_bits(8, false)
    }

    pub fn read_bits(&mut self, num_bits: usize, decrypt: bool) -> Result<u8> {
        if num_bits > 8 {
            return Err(DisasmError::InvalidRegisterIndex);
        }
        if self.pos + num_bits > self.size_bits {
            return Err(DisasmError::UnexpectedEof);
        }

        let mut result: u8 = 0;
        let mut bits_remaining = num_bits;
        let mut current_pos = self.pos;

        while bits_remaining > 0 {
            let bit_offset = current_pos % 8;
            let bits_available = 8 - bit_offset;
            let bits_to_read = bits_remaining.min(bits_available);
            let byte_idx = current_pos >> 3;

            if byte_idx >= self.data.len() {
                return Err(DisasmError::UnexpectedEof);
            }

            let mut byte_val = self.data[byte_idx];

            if decrypt && self.cipher.is_enabled() {
                byte_val ^= self.cipher.get_cipher_byte(current_pos, byte_idx);
            }

            let mask = ((1u16 << bits_to_read) - 1) as u8;
            let bits = (byte_val >> (8 - bit_offset - bits_to_read)) & mask;

            result |= bits << (bits_remaining - bits_to_read);

            bits_remaining -= bits_to_read;
            current_pos += bits_to_read;
        }

        self.pos = current_pos;
        Ok(result)
    }
    pub fn read_register_index(&mut self) -> Result<u16> {
        let first = self.read_bits(8, true)? as u16;

        if first & 0x80 != 0 {
            let low = first ^ 0x80;
            let extra = self.read_bits(2, true)? as u16;
            Ok((low << 2) + extra)
        } else {
            Ok(first)
        }
    }

    pub fn read_varint(&mut self) -> Result<u16> {
        let first = self.read_byte()? as u16;
        if first & 0x80 != 0 {
            let second = self.read_byte()? as u16;
            Ok((first & 0x7F) | (second << 7))
        } else {
            Ok(first)
        }
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let hi = self.read_byte()? as u16;
        let lo = self.read_byte()? as u16;
        Ok((hi << 8) | lo)
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let b0 = self.read_byte()? as u32;
        let b1 = self.read_byte()? as u32;
        let b2 = self.read_byte()? as u32;
        let b3 = self.read_byte()? as u32;
        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            result.push(self.read_byte()?);
        }
        Ok(result)
    }

    pub fn read_opcode(&mut self) -> Result<u16> {
        self.read_register_index()
    }

    pub fn skip_bits(&mut self, n: usize) {
        self.pos += n;
    }

    pub fn skip_bytes(&mut self, n: usize) {
        self.pos += n * 8;
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }

    pub fn size_bits(&self) -> usize {
        self.size_bits
    }

    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }

    pub fn checkpoint(&self) -> ReaderCheckpoint {
        ReaderCheckpoint { pos: self.pos }
    }

    pub fn restore(&mut self, checkpoint: &ReaderCheckpoint) {
        self.pos = checkpoint.pos;
    }
}

#[derive(Debug, Clone)]
pub struct ReaderCheckpoint {
    pos: usize,
}
