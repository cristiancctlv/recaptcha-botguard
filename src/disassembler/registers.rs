use std::collections::HashMap;

pub mod ids {
    pub const SEED: u16 = 0;
    pub const EVENT_LISTENER: u16 = 18;
    pub const RETURN_VALUE: u16 = 30;
    pub const IP: u16 = 43;
    pub const LAST_IP: u16 = 70;
    pub const RANDOM_1: u16 = 88;
    pub const OUTPUT_ENCRYPTED: u16 = 117;
    pub const RANDOM_2: u16 = 137;
    pub const SIZE_LIMIT: u16 = 156;
    pub const ASYNC_MARKERS: u16 = 201;
    pub const OUTPUT_PLAIN: u16 = 223;
    pub const PENDING_ASYNC: u16 = 228;
    pub const ASYNC_STATE: u16 = 236;
    pub const EVENT_ARGS: u16 = 257;
    pub const GLOBAL: u16 = 286;
    pub const EXCEPTION: u16 = 301;
    pub const OUTPUT_MAIN: u16 = 329;
    pub const CLEANUP_HANDLERS: u16 = 381;
    pub const ERROR_CODES: u16 = 383;
    pub const SIZE_TRACKING: u16 = 385;
    pub const CIPHER_STATE: u16 = 390;
    pub const STRING_TABLE: u16 = 477;
    pub const OPCODES: u16 = 497;
    pub const VM_SELF: u16 = 508;
}

#[derive(Debug, Clone)]
pub enum RegisterValue {
    Undefined,
    Null,
    Integer(i64),
    Float(f64),
    Boolean(bool),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<RegisterValue>),
    Object(HashMap<String, RegisterValue>),
    Function(u32),
    SlotProxy(i64),
}

impl RegisterValue {
    pub fn as_int(&self) -> i64 {
        match self {
            RegisterValue::Integer(n) => *n,
            RegisterValue::Float(f) => *f as i64,
            RegisterValue::SlotProxy(n) => *n,
            RegisterValue::Boolean(b) => {
                if *b {
                    1
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            RegisterValue::Bytes(b) => b.clone(),
            RegisterValue::String(s) => s.as_bytes().to_vec(),
            RegisterValue::Integer(n) => {
                vec![
                    ((*n >> 16) & 0xFF) as u8,
                    ((*n >> 8) & 0xFF) as u8,
                    (*n & 0xFF) as u8,
                ]
            }
            _ => vec![],
        }
    }

    pub fn as_usize(&self) -> usize {
        self.as_int() as usize
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, RegisterValue::Undefined)
    }

    pub fn len(&self) -> usize {
        match self {
            RegisterValue::Bytes(b) => b.len(),
            RegisterValue::Array(a) => a.len(),
            RegisterValue::String(s) => s.len(),
            _ => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RegisterValue {
    fn default() -> Self {
        RegisterValue::Undefined
    }
}

#[derive(Debug, Clone)]
pub struct RegisterFile {
    registers: HashMap<u16, RegisterValue>,
    stack: Vec<HashMap<u16, RegisterValue>>,
}

impl RegisterFile {
    pub fn new() -> Self {
        let mut rf = Self {
            registers: HashMap::new(),
            stack: Vec::new(),
        };

        rf.write(ids::IP, RegisterValue::SlotProxy(0));
        rf.write(ids::LAST_IP, RegisterValue::SlotProxy(0));
        rf.write(ids::RETURN_VALUE, RegisterValue::Object(HashMap::new()));
        rf.write(
            ids::SIZE_LIMIT,
            RegisterValue::Array(vec![RegisterValue::Integer(2048)]),
        );
        rf.write(ids::ERROR_CODES, RegisterValue::Bytes(vec![]));
        rf.write(ids::OUTPUT_ENCRYPTED, RegisterValue::Bytes(vec![]));
        rf.write(ids::OUTPUT_PLAIN, RegisterValue::Bytes(vec![]));
        rf.write(ids::OUTPUT_MAIN, RegisterValue::Bytes(vec![]));
        rf.write(ids::RANDOM_1, RegisterValue::Bytes(vec![]));
        rf.write(ids::RANDOM_2, RegisterValue::Bytes(vec![]));
        rf.write(ids::ASYNC_MARKERS, RegisterValue::Bytes(vec![]));
        rf.write(ids::PENDING_ASYNC, RegisterValue::Bytes(vec![]));
        rf.write(
            ids::CIPHER_STATE,
            RegisterValue::Array(vec![
                RegisterValue::Integer(0),
                RegisterValue::Integer(0),
                RegisterValue::Integer(0),
            ]),
        );
        rf.write(ids::CLEANUP_HANDLERS, RegisterValue::Array(vec![]));
        rf.write(ids::ASYNC_STATE, RegisterValue::Object(HashMap::new()));
        rf.write(ids::EXCEPTION, RegisterValue::Integer(344));

        rf
    }

    pub fn read(&self, reg: u16) -> &RegisterValue {
        self.registers
            .get(&reg)
            .unwrap_or(&RegisterValue::Undefined)
    }

    pub fn write(&mut self, reg: u16, value: RegisterValue) {
        self.registers.insert(reg, value);
    }

    pub fn ip(&self) -> usize {
        self.read(ids::IP).as_usize()
    }

    pub fn set_ip(&mut self, pos: usize) {
        self.write(ids::IP, RegisterValue::SlotProxy(pos as i64));
    }

    pub fn push_frame(&mut self) {
        if self.stack.len() > 104 {
            return;
        }
        self.stack.push(self.registers.clone());
        self.registers.remove(&ids::IP);
    }

    pub fn pop_frame(&mut self, preserve_regs: &[u16]) -> bool {
        if let Some(mut saved) = self.stack.pop() {
            for &reg in preserve_regs {
                if let Some(val) = self.registers.get(&reg) {
                    saved.insert(reg, val.clone());
                }
            }
            if let Some(val) = self.registers.get(&ids::ERROR_CODES) {
                saved.insert(ids::ERROR_CODES, val.clone());
            }
            if let Some(val) = self.registers.get(&ids::SIZE_LIMIT) {
                saved.insert(ids::SIZE_LIMIT, val.clone());
            }
            self.registers = saved;
            true
        } else {
            false
        }
    }

    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    pub fn append_to_buffer(&mut self, reg: u16, data: &[u8]) {
        let current = self.read(reg).clone();
        let mut bytes = match current {
            RegisterValue::Bytes(b) => b,
            _ => vec![],
        };
        bytes.extend_from_slice(data);
        self.write(reg, RegisterValue::Bytes(bytes));
    }

    pub fn buffer_len(&self, reg: u16) -> usize {
        self.read(reg).len()
    }
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::new()
    }
}
