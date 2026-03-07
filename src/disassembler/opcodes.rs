use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    LoadImm32,
    LoadImm16,
    LoadImm8,
    Or,
    Add,
    Sub,
    Ushr,
    In,
    CmpEqual,
    Cleanup,
    Jump,
    JumpIfNonZero,
    StoreIfNonZero,
    IterateChunks,
    CallConst,
    Apply,
    CallBack,
    AttachEvent,
    RemoveEvent,
    GetProperty,
    SetProperty,
    EmptyArray,
    NewArray,
    LoadString,
    ToString,
    Utf8Encode,
    Utf8Encode3,
    IntB32,
    IntB8,
    NewOpEval,
    Typeof,
    NewOp,
    SyncMemory,
    Nop,
    Mov,
    ModifyObject,
}

impl Opcode {
    pub fn name(self) -> &'static str {
        match self {
            Self::LoadImm32 => "LOAD_IMM_32",
            Self::LoadImm16 => "LOAD_IMM_16",
            Self::LoadImm8 => "LOAD_IMM_8",
            Self::Or => "OR",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Ushr => "USHR",
            Self::In => "IN",
            Self::CmpEqual => "CMP_EQ",
            Self::Cleanup => "CLEANUP",
            Self::JumpIfNonZero => "JNZ",
            Self::StoreIfNonZero => "STORE_IF_NZ",
            Self::IterateChunks => "ITERATE_CHUNKS",
            Self::CallConst => "CALL_CONST",
            Self::Apply => "APPLY",
            Self::CallBack => "CALLBACK",
            Self::AttachEvent => "ATTACH_EVENT",
            Self::RemoveEvent => "REMOVE_EVENT",
            Self::GetProperty => "GET_PROP",
            Self::SetProperty => "SET_PROP",
            Self::EmptyArray => "EMPTY_ARRAY",
            Self::NewArray => "NEW_ARRAY",
            Self::LoadString => "LOAD_STRING",
            Self::ToString => "TO_STRING",
            Self::Utf8Encode => "UTF8_ENCODE",
            Self::Utf8Encode3 => "UTF8_ENCODE3",
            Self::IntB32 => "INT_TO_BYTES_32",
            Self::IntB8 => "INT_TO_BYTES_8",
            Self::NewOpEval => "NEW_OPCODE_EVAL",
            Self::Typeof => "TYPEOF",
            Self::NewOp => "NEW_OPCODE",
            Self::SyncMemory => "SYNC_MEMORY",
            Self::Jump => "JUMP",
            Self::Nop => "NOP",
            Self::Mov => "MOV",
            Self::ModifyObject => "MODIFY_OBJ",
        }
    }
}

pub struct OpcodeHandler {
    opcodes: HashMap<u16, Opcode>,
}

impl Default for OpcodeHandler {
    fn default() -> Self {
        Self {
            opcodes: HashMap::from([]),
        }
    }
}

impl OpcodeHandler {
    pub fn new(opcodes: HashMap<u16, Opcode>) -> Self {
        Self { opcodes }
    }

    pub fn get(&self, id: u16) -> Option<Opcode> {
        self.opcodes.get(&id).copied()
    }

    pub fn insert(&mut self, id: u16, opcode: Opcode) {
        self.opcodes.insert(id, opcode);
    }

    pub fn contains(&self, id: u16) -> bool {
        self.opcodes.contains_key(&id)
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset: usize,
    pub raw_opcode: u16,
    pub opcode: Option<Opcode>,
    pub operands: Vec<u16>,
    pub immediates: Vec<ImmediateValue>,
    pub size_bits: usize,
}

impl Instruction {
    pub fn new(offset: usize, raw_opcode: u16, handler: &OpcodeHandler) -> Self {
        let opcode = handler.get(raw_opcode);

        Self {
            offset,
            raw_opcode,
            opcode,
            operands: Vec::new(),
            immediates: Vec::new(),
            size_bits: 0,
        }
    }

    pub fn add_operand(&mut self, reg: u16) {
        self.operands.push(reg);
    }

    pub fn add_immediate(&mut self, imm: ImmediateValue) {
        self.immediates.push(imm);
    }

    pub fn set_size(&mut self, size_bits: usize) {
        self.size_bits = size_bits;
    }

    pub fn name(&self) -> &'static str {
        match self.opcode {
            Some(op) => op.name(),
            None => "UNKNOWN",
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}: {:<18}", self.offset, self.name())?;

        if !self.operands.is_empty() {
            write!(f, " ")?;
            for (i, op) in self.operands.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "r{}", op)?;
            }
        }

        for imm in &self.immediates {
            write!(f, " {}", imm)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ImmediateValue {
    Byte(u8),
    U16(u16),
    U32(u32),
    Bytes(Vec<u8>),
    String(String),
    JumpTarget(usize),
}

impl fmt::Display for ImmediateValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImmediateValue::Byte(b) => write!(f, "0x{:02x}", b),
            ImmediateValue::U16(v) => write!(f, "0x{:04x}", v),
            ImmediateValue::U32(v) => write!(f, "0x{:08x}", v),
            ImmediateValue::Bytes(bytes) => {
                if bytes.len() <= 8 {
                    write!(f, "[")?;
                    for (i, b) in bytes.iter().enumerate() {
                        if i > 0 {
                            write!(f, " ")?;
                        }
                        write!(f, "{:02x}", b)?;
                    }
                    write!(f, "]")
                } else {
                    write!(f, "[{} bytes]", bytes.len())
                }
            }
            ImmediateValue::String(s) => {
                if s.len() <= 32 {
                    write!(f, "\"{}\"", s.escape_default())
                } else {
                    let truncated: String = s.chars().take(29).collect();
                    write!(f, "\"{}...\"", truncated.escape_default())
                }
            }
            ImmediateValue::JumpTarget(target) => write!(f, "@{:08x}", target),
        }
    }
}

pub mod flags {
    pub const VALID: u16 = 2048;
}
