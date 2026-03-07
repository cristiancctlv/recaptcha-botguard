use std::collections::HashMap;
use std::fs;
use std::env;
use std::time::Instant;

use bg::disassembler::{
    BytecodeReader, Opcode, OpcodeHandler, base64_decode
};
use bg::parser::ParserOutput;
use bg::parser::functions::FunctionsOutput;
use bg::parser::registers::RegisterInfo;

#[derive(Clone)]
enum RegValue {
    Int(i32),
    String(String),
    Opcode(Opcode),
    Bytes(Vec<u8>),
}

impl RegValue {
    pub fn as_int(&self) -> Option<i32> {
        match self {
            RegValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

struct Disassembler<'a> {
    ip: usize,

    stop: bool,
    stop_at: usize,

    string_array: Vec<u8>,

    reg_values: HashMap<u16, RegValue>,

    reader: BytecodeReader<'a>,
    handler: OpcodeHandler,
    registers: RegisterInfo,
    functions: FunctionsOutput,
    instructions: Vec<String>,
}

impl<'a> Disassembler<'a> {
    fn new(bytecode: &'a [u8], seed: &[i32; 3], parser_output: ParserOutput) -> Self {
        let mut handler = OpcodeHandler::default();

        for (id, opcode) in parser_output.opcodes {
            handler.insert(id, opcode);
        }

        let mut reader = BytecodeReader::with_seed(bytecode, seed);


        if let Some(ci) = parser_output.cipher {
            eprintln!(
                "Loaded cipher: {} rounds, {} operations",
                ci.rounds,
                ci.operations.len()
            );
            eprintln!("Cipher params: {:?}", parser_output.cipher_params);
            reader.set_cipher_info(ci, parser_output.cipher_params);
        }

        let registers = parser_output.register_info.unwrap();


        let stop_at = reader.size_bytes() << 3;
        Self {
            ip: 0,

            stop: false,
            stop_at,
            string_array: Vec::new(),
            reg_values: HashMap::new(),

            reader,
            handler,
            registers,
            functions: parser_output.functions,
            instructions: Vec::new(),
        }
    }

    fn disassemble(&mut self) {
        while !self.reader.is_eof()
            && self.reader.remaining_bits() >= 8
            && self.reader.pos() < self.stop_at
            && !self.stop
        {
            let offset = self.reader.pos();
            self.ip = offset;

            match self.read_opcode() {
                Some(raw_opcode) => {
                    if self.handler.contains(raw_opcode) {
                        let kind = self.handler.get(raw_opcode).unwrap();
                        self.disassemble_opcode(offset, raw_opcode, kind);
                    } else {
                        // NOTE: here unkown opcodes should have emitten an error!
                    };
                }

                _ => {}
            };
        }
    }

    fn emit(&mut self, line: String) {
        println!("{}", line);
        self.instructions.push(line);
    }

    fn read_opcode(&mut self) -> Option<u16> {
        Some(self.reader.read_register_index().unwrap_or(0))
    }

    fn read_reg(&mut self,) -> u16 {
        // NOTE: this is a simple register reader, if u wanted to do it like botguard does then you would need to handle unkown values and emit the errors!
        self.reader.read_register_index().unwrap_or(0)
    }

    fn read_byte(&mut self) -> u8 {
        self.reader.read_byte().unwrap_or(0)
    }

    fn read_varint(&mut self) -> u16 {
        self.reader.read_varint().unwrap_or(0)
    }

    fn read_imm(&mut self, x: i32) -> i32 {
        let mut val = 0;
        for _ in 0..x {
            val = val << 8 | self.read_byte() as i32;
        }

        val
    }

    fn match_new_opcode(&self, opcode: &String) -> Opcode {
        if opcode.contains(&self.functions.load_imm_fn) {
            match () {
                _ if opcode.contains('1') => Opcode::LoadImm8,
                _ if opcode.contains('2') => Opcode::LoadImm16,
                _ => Opcode::LoadImm32,
            }
        } else if opcode.contains("&&") {
            Opcode::Mov
        } else {
            Opcode::Nop
        }
    }

    fn get_reg_value_display(&self, reg: u16) -> String {
        match self.reg_values.get(&reg) {
            Some(RegValue::Int(v)) => v.to_string(),
            Some(RegValue::String(s)) => format!("\"{}\"", s),
            Some(RegValue::Opcode(s)) => format!("{:?}", s),
            Some(RegValue::Bytes(b)) => format!("[{} bytes]", b.len()),
            _ => format!("r{}", reg),
        }
    }

    fn disassemble_opcode(&mut self, offset: usize, _raw_opcode: u16, kind: Opcode) {
        let name = kind.name();

        let line = match kind {
            Opcode::NewArray => {
                let dst = self.read_reg();
                let len = self.read_varint() as usize;
                let mut bytes = Vec::new();
                for _ in 0..len {
                    bytes.push(self.read_byte());
                }

                if self.string_array.is_empty() {
                    self.string_array = bytes.clone();
                }

                self.reg_values.insert(dst, RegValue::Bytes(bytes.clone()));

                format!(
                    "{:08x}: {:<18} r{}, [{} bytes]",
                    offset,
                    name,
                    dst,
                    bytes.len()
                )
            }

            Opcode::LoadString => {
                let dst = self.read_reg();
                let len = self.read_varint() as usize;

                if self.reader.remaining_bits() < len * 8 {
                    self.stop = true;

                    return;
                }

                let mut w: usize = 0;
                let mut bytes = Vec::with_capacity(len);

                for _ in 0..len {
                    let delta = self.read_varint() as usize;
                    w = (w + delta) % self.string_array.len();

                    let byte = self.string_array[w];
                    bytes.push(byte);
                }

                let s: String = bytes.iter().map(|&b| b as char).collect();

                if s.contains("function") {
                    self.reg_values
                        .insert(dst, RegValue::Opcode(self.match_new_opcode(&s)));
                } else {
                    self.reg_values.insert(dst, RegValue::String(s.clone()));
                }

                format!("{:08x}: {:<18} r{} = {:?}", offset, name, dst, s)
            }

            Opcode::LoadImm32 => {
                let dst = self.read_reg();
                let val = self.read_imm(4);

                if self.registers.ip == dst {
                    self.reader.seek(val as usize);

                    format!("{:08x}: {:<18} {}", offset, "JUMP", val)
                } else {
                    self.reg_values.insert(dst, RegValue::Int(val));
                    format!(
                        "{:08x}: {:<18} r{} = {}",
                        offset,
                        name,
                        dst,
                        self.get_reg_value_display(dst)
                    )
                }
            }

            Opcode::LoadImm16 => {
                let dst = self.read_reg();
                let val = self.read_imm(2);

                self.reg_values.insert(dst, RegValue::Int(val));

                format!(
                    "{:08x}: {:<18} r{} = {}",
                    offset,
                    name,
                    dst,
                    self.get_reg_value_display(dst)
                )
            }

            Opcode::LoadImm8 => {
                let dst = self.read_reg();
                let val = self.read_imm(1);

                self.reg_values.insert(dst, RegValue::Int(val));

                format!(
                    "{:08x}: {:<18} r{} = {}",
                    offset,
                    name,
                    dst,
                    self.get_reg_value_display(dst)
                )
            }

            Opcode::NewOpEval => {
                let op = self.read_reg();
                let dst = self.read_reg();

                if let Some(RegValue::Opcode(opcode)) = self.reg_values.get(&op) {
                    self.handler.insert(dst, *opcode);

                    format!("{:08x}: {:<18} r{} = {:?}", offset, name, dst, opcode)
                } else {
                    format!(
                        "{:08x}: {:<18} r{} -> r{} (didnt match)",
                        offset, name, op, dst
                    )
                }
            }

            Opcode::SetProperty => {
                let obj = self.read_reg();
                let prop = self.read_reg();
                let val = self.read_reg();

                if obj == self.registers.seed_state {
                    if let Some(index) = self.reg_values.get(&prop).and_then(|v| v.as_int())
                        && let Some(value) = self.reg_values.get(&val).and_then(|v| v.as_int())
                    {
                        self.reader.update_seed(value, index as usize);

                        if index == 2 {
                            self.reader.set_cipher_key();
                        }
                    }

                    self.reader.reset_block_idx();
                }
                format!(
                    "{:08x}: {:<18} r{}[r{}] = r{}",
                    offset, name, obj, prop, val
                )
            }

            Opcode::Ushr => {
                let a = self.read_reg();
                let b = self.read_byte();
                let dst = self.read_reg();

                format!("{:08x}: {:<18} r{} = r{} >>> {}", offset, name, dst, a, b)
            }

            Opcode::Utf8Encode3 => {
                let src = self.read_reg();
                let dst = self.read_reg();

                if self.reg_values.contains_key(&src) {
                    // read data and write to the token buffer
                }

                format!("{:08x}: {:<18} r{} -> r{}", offset, name, src, dst)
            }

            Opcode::Utf8Encode => {
                let src = self.read_reg();
                let dst = self.read_reg();

                if self.reg_values.contains_key(&src) {
                    // read data and write to the token buffer
                }

                format!("{:08x}: {:<18} r{} -> r{}", offset, name, src, dst)
            }

            Opcode::CmpEqual => {
                let a = self.read_reg();
                let b = self.read_reg();
                let dst = self.read_reg();

                format!("{:08x}: {:<18} r{} = (r{} == r{})", offset, name, dst, a, b)
            }

            Opcode::JumpIfNonZero => {
                let cond = self.read_reg();
                let target = self.read_reg();

                format!("{:08x}: {:<18} r{}, r{}", offset, name, cond, target)
            }

            Opcode::RemoveEvent => {
                let a = self.read_reg();

                format!("{:08x}: {:<18} r{}", offset, name, a)
            }

            Opcode::Nop => {
                format!("{:08x}: {:<18}", offset, name)
            }

            Opcode::In => {
                let a = self.read_reg();
                let b = self.read_reg();
                let dst = self.read_reg();

                format!("{:08x}: {:<18} r{} = r{} in r{}", offset, name, dst, a, b)
            }

            Opcode::Mov => {
                let dst = self.read_reg();
                let src = self.read_reg();

                if let Some(val) = self.reg_values.get(&src).cloned() {
                    self.reg_values.insert(dst, val);
                }

                format!("{:08x}: {:<18} r{} = r{}", offset, name, dst, src)
            }

            Opcode::IntB8 => {
                let src = self.read_reg();
                let dst = self.read_reg();

                if self.reg_values.contains_key(&src) {
                    // read data and write to the token buffer
                }


                format!("{:08x}: {:<18} r{} -> r{}", offset, name, src, dst)
            }

            Opcode::IntB32 => {
                let src = self.read_reg();
                let dst = self.read_reg();

                if self.reg_values.contains_key(&src) {
                    // read data and write to the token buffer
                }


                format!("{:08x}: {:<18} r{} -> r{}", offset, name, src, dst)
            }

            Opcode::Typeof => {
                let src = self.read_reg();
                let dst = self.read_reg();

                format!("{:08x}: {:<18} r{} -> r{}", offset, name, src, dst)
            }

            Opcode::Add => {
                let a = self.read_reg();
                let dst = self.read_reg();

                format!("{:08x}: {:<18} r{} += r{}", offset, name, dst, a)
            }

            _ => format!("{:<18} {}", name, _raw_opcode),
        };

        self.emit(format!("{}", line));
    }
}

fn main() {
    let start = Instant::now();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <bytecode_file> <vm_js_file>", args[0]);
        std::process::exit(1);
    }

    let bytecode_path = &args[1];
    let js_path = &args[2];

    let text =
        fs::read_to_string(bytecode_path).expect("Failed to read bytecode file");
    let bytecode = &base64_decode(&text[3..]).unwrap(); // make sure its only once b64-encoded

    let flat_js =
        fs::read_to_string(js_path).expect("Failed to read vm JS file");

    let source_type = oxc::span::SourceType::default().with_module(false);
    let allocator = oxc::allocator::Allocator::default();
    let parsed = oxc::parser::Parser::new(&allocator, &flat_js, source_type).parse();
    let parser_output = bg::parser::parse(&parsed.program);

    eprintln!("Loaded {} opcodes from parser", parser_output.opcodes.len());

    let mut disasm = Disassembler::new(bytecode, &[0, 0, 0], parser_output);
    disasm.disassemble();

    let instruction_count = disasm.instructions.len();
    eprintln!("\nDisassembly complete: {} instructions in {:?}", instruction_count, start.elapsed());
}
