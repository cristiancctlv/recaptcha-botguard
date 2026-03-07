pub mod cipher;
pub mod flatten;
pub mod functions;
pub mod mapper;
pub mod opcodes;
pub mod registers;

use std::collections::HashMap;

use oxc::ast::ast::Program;

use crate::{
    disassembler::Opcode,
    parser::{cipher::CipherParam, functions::FunctionsOutput},
};

#[derive(Debug)]
pub struct ParserOutput {
    pub functions: FunctionsOutput,
    pub register_info: Option<registers::RegisterInfo>,
    pub cipher: Option<cipher::CipherInfo>,
    pub cipher_params: Vec<CipherParam>,
    pub opcodes: HashMap<u16, Opcode>,
    pub unmatched: Vec<(u16, String)>,
}

pub fn parse<'a>(program: &Program<'a>) -> ParserOutput {
    let funcs = functions::find_functions(program);

    let register_info = registers::analyze_registers(program, &funcs.register_fn);

    let read_bits_info = register_info.as_ref().and_then(|info| {
        cipher::analyze_read_bits(
            program,
            &info.read_bits_fn,
            &info.cipher_key_prop,
            &info.block_idx_prop,
        )
    });

    let cipher_params = read_bits_info
        .as_ref()
        .map(|(_, params)| params.clone())
        .unwrap_or_default();

    let cipher = read_bits_info
        .and_then(|(rb, params)| cipher::analyze_cipher(program, &rb.cipher_fn, &params));

    let (signatures, special_opcodes) = mapper::map_opcodes(
        program,
        &funcs.opcode_fn,
        &funcs.register_fn,
        &funcs.int_fn,
        &funcs.utf8encode_fn,
    );

    let opcodes = opcodes::build_opcode_table(&signatures, &special_opcodes);
    let unmatched = opcodes::report_unmatched(&signatures, &opcodes);

    ParserOutput {
        functions: funcs,
        register_info,
        cipher,
        cipher_params,
        opcodes,
        unmatched,
    }
}
