use std::fs;

use bg::parser::flatten::flatten_sequences;
use oxc::{allocator::Allocator, codegen::Codegen, parser::Parser, span::SourceType};

fn main() {
    let path = std::env::args().nth(1).unwrap_or("bg.js".into());
    let script = String::from_utf8(fs::read(&path).expect("failed to read file")).unwrap();

    let source_type = SourceType::default().with_module(false);
    let allocator = Allocator::default();
    let mut parsed = Parser::new(&allocator, &script, source_type).parse();

    flatten_sequences(&allocator, &mut parsed.program);

    let output = Codegen::new().build(&parsed.program).code;

    let out_path = std::path::Path::new(&path);
    let stem = out_path.file_stem().unwrap().to_str().unwrap();
    let ext = out_path.extension().map(|e| e.to_str().unwrap()).unwrap_or("js");
    let out_file = out_path.with_file_name(format!("{stem}.flat.{ext}"));
    fs::write(&out_file, output).expect("failed to write file");
    eprintln!("wrote {}", out_file.display());
}
