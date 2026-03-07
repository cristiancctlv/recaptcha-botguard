use std::fs;

use oxc::{allocator::Allocator, parser::Parser, span::SourceType};

fn main() {
    let script = String::from_utf8(
        fs::read("scripts/script_1/vm.flat.js").expect("failed to read the file"),
    )
    .unwrap();

    let source_type = SourceType::default().with_module(false);
    let allocator = Allocator::default();

    let parsed = Parser::new(&allocator, &script, source_type).parse();

    let output = bg::parser::parse(&parsed.program);

    dbg!(&output);
}
