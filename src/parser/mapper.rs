use std::collections::HashMap;

use oxc::{
    ast::ast::{
        Argument, AssignmentExpression, BinaryExpression, CallExpression, Function, FunctionBody,
        IdentifierName, IdentifierReference, LogicalExpression, NullLiteral, Program, Statement,
        UnaryExpression, UpdateExpression,
    },
    ast_visit::{
        Visit,
        walk::{
            walk_assignment_expression, walk_binary_expression, walk_call_expression,
            walk_function, walk_function_body, walk_identifier_name, walk_identifier_reference,
            walk_logical_expression, walk_null_literal, walk_program, walk_unary_expression,
            walk_update_expression,
        },
    },
    semantic::ScopeFlags,
};

use crate::disassembler::Opcode;

struct OpcodeMapperVisitor {
    opcode_fn: String,
    register_fn: String,
    int_fn: String,
    utf8encode_fn: String,

    signatures: HashMap<u16, String>,
    special_opcodes: HashMap<u16, Opcode>,
}

impl OpcodeMapperVisitor {
    fn new(opcode_fn: &str, register_fn: &str, int_fn: &str, utf8encode_fn: &str) -> Self {
        Self {
            opcode_fn: opcode_fn.to_string(),
            register_fn: register_fn.to_string(),
            int_fn: int_fn.to_string(),
            utf8encode_fn: utf8encode_fn.to_string(),
            signatures: HashMap::new(),
            special_opcodes: HashMap::new(),
        }
    }
}

impl<'a> Visit<'a> for OpcodeMapperVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(name) = call.callee_name() {
            if name == &self.opcode_fn
                && call.arguments.len() == 3
                && let Some(lit) = call.arguments.iter().find_map(|a| {
                    if let Argument::NumericLiteral(n) = a {
                        Some(n)
                    } else {
                        None
                    }
                })
                && let Some(func) = call.arguments.iter().find_map(|a| {
                    if let Argument::FunctionExpression(f) = a {
                        Some(f)
                    } else {
                        None
                    }
                })
            {
                let mut signature_maker = SignatureMaker::new(&self.int_fn, &self.utf8encode_fn);
                signature_maker.visit_function(func, ScopeFlags::empty());

                if let Some(special) = signature_maker.special_opcode {
                    self.special_opcodes.insert(lit.value as u16, special);
                } else {
                    self.signatures.insert(
                        lit.value as u16,
                        format!("{:#x}", md5::compute(signature_maker.signature.clone())),
                    );
                }
            } else if name != &self.register_fn {
                walk_call_expression(self, call);
            }
        }
    }
}

pub fn map_opcodes<'a>(
    program: &Program<'a>,
    opcode_fn: &str,
    register_fn: &str,
    int_fn: &str,
    utf8encode_fn: &str,
) -> (HashMap<u16, String>, HashMap<u16, Opcode>) {
    let mut opcode_mapper = OpcodeMapperVisitor::new(opcode_fn, register_fn, int_fn, utf8encode_fn);
    walk_program(&mut opcode_mapper, program);

    (opcode_mapper.signatures, opcode_mapper.special_opcodes)
}

pub struct SignatureMaker {
    fn_counter: u8,

    int_fn: String,
    utf8encode_fn: String,

    walking_body: bool,

    pub signature: String,
    pub special_opcode: Option<Opcode>,
}

impl SignatureMaker {
    pub fn new(int_fn: &str, utf8encode_fn: &str) -> Self {
        Self {
            fn_counter: 0,
            int_fn: int_fn.to_string(),
            utf8encode_fn: utf8encode_fn.to_string(),
            walking_body: false,
            signature: String::new(),
            special_opcode: None,
        }
    }
}

impl<'a> Visit<'a> for SignatureMaker {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if self.walking_body {
            self.fn_counter += 1;

            if self.fn_counter >= 2 {
                self.special_opcode = Some(Opcode::NewOp);
            }
        }

        walk_function(self, it, flags);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        if it.statements.is_empty() {
            self.signature.push_str("empty");
        }

        if it.statements.len() == 1 && matches!(it.statements[0], Statement::IfStatement(_)) {
            self.special_opcode = Some(Opcode::IterateChunks);
        }

        self.walking_body = true;
        walk_function_body(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let callee = it.callee_name().unwrap_or("");

        if callee == self.int_fn.as_str() && it.arguments.len() == 2 {
            for i in [0, 1] {
                if let Some(Argument::NumericLiteral(n)) = it.arguments.get(i) {
                    match n.value as u32 {
                        1 => self.signature.push_str("int(1)"),
                        4 => self.signature.push_str("int(4)"),
                        _ => {}
                    }
                }
            }
            return;
        }

        if callee == self.utf8encode_fn.as_str() && it.arguments.len() == 2 {
            for i in [0, 1] {
                if let Some(Argument::NumericLiteral(n)) = it.arguments.get(i) {
                    match n.value as u32 {
                        3 => self.signature.push_str("utf(3)"),
                        4 => self.signature.push_str("utf(4)"),
                        _ => {}
                    }
                }
            }
            return;
        }

        self.signature.push_str("c");

        walk_call_expression(self, it);
    }

    fn visit_identifier_name(&mut self, it: &IdentifierName<'a>) {
        if it.name == "pop" || it.name == "push" || it.name == "apply" || it.name == "splice" {
            self.signature.push_str(it.name.as_str());
        }

        walk_identifier_name(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        if it.name == "Function"
            || it.name == "atob"
            || it.name == "decodeURIComponent"
            || it.name == "undefined"
            || it.name == "window"
            || it.name == "String"
            || it.name == "arguments"
            || it.name == "Array"
        {
            self.signature.push_str(it.name.as_str());
        }

        walk_identifier_reference(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        self.signature.push_str(it.operator.as_str());
        walk_update_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        self.signature.push_str(it.operator.as_str());
        walk_unary_expression(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.signature.push_str(it.operator.as_str());
        walk_binary_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.signature.push_str(it.operator.as_str());
        walk_logical_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.signature.push_str(it.operator.as_str());
        walk_assignment_expression(self, it);
    }

    fn visit_null_literal(&mut self, it: &NullLiteral) {
        self.signature.push_str("null");
        walk_null_literal(self, it);
    }
}
