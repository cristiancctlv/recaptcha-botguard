use std::collections::{HashMap, HashSet};

use oxc::{
    ast::ast::{
        Argument, AssignmentExpression, AssignmentTarget, CallExpression, ConditionalExpression,
        Expression, Function, FunctionBody, Program, Statement, VariableDeclarator,
    },
    ast_visit::{
        Visit,
        walk::{
            walk_assignment_expression, walk_call_expression, walk_conditional_expression,
            walk_function, walk_function_body, walk_program, walk_variable_declarator,
        },
    },
    semantic::ScopeFlags,
};

#[derive(Debug)]
pub struct RegisterInfo {
    pub ip: u16,
    pub last_ip: u16,
    pub read_bits_fn: String,
    pub cipher_key_prop: String,
    pub block_idx_prop: String,
    pub output_main: u16,
    pub error_codes: u16,
    pub cipher_state: u16,
    pub seed_state: u16,
    pub random_bytes: Vec<u16>,
    pub buffer_ids: Vec<u16>,
}

#[derive(Debug)]
struct RegisterBasicInfo {
    ip: u16,
    last_ip: u16,
    read_bits_fn: String,
    cipher_key_prop: String,
    block_idx_prop: String,
    buffer_ids: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq)]
enum InitKind {
    AllZeroArray, // [0, 0, 0] → cipher_state
    ThisAllZeroArray,
    SingleElemArray, // [2048] → size_limit (helper for error_codes ID)
    NonZeroArray,    // [160, 0, 0] → output_encrypted
    FunctionCall,    // f(4) → outputs (random bytes)
    EmptyArray,      // [] → candidate pool
    Other,
}

#[derive(Debug)]
struct RegisterVisitor {
    register_fn_name: String,
    last_func: String,
    pub info: Option<RegisterBasicInfo>,
}

impl RegisterVisitor {
    fn new(register_fn_name: &str) -> Self {
        Self {
            register_fn_name: register_fn_name.to_string(),
            last_func: String::new(),
            info: None,
        }
    }
}

impl<'a> Visit<'a> for RegisterVisitor {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        if let Some(name) = func.name() {
            self.last_func = name.into_string();
        }
        walk_function(self, func, flags);
    }

    fn visit_variable_declarator(&mut self, var: &VariableDeclarator<'a>) {
        if let Some(init) = &var.init
            && matches!(init, Expression::FunctionExpression(_))
            && let Some(name) = var.id.get_identifier_name()
        {
            self.last_func = name.to_string();
        }
        walk_variable_declarator(self, var);
    }

    fn visit_function_body(&mut self, body: &FunctionBody<'a>) {
        if self.last_func == self.register_fn_name && body.statements.len() == 2 {
            if let Some(info) = parse_register_body(body) {
                self.info = Some(info);
            }
        }
        walk_function_body(self, body);
    }
}

fn parse_register_body(body: &FunctionBody) -> Option<RegisterBasicInfo> {
    let stmts = &body.statements;

    let Statement::IfStatement(if_stmt) = &stmts[0] else {
        return None;
    };

    let ip_ids = collect_or_chain_literals(&if_stmt.test);
    if ip_ids.len() < 2 {
        return None;
    }
    let ip = ip_ids[0];
    let last_ip = ip_ids[1];

    let buffer_ids = if let Some(alternate) = &if_stmt.alternate {
        extract_buffers(alternate)
    } else {
        Vec::new()
    };
    if buffer_ids.len() < 10 {
        return None;
    }

    let Statement::ExpressionStatement(expr_stmt) = &stmts[1] else {
        return None;
    };
    let Expression::LogicalExpression(logical) = &expr_stmt.expression else {
        return None;
    };

    let right = unwrap_parens(&logical.right);
    let Expression::SequenceExpression(seq) = right else {
        return None;
    };
    if seq.expressions.len() < 2 {
        return None;
    }

    let (cipher_key_prop, read_bits_fn) = if let Expression::AssignmentExpression(assign) =
        &seq.expressions[0]
        && let AssignmentTarget::StaticMemberExpression(member) = &assign.left
        && let Expression::CallExpression(call) = &assign.right
    {
        (
            member.property.name.to_string(),
            call.callee_name()?.to_string(),
        )
    } else {
        return None;
    };

    let block_idx_prop = if let Expression::AssignmentExpression(assign) = &seq.expressions[1]
        && let AssignmentTarget::StaticMemberExpression(member) = &assign.left
    {
        member.property.name.to_string()
    } else {
        return None;
    };

    Some(RegisterBasicInfo {
        ip,
        last_ip,
        read_bits_fn,
        cipher_key_prop,
        block_idx_prop,
        buffer_ids,
    })
}

#[derive(Debug)]
struct InitClassifierVisitor {
    register_fn_name: String,
    buffer_ids: HashSet<u16>,
    classifications: HashMap<u16, InitKind>,
    preserved_registers: Vec<u16>,
}

impl InitClassifierVisitor {
    fn new(register_fn_name: &str, buffer_ids: &[u16]) -> Self {
        Self {
            register_fn_name: register_fn_name.to_string(),
            buffer_ids: buffer_ids.iter().cloned().collect(),
            classifications: HashMap::new(),
            preserved_registers: Vec::new(),
        }
    }
}

impl<'a> Visit<'a> for InitClassifierVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(name) = call.callee_name()
            && name == self.register_fn_name
            && call.arguments.len() == 3
        {
            for arg in &call.arguments {
                if let Argument::NumericLiteral(lit) = arg {
                    let reg_id = lit.value as u16;
                    let mut kind = classify_init_value(&call.arguments[2]);

                    if matches!(call.arguments[0], Argument::ThisExpression(_))
                        && kind == InitKind::AllZeroArray
                    {
                        kind = InitKind::ThisAllZeroArray;
                    }

                    if kind != InitKind::Other {
                        self.classifications.insert(reg_id, kind);
                    }
                }
            }
        }

        walk_call_expression(self, call);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if let AssignmentTarget::ComputedMemberExpression(left) = &assign.left
            && let Expression::NumericLiteral(left_lit) = &left.expression
            && let Expression::ComputedMemberExpression(right) = &assign.right
            && let Expression::NumericLiteral(right_lit) = &right.expression
            && left_lit.value == right_lit.value
        {
            let reg_id = left_lit.value as u16;
            if self.buffer_ids.contains(&reg_id) {
                if !self.preserved_registers.contains(&reg_id) {
                    self.preserved_registers.push(reg_id);
                }
            }
        }
        walk_assignment_expression(self, assign);
    }
}

fn classify_init_value(arg: &Argument) -> InitKind {
    match arg {
        Argument::ArrayExpression(arr) => {
            if arr.elements.is_empty() {
                return InitKind::EmptyArray;
            }
            if arr.elements.len() == 1 {
                return InitKind::SingleElemArray;
            }
            let all_zero = arr.elements.iter().all(|elem| {
                matches!(elem, oxc::ast::ast::ArrayExpressionElement::NumericLiteral(lit) if lit.value == 0.0)
            });
            if all_zero {
                InitKind::AllZeroArray
            } else {
                InitKind::NonZeroArray
            }
        }
        Argument::CallExpression(_) => InitKind::FunctionCall,
        _ => InitKind::Other,
    }
}

#[derive(Debug)]
struct BufferRoleVisitor {
    empty_array_ids: HashSet<u16>,
    fn_call_ids: HashSet<u16>,

    async_pair: Option<(u16, u16)>,

    output_main: Option<u16>,

    current_fn_idx2_empty: Vec<u16>,
    current_fn_idx2_fncall: Vec<u16>,
}

impl BufferRoleVisitor {
    fn new(classifications: &HashMap<u16, InitKind>) -> Self {
        let mut empty_array_ids = HashSet::new();
        let mut fn_call_ids = HashSet::new();
        for (id, kind) in classifications {
            match kind {
                InitKind::EmptyArray => {
                    empty_array_ids.insert(*id);
                }
                InitKind::FunctionCall => {
                    fn_call_ids.insert(*id);
                }
                _ => {}
            }
        }
        Self {
            empty_array_ids,
            fn_call_ids,
            async_pair: None,
            output_main: None,
            current_fn_idx2_empty: Vec::new(),
            current_fn_idx2_fncall: Vec::new(),
        }
    }
}

impl<'a> Visit<'a> for BufferRoleVisitor {
    fn visit_function_body(&mut self, body: &FunctionBody<'a>) {
        let prev_empty = std::mem::take(&mut self.current_fn_idx2_empty);
        let prev_fncall = std::mem::take(&mut self.current_fn_idx2_fncall);

        walk_function_body(self, body);

        if !self.current_fn_idx2_empty.is_empty() && self.current_fn_idx2_fncall.len() == 1 {
            self.output_main = Some(self.current_fn_idx2_fncall[0]);
        }

        self.current_fn_idx2_empty = prev_empty;
        self.current_fn_idx2_fncall = prev_fncall;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        for arg in &call.arguments {
            if let Argument::NumericLiteral(lit) = arg {
                let reg_id = lit.value as u16;
                if self.empty_array_ids.contains(&reg_id)
                    && !self.current_fn_idx2_empty.contains(&reg_id)
                {
                    self.current_fn_idx2_empty.push(reg_id);
                } else if self.fn_call_ids.contains(&reg_id)
                    && !self.current_fn_idx2_fncall.contains(&reg_id)
                {
                    self.current_fn_idx2_fncall.push(reg_id);
                }
            }
        }
        walk_call_expression(self, call);
    }

    fn visit_conditional_expression(&mut self, cond: &ConditionalExpression<'a>) {
        if self.async_pair.is_none()
            && let Expression::CallExpression(cons_call) = &cond.consequent
            && let Expression::CallExpression(alt_call) = &cond.alternate
            && !cons_call.arguments.is_empty()
            && !alt_call.arguments.is_empty()
            && let Argument::NumericLiteral(cons_lit) = &cons_call.arguments[0]
            && let Argument::NumericLiteral(alt_lit) = &alt_call.arguments[0]
        {
            let a = cons_lit.value as u16;
            let b = alt_lit.value as u16;
            if a != b && self.empty_array_ids.contains(&a) && self.empty_array_ids.contains(&b) {
                self.async_pair = Some((a, b));
            }
        }
        walk_conditional_expression(self, cond);
    }
}

fn extract_buffers(stmt: &Statement) -> Vec<u16> {
    if let Statement::BlockStatement(block) = stmt {
        for s in &block.body {
            if let Statement::ExpressionStatement(expr_stmt) = s
                && let Expression::ConditionalExpression(cond) = &expr_stmt.expression
            {
                return collect_or_chain_literals(&cond.test);
            }
        }
    }
    Vec::new()
}

fn unwrap_parens<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(paren) => unwrap_parens(&paren.expression),
        _ => expr,
    }
}

pub fn collect_or_chain_literals(expr: &Expression) -> Vec<u16> {
    let mut result = Vec::new();
    match expr {
        Expression::LogicalExpression(logical) if logical.operator.as_str() == "||" => {
            result.extend(collect_or_chain_literals(&logical.left));
            result.extend(collect_or_chain_literals(&logical.right));
        }
        Expression::BinaryExpression(bin) if bin.operator.as_str() == "==" => {
            if let Expression::NumericLiteral(lit) = &bin.right {
                result.push(lit.value as u16);
            } else if let Expression::NumericLiteral(lit) = &bin.left {
                result.push(lit.value as u16);
            }
        }
        _ => {}
    }
    result
}

pub fn analyze_registers<'a>(
    program: &Program<'a>,
    register_fn_name: &str,
) -> Option<RegisterInfo> {
    let mut visitor = RegisterVisitor::new(register_fn_name);
    walk_program(&mut visitor, program);
    let basic = visitor.info?;

    let mut classifier = InitClassifierVisitor::new(register_fn_name, &basic.buffer_ids);
    walk_program(&mut classifier, program);

    let cipher_state = classifier
        .classifications
        .iter()
        .find(|(_, kind)| matches!(kind, InitKind::AllZeroArray))
        .map(|(id, _)| *id)?;

    let seed_state = classifier
        .classifications
        .iter()
        .find(|(_, kind)| matches!(kind, InitKind::ThisAllZeroArray))
        .map(|(id, _)| *id)?;

    let random_bytes: Vec<_> = classifier
        .classifications
        .iter()
        .filter(|(_, kind)| matches!(kind, InitKind::FunctionCall))
        .map(|(key, _)| *key)
        .collect();

    let size_limit = classifier
        .classifications
        .iter()
        .find(|(_, kind)| matches!(kind, InitKind::SingleElemArray))
        .map(|(id, _)| *id)?;

    let error_codes = classifier
        .preserved_registers
        .iter()
        .find(|id| **id != size_limit)
        .copied()?;

    let mut roles = BufferRoleVisitor::new(&classifier.classifications);
    walk_program(&mut roles, program);

    let output_main = roles.output_main?;

    Some(RegisterInfo {
        ip: basic.ip,
        last_ip: basic.last_ip,
        read_bits_fn: basic.read_bits_fn,
        cipher_key_prop: basic.cipher_key_prop,
        block_idx_prop: basic.block_idx_prop,
        output_main,
        error_codes,
        cipher_state,
        random_bytes,
        seed_state,
        buffer_ids: basic.buffer_ids,
    })
}
