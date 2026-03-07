use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

use oxc::{
    ast::ast::{
        Argument, AssignmentTarget, Expression, ForStatementInit, Function, FunctionBody, Program,
        Statement, VariableDeclarator,
    },
    ast_visit::{
        Visit,
        walk::{
            walk_expression, walk_function, walk_function_body, walk_program,
            walk_variable_declarator,
        },
    },
    semantic::ScopeFlags,
};

impl Display for CipherAssignment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.target, self.operator, self.value)
    }
}

impl Display for CipherExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CipherExpr::Param(p) => write!(f, "{p}"),
            CipherExpr::Literal(v) => write!(f, "{v}"),
            CipherExpr::LoopVar => write!(f, "i"),
            CipherExpr::BinaryOp { op, left, right } => {
                write!(f, "({} {} {})", left, op, right)
            }
        }
    }
}

impl Display for CipherParam {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            CipherParam::BlockIdx => "block_idx",
            CipherParam::Seed1 => "seed1",
            CipherParam::Seed2 => "seed2",
            CipherParam::Key => "key",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherParam {
    BlockIdx,
    Seed1,
    Seed2,
    Key,
}

#[derive(Debug, Clone)]
pub struct ReadBitsInfo {
    pub get_register_fn: String,
    pub cipher_fn: String,
    pub block_shift: u32,
}

struct ReadBitsVisitor {
    fn_name: String,
    cipher_key_prop: String,
    block_idx_prop: String,
    last_func: String,

    pub cipher_params: Vec<CipherParam>,
    pub info: Option<ReadBitsInfo>,
}

impl ReadBitsVisitor {
    fn new(fn_name: &str, cipher_key_prop: &str, block_idx_prop: &str) -> Self {
        Self {
            fn_name: fn_name.to_string(),
            cipher_key_prop: cipher_key_prop.to_string(),
            block_idx_prop: block_idx_prop.to_string(),
            last_func: String::new(),

            cipher_params: vec![],
            info: None,
        }
    }
}

impl<'a> Visit<'a> for ReadBitsVisitor {
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
        if self.last_func == self.fn_name && self.info.is_none() {
            let ckp = self.cipher_key_prop.clone();
            let bip = self.block_idx_prop.clone();
            match parse_read_bits_body(body, &ckp, &bip) {
                Some((info, cipher_params)) => {
                    self.info = Some(info);
                    self.cipher_params = cipher_params;
                }
                None => {}
            }
        }
        walk_function_body(self, body);
    }
}

fn parse_read_bits_body(
    body: &FunctionBody,
    cipher_key_prop: &str,
    block_idx_prop: &str,
) -> Option<(ReadBitsInfo, Vec<CipherParam>)> {
    let stmts = &body.statements;
    if stmts.is_empty() {
        return None;
    }

    let get_register_fn = if let Statement::ExpressionStatement(expr_stmt) = &stmts[0]
        && let Expression::AssignmentExpression(assign) = &expr_stmt.expression
        && let Expression::CallExpression(call) = &assign.right
    {
        call.callee_name()?.to_string()
    } else {
        return None;
    };

    let loop_stmt = stmts.iter().find_map(|stmt| match stmt {
        Statement::ForStatement(f) => Some(&f.body),
        Statement::WhileStatement(w) => Some(&w.body),
        _ => None,
    })?;

    let Statement::BlockStatement(block) = loop_stmt else {
        return None;
    };

    let mut visitor = CipherAnalysis::new(cipher_key_prop, block_idx_prop);
    visitor.visit_block_statement(block);

    let block_shift = visitor.block_shift;
    let (cipher_fn, cipher_params) = match visitor.cipher_call {
        Some((name, params)) => (Some(name), Some(params)),
        None => (None, None),
    };

    Some((
        ReadBitsInfo {
            get_register_fn,
            cipher_fn: cipher_fn?,
            block_shift: block_shift?,
        },
        cipher_params?,
    ))
}

struct CipherAnalysis<'a> {
    cipher_key_prop: &'a str,
    block_idx_prop: &'a str,
    block_shift: Option<u32>,
    cipher_call: Option<(String, Vec<CipherParam>)>,
}

impl<'a> CipherAnalysis<'a> {
    fn new(cipher_key_prop: &'a str, block_idx_prop: &'a str) -> Self {
        Self {
            cipher_key_prop,
            block_idx_prop,
            block_shift: None,
            cipher_call: None,
        }
    }
}

impl<'a> Visit<'a> for CipherAnalysis<'a> {
    fn visit_expression(&mut self, expr: &Expression<'a>) {
        match expr {
            Expression::BinaryExpression(bin) => {
                if self.block_shift.is_none()
                    && bin.operator.as_str() == "!="
                    && let Expression::BinaryExpression(shift) = &bin.right
                    && shift.operator.as_str() == ">>"
                    && let Expression::NumericLiteral(lit) = &shift.right
                {
                    self.block_shift = Some(lit.value as u32);
                }
            }

            Expression::CallExpression(call) => {
                if self.cipher_call.is_none() {
                    let has_array_arg = call
                        .arguments
                        .iter()
                        .any(|arg| matches!(arg, Argument::ArrayExpression(_)));

                    if has_array_arg {
                        if let Some(name) = call.callee_name() {
                            let params = call
                                .arguments
                                .iter()
                                .flat_map(|arg| {
                                    classify_cipher_arg(
                                        arg,
                                        self.cipher_key_prop,
                                        self.block_idx_prop,
                                    )
                                })
                                .collect();

                            self.cipher_call = Some((name.to_string(), params));
                        }
                    }
                }
            }

            _ => {}
        }

        walk_expression(self, expr);
    }
}

fn classify_cipher_arg(
    arg: &Argument,
    cipher_key_prop: &str,
    block_idx_prop: &str,
) -> Vec<CipherParam> {
    if let Argument::ArrayExpression(_) = arg {
        return vec![CipherParam::Seed1, CipherParam::Seed2];
    }
    if let Argument::StaticMemberExpression(member) = arg {
        if member.property.name == block_idx_prop {
            return vec![CipherParam::BlockIdx];
        }
        if member.property.name == cipher_key_prop {
            return vec![CipherParam::Key];
        }
    }
    if arg_contains_prop(arg, cipher_key_prop) {
        return vec![CipherParam::Key];
    }
    if arg_contains_prop(arg, block_idx_prop) {
        return vec![CipherParam::BlockIdx];
    }
    vec![CipherParam::Seed1]
}

fn arg_contains_prop(arg: &Argument, prop: &str) -> bool {
    match arg {
        Argument::StaticMemberExpression(member) => member.property.name == prop,
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub enum CipherExpr {
    Param(CipherParam),
    Literal(i64),
    LoopVar,
    BinaryOp {
        op: String,
        left: Box<CipherExpr>,
        right: Box<CipherExpr>,
    },
}

#[derive(Debug, Clone)]
pub struct CipherAssignment {
    pub target: CipherParam,
    pub operator: String,
    pub value: CipherExpr,
}

#[derive(Debug, Clone)]
pub struct CipherInfo {
    pub rounds: u32,
    pub round_constant: u32,
    pub operations: Vec<CipherAssignment>,
}

struct CipherVisitor {
    fn_name: String,
    cipher_params: Vec<CipherParam>,
    last_func: String,
    last_params: Vec<String>,
    pub info: Option<CipherInfo>,
}

impl CipherVisitor {
    fn new(fn_name: &str, cipher_params: Vec<CipherParam>) -> Self {
        Self {
            fn_name: fn_name.to_string(),
            cipher_params,
            last_func: String::new(),
            last_params: Vec::new(),
            info: None,
        }
    }
}

impl<'a> Visit<'a> for CipherVisitor {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        if let Some(name) = func.name() {
            self.last_func = name.into_string();
        }
        self.last_params = func
            .params
            .items
            .iter()
            .filter_map(|p| p.pattern.get_identifier_name().map(|n| n.to_string()))
            .collect();
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
        if self.last_func == self.fn_name && self.info.is_none() {
            let param_names = self.last_params.clone();
            let cipher_params = self.cipher_params.clone();
            self.info = parse_cipher_body(body, &param_names, &cipher_params);
        }
        walk_function_body(self, body);
    }
}

fn parse_cipher_body(
    body: &FunctionBody,
    param_names: &[String],
    cipher_params: &[CipherParam],
) -> Option<CipherInfo> {
    let mut param_map: HashMap<String, CipherParam> = HashMap::new();
    let mut name_idx = 0;
    let mut param_idx = 0;
    while name_idx < param_names.len() && param_idx < cipher_params.len() {
        let param = &cipher_params[param_idx];
        if *param == CipherParam::Seed1
            && param_idx + 1 < cipher_params.len()
            && cipher_params[param_idx + 1] == CipherParam::Seed2
        {
            // Array argument: seeds are extracted from this param inside the body,
            // so skip both Seed1 and Seed2 but only consume one param name.
            param_idx += 2;
            name_idx += 1;
        } else {
            param_map.insert(param_names[name_idx].clone(), param.clone());
            param_idx += 1;
            name_idx += 1;
        }
    }

    for stmt in &body.statements {
        if let Statement::ForStatement(for_stmt) = stmt {
            if let Some(ForStatementInit::AssignmentExpression(assign)) = &for_stmt.init
                && let AssignmentTarget::AssignmentTargetIdentifier(ident) = &assign.left
                && let Expression::BinaryExpression(bin_expr) = &assign.right
                && let Expression::ComputedMemberExpression(member) = &bin_expr.left
                && let Some(_arr_ident) = member.object.get_identifier_reference()
                && let Expression::NumericLiteral(lit) = &member.expression
            {
                let target_name = ident.name.to_string();
                let idx = lit.value as usize;
                if idx == 2 {
                    param_map.insert(target_name, CipherParam::Seed1);
                } else if idx == 3 {
                    param_map.insert(target_name, CipherParam::Seed2);
                }
            }

            break;
        }

        if let Statement::ExpressionStatement(expr_stmt) = stmt
            && let Expression::AssignmentExpression(assign) = &expr_stmt.expression
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
            && let Expression::BinaryExpression(bin_expr) = &assign.right
            && let Expression::ComputedMemberExpression(member) = &bin_expr.left
            && let Some(_arr_ident) = member.object.get_identifier_reference()
            && let Expression::NumericLiteral(lit) = &member.expression
        {
            let target_name = id.name.to_string();
            let idx = lit.value as usize;
            if idx == 2 {
                param_map.insert(target_name, CipherParam::Seed1);
            } else if idx == 3 {
                param_map.insert(target_name, CipherParam::Seed2);
            }
        }
    }

    let for_stmt = body.statements.iter().find_map(|stmt| {
        if let Statement::ForStatement(f) = stmt {
            Some(f)
        } else {
            None
        }
    })?;

    let rounds = if let Some(Expression::BinaryExpression(bin)) = &for_stmt.test
        && let Expression::NumericLiteral(lit) = &bin.right
    {
        lit.value as u32
    } else {
        return None;
    };

    let loop_var = if let Some(Expression::BinaryExpression(bin)) = &for_stmt.test
        && let Some(id) = bin.left.get_identifier_reference()
    {
        id.name.to_string()
    } else {
        String::new()
    };

    let Statement::BlockStatement(block) = &for_stmt.body else {
        return None;
    };

    let mut operations = Vec::new();
    for stmt in &block.body {
        if let Statement::ExpressionStatement(expr_stmt) = stmt
            && let Expression::AssignmentExpression(assign) = &expr_stmt.expression
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
        {
            let target_name = id.name.to_string();
            if let Some(target) = param_map.get(&target_name) {
                let value = expr_to_cipher_expr(&assign.right, &param_map, &loop_var);
                operations.push(CipherAssignment {
                    target: target.clone(),
                    operator: assign.operator.as_str().to_string(),
                    value,
                });
            }
        }
    }

    let round_constant = operations
        .iter()
        .filter(|op| op.operator == "^=")
        .find_map(|op| find_round_constant(&op.value))
        .unwrap_or(0);

    Some(CipherInfo {
        rounds,
        round_constant,
        operations,
    })
}

fn expr_to_cipher_expr(
    expr: &Expression,
    params: &HashMap<String, CipherParam>,
    loop_var: &str,
) -> CipherExpr {
    match expr {
        expr if expr.is_identifier_reference() => {
            let id = expr.get_identifier_reference().unwrap();
            if id.name == loop_var {
                CipherExpr::LoopVar
            } else if let Some(param) = params.get(id.name.as_str()) {
                CipherExpr::Param(param.clone())
            } else {
                CipherExpr::Literal(0)
            }
        }
        Expression::NumericLiteral(lit) => CipherExpr::Literal(lit.value as i64),
        Expression::BinaryExpression(bin) => CipherExpr::BinaryOp {
            op: bin.operator.as_str().to_string(),
            left: Box::new(expr_to_cipher_expr(&bin.left, params, loop_var)),
            right: Box::new(expr_to_cipher_expr(&bin.right, params, loop_var)),
        },
        Expression::ParenthesizedExpression(paren) => {
            expr_to_cipher_expr(&paren.expression, params, loop_var)
        }
        _ => CipherExpr::Literal(0),
    }
}

fn find_round_constant(expr: &CipherExpr) -> Option<u32> {
    match expr {
        CipherExpr::BinaryOp { op, left, right } if op == "+" => {
            if let CipherExpr::Literal(v) = right.as_ref() {
                if *v != 0 {
                    return Some(*v as u32);
                }
            }
            if let CipherExpr::Literal(v) = left.as_ref() {
                if *v != 0 {
                    return Some(*v as u32);
                }
            }
            None
        }
        CipherExpr::BinaryOp { left, right, .. } => {
            find_round_constant(left).or_else(|| find_round_constant(right))
        }
        _ => None,
    }
}

pub fn analyze_read_bits<'a>(
    program: &Program<'a>,
    read_bits_fn_name: &str,
    cipher_key_prop: &str,
    block_idx_prop: &str,
) -> Option<(ReadBitsInfo, Vec<CipherParam>)> {
    let mut visitor = ReadBitsVisitor::new(read_bits_fn_name, cipher_key_prop, block_idx_prop);
    walk_program(&mut visitor, program);
    Some((visitor.info.unwrap(), visitor.cipher_params))
}

pub fn analyze_cipher<'a>(
    program: &Program<'a>,
    cipher_fn_name: &str,
    cipher_params: &[CipherParam],
) -> Option<CipherInfo> {
    let mut visitor = CipherVisitor::new(cipher_fn_name, cipher_params.to_vec());
    walk_program(&mut visitor, program);
    visitor.info
}
