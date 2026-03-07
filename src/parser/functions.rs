use std::collections::HashMap;

use oxc::{
    ast::ast::{
        AssignmentTarget, Expression, Function, FunctionBody, Program, Statement,
        VariableDeclarator,
    },
    ast_visit::{
        Visit,
        walk::{walk_function, walk_function_body, walk_program, walk_variable_declarator},
    },
    semantic::ScopeFlags,
};

#[derive(Debug)]
pub struct FunctionsOutput {
    pub register_fn: String,
    pub opcode_fn: String,
    pub int_fn: String,
    pub load_imm_fn: String,
    pub utf8encode_fn: String,
}

#[derive(Default)]
struct FunctionFinderVisitor {
    last_func: String,

    register_fn: String,
    opcode_fn: String,
    int_fn_candidates: HashMap<String, u32>,
    load_imm_fn: String,
    utf8encode_fn: String,
}

impl<'a> Visit<'a> for FunctionFinderVisitor {
    fn visit_function(&mut self, func: &Function<'a>, _flags: ScopeFlags) {
        if let Some(name) = func.name() {
            self.last_func = name.into_string();
        }
        walk_function(self, func, _flags);
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
        let stmts = &body.statements;

        match stmts.len() {
            2 => {
                if let Statement::ExpressionStatement(expr) = &stmts[1]
                    && let Expression::AssignmentExpression(assign) = &expr.expression
                    && let AssignmentTarget::ComputedMemberExpression(_) = &assign.left
                    && let Expression::NumericLiteral(_lit) = &assign.right
                {
                    self.opcode_fn = self.last_func.clone();
                }

                if matches!(&stmts[0], Statement::IfStatement(_))
                    && let Statement::ExpressionStatement(expr) = &stmts[1]
                    && matches!(expr.expression, Expression::LogicalExpression(_))
                {
                    self.register_fn = self.last_func.clone();
                }
            }

            3 => {
                if let Statement::ExpressionStatement(expr1) = &stmts[0]
                    && let Expression::AssignmentExpression(assign1) = &expr1.expression
                    && matches!(assign1.right, Expression::CallExpression(_))
                    && let Statement::ExpressionStatement(expr2) = &stmts[1]
                    && let Expression::AssignmentExpression(assign2) = &expr2.expression
                    && matches!(assign2.right, Expression::CallExpression(_))
                    && let Statement::ExpressionStatement(expr3) = &stmts[2]
                    && matches!(expr3.expression, Expression::CallExpression(_))
                {
                    *self
                        .int_fn_candidates
                        .entry(self.last_func.clone())
                        .or_insert(0) += 1;
                }

                if let Statement::ExpressionStatement(expr1) = &stmts[0]
                    && let Expression::AssignmentExpression(assign1) = &expr1.expression
                    && matches!(assign1.right, Expression::CallExpression(_))
                    && matches!(stmts[1], Statement::ForStatement(_))
                    && let Statement::ExpressionStatement(expr3) = &stmts[2]
                    && matches!(expr3.expression, Expression::CallExpression(_))
                {
                    self.load_imm_fn = self.last_func.clone();
                }
            }

            8 => {
                if let Statement::ExpressionStatement(expr1) = &stmts[0]
                    && let Expression::AssignmentExpression(assign1) = &expr1.expression
                    && let Expression::BinaryExpression(bin1) = &assign1.right
                    && bin1.operator.as_str() == "&"
                    && let Statement::ExpressionStatement(expr2) = &stmts[1]
                    && matches!(expr2.expression, Expression::AssignmentExpression(_))
                    && let Statement::ExpressionStatement(expr3) = &stmts[2]
                    && matches!(expr3.expression, Expression::AssignmentExpression(_))
                    && let Statement::ExpressionStatement(expr4) = &stmts[3]
                    && matches!(expr4.expression, Expression::AssignmentExpression(_))
                    && let Statement::ExpressionStatement(expr5) = &stmts[4]
                    && matches!(expr5.expression, Expression::AssignmentExpression(_))
                    && let Statement::ExpressionStatement(expr6) = &stmts[5]
                    && matches!(expr6.expression, Expression::LogicalExpression(_))
                    && let Statement::ExpressionStatement(expr7) = &stmts[6]
                    && matches!(expr7.expression, Expression::LogicalExpression(_))
                    && let Statement::ExpressionStatement(expr8) = &stmts[7]
                    && matches!(expr8.expression, Expression::CallExpression(_))
                {
                    self.utf8encode_fn = self.last_func.clone();
                }
            }

            _ => {}
        }

        walk_function_body(self, body);
    }
}

pub(super) fn find_functions<'a>(program: &Program<'a>) -> FunctionsOutput {
    let mut visitor = FunctionFinderVisitor::default();
    walk_program(&mut visitor, program);

    let int_fn = visitor
        .int_fn_candidates
        .iter()
        .filter(|(_, count)| **count == 1)
        .map(|(name, _)| name.clone())
        .next()
        .unwrap_or_default();

    FunctionsOutput {
        register_fn: visitor.register_fn,
        opcode_fn: visitor.opcode_fn,
        int_fn,
        load_imm_fn: visitor.load_imm_fn,
        utf8encode_fn: visitor.utf8encode_fn,
    }
}
