use std::cell::Cell;

use oxc::{
    allocator::{Allocator, Box as ABox, Vec as AVec},
    ast::ast::{
        BlockStatement, ConditionalExpression, Expression, ExpressionStatement, LogicalExpression,
        NullLiteral, Program, Statement,
    },
    ast_visit::{
        walk_mut::{walk_arrow_function_expression, walk_expression, walk_function, walk_program},
        VisitMut,
    },
    semantic::ScopeFlags,
    span::SPAN,
};

pub struct SequenceFlattener<'a> {
    allocator: &'a Allocator,
    hoisted: Vec<Statement<'a>>,
    in_unsafe_context: bool,
}

impl<'a> SequenceFlattener<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            allocator,
            hoisted: Vec::new(),
            in_unsafe_context: false,
        }
    }

    fn make_expr_stmt(&self, expression: Expression<'a>) -> Statement<'a> {
        Statement::ExpressionStatement(ABox::new_in(
            ExpressionStatement {
                span: SPAN,
                expression,
            },
            self.allocator,
        ))
    }

    fn visit_sub_statement(&mut self, stmt: &mut Statement<'a>) {
        let prev_hoisted = std::mem::take(&mut self.hoisted);
        self.visit_statement(stmt);

        if !self.hoisted.is_empty() {
            let mut body = AVec::new_in(self.allocator);
            for h in self.hoisted.drain(..) {
                body.push(h);
            }
            let old_stmt = std::mem::replace(
                stmt,
                Statement::EmptyStatement(ABox::new_in(
                    oxc::ast::ast::EmptyStatement { span: SPAN },
                    self.allocator,
                )),
            );
            body.push(old_stmt);
            *stmt = Statement::BlockStatement(ABox::new_in(
                BlockStatement {
                    span: SPAN,
                    body,
                    scope_id: Cell::default(),
                },
                self.allocator,
            ));
        }

        self.hoisted = prev_hoisted;
    }
}

impl<'a> VisitMut<'a> for SequenceFlattener<'a> {
    fn visit_statements(&mut self, stmts: &mut AVec<'a, Statement<'a>>) {
        let mut new_stmts = AVec::new_in(self.allocator);

        for mut stmt in stmts.drain(..) {
            self.visit_statement(&mut stmt);

            for hoisted in self.hoisted.drain(..) {
                new_stmts.push(hoisted);
            }

            let is_seq = matches!(
                &stmt,
                Statement::ExpressionStatement(es)
                    if matches!(es.expression, Expression::SequenceExpression(_))
            );

            if is_seq {
                let Statement::ExpressionStatement(expr_stmt) = stmt else {
                    unreachable!()
                };
                let Expression::SequenceExpression(seq) = expr_stmt.unbox().expression else {
                    unreachable!()
                };
                for sub_expr in seq.unbox().expressions {
                    new_stmts.push(self.make_expr_stmt(sub_expr));
                }
            } else {
                new_stmts.push(stmt);
            }
        }

        *stmts = new_stmts;
    }

    fn visit_expression(&mut self, expr: &mut Expression<'a>) {
        walk_expression(self, expr);

        if self.in_unsafe_context {
            return;
        }

        if matches!(expr, Expression::SequenceExpression(_)) {
            let Expression::SequenceExpression(mut seq) = std::mem::replace(
                expr,
                Expression::NullLiteral(ABox::new_in(NullLiteral { span: SPAN }, self.allocator)),
            ) else {
                unreachable!()
            };

            let last = seq.expressions.pop().unwrap();

            for sub_expr in seq.expressions.drain(..) {
                self.hoisted.push(self.make_expr_stmt(sub_expr));
            }

            *expr = last;
        }
    }

    fn visit_logical_expression(&mut self, it: &mut LogicalExpression<'a>) {
        self.visit_expression(&mut it.left);

        let prev = self.in_unsafe_context;
        self.in_unsafe_context = true;
        self.visit_expression(&mut it.right);
        self.in_unsafe_context = prev;
    }

    fn visit_conditional_expression(&mut self, it: &mut ConditionalExpression<'a>) {
        self.visit_expression(&mut it.test);

        let prev = self.in_unsafe_context;
        self.in_unsafe_context = true;
        self.visit_expression(&mut it.consequent);
        self.visit_expression(&mut it.alternate);
        self.in_unsafe_context = prev;
    }

    fn visit_for_statement(&mut self, it: &mut oxc::ast::ast::ForStatement<'a>) {
        let prev = self.in_unsafe_context;

        if let Some(init) = &mut it.init {
            self.visit_for_statement_init(init);
        }

        self.in_unsafe_context = true;
        if let Some(test) = &mut it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &mut it.update {
            self.visit_expression(update);
        }
        self.in_unsafe_context = prev;

        self.visit_sub_statement(&mut it.body);
    }

    fn visit_while_statement(&mut self, it: &mut oxc::ast::ast::WhileStatement<'a>) {
        self.visit_expression(&mut it.test);
        self.visit_sub_statement(&mut it.body);
    }

    fn visit_do_while_statement(&mut self, it: &mut oxc::ast::ast::DoWhileStatement<'a>) {
        self.visit_sub_statement(&mut it.body);
        self.visit_expression(&mut it.test);
    }

    fn visit_for_in_statement(&mut self, it: &mut oxc::ast::ast::ForInStatement<'a>) {
        self.visit_expression(&mut it.right);
        self.visit_sub_statement(&mut it.body);
    }

    fn visit_for_of_statement(&mut self, it: &mut oxc::ast::ast::ForOfStatement<'a>) {
        self.visit_expression(&mut it.right);
        self.visit_sub_statement(&mut it.body);
    }

    fn visit_if_statement(&mut self, it: &mut oxc::ast::ast::IfStatement<'a>) {
        self.visit_expression(&mut it.test);
        self.visit_sub_statement(&mut it.consequent);
        if let Some(alt) = &mut it.alternate {
            self.visit_sub_statement(alt);
        }
    }

    fn visit_with_statement(&mut self, it: &mut oxc::ast::ast::WithStatement<'a>) {
        self.visit_expression(&mut it.object);
        self.visit_sub_statement(&mut it.body);
    }

    fn visit_labeled_statement(&mut self, it: &mut oxc::ast::ast::LabeledStatement<'a>) {
        self.visit_sub_statement(&mut it.body);
    }

    fn visit_function(&mut self, it: &mut oxc::ast::ast::Function<'a>, flags: ScopeFlags) {
        let prev_unsafe = self.in_unsafe_context;
        let prev_hoisted = std::mem::take(&mut self.hoisted);
        self.in_unsafe_context = false;

        walk_function(self, it, flags);

        self.in_unsafe_context = prev_unsafe;
        self.hoisted = prev_hoisted;
    }

    fn visit_arrow_function_expression(
        &mut self,
        it: &mut oxc::ast::ast::ArrowFunctionExpression<'a>,
    ) {
        let prev_unsafe = self.in_unsafe_context;
        let prev_hoisted = std::mem::take(&mut self.hoisted);
        self.in_unsafe_context = false;

        walk_arrow_function_expression(self, it);

        self.in_unsafe_context = prev_unsafe;
        self.hoisted = prev_hoisted;
    }
}

pub fn flatten_sequences<'a>(allocator: &'a Allocator, program: &mut Program<'a>) {
    let mut flattener = SequenceFlattener::new(allocator);
    walk_program(&mut flattener, program);
}
