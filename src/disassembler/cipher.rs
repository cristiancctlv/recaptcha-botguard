use crate::parser::cipher::{CipherInfo, CipherParam};

pub fn eval_cipher(
    info: &CipherInfo,
    params: &[CipherParam],
    block_idx: u32,
    seed: [i32; 4],
    key: i32,
) -> [u8; 8] {
    let mut vals = [0i32; 5];

    for (i, param) in params.iter().enumerate() {
        vals[i] = match param {
            CipherParam::BlockIdx => block_idx as i32,
            CipherParam::Seed1 => seed[2] as i32,
            CipherParam::Seed2 => seed[3] as i32,
            CipherParam::Key => key as i32,
        };
    }

    let param_idx = |p: &CipherParam| {
        params
            .iter()
            .position(|x| x == p)
            .expect("parameter not found")
    };

    for round in 0..info.rounds {
        for op in &info.operations {
            let rhs = eval_expr(&op.value, &vals, round, &param_idx);
            let idx = param_idx(&op.target);
            let target = &mut vals[idx];

            match op.operator.as_str() {
                "=" => *target = rhs,
                "^=" => *target ^= rhs,
                "+=" => *target = target.wrapping_add(rhs),
                "-=" => *target = target.wrapping_sub(rhs),
                "|=" => *target |= rhs,
                "&=" => *target &= rhs,
                _ => {}
            }
        }
    }

    let k = vals[param_idx(&CipherParam::Key)] as u32;
    let b = vals[param_idx(&CipherParam::BlockIdx)] as u32;

    [
        (k >> 24) as u8,
        (k >> 16) as u8,
        (k >> 8) as u8,
        k as u8,
        (b >> 24) as u8,
        (b >> 16) as u8,
        (b >> 8) as u8,
        b as u8,
    ]
}

fn eval_expr<F>(
    expr: &crate::parser::cipher::CipherExpr,
    vals: &[i32; 5],
    round: u32,
    param_idx: &F,
) -> i32
where
    F: Fn(&CipherParam) -> usize,
{
    use crate::parser::cipher::CipherExpr;

    match expr {
        CipherExpr::Param(p) => vals[param_idx(p)],
        CipherExpr::Literal(v) => *v as i32,
        CipherExpr::LoopVar => round as i32,
        CipherExpr::BinaryOp { op, left, right } => {
            let l = eval_expr(left, vals, round, param_idx);
            let r = eval_expr(right, vals, round, param_idx);

            match op.as_str() {
                ">>>" => ((l as u32) >> (r & 31)) as i32,
                ">>" => l >> (r & 31),
                "<<" => l << (r & 31),
                "+" => l.wrapping_add(r),
                "-" => l.wrapping_sub(r),
                "*" => l.wrapping_mul(r),
                "^" => l ^ r,
                "|" => l | r,
                "&" => l & r,
                _ => unreachable!("unsupported operator: {}", op),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CipherState {
    cipher_info: Option<CipherInfo>,
    cipher_params: Vec<CipherParam>,
    block_idx: Option<usize>,
    cipher_block: [u8; 8],
    cipher_key: i32,
    seed_bytes: [i32; 3],
    enabled: bool,
}

impl CipherState {
    pub fn new() -> Self {
        Self {
            cipher_info: None,
            cipher_params: Vec::new(),
            block_idx: None,
            cipher_block: [0u8; 8],
            cipher_key: 0,
            seed_bytes: [0, 0, 0],
            enabled: false,
        }
    }

    pub fn with_cipher(cipher_info: CipherInfo, cipher_params: Vec<CipherParam>) -> Self {
        Self {
            cipher_info: Some(cipher_info),
            cipher_params,
            block_idx: None,
            cipher_block: [0u8; 8],
            cipher_key: 0,
            seed_bytes: [0, 0, 0],
            enabled: true,
        }
    }

    pub fn update_seed(&mut self, value: i32, idx: usize) {
        self.seed_bytes[idx] = value;
    }

    pub fn set_seed(&mut self, seed: &[i32; 3]) {
        self.seed_bytes = *seed;
        self.enabled = true;
        self.block_idx = None;
    }

    pub fn set_cipher_info(&mut self, info: CipherInfo, params: Vec<CipherParam>) {
        self.cipher_info = Some(info);
        self.cipher_params = params;
        self.block_idx = None;
    }

    pub fn reset_block_idx(&mut self) {
        self.block_idx = None;
    }

    pub fn set_cipher_key(&mut self, key: i32) {
        self.cipher_key = key;
        self.block_idx = None;
    }

    pub fn get_cipher_key(&self) -> i32 {
        self.cipher_key
    }

    pub fn get_block_idx(&self) -> usize {
        self.block_idx.unwrap_or(0)
    }

    pub fn get_seed(&self) -> [i32; 3] {
        self.seed_bytes
    }

    pub fn get_cipher_byte(&mut self, bit_pos: usize, byte_idx: usize) -> u8 {
        if !self.enabled {
            return 0;
        }
        let new_block_idx = bit_pos >> 6;
        if self.block_idx != Some(new_block_idx) {
            self.block_idx = Some(new_block_idx);
            self.cipher_block = if let Some(ref info) = self.cipher_info {
                eval_cipher(
                    info,
                    &self.cipher_params,
                    new_block_idx as u32,
                    [0, 0, self.seed_bytes[1], self.seed_bytes[2]],
                    self.cipher_key,
                )
            } else {
                [0u8; 8]
            };
        }
        self.cipher_block[byte_idx & 7]
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }
}

impl Default for CipherState {
    fn default() -> Self {
        Self::new()
    }
}
