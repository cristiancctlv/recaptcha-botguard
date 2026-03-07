use std::collections::HashMap;

use crate::disassembler::Opcode;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SIGNATURE_TABLE: HashMap<Vec<String>, Opcode> = {
        let mut m = HashMap::new();
        m.insert(
            vec![
                "11fe42eda678e8af94dd2f948f8d0809".to_string(),
                "f707691740d4493cffd48f4a3d4d0ae2".to_string(),
            ],
            Opcode::CmpEqual,
        );
        m.insert(
            vec![
                "194356ea231b4775c0ca7556f8001a11".to_string(),
                "0f7bb83794f59bae17c6afa785c8787c".to_string(),
            ],
            Opcode::SetProperty,
        );
        m.insert(
            vec!["ad042dc3a3fd926f0e057de5d0134abd".to_string()],
            Opcode::Utf8Encode,
        );
        m.insert(
            vec!["acb5e943b89da07750b03f5816a39c71".to_string()],
            Opcode::IntB8,
        );
        m.insert(
            vec!["9eb9a6550ecf2ae956f083d19b988dbc".to_string()],
            Opcode::NewOpEval,
        );
        m.insert(
            vec!["7460170abf62b16ce7b0399c62511878".to_string()],
            Opcode::Or,
        );
        m.insert(
            vec!["5bcff46eada102c42a3fcd4c8aa1daae".to_string()],
            Opcode::Ushr,
        );
        m.insert(
            vec!["7b174fc2724678abdb4193a24df214f7".to_string()],
            Opcode::Jump,
        );
        m.insert(
            vec!["ba0be00583d00d3ab0ecfe46323bb437".to_string()],
            Opcode::Utf8Encode3,
        );
        m.insert(
            vec!["eeed2d1e154dca26d2f7bd32bf7c5150".to_string()],
            Opcode::IntB32,
        );
        m.insert(
            vec!["46efd9adba663789647ded7ec017a4db".to_string()],
            Opcode::CallBack,
        );
        m.insert(
            vec!["bf82cfd9a4d1758e4c0e00b41c9d1898".to_string()],
            Opcode::AttachEvent,
        );
        m.insert(
            vec!["637c4ec28029ba436b9d8e1c5fd31959".to_string()],
            Opcode::Apply,
        );
        m.insert(
            vec!["9db8527de5f0d89e198986c9295bc29e".to_string()],
            Opcode::GetProperty,
        );
        m.insert(
            vec!["19cdc4fd7b80ec154b6dd5d1212de94f".to_string()],
            Opcode::EmptyArray,
        );
        m.insert(
            vec!["4a8a08f09d37b73795649038408b5f33".to_string()],
            Opcode::LoadImm32,
        );
        m.insert(
            vec!["bf5795e841f675cdbf58cea08a0137a1".to_string()],
            Opcode::CallConst,
        );
        m.insert(
            vec!["b152da8af2535b21dfcaea5e63393bf7".to_string()],
            Opcode::SyncMemory,
        );
        m.insert(
            vec!["a2e4822a98337283e39f7b60acf85ec9".to_string()],
            Opcode::Nop,
        );
        m.insert(
            vec![
                "1a08849ed5c675a84c61d013dcea8c87".to_string(),
                "3f2710f20855f088f80be0ef9e541229".to_string(),
            ],
            Opcode::JumpIfNonZero,
        );
        m.insert(
            vec!["b2d7c2ed1ca84f87f4547ff0b7dfc17c".to_string()],
            Opcode::ToString,
        );
        m.insert(
            vec!["174c30237f0c2bb5519c272b8310deb3".to_string()],
            Opcode::In,
        );
        m.insert(
            vec!["61798718bba80f068fdc5e7881e550d3".to_string()],
            Opcode::LoadString,
        );
        m.insert(
            vec!["76f85a475b0a501e5ef5cf558639904e".to_string()],
            Opcode::Add,
        );
        m.insert(
            vec!["dba8e2593c3c0fe3ba989538dc542e26".to_string()],
            Opcode::NewArray,
        );
        m.insert(
            vec!["ec1e5fe9897c879f1096aeeaca4f2094".to_string()],
            Opcode::RemoveEvent,
        );
        m.insert(
            vec!["5b4571dd39b737a336c9054f58db0e6f".to_string()],
            Opcode::Typeof,
        );
        m.insert(
            vec!["7a2c5cf6421e9123e9893ab41cd32a95".to_string()],
            Opcode::Cleanup,
        );
        m
    };
}

pub fn build_opcode_table(
    signatures: &HashMap<u16, String>,
    special_opcodes: &HashMap<u16, Opcode>,
) -> HashMap<u16, Opcode> {
    let mut table = HashMap::new();

    for (&id, kind) in special_opcodes {
        table.insert(id, *kind);
    }

    for (&id, sig) in signatures {
        if let Some(kind) = lookup_opcode(sig) {
            table.insert(id, kind);
        }
    }
    table
}

pub fn lookup_opcode(sig: &str) -> Option<Opcode> {
    for (sigs, kind) in SIGNATURE_TABLE.iter() {
        if sigs.iter().any(|s| s == sig) {
            return Some(*kind);
        }
    }
    None
}

pub fn report_unmatched(
    signatures: &HashMap<u16, String>,
    table: &HashMap<u16, Opcode>,
) -> Vec<(u16, String)> {
    let mut unmatched: Vec<_> = signatures
        .iter()
        .filter(|(id, _)| !table.contains_key(id))
        .map(|(&id, sig)| (id, sig.clone()))
        .collect();
    unmatched.sort_by_key(|(id, _)| *id);
    unmatched
}
