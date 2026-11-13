//! Historical frame-3 vector reader only. Never linked into the library.
extern crate alloc;
use alloc::vec::Vec;
use serde::Serialize;
use serde_json::Value;

pub(crate) fn bytes(value: &impl Serialize) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("closed authority value");
    let mut out = Vec::new();
    frame(&value, &mut out);
    out
}
fn length(n: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(n as u64).to_be_bytes());
}
fn frame(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(0),
        Value::Bool(b) => out.push(if *b { 2 } else { 1 }),
        Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                out.push(3);
                out.extend_from_slice(&n.to_be_bytes());
            } else {
                let n = n.as_i64().expect("closed authority numbers are integers");
                out.push(4);
                out.extend_from_slice(&n.unsigned_abs().to_be_bytes());
            }
        }
        Value::String(s) => {
            out.push(5);
            length(s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(xs) => {
            out.push(6);
            length(xs.len(), out);
            for x in xs {
                frame(x, out);
            }
        }
        Value::Object(xs) => {
            out.push(7);
            length(xs.len(), out);
            let mut fields: Vec<_> = xs.iter().collect();
            fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for (k, v) in fields {
                frame(&Value::String(k.clone()), out);
                frame(v, out);
            }
        }
    }
}
