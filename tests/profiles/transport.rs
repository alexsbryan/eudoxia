//! Reference public delivery transport. Authenticating the carrier does not
//! replace the separate signature/authority of any carried act.
use super::*;
use ed25519_dalek::Signer;

pub struct Packet {
    pub carrier: Principal,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
fn message(payload: &[u8]) -> Vec<u8> {
    let mut m = b"reference-carrier/v1\0".to_vec();
    m.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    m.extend_from_slice(payload);
    m
}
pub fn send(carrier: u8, entries: &[NativeEvidence]) -> Packet {
    let payload = serde_json::to_vec(entries).unwrap();
    let signature = key(carrier).sign(&message(&payload)).to_bytes().to_vec();
    Packet {
        carrier: person(carrier),
        payload,
        signature,
    }
}
pub fn receive(packet: Packet) -> Result<Vec<NativeEvidence>, &'static str> {
    let signature =
        ed25519_dalek::Signature::from_slice(&packet.signature).map_err(|_| "carrier signature")?;
    ed25519_dalek::VerifyingKey::from_bytes(packet.carrier.bytes())
        .unwrap()
        .verify_strict(&message(&packet.payload), &signature)
        .map_err(|_| "carrier signature")?;
    serde_json::from_slice(&packet.payload).map_err(|_| "carrier data")
}
