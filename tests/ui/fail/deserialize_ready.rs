use eudoxia::*;
use serde::{Deserialize, de::DeserializeOwned};

fn decode<'de: 'scope, 'scope, G, D>(decoder: D) -> Result<Ready<'scope, G>, D::Error>
where
    G: ResourceGuard + DeserializeOwned,
    G::Action: DeserializeOwned,
    G::Witness: DeserializeOwned,
    D: serde::Deserializer<'de>,
{
    Ready::deserialize(decoder)
}
fn main() {}
