//! Source-based community authority. Carrier IDs, names, device descriptions and
//! content pins remain their original types; their interpretation belongs here.
//! The carrier verifies its own signatures and passes the results in; this
//! crate reads no clock, network, storage or wire format.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod app;
pub mod db;
mod history;
pub mod lend;
pub mod pass;
mod rule;
mod schema;
pub use history::*;
pub use schema::*;
