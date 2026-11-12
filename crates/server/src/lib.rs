//! 2F server: storage, the operations on it, and the HTTP API.

#![forbid(unsafe_code)]

pub mod cosigner;
pub mod delivery;
pub mod error;
pub mod http;
pub mod limit;
pub mod service;

pub use error::{Error, Result};
pub use service::{Config, Proof, Registration, Service};
