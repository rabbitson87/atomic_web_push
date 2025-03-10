//! Contains tooling for signing with VAPID.

pub use self::builder::VapidSignatureBuilder;
use self::key::VapidKey;
pub use self::signer::VapidSignature;
use self::signer::VapidSigner;

pub mod builder;
pub mod generator;
mod key;
mod signer;
