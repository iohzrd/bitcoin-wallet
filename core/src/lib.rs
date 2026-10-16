//! What every build of the wallet shares: the seed, the accounts and their descriptors, and the
//! review and signing of PSBTs. The hot wallet, the watch-only wallet and the offline signer are
//! all built on this crate, so it does no I/O and draws no randomness of its own: whatever needs
//! entropy takes it as an argument, which keeps the offline build free of anything it does not
//! need and every function here deterministic under test.

pub mod account;
pub mod dice;
pub mod psbt;
pub mod seed;

pub use bip39::{self, Mnemonic};
pub use bitcoin;
pub use miniscript;
