//! Getting a PSBT or an account's descriptor across the air gap in the forms other wallets and
//! signing devices read and write: a PSBT as a `.psbt` file, as base64 text, or as a loop of QR
//! codes in Blockchain Commons' Uniform Resources; a descriptor as text, in a file or a QR code;
//! and a seed as a SeedQR, to copy onto paper.

pub mod bcur;
pub mod file;
pub mod qr;
pub mod seedqr;
pub mod setup;
