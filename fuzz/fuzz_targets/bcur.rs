//! Any text, a QR code's to a line, as the camera hands the signer the parts of a UR: none may
//! panic it, and whatever PSBT comes out reads as one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_airgap::bcur::PsbtDecoder;
use wallet_airgap::file::{read_psbt, write_psbt};

fuzz_target!(|text: &str| {
    let mut decoder = PsbtDecoder::default();
    for part in text.lines() {
        if let Ok(Some(psbt)) = decoder.receive(part) {
            assert_eq!(read_psbt(&write_psbt(&psbt)).unwrap(), psbt);
        }
        if let Some((resolved, count)) = decoder.progress() {
            assert!(resolved <= count);
        }
    }
});
