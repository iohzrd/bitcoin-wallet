//! Any bytes, as a scanned SeedQR or a run of dice rolls: whatever decodes is a seed that encodes
//! back to the same in either form, and any 50 or 99 faces make a seed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_airgap::seedqr::{self, Format};
use wallet_core::dice;

fuzz_target!(|data: &[u8]| {
    if let Ok(mnemonic) = seedqr::decode(data) {
        let digits = seedqr::standard_digits(&mnemonic);
        assert_eq!(seedqr::decode(digits.as_bytes()).unwrap(), mnemonic);
        assert_eq!(seedqr::decode(&mnemonic.to_entropy()).unwrap(), mnemonic);
        let _ = (seedqr::qr(&mnemonic, Format::Standard), seedqr::qr(&mnemonic, Format::Compact));
    }
    let result = dice::mnemonic(data);
    let faces = data.iter().all(|roll| (1..=6).contains(roll));
    let count = data.len() == dice::ROLLS_12 || data.len() == dice::ROLLS_24;
    assert_eq!(result.is_ok(), faces && count);
    let rolls: Vec<u8> = data.iter().map(|byte| byte % 6 + 1).collect();
    for words in [12, 24] {
        let count = dice::rolls_for(words).unwrap();
        if let Some(rolls) = rolls.get(..count) {
            assert_eq!(dice::mnemonic(rolls).unwrap().word_count(), words);
        }
    }
});
