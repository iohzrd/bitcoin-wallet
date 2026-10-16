//! Any bytes, as a PSBT file or paste the signer is handed: whatever reads as one must review
//! against each wallet without a panic, keep what every review keeps, and sign as signing must.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_airgap::file::{read_psbt, signatures_only, write_psbt};
use wallet_core::psbt;
use wallet_fuzz::{check_review, check_sign, policies};

fuzz_target!(|data: &[u8]| {
    let Ok(psbt) = read_psbt(data) else { return };
    assert_eq!(read_psbt(&write_psbt(&psbt)).unwrap(), psbt, "the signer writes back what it read");
    assert_eq!(read_psbt(psbt.to_string().as_bytes()).unwrap(), psbt);
    // What the signer sends back combines with the PSBT the coordinator sent into the same PSBT.
    let mut combined = psbt.clone();
    combined.combine(signatures_only(&psbt)).expect("the signatures combine");
    assert_eq!(combined, psbt);
    for (policy, seed) in policies() {
        if let Ok(review) = psbt::review(policy, &psbt) {
            check_review(policy, &psbt, &review);
            check_sign(policy, seed, &psbt, &review);
        }
    }
});
