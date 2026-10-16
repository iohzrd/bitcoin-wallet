//! A PSBT through a loop of QR codes and back, at any fragment length, with any of the first parts
//! missed and the rest read in either case, as a camera reads a loop: the same PSBT comes out.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wallet_airgap::bcur::{PsbtDecoder, PsbtEncoder};
use wallet_fuzz::{Spec, build};

#[derive(Arbitrary, Debug)]
struct Loop {
    spec: Spec,
    fragment_len: u8,
    /// Which of the first 64 parts the camera misses.
    missed: u64,
    /// Which of the first 64 parts it reads in lower case.
    lower: u64,
}

fuzz_target!(|scan: Loop| {
    let psbt = build(&scan.spec);
    let mut encoder = PsbtEncoder::new(&psbt, usize::from(scan.fragment_len.max(10)));
    let mut decoder = PsbtDecoder::default();
    // A fountain code needs a few parts past the fragment count, many more for a handful of
    // fragments read from their mixtures alone; ten times as many is far past that.
    let count = encoder.fragment_count();
    let mut read = 0;
    for index in 0.. {
        let part = encoder.next_part();
        let bit = 1u64.checked_shl(index).unwrap_or(0);
        if scan.missed & bit != 0 {
            continue;
        }
        let part = if scan.lower & bit != 0 { part.to_lowercase() } else { part };
        read += 1;
        if let Some(decoded) = decoder.receive(&part).expect("a part of the loop") {
            assert_eq!(decoded, psbt);
            return;
        }
        assert!(
            read < count * 10 + 20,
            "{read} parts of a loop of {count} fragments decode nothing"
        );
    }
});
