//! Any bytes, as a kept wallet's file or the record sealed in one: a record that reads writes
//! back as itself, and a file opens only under its passphrase, without a panic either way.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_core::store::{self, Record};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(record) = Record::decode(text)
    {
        let written = record.encode();
        assert_eq!(Record::decode(&written).unwrap(), record, "{written:?}");
    }
    // A file's header names its key's cost; one asking more than a moment's is left alone, as
    // each run would otherwise spend it.
    let word =
        |at: usize| data.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let cheap = matches!((word(8), word(12), word(16)), (Some(..=64), Some(..=2), Some(..=2)));
    if cheap || data.len() < 20 {
        let _ = store::open("passphrase", data);
    }
});
