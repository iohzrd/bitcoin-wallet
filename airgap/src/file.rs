//! PSBTs as files and text. BIP174 gives `.psbt` files its binary format, which is what the
//! signer writes; wallets also write base64 (Bitcoin Core's RPCs speak it) or hex, and a file or a
//! paste may wrap either in whitespace, so all three are read.

use std::str::FromStr;

use wallet_core::bitcoin::hex::FromHex;
use wallet_core::bitcoin::psbt::{self, Psbt, PsbtParseError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a PSBT: neither BIP174's binary format nor its base64 or hex")]
    NotPsbt,
    #[error(transparent)]
    Psbt(#[from] psbt::Error),
    #[error(transparent)]
    Base64(#[from] PsbtParseError),
}

/// BIP174's magic: `psbt` and 0xff.
const MAGIC: &[u8] = b"psbt\xff";

pub fn read_psbt(data: &[u8]) -> Result<Psbt, Error> {
    if data.starts_with(MAGIC) {
        return Ok(Psbt::deserialize(data)?);
    }
    let text = std::str::from_utf8(data).map_err(|_| Error::NotPsbt)?.trim();
    if let Ok(bytes) = Vec::<u8>::from_hex(text) {
        if bytes.starts_with(MAGIC) {
            return Ok(Psbt::deserialize(&bytes)?);
        }
        return Err(Error::NotPsbt);
    }
    if text.starts_with("cHNidP8") {
        return Ok(Psbt::from_str(text)?);
    }
    Err(Error::NotPsbt)
}

/// The PSBT as a `.psbt` file holds it.
pub fn write_psbt(psbt: &Psbt) -> Vec<u8> {
    psbt.serialize()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wallet_core::bitcoin::hex::DisplayHex;

    /// BCR-2020-006's example PSBT: two inputs and two outputs, unsigned.
    pub(crate) const EXAMPLE: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";

    pub(crate) fn example() -> Psbt {
        Psbt::deserialize(&Vec::from_hex(EXAMPLE).unwrap()).unwrap()
    }

    #[test]
    fn a_psbt_reads_from_binary_base64_and_hex_alike() {
        let psbt = example();
        let binary = write_psbt(&psbt);
        assert_eq!(binary.to_lower_hex_string(), EXAMPLE);
        assert_eq!(read_psbt(&binary).unwrap(), psbt);
        let base64 = format!("\n  {psbt}\n");
        assert_eq!(read_psbt(base64.as_bytes()).unwrap(), psbt);
        let hex = format!("{}\r\n", EXAMPLE.to_uppercase());
        assert_eq!(read_psbt(hex.as_bytes()).unwrap(), psbt);
    }

    #[test]
    fn anything_else_is_not_a_psbt() {
        for data in [&b""[..], b"hello", b"deadbeef", b"cHNidP8", &[0xff, 0xfe, 0x00]] {
            assert!(read_psbt(data).is_err(), "{data:?}");
        }
        assert!(matches!(read_psbt(b"deadbeef"), Err(Error::NotPsbt)));
    }
}
