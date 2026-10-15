//! PSBTs as Blockchain Commons Uniform Resources (BCR-2020-005 and -006), the QR format the
//! signing devices and wallets that scan PSBTs share. The PSBT goes into a CBOR byte string and
//! out as bytewords; one too long for a QR code is cut by a fountain code into parts shown in an
//! endless loop, of which a camera needs only about as many as there are fragments, in any order.

use ::ur::ur::{Decoder, Encoder, Kind, Type};
use wallet_core::bitcoin::psbt::{self, Psbt};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("UR: {0}")]
    Ur(::ur::ur::Error),
    #[error("a UR of type {0}, not a PSBT")]
    NotPsbt(String),
    #[error("the UR's payload is not one CBOR byte string")]
    Cbor,
    #[error(transparent)]
    Psbt(#[from] psbt::Error),
}

impl From<::ur::ur::Error> for Error {
    fn from(error: ::ur::ur::Error) -> Error {
        Error::Ur(error)
    }
}

/// The UR type the signer writes PSBTs as. BCR-2020-006 has since renamed it `psbt`, but
/// `crypto-psbt` is the one the wallets and signing devices in use read. Both are read.
pub const PSBT_TYPE: &str = "crypto-psbt";
const PSBT_TYPES: [&str; 2] = [PSBT_TYPE, "psbt"];

/// The bytes of PSBT in each part. With the fountain code's header and bytewords' two letters a
/// byte, a part is about 310 characters, which a QR code of version 10 or 11 holds in its
/// alphanumeric mode: about 60 modules a side, a few pixels each on a 480-pixel screen.
pub const FRAGMENT_LEN: usize = 120;

/// The QR codes of one PSBT, in a loop.
pub struct PsbtEncoder {
    parts: Parts,
}

enum Parts {
    Single(String),
    Fountain(Box<Encoder<'static>>),
}

impl PsbtEncoder {
    pub fn new(psbt: &Psbt, fragment_len: usize) -> PsbtEncoder {
        let cbor = cbor_bytes(&psbt.serialize());
        let parts = if cbor.len() <= fragment_len {
            Parts::Single(::ur::ur::encode(&cbor, &Type::Custom(PSBT_TYPE)).to_uppercase())
        } else {
            let encoder = Encoder::new(&cbor, fragment_len, PSBT_TYPE);
            Parts::Fountain(Box::new(encoder.expect("a nonempty message and fragment")))
        };
        PsbtEncoder { parts }
    }

    /// How many fragments the PSBT is cut into: 1 for a PSBT that fits a single QR code.
    pub fn fragment_count(&self) -> usize {
        match &self.parts {
            Parts::Single(_) => 1,
            Parts::Fountain(encoder) => encoder.fragment_count(),
        }
    }

    /// The next QR code's text, in capitals, which QR's alphanumeric mode packs in 5.5 bits a
    /// character to its byte mode's 8. The first `fragment_count` parts are the fragments
    /// themselves; the fountain code mixes those after them.
    pub fn next_part(&mut self) -> String {
        match &mut self.parts {
            Parts::Single(part) => part.clone(),
            Parts::Fountain(encoder) => {
                encoder.next_part().expect("a fountain part encodes").to_uppercase()
            }
        }
    }
}

/// A PSBT put back together from scanned QR codes.
#[derive(Default)]
pub struct PsbtDecoder {
    fountain: Decoder,
}

impl PsbtDecoder {
    /// Takes one QR code's text, in either case. Returns the PSBT when it is complete: from a
    /// single-part UR at once, from a multi-part one once enough parts are in.
    pub fn receive(&mut self, part: &str) -> Result<Option<Psbt>, Error> {
        let part = part.trim().to_lowercase();
        let ur_type = part.strip_prefix("ur:").and_then(|rest| rest.split('/').next());
        let ur_type = ur_type.ok_or(Error::Ur(::ur::ur::Error::InvalidScheme))?;
        if !PSBT_TYPES.contains(&ur_type) {
            return Err(Error::NotPsbt(ur_type.to_owned()));
        }
        let message = match ::ur::ur::decode(&part)? {
            (Kind::SinglePart, message) => message,
            (Kind::MultiPart, _) => {
                self.fountain.receive(&part)?;
                match self.fountain.message()? {
                    Some(message) => message,
                    None => return Ok(None),
                }
            }
        };
        Ok(Some(Psbt::deserialize(cbor_bytes_payload(&message)?)?))
    }

    /// How many of the PSBT's fragments are in, and how many there are; `None` before the first
    /// part of a multi-part UR.
    pub fn progress(&self) -> Option<(usize, usize)> {
        let resolved = self.fountain.resolved_fragment_count()?;
        Some((resolved, self.fountain.fragment_count()))
    }
}

/// `data` as a CBOR byte string (major type 2): its length in the head's shortest form, then it.
fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut cbor = Vec::with_capacity(len + 9);
    match len {
        0..24 => cbor.push(0x40 | len as u8),
        24..0x100 => cbor.extend([0x58, len as u8]),
        0x100..0x1_0000 => {
            cbor.push(0x59);
            cbor.extend((len as u16).to_be_bytes());
        }
        _ => {
            cbor.push(0x5a);
            cbor.extend(u32::try_from(len).expect("a PSBT under 4 GiB").to_be_bytes());
        }
    }
    cbor.extend_from_slice(data);
    cbor
}

/// The bytes of a CBOR byte string that is the whole of `cbor`.
fn cbor_bytes_payload(cbor: &[u8]) -> Result<&[u8], Error> {
    let (&head, rest) = cbor.split_first().ok_or(Error::Cbor)?;
    if head >> 5 != 2 {
        return Err(Error::Cbor);
    }
    let (len, rest) = match head & 0x1f {
        len @ 0..24 => (len as usize, rest),
        24 => (*rest.first().ok_or(Error::Cbor)? as usize, &rest[1..]),
        25 => {
            let (len, rest) = rest.split_first_chunk::<2>().ok_or(Error::Cbor)?;
            (u16::from_be_bytes(*len) as usize, rest)
        }
        26 => {
            let (len, rest) = rest.split_first_chunk::<4>().ok_or(Error::Cbor)?;
            (u32::from_be_bytes(*len) as usize, rest)
        }
        _ => return Err(Error::Cbor),
    };
    if rest.len() != len {
        return Err(Error::Cbor);
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::tests::example;
    use wallet_core::bitcoin::{Amount, TxOut};

    /// BCR-2020-006's example, as its `psbt` UR.
    const EXAMPLE_UR: &str = "ur:psbt/hdosjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmnjojofejzeojlkerdonspkpkkdkykfelokgprpyutkpaeaeaeaeaezmzmzmzmlslgaaditiwpihbkispkfgrkbdaslewdfycprtjsprsgksecdratkkhktikewdcaadaeaeaeaezmzmzmzmaojopkwtayaeaeaeaecmaebbtphhdnjstiambdassoloimwmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbaeplptoevwwtyakoonlourgofgvsjydpcaltaemyaeaeaeaeaeaeaeaeaebkgdcarh";

    #[test]
    fn a_psbt_that_fits_one_part_encodes_as_bcr_2020_006s_example() {
        let mut encoder = PsbtEncoder::new(&example(), 200);
        assert_eq!(encoder.fragment_count(), 1);
        let part = encoder.next_part();
        let expected = EXAMPLE_UR.replacen("ur:psbt/", "ur:crypto-psbt/", 1).to_uppercase();
        assert_eq!(part, expected);
        assert_eq!(encoder.next_part(), part, "the one part, again");
    }

    #[test]
    fn a_single_part_decodes_under_either_type_name_in_either_case() {
        let crypto_psbt = EXAMPLE_UR.replacen("ur:psbt/", "ur:crypto-psbt/", 1);
        for part in [EXAMPLE_UR.to_owned(), EXAMPLE_UR.to_uppercase(), crypto_psbt] {
            let psbt = PsbtDecoder::default().receive(&part).unwrap();
            assert_eq!(psbt, Some(example()), "{part}");
        }
    }

    #[test]
    fn a_long_psbt_comes_back_from_any_fragment_count_of_its_parts() {
        let mut psbt = example();
        let previous = TxOut { value: Amount::from_sat(1), script_pubkey: vec![0x51; 200].into() };
        psbt.inputs[0].witness_utxo = Some(previous.clone());
        psbt.inputs[1].witness_utxo = Some(previous);
        let mut encoder = PsbtEncoder::new(&psbt, FRAGMENT_LEN);
        let fragments = encoder.fragment_count();
        assert!(fragments > 3, "{fragments} fragments");
        // Skip the first parts, as a camera that starts partway through the loop does.
        let parts: Vec<String> = (0..20).map(|_| encoder.next_part()).skip(3).collect();
        assert!(parts.iter().all(|part| part.starts_with("UR:CRYPTO-PSBT/")));

        let mut decoder = PsbtDecoder::default();
        assert_eq!(decoder.progress(), None);
        let mut decoded = None;
        for part in &parts {
            if let Some(psbt) = decoder.receive(part).unwrap() {
                decoded = Some(psbt);
                break;
            }
            let (resolved, total) = decoder.progress().unwrap();
            assert!(resolved < total && total == fragments);
        }
        assert_eq!(decoded, Some(psbt));
    }

    #[test]
    fn a_ur_of_another_type_is_not_a_psbt() {
        let bytes = ::ur::ur::encode(b"data", &Type::Bytes);
        let refused = PsbtDecoder::default().receive(&bytes);
        assert!(matches!(refused, Err(Error::NotPsbt(t)) if t == "bytes"));
        assert!(PsbtDecoder::default().receive("bitcoin:bc1q...").is_err());
    }

    #[test]
    fn cbor_byte_strings_round_trip_at_every_head_size() {
        for (len, head) in [(0, 0x40), (23, 0x57), (24, 0x58), (255, 0x58), (256, 0x59)] {
            let data = vec![7; len];
            let cbor = cbor_bytes(&data);
            assert_eq!(cbor[0], head, "{len}");
            assert_eq!(cbor_bytes_payload(&cbor).unwrap(), data);
        }
        let long = vec![7; 0x1_0000];
        assert_eq!(cbor_bytes(&long)[..5], [0x5a, 0, 1, 0, 0]);
        assert_eq!(cbor_bytes_payload(&cbor_bytes(&long)).unwrap(), long);
        let mut trailing = cbor_bytes(b"abc");
        trailing.push(0);
        assert!(cbor_bytes_payload(&trailing).is_err(), "a byte past the string");
        assert!(cbor_bytes_payload(&[0x63, b'a', b'b', b'c']).is_err(), "a text string");
        assert!(cbor_bytes_payload(&[0x59, 0x01]).is_err(), "a truncated head");
    }
}
