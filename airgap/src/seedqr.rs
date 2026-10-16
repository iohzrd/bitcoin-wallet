//! SeedQR, SeedSigner's QR code of a seed (`docs/seed_qr` in its repository): a backup copied onto
//! paper by hand, module by module, and scanned back into SeedSigner, Sparrow or this wallet. The
//! Standard form holds each word's place in the BIP39 list as four digits, in QR's numeric mode;
//! the Compact form holds the seed's entropy as bytes, which takes a code one size smaller and so
//! fewer modules to copy. Either is the smallest QR code at error correction level L that holds
//! it, which for 12 and 24 words are the sizes SeedSigner's paper templates are drawn for:
//! Standard 25 and 29 modules a side, Compact 21 and 25.

use qrcode::bits::Bits;
use qrcode::{EcLevel, QrCode, Version};
use wallet_core::Mnemonic;
use wallet_core::bip39::{self, Language};
use zeroize::Zeroizing;

use crate::qr::Qr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Standard,
    Compact,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a SeedQR: neither four digits a word nor a seed's entropy")]
    NotSeedQr,
    #[error(transparent)]
    Mnemonic(#[from] bip39::Error),
}

/// The SeedQR of `mnemonic`.
pub fn qr(mnemonic: &Mnemonic, format: Format) -> Qr {
    let data = match format {
        Format::Standard => Zeroizing::new(standard_digits(mnemonic).as_bytes().to_vec()),
        Format::Compact => Zeroizing::new(mnemonic.to_entropy()),
    };
    // The smallest version that holds it, in the one mode the format names.
    let code = (1..=40)
        .find_map(|version| {
            let mut bits = Bits::new(Version::Normal(version));
            match format {
                Format::Standard => bits.push_numeric_data(&data).ok()?,
                Format::Compact => bits.push_byte_data(&data).ok()?,
            }
            bits.push_terminator(EcLevel::L).ok()?;
            QrCode::with_bits(bits, EcLevel::L).ok()
        })
        .expect("a seed fits a QR code");
    Qr::from_code(&code)
}

/// The Standard SeedQR's digits: each word's place in the BIP39 list, from 0000 to 2047.
pub fn standard_digits(mnemonic: &Mnemonic) -> Zeroizing<String> {
    Zeroizing::new(mnemonic.word_indices().map(|index| format!("{index:04}")).collect())
}

/// The seed a scanned SeedQR holds, in either form.
pub fn decode(data: &[u8]) -> Result<Mnemonic, Error> {
    let words = data.len() / 4;
    if data.iter().all(u8::is_ascii_digit) && data.len().is_multiple_of(4) && is_word_count(words) {
        let list = Language::English.word_list();
        let words = (data.chunks(4))
            .map(|digits| {
                let index: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
                list.get(index).copied()
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::NotSeedQr)?;
        return Ok(Mnemonic::parse_in_normalized(Language::English, &words.join(" "))?);
    }
    // 16 bytes of entropy for 12 words, 4 more for each 3 words beyond.
    if is_word_count(data.len() * 3 / 4) && data.len().is_multiple_of(4) {
        return Ok(Mnemonic::from_entropy(data)?);
    }
    Err(Error::NotSeedQr)
}

fn is_word_count(words: usize) -> bool {
    matches!(words, 12 | 15 | 18 | 21 | 24)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qr::tests::scan_bytes;

    /// SeedSigner's test vectors (docs/seed_qr/README.md): the seed, its Standard digits, and
    /// its Compact bits.
    const VECTORS: [(&str, &str, &str); 4] = [
        (
            "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire",
            "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643",
            "0000111001110100101101100100000100000111111110010100110011000000110011001111101011100110101000010011110111001011111011000011011001100010000101010100111111101100011001111110000011100000000010011001100111000000011110001001001001011001011111010001100100001010",
        ),
        (
            // Its Compact bytes hold a zero, which many QR readers stop at.
            "atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid meadow quick medal plate wisdom swap noble shallow",
            "011416550964188800731119157218870156061002561932122514430573003611011405110613292018175411971576",
            "0000111001011001110111011110001001110110000000001001001100010111111100010010011101011111000100111000100110001000100000000111100011001001100100110110100011010001111010000010010010001001101101011111011000101001010100110001111111000101101101101010010101101110",
        ),
        (
            "forum undo fragile fade shy sign arrest garment culture tube off merit",
            "073318950739065415961602009907670428187212261116",
            "01011011101111011001110101110001101010001110110001111001100100001000001100011010111111110011010110011101010000100110010101000101",
        ),
        (
            "good battle boil exact add seed angle hurry success glad carbon whisper",
            "080301540200062600251559007008931730078802752004",
            "01100100011000100110100001100100001001110010000000110011100001011100001000110011011111011101100001001100010100001000100111111101",
        ),
    ];

    fn bytes(bits: &str) -> Vec<u8> {
        let bits = bits.as_bytes();
        (bits.chunks(8))
            .map(|byte| byte.iter().fold(0, |value, bit| value << 1 | (bit - b'0')))
            .collect()
    }

    #[test]
    fn a_seed_encodes_as_seedsigners_vectors() {
        for (words, digits, bits) in VECTORS {
            let mnemonic = Mnemonic::parse(words).unwrap();
            assert_eq!(*standard_digits(&mnemonic), digits);
            assert_eq!(mnemonic.to_entropy(), bytes(bits));
            assert_eq!(decode(digits.as_bytes()).unwrap(), mnemonic);
            assert_eq!(decode(&bytes(bits)).unwrap(), mnemonic);
        }
    }

    #[test]
    fn the_codes_are_the_sizes_the_paper_templates_are_drawn_for() {
        let twelve = Mnemonic::parse(VECTORS[2].0).unwrap();
        let twenty_four = Mnemonic::parse(VECTORS[0].0).unwrap();
        assert_eq!(qr(&twelve, Format::Standard).width(), 25);
        assert_eq!(qr(&twenty_four, Format::Standard).width(), 29);
        assert_eq!(qr(&twelve, Format::Compact).width(), 21);
        assert_eq!(qr(&twenty_four, Format::Compact).width(), 25);
    }

    #[test]
    fn each_code_scans_back_as_its_seed() {
        for (words, ..) in VECTORS {
            let mnemonic = Mnemonic::parse(words).unwrap();
            for format in [Format::Standard, Format::Compact] {
                let scanned = scan_bytes(&qr(&mnemonic, format), 4);
                assert_eq!(decode(&scanned).unwrap(), mnemonic, "{format:?} {words}");
            }
        }
    }

    #[test]
    fn anything_else_is_not_a_seedqr() {
        for data in
            [&b""[..], b"0000", &[0; 15], &[0; 33], b"20482048204820482048204820482048204820482048"]
        {
            assert!(decode(data).is_err(), "{data:?}");
        }
    }
}
