//! A seed from dice rolls, for whoever would rather trust a die than a device's random number
//! generator. The rolls are written as their digits, 1 to 6, and hashed with SHA-256: the first
//! 16 bytes of the hash are a 12-word seed's entropy, all 32 a 24-word seed's. That is how
//! SeedSigner and Coldcard make one, so the same rolls give the same words on either, and on any
//! machine with a SHA-256 tool: `echo -n 16253… | sha256sum` prints the entropy.

use bip39::Mnemonic;
use bitcoin::hashes::{Hash, sha256};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0} is not a face of a die")]
    NotAFace(u8),
    #[error("{0} rolls make no seed: 12 words take {ROLLS_12}, 24 take {ROLLS_24}")]
    Count(usize),
}

/// The rolls a 12-word seed takes: each holds log2(6), about 2.585 bits, so 50 hold the seed's
/// 128.
pub const ROLLS_12: usize = 50;
/// The rolls a 24-word seed takes: 99 hold 255.9 bits of its 256, as SeedSigner and Coldcard
/// count them.
pub const ROLLS_24: usize = 99;

/// The rolls a seed of `words` words takes, for the 12 and 24 this makes.
pub fn rolls_for(words: usize) -> Option<usize> {
    match words {
        12 => Some(ROLLS_12),
        24 => Some(ROLLS_24),
        _ => None,
    }
}

/// The seed of `rolls`, each the face a die showed, 1 to 6: 12 words from 50 rolls, 24 from 99.
pub fn mnemonic(rolls: &[u8]) -> Result<Mnemonic, Error> {
    let entropy_len = match rolls.len() {
        ROLLS_12 => 16,
        ROLLS_24 => 32,
        count => return Err(Error::Count(count)),
    };
    let mut digits = Zeroizing::new(Vec::with_capacity(rolls.len()));
    for &roll in rolls {
        if !(1..=6).contains(&roll) {
            return Err(Error::NotAFace(roll));
        }
        digits.push(b'0' + roll);
    }
    let hash = Zeroizing::new(sha256::Hash::hash(&digits).to_byte_array());
    Ok(Mnemonic::from_entropy(&hash[..entropy_len]).expect("16 or 32 bytes make a mnemonic"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rolls(digits: &str) -> Vec<u8> {
        digits.bytes().map(|digit| digit - b'0').collect()
    }

    /// SeedSigner's vectors (tests/test_mnemonic_generation.py), which it checks against
    /// iancoleman.io/bip39's "Hex" mode for 12 words and Coldcard's method for 24.
    #[test]
    fn rolls_make_the_words_seedsigner_makes() {
        let vectors = [
            (
                "12345612345612345612345612345612345612345612345612",
                "unveil nice picture region tragic fault cream strike tourist control recipe tourist",
            ),
            (
                "11111111111111111111111111111111111111111111111111",
                "diet glad hat rural panther lawsuit act drop gallery urge where fit",
            ),
            (
                "66666666666666666666666666666666666666666666666666",
                "senior morning song proud recycle toy search apple trigger lend vibrant arrest",
            ),
            (
                "522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555",
                "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious",
            ),
            (
                "222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555",
                "garden uphold level clog sword globe armor issue two cute scorpion improve verb artwork blind tail raw butter combine move produce foil feature wave",
            ),
            (
                "222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555556",
                "lizard broken love tired depend eyebrow excess lonely advance father various cram ignore panic feed plunge miss regret boring unique galaxy fan detail fly",
            ),
        ];
        for (digits, words) in vectors {
            assert_eq!(mnemonic(&rolls(digits)).unwrap().to_string(), words, "{digits}");
        }
    }

    #[test]
    fn the_count_decides_the_length() {
        assert_eq!(rolls_for(12), Some(50));
        assert_eq!(rolls_for(24), Some(99));
        assert_eq!(rolls_for(18), None);
        assert_eq!(mnemonic(&[3; ROLLS_12]).unwrap().word_count(), 12);
        assert_eq!(mnemonic(&[3; ROLLS_24]).unwrap().word_count(), 24);
        for count in [0, 6, 49, 51, 98, 100] {
            assert_eq!(mnemonic(&vec![3; count]), Err(Error::Count(count)));
        }
    }

    #[test]
    fn a_roll_is_a_face_from_1_to_6() {
        let mut rolls = vec![1; ROLLS_12];
        rolls[7] = 0;
        assert_eq!(mnemonic(&rolls), Err(Error::NotAFace(0)));
        rolls[7] = 7;
        assert_eq!(mnemonic(&rolls), Err(Error::NotAFace(7)));
    }
}
