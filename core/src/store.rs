//! A wallet kept on the device, for whoever opts into it: its seed (or a watch-only wallet's
//! descriptor) and the multisig wallets registered with it, encrypted with a passphrase. Without a
//! secure element to count failed tries, anyone who copies the file can guess at the passphrase on
//! their own hardware for as long as they like, so the key is Argon2id's, which makes each guess
//! cost memory as well as time (RFC 9106's second recommended setting: 64 MiB, three passes, four
//! lanes), and the file is sealed with XChaCha20-Poly1305, which refuses it whole if a byte of it
//! changed.
//!
//! The file: `WALLET`, 0, a format version; Argon2's memory in KiB, passes and lanes, each a
//! little-endian u32; a 16-byte salt and a 24-byte nonce; then the sealed record, the header its
//! associated data. The record is text, a line a field.

use std::fmt::Write;
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Version};
use bip39::{Language, Mnemonic};
use bitcoin::Network;
use bitcoin::bip32::Fingerprint;
use bitcoin::hex::{DisplayHex, FromHex};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use crate::account::Kind;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a wallet this app kept")]
    NotKept,
    #[error("kept in format {0}, which this version does not read")]
    Format(u8),
    #[error("its key would take more memory or time than this reads")]
    Params,
    #[error("wrong passphrase, or the file is damaged")]
    Passphrase,
    #[error("the wallet in it is damaged: {0}")]
    Record(String),
}

const MAGIC: &[u8; 7] = b"WALLET\0";
const FORMAT: u8 = 1;
const HEADER: usize = 8 + 3 * 4 + 16 + 24;

/// Argon2id's cost: memory in KiB, passes over it, and lanes through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Params {
    /// RFC 9106's second recommended setting, for memory-constrained devices: a handheld's
    /// gigabyte holds 64 MiB beside everything else, and its four cores run the four lanes at
    /// once.
    pub const DEFAULT: Params = Params { memory_kib: 64 * 1024, passes: 3, lanes: 4 };

    /// The most a file may ask: a file that asks more is refused rather than given the device's
    /// memory or minutes of its time.
    const MOST: Params = Params { memory_kib: 1024 * 1024, passes: 32, lanes: 16 };

    fn argon2(self) -> Result<Argon2<'static>, Error> {
        let Params { memory_kib, passes, lanes } = self;
        let most = Params::MOST;
        if memory_kib > most.memory_kib || passes > most.passes || lanes > most.lanes {
            return Err(Error::Params);
        }
        let params =
            argon2::Params::new(memory_kib, passes, lanes, Some(32)).map_err(|_| Error::Params)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// The key a passphrase gives, with the salt and cost it was made with, which sealing the wallet
/// again writes beside it. Made once, as making it takes seconds, and kept for as long as the
/// wallet is open, as the seed is.
pub struct Key {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    params: Params,
}

impl Key {
    /// The key of `passphrase` under `salt`, which should be fresh randomness for each new
    /// passphrase.
    pub fn derive(passphrase: &str, salt: [u8; 16], params: Params) -> Result<Key, Error> {
        let mut key = Zeroizing::new([0; 32]);
        (params.argon2()?)
            .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
            .map_err(|_| Error::Params)?;
        Ok(Key { key, salt, params })
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&(*self.key).into())
    }

    fn header(&self, nonce: &[u8; 24]) -> Vec<u8> {
        let Params { memory_kib, passes, lanes } = self.params;
        let mut header = Vec::with_capacity(HEADER);
        header.extend(MAGIC);
        header.push(FORMAT);
        for value in [memory_kib, passes, lanes] {
            header.extend(value.to_le_bytes());
        }
        header.extend(self.salt);
        header.extend(nonce);
        header
    }
}

/// The file that keeps `record` under `key`. `nonce` must be fresh randomness each time: a nonce
/// used twice under one key gives the two records away.
pub fn seal(key: &Key, nonce: [u8; 24], record: &Record) -> Vec<u8> {
    let mut file = key.header(&nonce);
    let plaintext = record.encode();
    let payload = Payload { msg: plaintext.as_bytes(), aad: &file };
    let sealed = key.cipher().encrypt(&nonce.into(), payload).expect("a record seals");
    file.extend(sealed);
    file
}

/// The record `file` keeps, and the key `passphrase` gives for it, to seal it again with.
pub fn open(passphrase: &str, file: &[u8]) -> Result<(Key, Record), Error> {
    if file.len() < HEADER || !file.starts_with(MAGIC) {
        return Err(Error::NotKept);
    }
    if file[7] != FORMAT {
        return Err(Error::Format(file[7]));
    }
    let word = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
    let params = Params { memory_kib: word(8), passes: word(12), lanes: word(16) };
    let salt: [u8; 16] = file[20..36].try_into().unwrap();
    let nonce: [u8; 24] = file[36..HEADER].try_into().unwrap();
    let key = Key::derive(passphrase, salt, params)?;
    let payload = Payload { msg: &file[HEADER..], aad: &file[..HEADER] };
    let plaintext = key.cipher().decrypt(&nonce.into(), payload).map_err(|_| Error::Passphrase)?;
    let plaintext = Zeroizing::new(plaintext);
    let text = std::str::from_utf8(&plaintext).map_err(|_| record_error("not text"))?;
    Ok((key, Record::decode(text)?))
}

/// What is kept: the wallet, the chain it is on, and the multisig wallets registered with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub network: Network,
    /// The earliest the wallet's coins could have come, in Unix time: what a node that does not
    /// know the wallet yet scans the chain from.
    pub birthday: u64,
    pub wallet: Kept,
    pub multisigs: Vec<KeptMultisig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kept {
    Seed {
        mnemonic: Mnemonic,
        /// The seed's BIP39 passphrase, if it has one and it is kept with it; one not kept is
        /// asked for on opening.
        passphrase: Option<Zeroizing<String>>,
        /// The seed's, its passphrase included: whether the seed has a passphrase, and whether
        /// one typed on opening is it.
        fingerprint: Fingerprint,
        kind: Kind,
    },
    Watch {
        descriptor: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptMultisig {
    pub descriptor: String,
    pub name: Option<String>,
}

/// `byte` as two hex digits, written in place rather than through a string of its own.
fn push_hex(text: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    text.push(char::from(DIGITS[usize::from(byte >> 4)]));
    text.push(char::from(DIGITS[usize::from(byte & 0xf)]));
}

fn record_error(what: impl Into<String>) -> Error {
    Error::Record(what.into())
}

impl Record {
    pub fn encode(&self) -> Zeroizing<String> {
        // Written into one buffer, made large enough that it never moves: a buffer that grew
        // would leave the words behind in the memory it gave back.
        let multisigs: usize = (self.multisigs.iter())
            .map(|multisig| {
                multisig.descriptor.len() + 2 * multisig.name.as_ref().map_or(0, String::len) + 16
            })
            .sum();
        let passphrase = match &self.wallet {
            Kept::Seed { passphrase: Some(passphrase), .. } => 2 * passphrase.len(),
            Kept::Seed { .. } => 0,
            Kept::Watch { descriptor } => descriptor.len(),
        };
        let mut text = Zeroizing::new(String::with_capacity(512 + passphrase + multisigs));
        let line = |text: &mut String, args: std::fmt::Arguments| {
            text.write_fmt(args).expect("a String takes any text");
            text.push('\n');
        };
        line(&mut text, format_args!("network {}", self.network));
        line(&mut text, format_args!("birthday {}", self.birthday));
        match &self.wallet {
            Kept::Seed { mnemonic, passphrase, fingerprint, kind } => {
                line(&mut text, format_args!("words {mnemonic}"));
                if let Some(passphrase) = passphrase {
                    text.push_str("passphrase ");
                    for byte in passphrase.as_bytes() {
                        push_hex(&mut text, *byte);
                    }
                    text.push('\n');
                }
                line(&mut text, format_args!("fingerprint {fingerprint}"));
                let kind = match kind {
                    Kind::Taproot => "taproot",
                    Kind::SegwitV0 => "segwit",
                };
                line(&mut text, format_args!("kind {kind}"));
            }
            Kept::Watch { descriptor } => line(&mut text, format_args!("descriptor {descriptor}")),
        }
        for KeptMultisig { descriptor, name } in &self.multisigs {
            let name = name.as_deref().unwrap_or_default().as_bytes().to_lower_hex_string();
            line(&mut text, format_args!("multisig {descriptor} {name}"));
        }
        text
    }

    /// The record `text` holds, every field in it known and every one it needs there.
    pub fn decode(text: &str) -> Result<Record, Error> {
        let (mut network, mut birthday, mut words, mut passphrase, mut fingerprint, mut kind) =
            (None, None, None, None, None, None);
        let mut descriptor = None;
        let mut multisigs = Vec::new();
        for line in text.lines() {
            let (field, value) = line.split_once(' ').unwrap_or((line, ""));
            let once = |seen: bool| match seen {
                true => Err(record_error(format!("two {field} lines"))),
                false => Ok(()),
            };
            match field {
                "network" => {
                    once(network.is_some())?;
                    network =
                        Some(Network::from_str(value).map_err(|_| record_error("its network"))?);
                }
                "birthday" => {
                    once(birthday.is_some())?;
                    birthday = Some(value.parse().map_err(|_| record_error("its birthday"))?);
                }
                "words" => {
                    once(words.is_some())?;
                    let mnemonic = Mnemonic::parse_in_normalized(Language::English, value);
                    words = Some(mnemonic.map_err(|error| record_error(error.to_string()))?);
                }
                "passphrase" => {
                    once(passphrase.is_some())?;
                    let bytes = Zeroizing::new(
                        Vec::from_hex(value).map_err(|_| record_error("its passphrase"))?,
                    );
                    let text =
                        std::str::from_utf8(&bytes).map_err(|_| record_error("its passphrase"))?;
                    passphrase = Some(Zeroizing::new(text.to_owned()));
                }
                "fingerprint" => {
                    once(fingerprint.is_some())?;
                    fingerprint = Some(value.parse().map_err(|_| record_error("its fingerprint"))?);
                }
                "kind" => {
                    once(kind.is_some())?;
                    kind = Some(match value {
                        "taproot" => Kind::Taproot,
                        "segwit" => Kind::SegwitV0,
                        _ => return Err(record_error("its address type")),
                    });
                }
                "descriptor" => {
                    once(descriptor.is_some())?;
                    descriptor = Some(value.to_owned());
                }
                "multisig" => {
                    let (descriptor, name) = value.split_once(' ').unwrap_or((value, ""));
                    let name =
                        Vec::from_hex(name).ok().and_then(|name| String::from_utf8(name).ok());
                    let name = name.ok_or_else(|| record_error("a multisig wallet's name"))?;
                    let name = Some(name).filter(|name| !name.is_empty());
                    multisigs.push(KeptMultisig { descriptor: descriptor.to_owned(), name });
                }
                _ => return Err(record_error(format!("a line {field:?}"))),
            }
        }
        let missing = |what: &str| record_error(format!("no {what}"));
        let wallet = match (words, descriptor) {
            (Some(mnemonic), None) => Kept::Seed {
                mnemonic,
                passphrase,
                fingerprint: fingerprint.ok_or_else(|| missing("fingerprint"))?,
                kind: kind.ok_or_else(|| missing("address type"))?,
            },
            (None, Some(descriptor))
                if passphrase.is_none() && fingerprint.is_none() && kind.is_none() =>
            {
                Kept::Watch { descriptor }
            }
            _ => return Err(record_error("neither a seed nor a descriptor alone")),
        };
        Ok(Record {
            network: network.ok_or_else(|| missing("network"))?,
            birthday: birthday.ok_or_else(|| missing("birthday"))?,
            wallet,
            multisigs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::tests::ABANDON;

    /// Argon2's least cost, for tests that do not time it.
    const CHEAP: Params = Params { memory_kib: 8, passes: 1, lanes: 1 };

    fn record(passphrase: Option<&str>) -> Record {
        Record {
            network: Network::Regtest,
            birthday: 1_700_000_000,
            wallet: Kept::Seed {
                mnemonic: Mnemonic::parse(ABANDON).unwrap(),
                passphrase: passphrase.map(|passphrase| Zeroizing::new(passphrase.to_owned())),
                fingerprint: "73c5da0a".parse().unwrap(),
                kind: Kind::Taproot,
            },
            multisigs: vec![
                KeptMultisig {
                    descriptor: "wsh(sortedmulti(2,a,b,c))#checksum".into(),
                    name: Some("Vault 1".into()),
                },
                KeptMultisig { descriptor: "wsh(multi(1,a))".into(), name: None },
            ],
        }
    }

    #[test]
    fn a_kept_wallet_opens_with_its_passphrase_alone() {
        let key = Key::derive("correct horse battery staple", [1; 16], CHEAP).unwrap();
        for kept in [
            record(None),
            record(Some("TREZOR ü\n")),
            Record {
                wallet: Kept::Watch {
                    descriptor: "tr([73c5da0a/86h/1h/0h]tpub.../<0;1>/*)".into(),
                },
                multisigs: Vec::new(),
                ..record(None)
            },
        ] {
            let file = seal(&key, [2; 24], &kept);
            let (again, opened) = open("correct horse battery staple", &file).unwrap();
            assert_eq!(opened, kept);
            // The key it gives back seals it as it was.
            assert_eq!(seal(&again, [2; 24], &opened), file);
            assert!(matches!(open("correct horse battery stapler", &file), Err(Error::Passphrase)));
        }
    }

    #[test]
    fn the_file_holds_nothing_in_the_clear() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let file = seal(&key, [2; 24], &record(Some("TREZOR")));
        let text = String::from_utf8_lossy(&file);
        for secret in ["abandon", "TREZOR", "5452455a4f52", "73c5da0a", "Vault", "regtest"] {
            assert!(!text.contains(secret), "{secret}");
        }
    }

    #[test]
    fn a_byte_changed_anywhere_refuses_the_file() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let file = seal(&key, [2; 24], &record(None));
        for at in 0..file.len() {
            let mut tampered = file.clone();
            tampered[at] ^= 1;
            assert!(open("passphrase", &tampered).is_err(), "byte {at}");
        }
        assert!(matches!(open("passphrase", &file[..file.len() - 1]), Err(Error::Passphrase)));
        assert!(matches!(open("passphrase", b"WALLET"), Err(Error::NotKept)));
    }

    #[test]
    fn a_file_asking_too_much_of_the_device_is_refused() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let mut file = seal(&key, [2; 24], &record(None));
        file[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open("passphrase", &file), Err(Error::Params)));
        file[7] = 2;
        assert!(matches!(open("passphrase", &file), Err(Error::Format(2))));
    }

    /// The format, byte for byte: a change to it fails this, and needs a new format version.
    #[test]
    fn the_format_stays_as_it_was() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let file = seal(&key, [2; 24], &record(None));
        assert_eq!(
            file[..HEADER].to_lower_hex_string(),
            "57414c4c4554000108000000010000000100000001010101010101010101010101010101\
             020202020202020202020202020202020202020202020202"
        );
        let expected = "network regtest\nbirthday 1700000000\nwords abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\nfingerprint 73c5da0a\nkind taproot\nmultisig wsh(sortedmulti(2,a,b,c))#checksum 5661756c742031\nmultisig wsh(multi(1,a)) \n";
        assert_eq!(*record(None).encode(), expected);
        assert_eq!(Record::decode(expected).unwrap(), record(None));
    }

    /// How long the default cost takes here: `cargo test --release -p wallet-core -- --ignored
    /// default_cost --nocapture`.
    #[test]
    #[ignore]
    fn default_cost() {
        let start = std::time::Instant::now();
        Key::derive("passphrase", [1; 16], Params::DEFAULT).unwrap();
        println!("Argon2id at {:?}: {:?}", Params::DEFAULT, start.elapsed());
    }

    #[test]
    fn a_damaged_record_is_refused() {
        let good = record(None).encode();
        let bad = [
            good.replace("network regtest\n", ""),
            good.replace("kind taproot", "kind p2sh"),
            good.replace("about", "abandon"),
            format!("{}network regtest\n", *good),
            format!("{}descriptor wpkh(a)\n", *good),
            format!("{}color blue\n", *good),
            good.replace("5661756c742031", "zz"),
        ];
        for text in bad {
            assert!(matches!(Record::decode(&text), Err(Error::Record(_))), "{text}");
        }
    }
}
