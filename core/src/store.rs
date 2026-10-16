//! A wallet kept on the device, for whoever opts into it: its seed (or a watch-only wallet's
//! descriptor) and the multisig wallets registered with it, encrypted with a passphrase, a
//! security key, or both. Without a secure element to count failed tries, anyone who copies the
//! file can guess at a passphrase on their own hardware for as long as they like, so its key is
//! Argon2id's, which makes each guess cost memory as well as time (RFC 9106's second recommended
//! setting: 64 MiB, three passes, four lanes). A FIDO2 security key is the secure element the
//! device lacks: its hmac-secret, which it computes only when touched and given its PIN, and
//! which it locks after eight wrong PINs, goes into the key as well, so a copy of the file is no
//! use without the security key in hand. The file is sealed with XChaCha20-Poly1305, which
//! refuses it whole if a byte of it changed.
//!
//! The file: `WALLET`, 0, a format version; Argon2's memory in KiB, passes and lanes, each a
//! little-endian u32; a 16-byte salt; in format 2, sealed with a security key, a byte of flags
//! (1: a passphrase too), the 32-byte salt the security key's secret is asked under, and the
//! credential's ID, after its length as a little-endian u16; a 24-byte nonce; then the sealed
//! record, the header its associated data. The record is text, a line a field.

use std::fmt::Write;
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Version};
use bip39::{Language, Mnemonic};
use bitcoin::Network;
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
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
    #[error("wrong passphrase or security key, or the file is damaged")]
    Unsealed,
    #[error("it is sealed with a security key, whose secret is needed to open it")]
    NeedsSecurityKey,
    #[error("the wallet in it is damaged: {0}")]
    Record(String),
}

const MAGIC: &[u8; 7] = b"WALLET\0";
/// Sealed under a passphrase alone.
const FORMAT: u8 = 1;
/// Sealed under a security key's secret, and a passphrase if one was given.
const FORMAT_KEYED: u8 = 2;
/// The magic, the format, Argon2's cost and its salt: what every format begins with.
const FIXED: usize = 8 + 3 * 4 + 16;
const NONCE: usize = 24;
/// The longest credential ID a file may hold. CTAP sets none; keys make IDs of tens of bytes.
const MOST_CREDENTIAL: usize = 1024;
/// Set in format 2's flags when a passphrase was given beside the security key.
const WITH_PASSPHRASE: u8 = 1;

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

/// A FIDO2 credential a file is sealed with: made on a security key for the file, whose
/// hmac-secret under `salt` goes into the file's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKey {
    pub credential: Vec<u8>,
    pub salt: [u8; 32],
}

/// What a file's header says of opening it, which can be read before it is opened: the security
/// key to ask for a secret, if any, and whether a passphrase is needed too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub security_key: Option<SecurityKey>,
    pub passphrase: bool,
    params: Params,
    salt: [u8; 16],
    nonce: [u8; NONCE],
    len: usize,
}

impl Header {
    pub fn read(file: &[u8]) -> Result<Header, Error> {
        if file.len() < FIXED + NONCE || !file.starts_with(MAGIC) {
            return Err(Error::NotKept);
        }
        let word = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
        let params = Params { memory_kib: word(8), passes: word(12), lanes: word(16) };
        let salt: [u8; 16] = file[20..FIXED].try_into().unwrap();
        let (security_key, passphrase, nonce_at) = match file[7] {
            FORMAT => (None, true, FIXED),
            FORMAT_KEYED => {
                let flags = *file.get(FIXED).ok_or(Error::NotKept)?;
                let salt: [u8; 32] = (file.get(FIXED + 1..FIXED + 33))
                    .and_then(|salt| salt.try_into().ok())
                    .ok_or(Error::NotKept)?;
                let len = file.get(FIXED + 33..FIXED + 35).ok_or(Error::NotKept)?;
                let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
                if flags & !WITH_PASSPHRASE != 0 || len == 0 || len > MOST_CREDENTIAL {
                    return Err(Error::NotKept);
                }
                let credential = file.get(FIXED + 35..FIXED + 35 + len).ok_or(Error::NotKept)?;
                let security_key = SecurityKey { credential: credential.to_vec(), salt };
                (Some(security_key), flags & WITH_PASSPHRASE != 0, FIXED + 35 + len)
            }
            format => return Err(Error::Format(format)),
        };
        let nonce = (file.get(nonce_at..nonce_at + NONCE))
            .and_then(|nonce| nonce.try_into().ok())
            .ok_or(Error::NotKept)?;
        Ok(Header { security_key, passphrase, params, salt, nonce, len: nonce_at + NONCE })
    }

    fn write(&self) -> Vec<u8> {
        let Params { memory_kib, passes, lanes } = self.params;
        let mut header = Vec::with_capacity(self.len);
        header.extend(MAGIC);
        header.push(if self.security_key.is_some() { FORMAT_KEYED } else { FORMAT });
        for value in [memory_kib, passes, lanes] {
            header.extend(value.to_le_bytes());
        }
        header.extend(self.salt);
        if let Some(SecurityKey { credential, salt }) = &self.security_key {
            header.push(if self.passphrase { WITH_PASSPHRASE } else { 0 });
            header.extend(salt);
            header.extend((credential.len() as u16).to_le_bytes());
            header.extend(credential);
        }
        header.extend(self.nonce);
        header
    }
}

/// The key a passphrase gives, and a security key's secret with it, with the salt, cost and
/// credential it was made with, which sealing the wallet again writes beside it. Made once, as
/// making it takes seconds, and kept for as long as the wallet is open, as the seed is.
pub struct Key {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    params: Params,
    security_key: Option<SecurityKey>,
    passphrase: bool,
}

impl Key {
    /// The key of `passphrase` under `salt`, which should be fresh randomness for each new
    /// passphrase.
    pub fn derive(passphrase: &str, salt: [u8; 16], params: Params) -> Result<Key, Error> {
        let key = argon2id(passphrase, &salt, params)?;
        Ok(Key { key, salt, params, security_key: None, passphrase: true })
    }

    /// The key of `passphrase`, which may be empty, and of the secret the security key gave for
    /// its credential.
    pub fn derive_with(
        passphrase: &str,
        salt: [u8; 16],
        params: Params,
        security_key: SecurityKey,
        secret: &[u8; 32],
    ) -> Result<Key, Error> {
        let stretched = argon2id(passphrase, &salt, params)?;
        // HKDF's extract, with the security key's secret for its salt: the key is as hard to
        // find as the harder of the two to get.
        let mut engine = HmacEngine::<sha256::Hash>::new(secret);
        engine.input(b"WALLET security key\0");
        engine.input(stretched.as_ref());
        let key = Zeroizing::new(Hmac::from_engine(engine).to_byte_array());
        let passphrase = !passphrase.is_empty();
        Ok(Key { key, salt, params, security_key: Some(security_key), passphrase })
    }

    /// The security key the wallet is sealed with, if any.
    pub fn security_key(&self) -> Option<&SecurityKey> {
        self.security_key.as_ref()
    }

    /// Whether a passphrase went into it: always, unless a security key alone did.
    pub fn has_passphrase(&self) -> bool {
        self.passphrase
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&(*self.key).into())
    }

    fn header(&self, nonce: [u8; NONCE]) -> Header {
        let credential = self.security_key.as_ref().map_or(0, |key| 35 + key.credential.len());
        Header {
            security_key: self.security_key.clone(),
            passphrase: self.passphrase,
            params: self.params,
            salt: self.salt,
            nonce,
            len: FIXED + credential + NONCE,
        }
    }
}

fn argon2id(
    passphrase: &str,
    salt: &[u8; 16],
    params: Params,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0; 32]);
    (params.argon2()?)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Params)?;
    Ok(key)
}

/// The file that keeps `record` under `key`. `nonce` must be fresh randomness each time: a nonce
/// used twice under one key gives the two records away.
pub fn seal(key: &Key, nonce: [u8; 24], record: &Record) -> Vec<u8> {
    let mut file = key.header(nonce).write();
    let plaintext = record.encode();
    let payload = Payload { msg: plaintext.as_bytes(), aad: &file };
    let sealed = key.cipher().encrypt(&nonce.into(), payload).expect("a record seals");
    file.extend(sealed);
    file
}

/// The record `file` keeps, and the key `passphrase` gives for it (with the security key's
/// `secret`, for a file sealed with one), to seal it again with.
pub fn open(
    passphrase: &str,
    secret: Option<&[u8; 32]>,
    file: &[u8],
) -> Result<(Key, Record), Error> {
    let header = Header::read(file)?;
    let (key, refused) = match (&header.security_key, secret) {
        (None, _) => (Key::derive(passphrase, header.salt, header.params)?, Error::Passphrase),
        (Some(security_key), Some(secret)) => {
            let security_key = security_key.clone();
            let key =
                Key::derive_with(passphrase, header.salt, header.params, security_key, secret)?;
            (key, Error::Unsealed)
        }
        (Some(_), None) => return Err(Error::NeedsSecurityKey),
    };
    let payload = Payload { msg: &file[header.len..], aad: &file[..header.len] };
    let plaintext = key.cipher().decrypt(&header.nonce.into(), payload).map_err(|_| refused)?;
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
            let (again, opened) = open("correct horse battery staple", None, &file).unwrap();
            assert_eq!(opened, kept);
            // The key it gives back seals it as it was.
            assert_eq!(seal(&again, [2; 24], &opened), file);
            assert!(matches!(
                open("correct horse battery stapler", None, &file),
                Err(Error::Passphrase)
            ));
        }
    }

    fn security_key() -> SecurityKey {
        SecurityKey { credential: vec![9; 48], salt: [3; 32] }
    }

    #[test]
    fn a_wallet_sealed_with_a_security_key_takes_its_secret_and_any_passphrase() {
        let secret = [5; 32];
        for passphrase in ["", "correct horse"] {
            let key =
                Key::derive_with(passphrase, [1; 16], CHEAP, security_key(), &secret).unwrap();
            let file = seal(&key, [2; 24], &record(None));
            let header = Header::read(&file).unwrap();
            assert_eq!(header.security_key, Some(security_key()));
            assert_eq!(header.passphrase, !passphrase.is_empty());
            let (again, opened) = open(passphrase, Some(&secret), &file).unwrap();
            assert_eq!(opened, record(None));
            assert_eq!(again.security_key(), Some(&security_key()));
            assert_eq!(seal(&again, [2; 24], &opened), file, "sealed again as it was");
            // Without the security key's secret, or with another, it stays shut, the right
            // passphrase or not.
            assert!(matches!(open(passphrase, None, &file), Err(Error::NeedsSecurityKey)));
            assert!(matches!(open(passphrase, Some(&[6; 32]), &file), Err(Error::Unsealed)));
            assert!(matches!(open("wrong", Some(&secret), &file), Err(Error::Unsealed)));
        }
    }

    #[test]
    fn a_byte_changed_anywhere_refuses_a_file_sealed_with_a_security_key() {
        let key = Key::derive_with("", [1; 16], CHEAP, security_key(), &[5; 32]).unwrap();
        let file = seal(&key, [2; 24], &record(None));
        for at in 0..file.len() {
            let mut tampered = file.clone();
            tampered[at] ^= 1;
            assert!(open("", Some(&[5; 32]), &tampered).is_err(), "byte {at}");
        }
        // A header cut short anywhere reads as no file of ours, rather than past its end.
        for len in 0..FIXED + 35 + 48 + NONCE {
            assert!(Header::read(&file[..len]).is_err(), "{len} bytes");
        }
        // A key that is its passphrase alone is no key sealed with a security key's.
        let plain = Key::derive("", [1; 16], CHEAP).unwrap();
        assert!(open("", None, &seal(&plain, [2; 24], &record(None))).is_ok());
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
            assert!(open("passphrase", None, &tampered).is_err(), "byte {at}");
        }
        assert!(matches!(
            open("passphrase", None, &file[..file.len() - 1]),
            Err(Error::Passphrase)
        ));
        assert!(matches!(open("passphrase", None, b"WALLET"), Err(Error::NotKept)));
    }

    #[test]
    fn a_file_asking_too_much_of_the_device_is_refused() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let mut file = seal(&key, [2; 24], &record(None));
        file[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open("passphrase", None, &file), Err(Error::Params)));
        file[7] = 3;
        assert!(matches!(open("passphrase", None, &file), Err(Error::Format(3))));
    }

    /// The format, byte for byte: a change to it fails this, and needs a new format version.
    #[test]
    fn the_format_stays_as_it_was() {
        let key = Key::derive("passphrase", [1; 16], CHEAP).unwrap();
        let file = seal(&key, [2; 24], &record(None));
        assert_eq!(
            file[..FIXED + NONCE].to_lower_hex_string(),
            "57414c4c4554000108000000010000000100000001010101010101010101010101010101\
             020202020202020202020202020202020202020202020202"
        );
        let key = Key::derive_with("", [1; 16], CHEAP, security_key(), &[5; 32]).unwrap();
        let keyed = seal(&key, [2; 24], &record(None));
        assert_eq!(
            keyed[..FIXED + 35 + 48 + NONCE].to_lower_hex_string(),
            [
                "57414c4c4554000208000000010000000100000001010101010101010101010101010101",
                &format!("00{}", "03".repeat(32)),
                "3000",
                &"09".repeat(48),
                &"02".repeat(24),
            ]
            .concat()
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
