//! Messages to sign as they cross the air gap: a text file on the card, as Coldcard reads one, the
//! message on its first line and, on its second, the key to sign with, by its path (Coldcard's
//! `m/84h/0h/0h/0/5`) or here by its address; and the signed message written back in the armor
//! Electrum and Sparrow read. A message is plain ASCII, as Coldcard has it, so that what the
//! screen shows is what is signed: no look-alike letters, no characters that do not show.

use std::str::FromStr;

use wallet_core::bitcoin::bip32::DerivationPath;

/// The longest message signed. Coldcard's is 240 characters; a handheld's screen shows this
/// many in a scroll.
pub const LONGEST: usize = 1000;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no message in it: its first line is the message")]
    Empty,
    #[error("its message is longer than {LONGEST} characters")]
    TooLong,
    #[error("its message is not plain ASCII text, which is all that is signed")]
    NotPlain,
    #[error("its second line, {0:?}, is neither a key's path nor an address")]
    Key(String),
}

/// What to sign, and with which key, if the request names one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub message: String,
    pub key: Option<KeyRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    Path(DerivationPath),
    Address(String),
}

/// Whether `message` is one this signs: some plain ASCII text, not too long.
pub fn check(message: &str) -> Result<(), Error> {
    if message.is_empty() {
        return Err(Error::Empty);
    }
    if !message.chars().all(|char| char.is_ascii_graphic() || char == ' ') {
        return Err(Error::NotPlain);
    }
    if message.len() > LONGEST {
        return Err(Error::TooLong);
    }
    Ok(())
}

/// The request a file on the card holds. A third line, which Coldcard reads as the address's
/// type, is passed over: the account's own decides it.
pub fn read(text: &str) -> Result<Request, Error> {
    let mut lines = text.trim_start_matches('\u{feff}').lines();
    let message = lines.next().unwrap_or_default().trim();
    check(message)?;
    let key = match lines.next().map(str::trim).filter(|line| !line.is_empty()) {
        None => None,
        Some(path) if path.starts_with(['m', 'M']) => {
            let parsed = DerivationPath::from_str(&path.replace(['H'], "h").to_lowercase());
            Some(KeyRef::Path(parsed.map_err(|_| Error::Key(path.to_owned()))?))
        }
        Some(address) if address.chars().all(|char| char.is_ascii_alphanumeric()) => {
            Some(KeyRef::Address(address.to_owned()))
        }
        Some(other) => return Err(Error::Key(other.to_owned())),
    };
    Ok(Request { message: message.to_owned(), key })
}

/// The signed message as Electrum, Sparrow and Bitcoin Core's GUI write and read one.
pub fn armor(message: &str, address: &str, signature: &str) -> String {
    format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n{message}\n-----BEGIN BITCOIN SIGNATURE-----\n{address}\n{signature}\n-----END BITCOIN SIGNATURE-----\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coldcard_request_reads_with_its_path() {
        let request = read("Hello World\nm/84h/0h/0h/0/5\np2wpkh\n").unwrap();
        assert_eq!(request.message, "Hello World");
        let path = DerivationPath::from_str("m/84h/0h/0h/0/5").unwrap();
        assert_eq!(request.key, Some(KeyRef::Path(path.clone())));
        // With apostrophes, or capitals, as other wallets write paths.
        assert_eq!(read("Hi\nm/84'/0'/0'/0/5").unwrap().key, Some(KeyRef::Path(path.clone())));
        assert_eq!(read("Hi\r\nM/84H/0H/0H/0/5\r\n").unwrap().key, Some(KeyRef::Path(path)));
    }

    #[test]
    fn a_request_may_name_its_address_or_no_key() {
        let address = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
        let request = read(&format!("\u{feff}  I own this  \n{address}")).unwrap();
        assert_eq!(request.message, "I own this");
        assert_eq!(request.key, Some(KeyRef::Address(address.to_owned())));
        assert_eq!(read("Just this").unwrap().key, None);
    }

    #[test]
    fn only_plain_text_is_signed() {
        assert_eq!(read(""), Err(Error::Empty));
        assert_eq!(read("\n\nm/0"), Err(Error::Empty));
        // A Cyrillic a, which looks like a Latin one, and a character that shows nothing.
        assert_eq!(read("p\u{0430}y Bob"), Err(Error::NotPlain));
        assert_eq!(read("pay\u{200b}Bob"), Err(Error::NotPlain));
        assert_eq!(read("tab\there"), Err(Error::NotPlain));
        assert_eq!(read(&"x".repeat(LONGEST + 1)), Err(Error::TooLong));
        assert!(matches!(read("Hi\nm/84h/zz"), Err(Error::Key(_))));
        assert!(matches!(read("Hi\nnot an address!"), Err(Error::Key(_))));
    }

    #[test]
    fn the_armor_is_electrums() {
        let armored = armor("Hello World", "bc1qexample", "smpAAA=");
        assert_eq!(
            armored,
            "-----BEGIN BITCOIN SIGNED MESSAGE-----\nHello World\n-----BEGIN BITCOIN SIGNATURE-----\nbc1qexample\nsmpAAA=\n-----END BITCOIN SIGNATURE-----\n"
        );
    }
}
