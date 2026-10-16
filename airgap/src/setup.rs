//! Multisig setup files as coordinators write them, read into the one descriptor the signer
//! registers. Sparrow's "Output Descriptor" export (a `#` comment, then the receive-and-change
//! descriptor, then each alone, each perhaps with BIP-393 annotations such as `?bh=850123`), a
//! BSMS 1.0 record (BIP-129: the descriptor and the wallet's first address), Coldcard's setup file
//! (`Policy: 2 of 3`, `Derivation: m/48'/0'/0'/2'`, `Format: P2WSH`, then `XFP: xpub` lines),
//! Specter DIY's `addwallet name&descriptor`, or a bare descriptor: whichever a file holds, what
//! comes out is a descriptor with `<0;1>` keychains, or its receive and change lines.

use wallet_core::bitcoin::base58;
use wallet_core::miniscript::descriptor::checksum::verify_checksum;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no multisig descriptor or setup in it")]
    Empty,
    #[error("its descriptor's checksum is wrong: {0}")]
    Checksum(String),
    #[error("a {0} multisig, where the wallet signs P2WSH only")]
    Format(String),
    #[error("its line {0:?} is not one of a Coldcard setup file's")]
    Coldcard(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    /// The wallet's descriptor, `<0;1>` for its keychains, or its receive and change descriptors
    /// on two lines.
    pub descriptor: String,
    /// The wallet's first receive address, as a BSMS record states it for the signer to check.
    pub first_address: Option<String>,
    /// What the coordinator named the wallet.
    pub name: Option<String>,
}

/// Whether `text` looks like a setup this reads, for picking files out of a directory.
pub fn looks_like(text: &str) -> bool {
    let text = text.trim_start_matches('\u{feff}');
    text.contains("wsh(") || text.trim_start().starts_with("BSMS 1.0") || coldcard_policy(text)
}

pub fn read(text: &str) -> Result<Setup, Error> {
    let text = text.trim_start_matches('\u{feff}');
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if lines.first() == Some(&"BSMS 1.0") {
        return bsms(&lines);
    }
    if coldcard_policy(text) {
        return coldcard(&lines);
    }
    let mut name = None;
    let mut descriptors = Vec::new();
    for line in lines.iter().filter(|line| !line.starts_with('#')) {
        let line = match line.strip_prefix("addwallet ") {
            Some(wallet) => {
                let (wallet_name, descriptor) = wallet.split_once('&').unwrap_or(("", wallet));
                name = Some(wallet_name.to_owned()).filter(|name| !name.is_empty());
                descriptor
            }
            None => line,
        };
        if line.contains("wsh(") {
            descriptors.push(descriptor(line)?);
        }
    }
    // Sparrow's file holds the multipath descriptor and then each keychain's; the first, if it
    // is multipath, is the wallet, and otherwise the first two are its keychains.
    let descriptor = match descriptors.as_slice() {
        [] => return Err(Error::Empty),
        [first, ..] if first.contains("<0;1>") => first.clone(),
        [receive, change, ..] => format!("{receive}\n{change}"),
        [only] => only.clone(),
    };
    Ok(Setup { descriptor, first_address: None, name })
}

/// A descriptor line made plain: its checksum checked over the line as written and dropped with
/// any BIP-393 annotations, and its keys given `<0;1>` keychains where they have none or write
/// them as BIP-389's `/**`.
fn descriptor(line: &str) -> Result<String, Error> {
    let line = match line.contains('#') {
        true => verify_checksum(line).map_err(|error| Error::Checksum(error.to_string()))?,
        false => line,
    };
    let bare = line.split('?').next().unwrap_or(line);
    Ok(with_keychains(&bare.replace("/**", "/<0;1>/*")))
}

/// `descriptor` with `/<0;1>/*` after every xpub or tpub that ends a key, as Specter's wallets and
/// BSMS templates write them, with no derivation after the key.
fn with_keychains(descriptor: &str) -> String {
    let mut out = String::with_capacity(descriptor.len() + 64);
    let mut rest = descriptor;
    while let Some(at) = ["xpub", "tpub"].iter().filter_map(|prefix| rest.find(prefix)).min() {
        let key_len =
            rest[at..].find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len() - at);
        let (head, tail) = rest.split_at(at + key_len);
        out.push_str(head);
        if tail.starts_with([',', ')']) {
            out.push_str("/<0;1>/*");
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// BIP-129's descriptor record: `BSMS 1.0`, the descriptor template, the path restrictions, and
/// the first address.
fn bsms(lines: &[&str]) -> Result<Setup, Error> {
    let template = lines.get(1).ok_or(Error::Empty)?;
    let first_address = lines.get(3).map(|address| address.to_string());
    Ok(Setup { descriptor: descriptor(template)?, first_address, name: None })
}

fn coldcard_policy(text: &str) -> bool {
    text.lines().any(|line| line.trim().to_ascii_lowercase().starts_with("policy:"))
}

/// Coldcard's multisig setup file, which Sparrow, Nunchuk, Keystone and Passport write too: a
/// sorted multisig of the keys listed, each at the derivation last given before it.
fn coldcard(lines: &[&str]) -> Result<Setup, Error> {
    let (mut name, mut threshold, mut derivation) = (None, None, None);
    let mut keys = Vec::new();
    for line in lines.iter().filter(|line| !line.starts_with('#')) {
        let (field, value) =
            line.split_once(':').ok_or_else(|| Error::Coldcard(line.to_string()))?;
        let (field, value) = (field.trim(), value.trim());
        match field.to_ascii_lowercase().as_str() {
            "name" => name = Some(value.to_owned()),
            // "2 of 3", or "2/3".
            "policy" => {
                threshold = value.split(|c: char| !c.is_ascii_digit()).next().map(str::to_owned)
            }
            "derivation" => derivation = Some(value.trim_start_matches("m/").to_owned()),
            "format" => match value.to_ascii_uppercase().as_str() {
                "P2WSH" => {}
                other => return Err(Error::Format(other.to_owned())),
            },
            fingerprint
                if fingerprint.len() == 8 && fingerprint.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                let derivation =
                    derivation.as_ref().ok_or_else(|| Error::Coldcard(line.to_string()))?;
                let xpub = to_xpub(value).ok_or_else(|| Error::Coldcard(line.to_string()))?;
                keys.push(format!("[{fingerprint}/{derivation}]{xpub}/<0;1>/*"));
            }
            _ => return Err(Error::Coldcard(line.to_string())),
        }
    }
    let threshold = threshold.filter(|threshold| !threshold.is_empty()).ok_or(Error::Empty)?;
    if keys.is_empty() {
        return Err(Error::Empty);
    }
    let descriptor = format!("wsh(sortedmulti({threshold},{}))", keys.join(","));
    Ok(Setup { descriptor, first_address: None, name })
}

/// An extended public key in any of SLIP-132's encodings (`Zpub`, `Vpub`, `zpub`...) as the plain
/// `xpub` or `tpub` a descriptor takes: the same key under BIP32's own version bytes.
pub fn to_xpub(key: &str) -> Option<String> {
    const MAINNET: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
    const TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
    let mut data = base58::decode_check(key).ok()?;
    if data.len() != 78 {
        return None;
    }
    let version = match data[..4] {
        // xpub, ypub, zpub, Ypub, Zpub.
        [0x04, 0x88, 0xb2, 0x1e]
        | [0x04, 0x9d, 0x7c, 0xb2]
        | [0x04, 0xb2, 0x47, 0x46]
        | [0x02, 0x95, 0xb4, 0x3f]
        | [0x02, 0xaa, 0x7e, 0xd3] => MAINNET,
        // tpub, upub, vpub, Upub, Vpub.
        [0x04, 0x35, 0x87, 0xcf]
        | [0x04, 0x4a, 0x52, 0x62]
        | [0x04, 0x5f, 0x1c, 0xf6]
        | [0x02, 0x42, 0x89, 0xef]
        | [0x02, 0x57, 0x54, 0x83] => TESTNET,
        _ => return None,
    };
    data[..4].copy_from_slice(&version);
    Some(base58::encode_check(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two real mainnet xpubs: two passphrases' BIP48 keys.
    fn keys() -> (String, String) {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon about";
        let key = |passphrase: &str| {
            let seed = wallet_core::seed::Seed::new(&mnemonic.parse().unwrap(), passphrase);
            let network = wallet_core::bitcoin::Network::Bitcoin;
            wallet_core::multisig::CosignerKey::new(&seed, network, 0).unwrap().xpub.to_string()
        };
        (key("a"), key("b"))
    }

    fn checksum(line: &str) -> String {
        let mut engine = wallet_core::miniscript::descriptor::checksum::Engine::new();
        engine.input(line).unwrap();
        engine.checksum()
    }

    fn slip132(xpub: &str, version: [u8; 4]) -> String {
        let mut data = base58::decode_check(xpub).unwrap();
        data[..4].copy_from_slice(&version);
        base58::encode_check(&data)
    }

    #[test]
    fn sparrows_descriptor_export_reads_as_its_multipath_line() {
        let (a, b) = keys();
        // As Sparrow writes it (io/Descriptor.java), annotations included.
        let both = format!(
            "wsh(sortedmulti(1,[11111111/48h/0h/0h/2h]{a}/<0;1>/*,[22222222/48h/0h/0h/2h]{b}/<0;1>/*))?bh=850123"
        );
        let checksummed = |line: String| format!("{line}#{}", checksum(&line));
        let text = format!(
            "# Receive and change descriptor:\n{}\n\n\n\n# Receive descriptor:\n{}\n\n# Change descriptor:\n{}\n",
            checksummed(both.clone()),
            checksummed(both.replace("<0;1>", "0")),
            checksummed(both.replace("<0;1>", "1")),
        );
        let setup = read(&text).unwrap();
        assert_eq!(setup.descriptor, both.split('?').next().unwrap());
        let tampered = text.replacen("850123", "850124", 1);
        assert!(matches!(read(&tampered), Err(Error::Checksum(_))), "checked over the annotations");
    }

    #[test]
    fn a_bsms_record_reads_with_its_first_address() {
        let (a, b) = keys();
        let text = format!(
            "BSMS 1.0\nwsh(sortedmulti(1,[11111111/48'/0'/0'/2']{a}/**,[22222222/48'/0'/0'/2']{b}/**))\n/0/*,/1/*\nbc1qexample\n"
        );
        let setup = read(&text).unwrap();
        assert_eq!(setup.first_address.as_deref(), Some("bc1qexample"));
        assert!(setup.descriptor.contains(&format!("{a}/<0;1>/*,")), "{}", setup.descriptor);
    }

    #[test]
    fn a_coldcard_setup_file_reads_as_a_sorted_multisig() {
        let (a, b) = keys();
        let zpub = slip132(&b, [0x02, 0xaa, 0x7e, 0xd3]);
        let text = format!(
            "# Coldcard Multisig setup file (created by Sparrow)\n#\nName: Vault\nPolicy: 2 of 2\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n\n11111111: {a}\nDerivation: m/48'/0'/1'/2'\n22222222: {zpub}\n"
        );
        let setup = read(&text).unwrap();
        assert_eq!(setup.name.as_deref(), Some("Vault"));
        let expected = format!(
            "wsh(sortedmulti(2,[11111111/48'/0'/0'/2']{a}/<0;1>/*,[22222222/48'/0'/1'/2']{b}/<0;1>/*))"
        );
        assert_eq!(setup.descriptor, expected);
        let nested = text.replace("Format: P2WSH", "Format: P2SH-P2WSH");
        assert!(matches!(read(&nested), Err(Error::Format(_))));
    }

    #[test]
    fn specters_addwallet_line_reads_with_keychains_added() {
        let (a, b) = keys();
        let text = format!(
            "addwallet Vault&wsh(sortedmulti(1,[11111111/48h/0h/0h/2h]{a},[22222222/48h/0h/0h/2h]{b}))"
        );
        let setup = read(&text).unwrap();
        assert_eq!(setup.name.as_deref(), Some("Vault"));
        let expected = format!(
            "wsh(sortedmulti(1,[11111111/48h/0h/0h/2h]{a}/<0;1>/*,[22222222/48h/0h/0h/2h]{b}/<0;1>/*))"
        );
        assert_eq!(setup.descriptor, expected);
    }

    #[test]
    fn a_bare_pair_of_keychains_stays_a_pair() {
        let (a, _) = keys();
        let receive = format!("wsh(multi(1,[11111111/48h/0h/0h/2h]{a}/0/*))");
        let setup = read(&format!("{receive}\n{}", receive.replace("/0/*", "/1/*"))).unwrap();
        assert_eq!(setup.descriptor.lines().count(), 2);
        assert!(
            looks_like(&setup.descriptor) && !looks_like("hello") && looks_like("Policy: 2 of 3")
        );
    }

    #[test]
    fn slip132_keys_read_as_xpubs_and_tpubs() {
        let (a, _) = keys();
        assert_eq!(to_xpub(&slip132(&a, [0x04, 0xb2, 0x47, 0x46])), Some(a.clone()));
        let tpub = to_xpub(&slip132(&a, [0x02, 0x57, 0x54, 0x83])).unwrap();
        assert!(tpub.starts_with("tpub"));
        assert_eq!(to_xpub("not a key"), None);
    }
}
