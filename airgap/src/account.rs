//! An account as a BC-UR `crypto-account` (BCR-2020-015), the QR code Sparrow, Nunchuk, BlueWallet
//! and Keeper scan to watch a signer's account, as SeedSigner, Passport and Keystone show it: the
//! master fingerprint, and the account's output descriptor as a `crypto-output` (BCR-2020-010) of
//! its key, a `crypto-hdkey` (BCR-2020-007) with the path it was derived at. BCR-2023-019's
//! `account-descriptor` has since superseded it, but the coordinators in use read this one. Its
//! tags are the first registry's (303 for a key, 308 for an output), which it was written with.

use wallet_core::account::{Account, Kind};
use wallet_core::bitcoin::Network;
use wallet_core::bitcoin::bip32::ChildNumber;

/// The UR type.
pub const ACCOUNT_TYPE: &str = "crypto-account";

const HDKEY: u64 = 303;
const KEYPATH: u64 = 304;
const COININFO: u64 = 305;
const OUTPUT: u64 = 308;
const WPKH: u64 = 404;
const TR: u64 = 409;

/// The account's `crypto-account`, as CBOR.
pub fn crypto_account(account: &Account) -> Vec<u8> {
    let mut cbor = Cbor::default();
    cbor.map(2);
    cbor.uint(1);
    cbor.uint(u32::from_be_bytes(account.fingerprint().to_bytes()).into());
    cbor.uint(2);
    cbor.array(1);
    cbor.0.extend(crypto_output(account));
    cbor.0
}

/// The account's output descriptor as a `crypto-output`: its script around its key.
pub fn crypto_output(account: &Account) -> Vec<u8> {
    let mut cbor = Cbor::default();
    cbor.tag(OUTPUT);
    cbor.tag(match account.kind() {
        Kind::SegwitV0 => WPKH,
        Kind::Taproot => TR,
    });
    let xpub = account.xpub();
    let testnet = account.network() != Network::Bitcoin;
    cbor.tag(HDKEY);
    cbor.map(if testnet { 5 } else { 4 });
    cbor.uint(3);
    cbor.bytes(&xpub.public_key.serialize());
    cbor.uint(4);
    cbor.bytes(xpub.chain_code.as_bytes());
    if testnet {
        // How the key is used: the default coin, on a test network.
        cbor.uint(5);
        cbor.tag(COININFO);
        cbor.map(1);
        cbor.uint(2);
        cbor.uint(1);
    }
    cbor.uint(6);
    cbor.tag(KEYPATH);
    cbor.map(2);
    cbor.uint(1);
    let path = account.path();
    cbor.array(2 * path.len() as u64);
    for step in path {
        let (index, hardened) = match *step {
            ChildNumber::Normal { index } => (index, false),
            ChildNumber::Hardened { index } => (index, true),
        };
        cbor.uint(index.into());
        cbor.bool(hardened);
    }
    cbor.uint(2);
    cbor.uint(u32::from_be_bytes(account.fingerprint().to_bytes()).into());
    cbor.uint(8);
    cbor.uint(u32::from_be_bytes(xpub.parent_fingerprint.to_bytes()).into());
    cbor.0
}

/// The account's `crypto-account` as a single-part UR, in capitals for QR's alphanumeric mode.
pub fn account_ur(account: &Account) -> String {
    let cbor = crypto_account(account);
    ::ur::ur::encode(&cbor, &::ur::ur::Type::Custom(ACCOUNT_TYPE)).to_uppercase()
}

/// The little CBOR (RFC 8949) the types take, in its shortest heads, as their test vectors are.
#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..24 => self.0.push(major | value as u8),
            24..0x100 => self.0.extend([major | 24, value as u8]),
            0x100..0x1_0000 => {
                self.0.push(major | 25);
                self.0.extend((value as u16).to_be_bytes());
            }
            0x1_0000..0x1_0000_0000 => {
                self.0.push(major | 26);
                self.0.extend((value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(major | 27);
                self.0.extend(value.to_be_bytes());
            }
        }
    }

    fn uint(&mut self, value: u64) {
        self.head(0, value);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.head(2, bytes.len() as u64);
        self.0.extend(bytes);
    }

    fn array(&mut self, len: u64) {
        self.head(4, len);
    }

    fn map(&mut self, len: u64) {
        self.head(5, len);
    }

    fn tag(&mut self, tag: u64) {
        self.head(6, tag);
    }

    fn bool(&mut self, value: bool) {
        self.0.push(if value { 0xf5 } else { 0xf4 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_core::bitcoin::hex::{DisplayHex, FromHex};
    use wallet_core::seed::Seed;

    /// BCR-2020-015's test vector: the account #0 of each script type for this seed, on mainnet.
    const MNEMONIC: &str = "shield group erode awake lock sausage cash glare wave crew flame glove";
    const UR: &str = "ur:crypto-account/oeadcyemrewytyaolttaadeetaadmutaaddloxaxhdclaxwmfmdeiamecsdsemgtvsjzcncygrkowtrontzschgezokstswkkscfmklrtauteyaahdcxiehfonurdppfyntapejpproypegrdawkgmaewejlsfdtsrfybdehcaflmtrlbdhpamtaaddyoeadlncsdwykaeykaeykaocyemrewytyaycynlytsnyltaadeetaadmhtaadmwtaaddloxaxhdclaostvelfemdyynwydwyaievosrgmambklovabdgypdglldvespsthysadamhpmjeinaahdcxntdllnaaeykoytdacygegwhgjsiyonpywmcmrpwphsvodsrerozsbyaxluzcoxdpamtaaddyoeadlncsehykaeykaeykaocyemrewytyaycypdbskeuytaadeetaadmwtaaddloxaxhdclaxzcfxeegdrpmogrgwkbzctlttweadkiengrwlhtprremouoluutqdpfbncedkynfhaahdcxjpwevdeogthttkmeswzcolcpsaahcfnshkhtehytclmnteatmoteadtlwynnftloamtaaddyoeadlncsghykaeykaeykaocyemrewytyaycybthlvytstaadeetaadmhtaadnytaaddloxaxhdclaxhhsnhdrpftdwuocntilydibehnecmovdfekpjkclcslasbhkpawsaddmcmmnahnyaahdcxlotedtndfymyltclhlmtpfsadscnhtztaolbnnkistaedegwfmmedreetnwmcycnamtaaddyoeadlfcsdpykaocyemrewytyaycyemrewytytaadeetaadmhtaadmetaadnytaaddloxaxhdclaxdwkswmztpytnswtsecnblfbayajkdldeclqzzolrsnhljedsgminetytbnahatbyaahdcxkkguwsvyimjkvwteytwztyswvendtpmncpasfrrylprnhtkblndrgrmkoyjtbkrpamtaaddyoeadlocsdyykaeykaeykadykaocyemrewytyaycyhkrpnddrtaadeetaadmetaadnytaaddloxaxhdclaohnhffmvsbndslrfgclpfjejyatbdpebacnzokotofxntaoemvskpaowmryfnotfgaahdcxdlnbvecentssfsssgylnhkrstoytecrdlyadrekirfaybglahltalsrfcaeerobwamtaaddyoeadlocsdyykaeykaeykaoykaocyemrewytyaycyhkrpnddrtaadeetaadnltaaddloxaxhdclaorkrhkeytwsoykorletwstbwycagtbsotmeptjkesgwrfcmveskvdmngujzttgtdpaahdcxgrfgmuvyylmwcxjtttechplslgoegagaptdniatidmhdmebdwfryfsnsdkcplyvaamtaaddyoeadlncshfykaeykaeykaocyemrewytyaycytostatbngmdavolk";

    fn account(kind: Kind, network: Network) -> Account {
        let seed = Seed::new(&MNEMONIC.parse().unwrap(), "");
        Account::from_seed(&seed, network, kind, 0).unwrap()
    }

    /// An output as the vector writes it, from its key, chain code and parent fingerprint.
    fn vector_output(
        script: &str,
        purpose: &str,
        key: &str,
        chain_code: &str,
        parent: &str,
    ) -> String {
        // The key, its chain code, its path 86h/0h/0h (or 84h…) from the master 37b5eed4, and its
        // parent's fingerprint.
        format!(
            "d90134{script}d9012fa4035821{key}045820{chain_code}06d90130a2018618{purpose}f500f500f5021a37b5eed4081a{parent}"
        )
        .to_lowercase()
    }

    #[test]
    fn segwit_and_taproot_accounts_encode_as_the_vectors_do() {
        let wpkh = vector_output(
            "d90194",
            "54",
            "03FD433450B6924B4F7EFDD5D1ED017D364BE95AB2B592DC8BDDB3B00C1C24F63F",
            "72EDE7334D5ACF91C6FDA622C205199C595A31F9218ED30792D301D5EE9E3A88",
            "0D5DE1D7",
        );
        let tr = vector_output(
            "d90199",
            "56",
            "02BBB97CF9EFA176B738EFD6EE1D4D0FA391A973394FBC16E4C5E78E536CD14D2D",
            "4B4693E1F794206ED1355B838DA24949A92B63D02E58910BF3BD3D9C242281E6",
            "CEC7070C",
        );
        let ours = |kind| crypto_output(&account(kind, Network::Bitcoin)).to_lower_hex_string();
        assert_eq!(ours(Kind::SegwitV0), wpkh);
        assert_eq!(ours(Kind::Taproot), tr);
        // And so they are within the vector's whole account, as its UR has it.
        let (_, cbor) = ::ur::ur::decode(UR).unwrap();
        let whole = cbor.to_lower_hex_string();
        assert!(whole.starts_with("a2011a37b5eed40287"), "{whole}");
        assert!(whole.contains(&wpkh) && whole.contains(&tr));
    }

    #[test]
    fn an_account_is_one_ur_with_its_fingerprint_and_its_network() {
        let ur = account_ur(&account(Kind::Taproot, Network::Bitcoin));
        assert!(ur.starts_with("UR:CRYPTO-ACCOUNT/"));
        let (_, cbor) = ::ur::ur::decode(&ur.to_lowercase()).unwrap();
        let expected = account(Kind::Taproot, Network::Bitcoin);
        assert_eq!(cbor[..8], Vec::from_hex("a2011a37b5eed402").unwrap()[..]);
        assert_eq!(cbor[8], 0x81, "one output");
        assert!(cbor.ends_with(&crypto_output(&expected)));
        // A test network's key says so.
        let testnet = crypto_output(&account(Kind::SegwitV0, Network::Testnet));
        assert!(testnet.to_lower_hex_string().contains("05d90131a10201"));
        assert!(!crypto_output(&expected).to_lower_hex_string().contains("05d90131"));
        // Short enough for one QR code.
        assert!(crate::qr::Qr::new(&ur).is_ok());
    }
}
