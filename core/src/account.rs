//! An account: the key at `m/purpose'/coin'/account'` under a seed, written as the descriptor
//! `wpkh([fingerprint/path]xpub/<0;1>/*)` (BIP84) or `tr([fingerprint/path]xpub/<0;1>/*)` (BIP86),
//! whose two branches are the receive and change keychains. The descriptor is what crosses the
//! air gap from the signer to the watch-only wallet, and both derive every address from it, so
//! the address one shows and the change the other recognizes are the same.

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::psbt;
use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::{Address, Network, NetworkKind, Script, ScriptBuf, Weight};
use miniscript::descriptor::{
    DefiniteDescriptorKey, DerivPaths, Descriptor, DescriptorMultiXKey, DescriptorPublicKey,
    Wildcard,
};

use crate::policy::{Policy, Spend};
use crate::seed::Seed;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Descriptor(#[from] miniscript::Error),
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
    #[error("the wallet supports wpkh(KEY), and tr(KEY) with no script tree")]
    UnsupportedScript,
    #[error("the account key must be an xpub with its origin, ending in /<0;1>/*")]
    UnsupportedKey,
    #[error("the xpub is for {xpub:?} but the wallet is on {network}")]
    NetworkMismatch { xpub: NetworkKind, network: Network },
    #[error(
        "two descriptors must be one account's receive and change, the same but for /0/* and /1/*"
    )]
    NotKeychains,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// BIP84: pay-to-witness-pubkey-hash, `bc1q…` addresses.
    SegwitV0,
    /// BIP86: a taproot key spend with no script tree, `bc1p…` addresses.
    Taproot,
}

impl Kind {
    /// The BIP43 purpose at the head of the account's path.
    pub fn purpose(self) -> u32 {
        match self {
            Kind::SegwitV0 => 84,
            Kind::Taproot => 86,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Keychain {
    Receive,
    Change,
}

impl Keychain {
    /// The keychain's branch under the account key: the `0` or the `1` of `<0;1>`.
    pub fn branch(self) -> u32 {
        self as u32
    }

    fn from_branch(branch: u32) -> Option<Keychain> {
        match branch {
            0 => Some(Keychain::Receive),
            1 => Some(Keychain::Change),
            _ => None,
        }
    }
}

/// One of the account's keys. The index is below 2^31, BIP32's unhardened range; the methods
/// that take a `Derivation` panic on one that is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Derivation {
    pub keychain: Keychain,
    pub index: u32,
}

impl Derivation {
    pub fn receive(index: u32) -> Derivation {
        Derivation { keychain: Keychain::Receive, index }
    }

    pub fn change(index: u32) -> Derivation {
        Derivation { keychain: Keychain::Change, index }
    }

    /// The key's path below the account key.
    pub fn path(self) -> [ChildNumber; 2] {
        let normal = |i| ChildNumber::from_normal_idx(i).expect("an index below 2^31");
        [normal(self.keychain.branch()), normal(self.index)]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    network: Network,
    kind: Kind,
    origin: KeySource,
    xpub: Xpub,
    descriptor: Descriptor<DescriptorPublicKey>,
    /// The descriptor's receive and change branches, in that order.
    keychains: [Descriptor<DescriptorPublicKey>; 2],
}

impl Account {
    /// Account number `account` of `kind` under `seed`, at `m/purpose'/coin'/account'` with coin
    /// type 0 on mainnet and 1 on every test network, as BIP44 assigns them.
    pub fn from_seed(
        seed: &Seed,
        network: Network,
        kind: Kind,
        account: u32,
    ) -> Result<Account, Error> {
        let secp = Secp256k1::signing_only();
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(kind.purpose())?,
            ChildNumber::from_hardened_idx(coin)?,
            ChildNumber::from_hardened_idx(account)?,
        ]);
        let master = seed.master(network);
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
        let key = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((master.fingerprint(&secp), path)),
            xkey: xpub,
            derivation_paths: receive_and_change(),
            wildcard: Wildcard::Unhardened,
        });
        let descriptor = match kind {
            Kind::SegwitV0 => Descriptor::new_wpkh(key)?,
            Kind::Taproot => Descriptor::new_tr(key, None)?,
        };
        Account::from_parsed(descriptor, network)
    }

    /// The account a descriptor describes, as another wallet or this one's signer exports it,
    /// with or without its checksum. The descriptor's shape is the one `from_seed` makes, but its
    /// path is not checked against BIP84's or BIP86's: an account another wallet made at a path
    /// of its own still derives and signs the same way.
    pub fn from_descriptor(descriptor: &str, network: Network) -> Result<Account, Error> {
        Account::from_parsed(parse_keychains(descriptor)?, network)
    }

    fn from_parsed(
        descriptor: Descriptor<DescriptorPublicKey>,
        network: Network,
    ) -> Result<Account, Error> {
        let (kind, key) = match &descriptor {
            Descriptor::Wpkh(wpkh) => (Kind::SegwitV0, wpkh.as_inner()),
            Descriptor::Tr(tr) if tr.tap_tree().is_none() => (Kind::Taproot, tr.internal_key()),
            _ => return Err(Error::UnsupportedScript),
        };
        let (origin, xpub) = account_key(key, network)?;
        let keychains = descriptor.clone().into_single_descriptors()?;
        let keychains = keychains.try_into().expect("<0;1> makes two descriptors");
        Ok(Account { network, kind, origin, xpub, descriptor, keychains })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The fingerprint of the master key the account derives from.
    pub fn fingerprint(&self) -> Fingerprint {
        self.origin.0
    }

    /// The account key's path from the master key.
    pub fn path(&self) -> &DerivationPath {
        &self.origin.1
    }

    pub fn xpub(&self) -> &Xpub {
        &self.xpub
    }

    /// The account's descriptor, which `Display` writes with its checksum.
    pub fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    /// One keychain's descriptor: the account's, with `<0;1>` resolved to the keychain's branch.
    /// Wallets that predate multipath descriptors, Bitcoin Core before 29 among them, import an
    /// account as these two.
    pub fn keychain_descriptor(&self, keychain: Keychain) -> &Descriptor<DescriptorPublicKey> {
        &self.keychains[keychain.branch() as usize]
    }

    pub fn script_pubkey(&self, derivation: Derivation) -> ScriptBuf {
        self.definite(derivation).script_pubkey()
    }

    pub fn address(&self, derivation: Derivation) -> Address {
        self.definite(derivation).address(self.network).expect("wpkh and tr have addresses")
    }

    /// The most an input spending one of the account's outputs can weigh beyond its weight
    /// unsigned: the witness that signing adds to it.
    pub fn max_satisfaction_weight(&self) -> Weight {
        let any = self.definite(Derivation::receive(0));
        any.max_weight_to_satisfy().expect("wpkh and tr are satisfiable")
    }

    /// The fingerprint and full path a PSBT names the key at `derivation` by.
    pub fn key_source(&self, derivation: Derivation) -> KeySource {
        (self.fingerprint(), self.path().extend(derivation.path()))
    }

    /// Which of the account's keys `source` names, if paying `script_pubkey` is what that key
    /// does. A PSBT's key origins come from a machine the signer does not trust, so a key is the
    /// account's only when deriving it from the account at the claimed path gives back the script
    /// the input spends or the output pays.
    pub fn derivation_of(&self, source: &KeySource, script_pubkey: &Script) -> Option<Derivation> {
        let (fingerprint, path) = source;
        if *fingerprint != self.fingerprint() {
            return None;
        }
        let derivation = self.derivation_at(path)?;
        (self.script_pubkey(derivation) == *script_pubkey).then_some(derivation)
    }

    /// Which of the account's keys the full path `path` names: the account's own path, then a
    /// receive or change branch and an index.
    pub fn derivation_at(&self, path: &DerivationPath) -> Option<Derivation> {
        let rest = path.as_ref().strip_prefix(self.path().as_ref())?;
        let [ChildNumber::Normal { index: branch }, ChildNumber::Normal { index }] = *rest else {
            return None;
        };
        Some(Derivation { keychain: Keychain::from_branch(branch)?, index })
    }

    /// Which of the account's first `within` receive and change keys pays `script_pubkey`.
    pub fn find(&self, script_pubkey: &Script, within: u32) -> Option<Derivation> {
        (0..within)
            .flat_map(|index| [Derivation::receive(index), Derivation::change(index)])
            .find(|derivation| self.script_pubkey(*derivation) == *script_pubkey)
    }

    /// Records in a PSBT input that it spends the key at `derivation`, which is how the signer
    /// finds the key to sign it with.
    pub fn annotate_input(&self, input: &mut psbt::Input, derivation: Derivation) {
        let key = self.public_key(&Secp256k1::verification_only(), derivation);
        let source = self.key_source(derivation);
        match self.kind {
            Kind::SegwitV0 => {
                input.bip32_derivation.insert(key, source);
            }
            Kind::Taproot => {
                let key = key.x_only_public_key().0;
                input.tap_internal_key = Some(key);
                input.tap_key_origins.insert(key, (Vec::new(), source));
            }
        }
    }

    /// Records in a PSBT output that it pays the key at `derivation`, which is how the signer
    /// tells change from a payment.
    pub fn annotate_output(&self, output: &mut psbt::Output, derivation: Derivation) {
        let key = self.public_key(&Secp256k1::verification_only(), derivation);
        let source = self.key_source(derivation);
        match self.kind {
            Kind::SegwitV0 => {
                output.bip32_derivation.insert(key, source);
            }
            Kind::Taproot => {
                let key = key.x_only_public_key().0;
                output.tap_internal_key = Some(key);
                output.tap_key_origins.insert(key, (Vec::new(), source));
            }
        }
    }

    fn public_key<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        derivation: Derivation,
    ) -> secp256k1::PublicKey {
        self.xpub.derive_pub(secp, &derivation.path()).expect("unhardened derivation").public_key
    }

    fn definite(&self, derivation: Derivation) -> Descriptor<DefiniteDescriptorKey> {
        let keychain = &self.keychains[derivation.keychain.branch() as usize];
        keychain.at_derivation_index(derivation.index).expect("an index below 2^31")
    }
}

/// The descriptor `text` holds: one with `<0;1>` for its receive and change keychains, or, as
/// Bitcoin Core's `listdescriptors` and wallets that predate multipath descriptors write an
/// account, two on lines of their own, one ending its keys in `/0/*` and the other the same but
/// for `/1/*`, which this makes the one.
pub(crate) fn parse_keychains(text: &str) -> Result<Descriptor<DescriptorPublicKey>, Error> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    let (receive, change) = match lines[..] {
        [one] => return Ok(one.parse()?),
        [first, second] => (first, second),
        _ => return Err(Error::NotKeychains),
    };
    // Each parsed alone first, so its checksum is checked before the rewriting drops it.
    for line in [receive, change] {
        line.parse::<Descriptor<DescriptorPublicKey>>()?;
    }
    let bare = |line: &str| line.split('#').next().unwrap_or_default().to_owned();
    let (first, second) = (bare(receive), bare(change));
    let receive = [(&first, &second), (&second, &first)]
        .into_iter()
        .find(|(receive, change)| {
            receive.contains("/0/*") && receive.replace("/0/*", "/1/*") == **change
        })
        .map(|(receive, _)| receive)
        .ok_or(Error::NotKeychains)?;
    Ok(receive.replace("/0/*", "/<0;1>/*").parse()?)
}

/// The origin and xpub of an account's key in a descriptor: an xpub with its origin, ending in
/// `/<0;1>/*` for the receive and change keychains, on `network`.
pub(crate) fn account_key(
    key: &DescriptorPublicKey,
    network: Network,
) -> Result<(KeySource, Xpub), Error> {
    let DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin: Some(origin),
        xkey,
        derivation_paths,
        wildcard: Wildcard::Unhardened,
    }) = key
    else {
        return Err(Error::UnsupportedKey);
    };
    if *derivation_paths != receive_and_change() {
        return Err(Error::UnsupportedKey);
    }
    if xkey.network != NetworkKind::from(network) {
        return Err(Error::NetworkMismatch { xpub: xkey.network, network });
    }
    Ok((origin.clone(), *xkey))
}

impl Policy for Account {
    fn network(&self) -> Network {
        self.network
    }

    fn script_pubkey(&self, derivation: Derivation) -> ScriptBuf {
        Account::script_pubkey(self, derivation)
    }

    fn address(&self, derivation: Derivation) -> Address {
        Account::address(self, derivation)
    }

    fn derivation_of(&self, source: &KeySource, script_pubkey: &Script) -> Option<Derivation> {
        Account::derivation_of(self, source, script_pubkey)
    }

    fn claims(&self, source: &KeySource) -> bool {
        is_keychain_path(source, &self.origin)
    }

    fn spend(&self, _: Derivation) -> Spend {
        match self.kind {
            Kind::SegwitV0 => Spend::SegwitV0Key,
            Kind::Taproot => Spend::TaprootKey,
        }
    }

    fn threshold(&self) -> usize {
        1
    }

    fn max_satisfaction_weight(&self) -> Weight {
        Account::max_satisfaction_weight(self)
    }

    fn signer(&self) -> Option<(&KeySource, &Xpub)> {
        Some((&self.origin, &self.xpub))
    }

    fn annotate_input(&self, input: &mut psbt::Input, derivation: Derivation) {
        Account::annotate_input(self, input, derivation);
    }

    fn annotate_output(&self, output: &mut psbt::Output, derivation: Derivation) {
        Account::annotate_output(self, output, derivation);
    }
}

/// Whether `source` names the key at `origin` on its receive or change branch: the same master
/// fingerprint, and the origin's path followed by 0 or 1 and an index.
pub(crate) fn is_keychain_path(source: &KeySource, origin: &KeySource) -> bool {
    let ((fingerprint, path), (key_fingerprint, key_path)) = (source, origin);
    fingerprint == key_fingerprint
        && path.as_ref().strip_prefix(key_path.as_ref()).is_some_and(|rest| {
            matches!(rest, [ChildNumber::Normal { index: 0 | 1 }, ChildNumber::Normal { .. }])
        })
}

/// `<0;1>`: the receive and change branches.
fn receive_and_change() -> DerivPaths {
    let branch =
        |keychain: Keychain| DerivationPath::from(vec![ChildNumber::from(keychain.branch())]);
    DerivPaths::new(vec![branch(Keychain::Receive), branch(Keychain::Change)]).expect("two paths")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::tests::abandon;
    use std::str::FromStr;

    /// A BIP84 `zpub` as the `xpub` a descriptor writes: the same key under the version bytes of
    /// BIP32's mainnet public keys.
    fn zpub_to_xpub(zpub: &str) -> Xpub {
        let mut data = bitcoin::base58::decode_check(zpub).unwrap();
        data[..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        Xpub::decode(&data).unwrap()
    }

    #[test]
    fn a_segwit_v0_account_derives_bip84s_test_vectors() {
        let account =
            Account::from_seed(&abandon(""), Network::Bitcoin, Kind::SegwitV0, 0).unwrap();
        assert_eq!(account.fingerprint(), Fingerprint::from_str("73c5da0a").unwrap());
        assert_eq!(*account.path(), DerivationPath::from_str("m/84'/0'/0'").unwrap());
        let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        assert_eq!(*account.xpub(), zpub_to_xpub(zpub));
        let address = |d| account.address(d).to_string();
        assert_eq!(address(Derivation::receive(0)), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(address(Derivation::receive(1)), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(address(Derivation::change(0)), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");

        let mut input = psbt::Input::default();
        account.annotate_input(&mut input, Derivation::receive(0));
        let pubkey = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
        let (key, source) = input.bip32_derivation.pop_first().unwrap();
        assert_eq!(key, secp256k1::PublicKey::from_str(pubkey).unwrap());
        assert_eq!(source, account.key_source(Derivation::receive(0)));
        assert_eq!(source.1, DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap());
    }

    #[test]
    fn a_taproot_account_derives_bip86s_test_vectors() {
        let account = Account::from_seed(&abandon(""), Network::Bitcoin, Kind::Taproot, 0).unwrap();
        assert_eq!(*account.path(), DerivationPath::from_str("m/86'/0'/0'").unwrap());
        let xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
        assert_eq!(*account.xpub(), Xpub::from_str(xpub).unwrap());
        let vectors = [
            (
                Derivation::receive(0),
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (
                Derivation::receive(1),
                "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
                "5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
            ),
            (
                Derivation::change(0),
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
                "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            ),
        ];
        for (derivation, internal_key, script_pubkey, address) in vectors {
            assert_eq!(account.script_pubkey(derivation).to_hex_string(), script_pubkey);
            assert_eq!(account.address(derivation).to_string(), address);
            let mut output = psbt::Output::default();
            account.annotate_output(&mut output, derivation);
            let key = output.tap_internal_key.unwrap();
            assert_eq!(key.to_string(), internal_key);
            assert_eq!(output.tap_key_origins[&key], (vec![], account.key_source(derivation)));
        }
    }

    #[test]
    fn test_networks_use_coin_type_1() {
        let account =
            Account::from_seed(&abandon(""), Network::Regtest, Kind::SegwitV0, 3).unwrap();
        assert_eq!(*account.path(), DerivationPath::from_str("m/84'/1'/3'").unwrap());
        assert!(account.xpub().to_string().starts_with("tpub"));
        assert!(account.address(Derivation::receive(0)).to_string().starts_with("bcrt1q"));
    }

    #[test]
    fn an_exported_descriptor_imports_as_the_same_account() {
        for kind in [Kind::SegwitV0, Kind::Taproot] {
            let account = Account::from_seed(&abandon(""), Network::Signet, kind, 0).unwrap();
            let exported = account.descriptor().to_string();
            assert!(
                exported.contains("[73c5da0a/") && exported.contains("/<0;1>/*)#"),
                "{exported}"
            );
            assert_eq!(Account::from_descriptor(&exported, Network::Signet).unwrap(), account);
            let unchecked = exported.split('#').next().unwrap();
            assert_eq!(Account::from_descriptor(unchecked, Network::Signet).unwrap(), account);
        }
    }

    #[test]
    fn an_account_reads_as_its_two_keychains_as_bitcoin_core_lists_them() {
        let account = Account::from_seed(&abandon(""), Network::Regtest, Kind::Taproot, 0).unwrap();
        let receive = account.keychain_descriptor(Keychain::Receive).to_string();
        let change = account.keychain_descriptor(Keychain::Change).to_string();
        for pair in [format!("{receive}\n{change}"), format!("{change}\n\n{receive}\n")] {
            assert_eq!(Account::from_descriptor(&pair, Network::Regtest).unwrap(), account);
        }
        let other = Account::from_seed(&abandon("x"), Network::Regtest, Kind::Taproot, 0).unwrap();
        let mismatched = format!("{receive}\n{}", other.keychain_descriptor(Keychain::Change));
        let refused = Account::from_descriptor(&mismatched, Network::Regtest);
        assert!(matches!(refused, Err(Error::NotKeychains)));
        let mangled = format!("{receive}\n{}", change.replace('#', "#x"));
        assert!(Account::from_descriptor(&mangled, Network::Regtest).is_err(), "a bad checksum");
    }

    #[test]
    fn descriptors_of_other_shapes_are_refused() {
        let account =
            Account::from_seed(&abandon(""), Network::Bitcoin, Kind::SegwitV0, 0).unwrap();
        let exported = account.descriptor().to_string();
        let exported = exported.split('#').next().unwrap();
        let key = exported.strip_prefix("wpkh(").unwrap().strip_suffix(')').unwrap();
        let xpub = account.xpub();
        let refused = |descriptor: &str| Account::from_descriptor(descriptor, Network::Bitcoin);
        assert!(matches!(refused(&format!("sh(wpkh({key}))")), Err(Error::UnsupportedScript)));
        assert!(matches!(refused(&format!("pkh({key})")), Err(Error::UnsupportedScript)));
        let tree = "pk(02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443)";
        let with_tree = format!("tr({key},{tree})");
        assert!(matches!(refused(&with_tree), Err(Error::UnsupportedScript)));
        assert!(matches!(refused(&format!("wpkh({xpub}/<0;1>/*)")), Err(Error::UnsupportedKey)));
        let one_branch = key.replace("<0;1>", "0");
        assert!(matches!(refused(&format!("wpkh({one_branch})")), Err(Error::UnsupportedKey)));
        let swapped = key.replace("<0;1>", "<1;0>");
        assert!(matches!(refused(&format!("wpkh({swapped})")), Err(Error::UnsupportedKey)));
        let hardened = key.replace("/*", "/*'");
        assert!(refused(&format!("wpkh({hardened})")).is_err(), "a hardened wildcard");
        let mainnet = Account::from_descriptor(exported, Network::Testnet);
        assert!(matches!(mainnet, Err(Error::NetworkMismatch { .. })));
    }

    #[test]
    fn a_key_is_the_accounts_only_if_it_derives_the_script() {
        let account =
            Account::from_seed(&abandon(""), Network::Bitcoin, Kind::SegwitV0, 0).unwrap();
        let change = Derivation::change(7);
        let script = account.script_pubkey(change);
        let source = account.key_source(change);
        assert_eq!(account.derivation_of(&source, &script), Some(change));

        let other_script = account.script_pubkey(Derivation::change(8));
        assert_eq!(account.derivation_of(&source, &other_script), None, "a different script");
        let other_seed = (Fingerprint::from([1, 2, 3, 4]), source.1.clone());
        assert_eq!(account.derivation_of(&other_seed, &script), None, "another seed's fingerprint");
        let other_account = DerivationPath::from_str("m/84'/0'/1'/1/7").unwrap();
        let other_account = (account.fingerprint(), other_account);
        assert_eq!(account.derivation_of(&other_account, &script), None, "another account");
        let third_branch = DerivationPath::from_str("m/84'/0'/0'/2/7").unwrap();
        let third_branch = (account.fingerprint(), third_branch);
        assert_eq!(account.derivation_of(&third_branch, &script), None, "not receive or change");
        let too_deep = (account.fingerprint(), source.1.child(ChildNumber::from(0)));
        assert_eq!(account.derivation_of(&too_deep, &script), None, "below a key");
    }
}
