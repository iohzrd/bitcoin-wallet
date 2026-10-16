//! A multisig wallet the seed co-signs: `wsh(sortedmulti(k, ...))` (or `multi`) of the keys of
//! several signers, as Sparrow, Nunchuk, Liana and Bitcoin Core write one. The seed's part in it is
//! its BIP48 key, which a coordinator puts in the descriptor beside the others'. Registering the
//! descriptor with the signer is what lets it check a PSBT's change: a change output is the
//! wallet's only when the whole descriptor, every key of it, gives its script, so a coordinator
//! cannot pass off a wallet of its own keys that happens to hold this seed's as this one.

use std::fmt;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::psbt;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Address, Network, Script, ScriptBuf, Weight};
use miniscript::descriptor::{
    DefiniteDescriptorKey, DescriptorPublicKey, DescriptorXKey, Wildcard, WshInner,
};
use miniscript::{Descriptor, Terminal};

use crate::account::{self, Derivation, Keychain, account_key, is_keychain_path, parse_keychains};
use crate::policy::{Policy, Spend};
use crate::seed::Seed;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Descriptor(#[from] miniscript::Error),
    #[error(transparent)]
    Key(#[from] account::Error),
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
    #[error("the wallet supports wsh(sortedmulti(...)) and wsh(multi(...))")]
    UnsupportedScript,
    #[error("this seed holds none of the wallet's keys (a different passphrase?)")]
    NotACosigner,
    #[error("this seed holds {0} of the wallet's keys, which leaves it a wallet of fewer signers")]
    SeveralKeys(usize),
    #[error("the wallet names one key twice")]
    RepeatedKey,
    #[error("the wallet names two keys by one fingerprint, {0}")]
    RepeatedFingerprint(Fingerprint),
    #[error("key {0}'s xpub is not as deep as its path says")]
    KeyDepth(Fingerprint),
}

/// BIP48's script type for pay-to-witness-script-hash: the last step of a cosigner key's path.
const P2WSH: u32 = 2;

/// The key the seed brings to multisig wallets: BIP48's, at `m/48'/coin'/account'/2'` for
/// pay-to-witness-script-hash. `Display` writes it as `[fingerprint/path]xpub`, the form a
/// coordinator puts in a wallet's descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignerKey {
    pub origin: KeySource,
    pub xpub: Xpub,
}

impl CosignerKey {
    pub fn new(seed: &Seed, network: Network, account: u32) -> Result<CosignerKey, bip32::Error> {
        let secp = Secp256k1::signing_only();
        let coin = if network == Network::Bitcoin { 0 } else { 1 };
        let path: DerivationPath = [48, coin, account, P2WSH]
            .into_iter()
            .map(ChildNumber::from_hardened_idx)
            .collect::<Result<Vec<_>, _>>()?
            .into();
        let master = seed.master(network);
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
        Ok(CosignerKey { origin: (master.fingerprint(&secp), path), xpub })
    }
}

impl fmt::Display for CosignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some(self.origin.clone()),
            xkey: self.xpub,
            derivation_path: DerivationPath::master(),
            wildcard: Wildcard::None,
        });
        write!(f, "{key}")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multisig {
    network: Network,
    descriptor: Descriptor<DescriptorPublicKey>,
    /// The descriptor's receive and change branches, in that order.
    keychains: [Descriptor<DescriptorPublicKey>; 2],
    threshold: usize,
    /// Each signer's key: its origin, and its xpub there.
    keys: Vec<(KeySource, Xpub)>,
    /// Which of `keys` is the seed's, once `with_seed` has found it.
    ours: Option<usize>,
}

impl Multisig {
    /// The wallet `descriptor` describes, with or without its checksum: one descriptor with
    /// `<0;1>`, or its receive and change keychains on two lines. Every key must be an xpub with
    /// its origin, so a PSBT can name it.
    pub fn from_descriptor(descriptor: &str, network: Network) -> Result<Multisig, Error> {
        let descriptor = parse_keychains(descriptor)?;
        let Descriptor::Wsh(wsh) = &descriptor else { return Err(Error::UnsupportedScript) };
        let (threshold, keys): (usize, Vec<&DescriptorPublicKey>) = match wsh.as_inner() {
            WshInner::SortedMulti(multi) => (multi.k(), multi.pks().iter().collect()),
            WshInner::Ms(ms) => match ms.as_inner() {
                Terminal::Multi(multi) => (multi.k(), multi.iter().collect()),
                _ => return Err(Error::UnsupportedScript),
            },
        };
        let keys = (keys.into_iter())
            .map(|key| account_key(key, network))
            .collect::<Result<Vec<_>, _>>()?;
        // What Coldcard and BIP-388 check of a wallet before they register it.
        for (index, ((fingerprint, path), xpub)) in keys.iter().enumerate() {
            if usize::from(xpub.depth) != path.len() {
                return Err(Error::KeyDepth(*fingerprint));
            }
            for ((other_fingerprint, _), other) in &keys[..index] {
                if other.public_key == xpub.public_key {
                    return Err(Error::RepeatedKey);
                }
                if other_fingerprint == fingerprint {
                    return Err(Error::RepeatedFingerprint(*fingerprint));
                }
            }
        }
        let keychains = descriptor.clone().into_single_descriptors()?;
        let keychains = keychains.try_into().expect("<0;1> makes two descriptors");
        Ok(Multisig { network, descriptor, keychains, threshold, keys, ours: None })
    }

    /// The wallet as `seed` co-signs it: with the one key of the wallet's that the seed derives.
    /// Each key is tried at its own path whatever fingerprint it is given, so a key of the seed's
    /// passed off under another's fingerprint is found too: a seed that holds two keys of a 2-of-3
    /// signs alone.
    pub fn with_seed(mut self, seed: &Seed) -> Result<Multisig, Error> {
        let secp = Secp256k1::signing_only();
        let master = seed.master(self.network);
        let mut ours = Vec::new();
        for (index, ((_, path), xpub)) in self.keys.iter().enumerate() {
            if Xpub::from_priv(&secp, &master.derive_priv(&secp, path)?) == *xpub {
                ours.push(index);
            }
        }
        match ours[..] {
            [] => Err(Error::NotACosigner),
            [index] if self.keys[index].0.0 == master.fingerprint(&secp) => {
                self.ours = Some(index);
                Ok(self)
            }
            [_] => Err(Error::NotACosigner),
            _ => Err(Error::SeveralKeys(ours.len())),
        }
    }

    pub fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    /// One keychain's descriptor, as wallets that predate multipath descriptors import it.
    pub fn keychain_descriptor(&self, keychain: Keychain) -> &Descriptor<DescriptorPublicKey> {
        &self.keychains[keychain.branch() as usize]
    }

    /// The signatures a spend takes.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Each signer's master key fingerprint, in the descriptor's order.
    pub fn fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.keys.iter().map(|((fingerprint, _), _)| *fingerprint)
    }

    /// Which signer is the seed, by its place among `fingerprints`.
    pub fn ours(&self) -> Option<usize> {
        self.ours
    }

    /// The descriptor's checksum, which tells two wallets apart at a glance.
    pub fn checksum(&self) -> String {
        let descriptor = self.descriptor.to_string();
        descriptor.rsplit('#').next().unwrap_or_default().to_owned()
    }

    /// The witness script of the wallet's output at `derivation`.
    pub fn witness_script(&self, derivation: Derivation) -> ScriptBuf {
        self.definite(derivation).explicit_script().expect("wsh has a witness script")
    }

    fn definite(&self, derivation: Derivation) -> Descriptor<DefiniteDescriptorKey> {
        let keychain = &self.keychains[derivation.keychain.branch() as usize];
        keychain.at_derivation_index(derivation.index).expect("an index below 2^31")
    }

    /// Every signer's public key at `derivation`, with the origin a PSBT names it by.
    fn keys_at(&self, derivation: Derivation) -> Vec<(secp256k1::PublicKey, KeySource)> {
        let secp = Secp256k1::verification_only();
        (self.keys.iter())
            .map(|((fingerprint, path), xpub)| {
                let child = xpub.derive_pub(&secp, &derivation.path()).expect("unhardened");
                (child.public_key, (*fingerprint, path.extend(derivation.path())))
            })
            .collect()
    }
}

impl Policy for Multisig {
    fn network(&self) -> Network {
        self.network
    }

    fn script_pubkey(&self, derivation: Derivation) -> ScriptBuf {
        self.definite(derivation).script_pubkey()
    }

    fn address(&self, derivation: Derivation) -> Address {
        self.definite(derivation).address(self.network).expect("wsh has an address")
    }

    fn derivation_of(&self, source: &KeySource, script_pubkey: &Script) -> Option<Derivation> {
        let (fingerprint, path) = source;
        self.keys.iter().find_map(|((key_fingerprint, key_path), _)| {
            if key_fingerprint != fingerprint {
                return None;
            }
            let rest = path.as_ref().strip_prefix(key_path.as_ref())?;
            let [ChildNumber::Normal { index: branch }, ChildNumber::Normal { index }] = *rest
            else {
                return None;
            };
            let keychain = match branch {
                0 => Keychain::Receive,
                1 => Keychain::Change,
                _ => return None,
            };
            let derivation = Derivation { keychain, index };
            (self.script_pubkey(derivation) == *script_pubkey).then_some(derivation)
        })
    }

    fn claims(&self, source: &KeySource) -> bool {
        self.keys.iter().any(|(origin, _)| is_keychain_path(source, origin))
    }

    fn spend(&self, derivation: Derivation) -> Spend {
        Spend::SegwitV0Script(self.witness_script(derivation))
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn max_satisfaction_weight(&self) -> Weight {
        let any = self.definite(Derivation::receive(0));
        any.max_weight_to_satisfy().expect("a multisig is satisfiable")
    }

    fn signer(&self) -> Option<(&KeySource, &Xpub)> {
        self.ours.map(|index| (&self.keys[index].0, &self.keys[index].1))
    }

    fn annotate_input(&self, input: &mut psbt::Input, derivation: Derivation) {
        input.bip32_derivation.extend(self.keys_at(derivation));
        input.witness_script = Some(self.witness_script(derivation));
    }

    fn annotate_output(&self, output: &mut psbt::Output, derivation: Derivation) {
        output.bip32_derivation.extend(self.keys_at(derivation));
        output.witness_script = Some(self.witness_script(derivation));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::{review, sign};
    use crate::seed::tests::abandon;
    use crate::testing::{AUX_RAND, finalize_and_verify, funding, spend};
    use std::str::FromStr;

    /// The seeds of a 2-of-3: three passphrases of one mnemonic, which are three wallets.
    const SIGNERS: [&str; 3] = ["", "TREZOR", "a third"];

    fn descriptor(signers: &[&str], threshold: usize) -> String {
        let keys: Vec<String> = (signers.iter())
            .map(|passphrase| {
                let key = CosignerKey::new(&abandon(passphrase), Network::Regtest, 0).unwrap();
                format!("{key}/<0;1>/*")
            })
            .collect();
        format!("wsh(sortedmulti({threshold},{}))", keys.join(","))
    }

    /// The 2-of-3 as `passphrase`'s seed co-signs it.
    fn wallet(passphrase: &str) -> Multisig {
        let wallet = Multisig::from_descriptor(&descriptor(&SIGNERS, 2), Network::Regtest).unwrap();
        wallet.with_seed(&abandon(passphrase)).unwrap()
    }

    #[test]
    fn the_cosigner_key_is_bip48s_for_p2wsh() {
        let key = CosignerKey::new(&abandon(""), Network::Bitcoin, 0).unwrap();
        assert_eq!(key.origin.1, DerivationPath::from_str("m/48'/0'/0'/2'").unwrap());
        assert!(key.to_string().starts_with("[73c5da0a/48'/0'/0'/2']xpub"), "{key}");
        let key = CosignerKey::new(&abandon(""), Network::Regtest, 3).unwrap();
        assert!(key.to_string().starts_with("[73c5da0a/48'/1'/3'/2']tpub"), "{key}");
    }

    #[test]
    fn each_seed_finds_its_own_key_and_another_none() {
        for (index, passphrase) in SIGNERS.iter().enumerate() {
            let wallet = wallet(passphrase);
            let fingerprint = abandon(passphrase).fingerprint(&Secp256k1::signing_only());
            let ours = wallet.ours().unwrap();
            assert_eq!(wallet.fingerprints().nth(ours), Some(fingerprint), "{index}");
            assert_eq!((wallet.threshold(), wallet.fingerprints().count()), (2, 3));
        }
        let outsider = Multisig::from_descriptor(&descriptor(&SIGNERS, 2), Network::Regtest);
        let outsider = outsider.unwrap().with_seed(&abandon("an outsider"));
        assert!(matches!(outsider, Err(Error::NotACosigner)));
    }

    #[test]
    fn a_wallet_reads_as_one_descriptor_or_its_two_keychains() {
        let wallet = wallet("");
        let pair = format!(
            "{}\n{}\n",
            wallet.keychain_descriptor(Keychain::Change),
            wallet.keychain_descriptor(Keychain::Receive),
        );
        let read = Multisig::from_descriptor(&pair, Network::Regtest).unwrap();
        assert_eq!(read.with_seed(&abandon("")).unwrap(), wallet);
        let unsorted = descriptor(&SIGNERS, 2).replace("sortedmulti", "multi");
        assert!(Multisig::from_descriptor(&unsorted, Network::Regtest).is_ok());
    }

    #[test]
    fn a_wallet_that_repeats_a_key_or_gives_the_seed_two_is_refused() {
        let key = |passphrase: &str, account: u32| {
            CosignerKey::new(&abandon(passphrase), Network::Regtest, account).unwrap()
        };
        let wallet = |keys: &[String]| {
            let keys: Vec<String> = keys.iter().map(|key| format!("{key}/<0;1>/*")).collect();
            let descriptor = format!("wsh(sortedmulti(2,{}))", keys.join(","));
            Multisig::from_descriptor(&descriptor, Network::Regtest)
        };
        let (ours, theirs) = (key("", 0), key("TREZOR", 0));

        // The same key twice, under another fingerprint the second time.
        let relabeled = format!("[deadbeef/48'/1'/0'/2']{}", theirs.xpub);
        let repeated = wallet(&[ours.to_string(), theirs.to_string(), relabeled]);
        assert!(matches!(repeated, Err(Error::RepeatedKey)));

        // The seed's own keys at two accounts: both under its fingerprint, which is refused, and
        // the second passed off under another's, which the seed still finds.
        let second = key("", 1);
        let doubled = wallet(&[ours.to_string(), theirs.to_string(), second.to_string()]);
        assert!(matches!(doubled, Err(Error::RepeatedFingerprint(_))));
        let disguised = format!("[deadbeef/48'/1'/1'/2']{}", second.xpub);
        let disguised = wallet(&[ours.to_string(), theirs.to_string(), disguised]).unwrap();
        assert!(matches!(disguised.with_seed(&abandon("")), Err(Error::SeveralKeys(2))));

        // An xpub one level below where its path says it is.
        let shallow = format!("[{}/48'/1'/0']{}", ours.origin.0, ours.xpub);
        let shallow = wallet(&[shallow, theirs.to_string(), key("a third", 0).to_string()]);
        assert!(matches!(shallow, Err(Error::KeyDepth(_))));
    }

    #[test]
    fn other_shapes_are_refused() {
        let sorted = descriptor(&SIGNERS, 2);
        let nested = format!("sh({sorted})");
        let refused = |text: &str| Multisig::from_descriptor(text, Network::Regtest);
        assert!(matches!(refused(&nested), Err(Error::UnsupportedScript)));
        let key = CosignerKey::new(&abandon(""), Network::Regtest, 0).unwrap();
        let single = format!("wsh(pk({key}/<0;1>/*))");
        assert!(matches!(refused(&single), Err(Error::UnsupportedScript)));
        let bare_key = sorted.replacen(&format!("[{}/48'/1'/0'/2']", key.origin.0), "", 1);
        assert!(matches!(refused(&bare_key), Err(Error::Key(account::Error::UnsupportedKey))));
        let mainnet = Multisig::from_descriptor(&sorted, Network::Bitcoin);
        assert!(matches!(mainnet, Err(Error::Key(account::Error::NetworkMismatch { .. }))));
    }

    /// The wallet's two outputs, a payment to someone else, and change.
    fn payment(wallet: &Multisig) -> psbt::Psbt {
        let spends = [Derivation::receive(0), Derivation::change(2)];
        let funding = funding(&[
            (wallet.script_pubkey(spends[0]), 70_000),
            (wallet.script_pubkey(spends[1]), 50_000),
        ]);
        let someone = crate::account::Account::from_seed(
            &abandon("someone else"),
            Network::Regtest,
            crate::account::Kind::Taproot,
            0,
        );
        let change = Derivation::change(3);
        let outputs = [
            (someone.unwrap().script_pubkey(Derivation::receive(0)), 100_000, None),
            (wallet.script_pubkey(change), 19_000, Some(change)),
        ];
        spend(wallet, &funding, &spends.map(Some), &outputs)
    }

    #[test]
    fn two_of_three_sign_a_spend_valid_for_core() {
        for second in ["TREZOR", "a third"] {
            let mut psbt = payment(&wallet(""));
            let first = review(&wallet(""), &psbt).unwrap();
            assert_eq!(first.threshold, 2);
            let derivations: Vec<_> = first.inputs.iter().map(|input| input.derivation).collect();
            assert_eq!(derivations, [Some(Derivation::receive(0)), Some(Derivation::change(2))]);
            assert_eq!(first.outputs[1].derivation, Some(Derivation::change(3)), "the change");
            assert_eq!(first.warnings, []);
            assert!(!first.complete());

            assert_eq!(sign(&wallet(""), &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 2);
            let half = review(&wallet(second), &psbt).unwrap();
            assert!(half.inputs.iter().all(|input| input.signatures == 1));
            assert!(!half.complete(), "one signature of two");
            let mut psbt = psbt::Psbt::from_str(&psbt.to_string()).unwrap();
            assert_eq!(sign(&wallet(second), &abandon(second), &mut psbt, &AUX_RAND).unwrap(), 2);
            assert!(review(&wallet(""), &psbt).unwrap().complete());

            let tx = finalize_and_verify(psbt);
            let max_weight = first.max_weight.unwrap();
            assert!(tx.weight() <= max_weight && (max_weight - tx.weight()).to_wu() <= 8);
        }
    }

    #[test]
    fn change_to_another_wallet_holding_this_seeds_key_is_a_payment() {
        let wallet = wallet("");
        let mut psbt = payment(&wallet);
        // A wallet of the coordinator's own: this seed's key beside two keys it holds.
        let theirs =
            Multisig::from_descriptor(&descriptor(&["", "evil 1", "evil 2"], 2), Network::Regtest);
        let theirs = theirs.unwrap();
        let change = Derivation::change(3);
        psbt.unsigned_tx.output[1].script_pubkey = theirs.script_pubkey(change);
        psbt.outputs[1] = Default::default();
        theirs.annotate_output(&mut psbt.outputs[1], change);
        let review = review(&wallet, &psbt).unwrap();
        assert_eq!(review.outputs[1].derivation, None, "shown as a payment, with its address");
        assert!(review.outputs[1].address.is_some());
        let fake = crate::psbt::Warning::FakeChange { output: 1 };
        assert_eq!(review.warnings, [fake], "and said so");
    }

    #[test]
    fn a_single_key_account_of_the_same_seed_owns_none_of_it() {
        let account = crate::account::Account::from_seed(
            &abandon(""),
            Network::Regtest,
            crate::account::Kind::SegwitV0,
            0,
        )
        .unwrap();
        let review = review(&account, &payment(&wallet(""))).unwrap();
        assert!(review.inputs.iter().all(|input| input.derivation.is_none()));
        assert!(review.outputs.iter().all(|output| output.derivation.is_none()));
    }

    #[test]
    fn a_watch_only_wallet_signs_nothing() {
        let watching =
            Multisig::from_descriptor(&descriptor(&SIGNERS, 2), Network::Regtest).unwrap();
        let mut psbt = payment(&watching);
        let signed = sign(&watching, &abandon(""), &mut psbt, &AUX_RAND);
        assert!(matches!(signed, Err(crate::psbt::Error::WrongSeed)));
    }
}
