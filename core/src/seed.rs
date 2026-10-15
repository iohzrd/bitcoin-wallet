//! The one secret: a BIP39 mnemonic and its optional passphrase, stretched into the 64-byte seed
//! every key derives from.

use bip39::Mnemonic;
use bitcoin::NetworkKind;
use bitcoin::bip32::{Fingerprint, Xpriv};
use bitcoin::secp256k1::{Secp256k1, Signing};
use zeroize::Zeroizing;

/// The BIP32 seed, wiped from memory when dropped. Keys derived from it are copied out by
/// `bitcoin`'s types, which do not wipe themselves; the signer keeps them in scope only for as
/// long as it signs.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    /// The seed of `mnemonic` under `passphrase`, BIP39's "25th word" (empty for none). Every
    /// passphrase opens a valid wallet of its own, so a mistyped one is caught only by comparing
    /// the fingerprint with the one written down beside the words.
    pub fn new(mnemonic: &Mnemonic, passphrase: &str) -> Seed {
        Seed(Zeroizing::new(mnemonic.to_seed(passphrase)))
    }

    /// The BIP32 master key. Its network decides only how its extended keys are encoded (xprv or
    /// tprv), not which keys derive from it.
    pub fn master(&self, network: impl Into<NetworkKind>) -> Xpriv {
        // Fails only when the seed's HMAC is not a valid secret key, with odds of about 2^-127.
        Xpriv::new_master(network, self.0.as_slice()).expect("the seed makes a valid master key")
    }

    /// The master key's fingerprint, which identifies the seed (and passphrase) in descriptors
    /// and PSBTs without revealing it.
    pub fn fingerprint<C: Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.master(NetworkKind::Main).fingerprint(secp)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::str::FromStr;

    /// The mnemonic of the BIP84 and BIP86 test vectors.
    pub(crate) const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                      abandon abandon abandon abandon about";

    pub(crate) fn abandon(passphrase: &str) -> Seed {
        Seed::new(&Mnemonic::parse(ABANDON).unwrap(), passphrase)
    }

    #[test]
    fn the_master_key_is_bip86s_root_key() {
        let secp = Secp256k1::signing_only();
        let root = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
        assert_eq!(abandon("").master(NetworkKind::Main), Xpriv::from_str(root).unwrap());
        assert_eq!(abandon("").fingerprint(&secp), Fingerprint::from_str("73c5da0a").unwrap());
    }

    #[test]
    fn a_passphrase_opens_a_different_wallet() {
        let secp = Secp256k1::signing_only();
        assert_ne!(abandon("").fingerprint(&secp), abandon("TREZOR").fingerprint(&secp));
        assert_ne!(abandon("TREZOR").fingerprint(&secp), abandon("trezor").fingerprint(&secp));
    }
}
