//! What a PSBT is reviewed and signed against: an account of one key, or a multisig wallet one of
//! whose keys is the seed's. Either is a descriptor with receive and change keychains; this is
//! what review and signing need to know of it.

use bitcoin::bip32::{KeySource, Xpub};
use bitcoin::psbt;
use bitcoin::{Address, Network, Script, ScriptBuf, Weight};

use crate::account::Derivation;

/// How an input of a policy's is spent, which decides how it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spend {
    /// Pay-to-witness-pubkey-hash: an ECDSA signature by the key.
    SegwitV0Key,
    /// Pay-to-witness-script-hash: an ECDSA signature over this witness script by one of its keys.
    SegwitV0Script(ScriptBuf),
    /// A taproot key spend: a Schnorr signature by the key, tweaked with no script tree.
    TaprootKey,
}

impl Spend {
    /// Whether the input's signature commits to its own amount alone, as segwit v0's do.
    pub fn is_segwit_v0(&self) -> bool {
        !matches!(self, Spend::TaprootKey)
    }
}

pub trait Policy {
    fn network(&self) -> Network;

    fn script_pubkey(&self, derivation: Derivation) -> ScriptBuf;

    fn address(&self, derivation: Derivation) -> Address;

    /// Which of the policy's keys `source` names, if paying `script_pubkey` is what deriving the
    /// policy there does. A PSBT's key origins come from a machine the signer does not trust, so a
    /// key is the policy's only when the policy's own descriptor gives back the script.
    fn derivation_of(&self, source: &KeySource, script_pubkey: &Script) -> Option<Derivation>;

    /// Whether `source` names one of the policy's keys at a receive or change path, whatever the
    /// script beside it: an output that does so but is not the policy's is a payment dressed as
    /// change.
    fn claims(&self, source: &KeySource) -> bool;

    /// How an input spending the policy at `derivation` is spent.
    fn spend(&self, derivation: Derivation) -> Spend;

    /// The signatures an input takes: 1, or a multisig's threshold.
    fn threshold(&self) -> usize;

    /// The most an input spending the policy can weigh beyond its weight unsigned: the witness
    /// that signing adds to it.
    fn max_satisfaction_weight(&self) -> Weight;

    /// The seed's key in the policy, by its origin and the xpub there, which signing checks the
    /// seed against; `None` when the policy holds no key of the seed's.
    fn signer(&self) -> Option<(&KeySource, &Xpub)>;

    /// Records in a PSBT input that it spends the policy at `derivation`, as a coordinator does
    /// for the signers to find their keys.
    fn annotate_input(&self, input: &mut psbt::Input, derivation: Derivation);

    /// Records in a PSBT output that it pays the policy at `derivation`, which is how a signer
    /// tells change from a payment.
    fn annotate_output(&self, output: &mut psbt::Output, derivation: Derivation);
}
