//! What the signer shows before it signs, and the signing, for an account of one key or a
//! multisig wallet alike. A PSBT comes from a machine the signer does not trust, so it takes
//! nothing in it on its word: an input is the policy's, and is signed, only when the policy's
//! descriptor at the path the PSBT claims gives the script it spends; an output is change only
//! when the same holds for the script it pays; and the fee is what the spent outputs hold less
//! what the transaction pays, with each amount read from the input's whole previous transaction,
//! which its outpoint commits to, when the PSBT carries it. Where established signers (Coldcard,
//! Ledger, Trezor, Jade, BDK) refuse or warn, this does too; their thresholds are noted where
//! they are used.

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{self, KeySource, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::psbt::{self as bip174, Psbt, PsbtSighashType};
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{self, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{
    Address, Amount, OutPoint, Sequence, SignedAmount, TxOut, Weight, ecdsa, taproot, transaction,
};

use crate::account::Derivation;
use crate::policy::{Policy, Spend};
use crate::seed::Seed;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the PSBT's inputs and outputs do not match its transaction's")]
    Malformed,
    #[error("the transaction's version, {0}, is none of the 1, 2 and 3 the network relays")]
    UnsupportedVersion(i32),
    #[error("inputs {first} and {second} spend the same output")]
    DuplicateInput { first: usize, second: usize },
    #[error("input {input} carries neither the output it spends nor that output's transaction")]
    MissingSpentOutput { input: usize },
    #[error("input {input} carries a previous transaction that is not the one it spends")]
    PreviousTxMismatch { input: usize },
    #[error("input {input} carries a witness script that is not the wallet's")]
    WitnessScriptMismatch { input: usize },
    #[error("input {input} asks for sighash type {sighash}, which the signer does not sign")]
    UnsupportedSighash { input: usize, sighash: PsbtSighashType },
    #[error("an amount is more than there are bitcoin")]
    ExcessiveAmount,
    #[error("the outputs pay more than the inputs spend")]
    NegativeFee,
    #[error("the amounts overflow")]
    AmountOverflow,
    #[error("the seed holds no key of this wallet's (a different passphrase?)")]
    WrongSeed,
    #[error("the signature made for input {input} does not verify; nothing was signed")]
    SignatureCheck { input: usize },
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
    #[error(transparent)]
    SegwitV0Sighash(#[from] sighash::P2wpkhError),
    #[error(transparent)]
    TaprootSighash(#[from] sighash::TaprootError),
    #[error(transparent)]
    InputIndex(#[from] transaction::InputsIndexError),
}

/// How far past the inputs' highest index change may sit before it is flagged: a wallet restored
/// from its seed scans only so far ahead of the last address it finds used. Coldcard's margin.
pub const GAP: u32 = 200;

/// A fee this large a share of what the inputs hold, in percent, is flagged. Coldcard warns at 5%
/// of the outputs (and refuses at 10%); Ledger at 10% of the inputs.
pub const HIGH_FEE_PERCENT: u64 = 5;

/// A fee rate above this, in sat/vB, is flagged whatever its share. Trezor asks for confirmation
/// above 2,000; no transaction has needed 1,000 to confirm in years.
pub const HIGH_FEE_RATE: f64 = 1_000.0;

/// A PSBT as the policy sees it: what the signer shows before it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: Amount,
    /// The signatures each of the policy's inputs takes: 1, or a multisig's threshold.
    pub threshold: usize,
    /// The most the transaction can weigh once signed. It is known when every input is the
    /// account's, as another's input's witness is not.
    pub max_weight: Option<Weight>,
    /// The transaction's nLockTime: the block or the time before which it is not valid, which
    /// Bitcoin Core sets near the chain's tip to discourage fee sniping.
    pub lock_time: LockTime,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub previous_output: OutPoint,
    /// The output the input spends.
    pub spent: TxOut,
    /// The policy's key the input spends, when it is the policy's.
    pub derivation: Option<Derivation>,
    /// The signatures the input carries; `usize::MAX` once it is finalized.
    pub signatures: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub txout: TxOut,
    /// The output's address, unless its script has none (an `OP_RETURN`, say).
    pub address: Option<Address>,
    /// The policy's key the output pays, when it is the policy's: change, or a payment to one of
    /// its own receive addresses.
    pub derivation: Option<Derivation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// Segwit v0 inputs of the policy's whose PSBT carries the outputs they spend but not those
    /// outputs' transactions, so their amounts are the coordinator's word. A segwit v0 signature
    /// commits to its own input's amount alone: a coordinator that understates one input's amount
    /// in one PSBT and another's in a second can combine the signatures of both into a
    /// transaction whose fee the user never saw. It takes two such inputs, so one is not flagged
    /// (as Krux does); taproot signatures commit to every amount.
    UnverifiedAmounts { inputs: Vec<usize> },
    /// An output that names one of the policy's keys at a change or receive path but pays a
    /// script the policy does not: a payment dressed as change, which Coldcard calls fraud. It
    /// is shown as the payment it is.
    FakeChange { output: usize },
    /// An output of the policy's at an index further past its inputs' highest than `GAP`, which a
    /// wallet restored from the seed would not scan far enough to find.
    DistantIndex { output: usize, index: u32 },
    /// A fee of `HIGH_FEE_PERCENT` or more of what the inputs hold, or above `HIGH_FEE_RATE`.
    HighFee,
    /// Inputs that are not the policy's, which it does not sign. Its signatures commit to its own
    /// inputs' amounts only, so what leaves the policy is `Review::net_spent`; the fee is as
    /// good as the others' amounts.
    ForeignInputs { count: usize },
    /// A locktime that does nothing, as every input's sequence is final.
    LocktimeIgnored,
}

impl Review {
    /// The fee rate in sat/vB, at least: the fee over the most the signed transaction can weigh.
    pub fn min_fee_rate(&self) -> Option<f64> {
        let vsize = self.max_weight?.to_vbytes_ceil();
        Some(self.fee.to_sat() as f64 / vsize as f64)
    }

    /// Whether every input carries the signatures it takes, so the transaction can be finalized:
    /// the policy's inputs `threshold` each, and any other one at least one.
    pub fn complete(&self) -> bool {
        (self.inputs.iter()).all(|input| match input.derivation {
            Some(_) => input.signatures >= self.threshold,
            None => input.signatures > 0,
        })
    }

    /// What leaves the policy: what its inputs hold less what its outputs get back. With no other
    /// inputs, that is the payments and the fee.
    pub fn net_spent(&self) -> SignedAmount {
        let ours_in: u64 = (self.inputs.iter())
            .filter(|input| input.derivation.is_some())
            .map(|input| input.spent.value.to_sat())
            .sum();
        let ours_out: u64 = (self.outputs.iter())
            .filter(|output| output.derivation.is_some())
            .map(|output| output.txout.value.to_sat())
            .sum();
        // Every amount is at most 21 million bitcoin, which `review` checks, so neither sum
        // overflows i64 in a transaction the network would accept.
        SignedAmount::from_sat(ours_in as i64 - ours_out as i64)
    }
}

/// The signatures `input` carries, of any kind; `usize::MAX` once it is finalized.
pub fn signatures(input: &bip174::Input) -> usize {
    if is_finalized(input) {
        return usize::MAX;
    }
    input.partial_sigs.len()
        + input.tap_script_sigs.len()
        + usize::from(input.tap_key_sig.is_some())
}

fn is_finalized(input: &bip174::Input) -> bool {
    input.final_script_witness.is_some() || input.final_script_sig.is_some()
}

pub fn review(policy: &dyn Policy, psbt: &Psbt) -> Result<Review, Error> {
    let tx = &psbt.unsigned_tx;
    if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
        return Err(Error::Malformed);
    }
    if !(1..=3).contains(&tx.version.0) {
        return Err(Error::UnsupportedVersion(tx.version.0));
    }
    let mut seen = BTreeMap::new();
    for (index, txin) in tx.input.iter().enumerate() {
        if let Some(first) = seen.insert(txin.previous_output, index) {
            return Err(Error::DuplicateInput { first, second: index });
        }
    }

    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut warnings = Vec::new();
    let mut unverified = Vec::new();
    for (index, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        let spent = spent_output(index, txin.previous_output, input)?;
        let derivation = claimed_keys(&input.bip32_derivation, &input.tap_key_origins)
            .find_map(|source| policy.derivation_of(source, &spent.script_pubkey));
        if let Some(derivation) = derivation {
            let spend = policy.spend(derivation);
            check_sighash(&spend, index, input)?;
            if let Spend::SegwitV0Script(witness_script) = &spend
                && input.witness_script.as_ref().is_some_and(|given| given != witness_script)
            {
                return Err(Error::WitnessScriptMismatch { input: index });
            }
            if spend.is_segwit_v0() && input.non_witness_utxo.is_none() {
                unverified.push(index);
            }
        }
        let signatures = signatures(input);
        inputs.push(Input { previous_output: txin.previous_output, spent, derivation, signatures });
    }
    if unverified.len() > 1 {
        warnings.push(Warning::UnverifiedAmounts { inputs: unverified });
    }
    let others = inputs.iter().filter(|input| input.derivation.is_none()).count();
    if others > 0 {
        warnings.push(Warning::ForeignInputs { count: others });
    }

    let highest_input = inputs.iter().filter_map(|input| input.derivation).map(|d| d.index).max();
    let mut outputs = Vec::with_capacity(tx.output.len());
    for (index, (txout, output)) in tx.output.iter().zip(&psbt.outputs).enumerate() {
        let claimed: Vec<&KeySource> =
            claimed_keys(&output.bip32_derivation, &output.tap_key_origins).collect();
        let derivation =
            claimed.iter().find_map(|source| policy.derivation_of(source, &txout.script_pubkey));
        match (derivation, highest_input) {
            (None, _) if claimed.iter().any(|source| policy.claims(source)) => {
                warnings.push(Warning::FakeChange { output: index });
            }
            (Some(derivation), Some(highest)) if derivation.index > highest.saturating_add(GAP) => {
                warnings.push(Warning::DistantIndex { output: index, index: derivation.index });
            }
            _ => {}
        }
        let address = Address::from_script(&txout.script_pubkey, policy.network()).ok();
        outputs.push(Output { txout: txout.clone(), address, derivation });
    }

    let amounts = inputs.iter().map(|input| input.spent.value);
    let amounts = amounts.chain(outputs.iter().map(|output| output.txout.value));
    if amounts.clone().any(|amount| amount > Amount::MAX_MONEY) {
        return Err(Error::ExcessiveAmount);
    }
    let spent = total(inputs.iter().map(|input| input.spent.value))?;
    let paid = total(outputs.iter().map(|output| output.txout.value))?;
    let fee = spent.checked_sub(paid).ok_or(Error::NegativeFee)?;
    let max_weight = inputs.iter().all(|input| input.derivation.is_some()).then(|| {
        // Unsigned, the transaction has no witness, which its weight counts as having no segwit
        // marker and flag (2 WU) and no witness stack counts (1 WU an input). Signing adds those,
        // and to each input the satisfaction weight, which counts from an empty stack.
        let inputs = inputs.len() as u64;
        tx.weight() + Weight::from_wu(2 + inputs) + policy.max_satisfaction_weight() * inputs
    });
    let lock_time = tx.lock_time;
    if lock_time != LockTime::ZERO && tx.input.iter().all(|txin| txin.sequence == Sequence::MAX) {
        warnings.push(Warning::LocktimeIgnored);
    }
    let threshold = policy.threshold();
    let mut review = Review { inputs, outputs, fee, threshold, max_weight, lock_time, warnings };
    let large_share = fee.to_sat() * 100 >= spent.to_sat() * HIGH_FEE_PERCENT && fee > Amount::ZERO;
    if large_share || review.min_fee_rate().is_some_and(|rate| rate > HIGH_FEE_RATE) {
        review.warnings.push(Warning::HighFee);
    }
    Ok(review)
}

/// Signs every input `review` finds to be the policy's with the key `seed` derives for it, and
/// returns how many it signed. Inputs already finalized are left as they are. `aux_rand` is
/// fresh randomness for BIP340, which mixes it into each taproot signature's nonce to guard the
/// key against side channels; the nonce commits to the key and the message as well, so one draw
/// serves every input. ECDSA nonces are RFC6979's. Each signature is verified once made, as BDK
/// does, against a fault in the signing; if one fails, the PSBT is left unsigned.
pub fn sign(
    policy: &dyn Policy,
    seed: &Seed,
    psbt: &mut Psbt,
    aux_rand: &[u8; 32],
) -> Result<usize, Error> {
    let review = review(policy, psbt)?;
    let ((fingerprint, path), xpub) = policy.signer().ok_or(Error::WrongSeed)?;
    let secp = Secp256k1::new();
    let master = seed.master(policy.network());
    let signer_key = master.derive_priv(&secp, path)?;
    if master.fingerprint(&secp) != *fingerprint || Xpub::from_priv(&secp, &signer_key) != *xpub {
        return Err(Error::WrongSeed);
    }

    let prevouts: Vec<TxOut> = review.inputs.iter().map(|input| input.spent.clone()).collect();
    let mut signed_psbt = psbt.clone();
    let mut sighashes = SighashCache::new(&psbt.unsigned_tx);
    let mut signed = 0;
    for (index, input) in review.inputs.iter().enumerate() {
        let Some(derivation) = input.derivation else { continue };
        if is_finalized(&psbt.inputs[index]) {
            continue;
        }
        let key = signer_key.derive_priv(&secp, &derivation.path())?;
        let psbt_input = &mut signed_psbt.inputs[index];
        let TxOut { value, script_pubkey } = &input.spent;
        let ecdsa_sighash = match policy.spend(derivation) {
            Spend::SegwitV0Key => Some(sighashes.p2wpkh_signature_hash(
                index,
                script_pubkey,
                *value,
                EcdsaSighashType::All,
            )?),
            Spend::SegwitV0Script(witness_script) => {
                let sighash = sighashes.p2wsh_signature_hash(
                    index,
                    &witness_script,
                    *value,
                    EcdsaSighashType::All,
                )?;
                // The finalizer needs it beside the signatures; `review` refused any other.
                psbt_input.witness_script = Some(witness_script);
                Some(sighash)
            }
            Spend::TaprootKey => {
                let sighash_type = psbt_input.taproot_hash_ty().expect("review checked it");
                let prevouts = Prevouts::All(&prevouts);
                let sighash =
                    sighashes.taproot_key_spend_signature_hash(index, &prevouts, sighash_type)?;
                let message = Message::from_digest(sighash.to_byte_array());
                // BIP86's output key is the internal key tweaked with no script tree.
                let keypair = key.to_keypair(&secp).tap_tweak(&secp, None).to_keypair();
                let signature = secp.sign_schnorr_with_aux_rand(&message, &keypair, aux_rand);
                let output_key = keypair.x_only_public_key().0;
                if secp.verify_schnorr(&signature, &message, &output_key).is_err() {
                    return Err(Error::SignatureCheck { input: index });
                }
                psbt_input.tap_key_sig = Some(taproot::Signature { signature, sighash_type });
                None
            }
        };
        if let Some(sighash) = ecdsa_sighash {
            let message = Message::from_digest(sighash.to_byte_array());
            let signature = secp.sign_ecdsa_low_r(&message, &key.private_key);
            let public_key = key.private_key.public_key(&secp);
            if secp.verify_ecdsa(&message, &signature, &public_key).is_err() {
                return Err(Error::SignatureCheck { input: index });
            }
            let sighash_type = EcdsaSighashType::All;
            let signature = ecdsa::Signature { signature, sighash_type };
            psbt_input.partial_sigs.insert(bitcoin::PublicKey::new(public_key), signature);
        }
        signed += 1;
    }
    *psbt = signed_psbt;
    Ok(signed)
}

/// The output an input spends: from its previous transaction when the PSBT carries it, as the
/// outpoint's txid commits to that, and otherwise from its witness UTXO, as nothing commits to it.
fn spent_output(index: usize, outpoint: OutPoint, input: &bip174::Input) -> Result<TxOut, Error> {
    let mismatch = || Error::PreviousTxMismatch { input: index };
    let Some(previous) = &input.non_witness_utxo else {
        return input.witness_utxo.clone().ok_or(Error::MissingSpentOutput { input: index });
    };
    if previous.compute_txid() != outpoint.txid {
        return Err(mismatch());
    }
    let spent = previous.output.get(outpoint.vout as usize).ok_or_else(mismatch)?;
    if input.witness_utxo.as_ref().is_some_and(|witness_utxo| witness_utxo != spent) {
        return Err(mismatch());
    }
    Ok(spent.clone())
}

/// Every key origin an input or output claims, BIP32's and taproot's alike. Which of them, if
/// any, is the account's is for the account's script to decide.
fn claimed_keys<'a>(
    bip32: &'a BTreeMap<secp256k1::PublicKey, KeySource>,
    taproot: &'a BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
) -> impl Iterator<Item = &'a KeySource> {
    bip32.values().chain(taproot.values().map(|(_, source)| source))
}

/// Refuses a sighash type that leaves part of the transaction open: whoever holds a signature
/// made with one can change the inputs or outputs it does not commit to. ALL commits to the
/// whole transaction, as does taproot's DEFAULT, which is what an input with none set gets.
fn check_sighash(spend: &Spend, index: usize, input: &bip174::Input) -> Result<(), Error> {
    let Some(sighash) = input.sighash_type else { return Ok(()) };
    let whole = match spend {
        Spend::SegwitV0Key | Spend::SegwitV0Script(_) => {
            matches!(sighash.ecdsa_hash_ty(), Ok(EcdsaSighashType::All))
        }
        Spend::TaprootKey => {
            matches!(sighash.taproot_hash_ty(), Ok(TapSighashType::Default | TapSighashType::All))
        }
    };
    if whole { Ok(()) } else { Err(Error::UnsupportedSighash { input: index, sighash }) }
}

fn total(mut amounts: impl Iterator<Item = Amount>) -> Result<Amount, Error> {
    amounts
        .try_fold(Amount::ZERO, |sum, amount| sum.checked_add(amount))
        .ok_or(Error::AmountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Kind};
    use crate::seed::tests::abandon;
    use crate::testing::{
        AUX_RAND, finalize, finalize_and_verify, funding, spend, verify_with_core,
    };
    use bitcoin::{Network, ScriptBuf};
    use std::str::FromStr;

    fn account(kind: Kind) -> Account {
        Account::from_seed(&abandon(""), Network::Regtest, kind, 0).unwrap()
    }

    /// A script that is not the account's: another passphrase's first receive address.
    fn someone_else(kind: Kind) -> ScriptBuf {
        let other = Account::from_seed(&abandon("someone else"), Network::Regtest, kind, 0);
        other.unwrap().script_pubkey(Derivation::receive(0))
    }

    /// Two of the account's outputs, a payment to someone else, and change.
    fn payment(kind: Kind) -> (Account, Psbt) {
        let account = account(kind);
        let spends = [Derivation::receive(0), Derivation::change(3)];
        let funding = funding(&[
            (account.script_pubkey(spends[0]), 70_000),
            (account.script_pubkey(spends[1]), 50_000),
        ]);
        let change = Derivation::change(4);
        let outputs = [
            (someone_else(kind), 100_000, None),
            (account.script_pubkey(change), 19_000, Some(change)),
        ];
        let psbt = spend(&account, &funding, &spends.map(Some), &outputs);
        (account, psbt)
    }

    #[test]
    fn a_payment_reviews_as_the_account_sees_it_and_signs_valid_for_core() {
        for kind in [Kind::SegwitV0, Kind::Taproot] {
            let (account, psbt) = payment(kind);
            // It crosses the air gap as base64.
            let mut psbt = Psbt::from_str(&psbt.to_string()).unwrap();

            let review = review(&account, &psbt).unwrap();
            let derivations: Vec<_> = review.inputs.iter().map(|input| input.derivation).collect();
            assert_eq!(derivations, [Some(Derivation::receive(0)), Some(Derivation::change(3))]);
            assert_eq!(review.outputs[0].derivation, None, "the payment");
            assert_eq!(review.outputs[0].txout.value, Amount::from_sat(100_000));
            let address = Address::from_script(&someone_else(kind), Network::Regtest).unwrap();
            assert_eq!(review.outputs[0].address, Some(address));
            assert_eq!(review.outputs[1].derivation, Some(Derivation::change(4)), "the change");
            assert_eq!(review.fee, Amount::from_sat(1_000));
            assert_eq!(review.warnings, []);

            assert_eq!(sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 2);
            let tx = finalize_and_verify(psbt);

            let max_weight = review.max_weight.unwrap();
            assert!(tx.weight() <= max_weight, "{kind:?}: {} > {max_weight}", tx.weight());
            let slack = (max_weight - tx.weight()).to_wu();
            assert!(slack <= 4, "{kind:?}: the estimate is {slack} WU over");
        }
    }

    #[test]
    #[should_panic(expected = "fails Core's checks")]
    fn cores_checks_fail_a_transaction_changed_after_signing() {
        let (account, mut psbt) = payment(Kind::Taproot);
        sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap();
        let (mut tx, spent) = finalize(psbt);
        tx.output[1].value = Amount::from_sat(18_000);
        verify_with_core(&tx, &spent);
    }

    #[test]
    fn a_taproot_input_signs_with_the_sighash_all_its_psbt_asks_for() {
        let (account, mut psbt) = payment(Kind::Taproot);
        for input in &mut psbt.inputs {
            input.sighash_type = Some(TapSighashType::All.into());
        }
        assert_eq!(sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 2);
        let sighash_type = psbt.inputs[0].tap_key_sig.unwrap().sighash_type;
        assert_eq!(sighash_type, TapSighashType::All);
        finalize_and_verify(psbt);
    }

    #[test]
    fn change_that_claims_the_accounts_key_but_pays_another_script_is_a_payment() {
        for kind in [Kind::SegwitV0, Kind::Taproot] {
            let account = account(kind);
            let spends = [Some(Derivation::receive(0))];
            let funding = funding(&[(account.script_pubkey(Derivation::receive(0)), 50_000)]);
            // The coordinator records the account's change key for an output paying someone else.
            let outputs = [(someone_else(kind), 49_000, Some(Derivation::change(0)))];
            let psbt = spend(&account, &funding, &spends, &outputs);
            let review = review(&account, &psbt).unwrap();
            assert_eq!(review.outputs[0].derivation, None);
            assert!(review.outputs[0].address.is_some());
            assert_eq!(review.warnings, [Warning::FakeChange { output: 0 }], "and said so");
        }
    }

    #[test]
    fn only_the_accounts_inputs_are_signed() {
        for kind in [Kind::SegwitV0, Kind::Taproot] {
            let account = account(kind);
            let funding = funding(&[
                (account.script_pubkey(Derivation::receive(0)), 50_000),
                (someone_else(kind), 50_000),
            ]);
            let spends = [Some(Derivation::receive(0)), None];
            let outputs = [(someone_else(kind), 99_000, None)];
            let mut psbt = spend(&account, &funding, &spends, &outputs);
            // Another's input whose sighash type the signer would refuse for its own.
            psbt.inputs[1].sighash_type = Some(PsbtSighashType::from_u32(0x83));

            let review = review(&account, &psbt).unwrap();
            assert_eq!(review.inputs[1].derivation, None);
            assert_eq!(review.max_weight, None, "another's input's witness is unknown");
            assert_eq!(review.min_fee_rate(), None);
            assert_eq!(review.fee, Amount::from_sat(1_000));
            assert_eq!(review.warnings, [Warning::ForeignInputs { count: 1 }]);
            assert_eq!(review.net_spent(), SignedAmount::from_sat(50_000), "this wallet's coin");
            assert_eq!(sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 1);
            assert!(psbt.inputs[1].partial_sigs.is_empty() && psbt.inputs[1].tap_key_sig.is_none());
        }
    }

    #[test]
    fn an_input_key_claimed_under_another_seed_is_not_the_accounts() {
        let (account, mut psbt) = payment(Kind::SegwitV0);
        let (key, (_, path)) = psbt.inputs[0].bip32_derivation.pop_first().unwrap();
        psbt.inputs[0].bip32_derivation.insert(key, ([9; 4].into(), path));
        assert_eq!(review(&account, &psbt).unwrap().inputs[0].derivation, None);
        assert_eq!(sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 1);
    }

    #[test]
    fn another_seed_signs_nothing() {
        let (account, mut psbt) = payment(Kind::Taproot);
        let signed = sign(&account, &abandon("TREZOR"), &mut psbt, &AUX_RAND);
        assert!(matches!(signed, Err(Error::WrongSeed)));
        assert!(psbt.inputs.iter().all(|input| input.tap_key_sig.is_none()));
    }

    #[test]
    fn an_input_must_carry_what_it_spends() {
        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.inputs[1].witness_utxo = None;
        psbt.inputs[1].non_witness_utxo = None;
        let refused = review(&account, &psbt);
        assert!(matches!(refused, Err(Error::MissingSpentOutput { input: 1 })));
    }

    #[test]
    fn an_amount_is_read_from_the_previous_transaction_and_must_agree_with_it() {
        let (account, mut psbt) = payment(Kind::SegwitV0);
        let understated = Amount::from_sat(40_000);
        psbt.inputs[1].witness_utxo.as_mut().unwrap().value = understated;
        let refused = review(&account, &psbt);
        assert!(matches!(refused, Err(Error::PreviousTxMismatch { input: 1 })));

        let other = funding(&[(account.script_pubkey(Derivation::change(3)), 50_000)]);
        psbt.inputs[1].non_witness_utxo = Some(other);
        psbt.inputs[1].witness_utxo = None;
        let refused = review(&account, &psbt);
        assert!(matches!(refused, Err(Error::PreviousTxMismatch { input: 1 })), "another txid");
    }

    #[test]
    fn two_segwit_v0_inputs_without_their_previous_transactions_are_flagged() {
        let (account, mut psbt) = payment(Kind::SegwitV0);
        psbt.inputs[0].non_witness_utxo = None;
        assert_eq!(review(&account, &psbt).unwrap().warnings, [], "one alone cannot be played");
        psbt.inputs[1].non_witness_utxo = None;
        let warnings = review(&account, &psbt).unwrap().warnings;
        assert_eq!(warnings, [Warning::UnverifiedAmounts { inputs: vec![0, 1] }]);

        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.inputs[0].non_witness_utxo = None;
        psbt.inputs[1].non_witness_utxo = None;
        assert_eq!(review(&account, &psbt).unwrap().warnings, [], "taproot commits to them");
    }

    #[test]
    fn transactions_the_network_would_not_take_are_refused() {
        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.unsigned_tx.version = bitcoin::transaction::Version(4);
        assert!(matches!(review(&account, &psbt), Err(Error::UnsupportedVersion(4))));

        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.unsigned_tx.input[1].previous_output = psbt.unsigned_tx.input[0].previous_output;
        let refused = review(&account, &psbt);
        assert!(matches!(refused, Err(Error::DuplicateInput { first: 0, second: 1 })));

        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.unsigned_tx.output[0].value = Amount::MAX_MONEY + Amount::from_sat(1);
        assert!(matches!(review(&account, &psbt), Err(Error::ExcessiveAmount)));
    }

    #[test]
    fn a_high_fee_is_flagged_by_share_or_by_rate() {
        let account = account(Kind::Taproot);
        let small = funding(&[(account.script_pubkey(Derivation::receive(0)), 100_000)]);
        let spends = [Some(Derivation::receive(0))];
        let change = Derivation::change(0);
        let review_of = |kept: u64| {
            let outputs = [(account.script_pubkey(change), kept, Some(change))];
            review(&account, &spend(&account, &small, &spends, &outputs)).unwrap()
        };
        // A consolidation pays no one else, and its fee is still the user's.
        assert_eq!(review_of(99_000).warnings, [], "1%");
        assert_eq!(review_of(94_000).warnings, [Warning::HighFee], "6% of the inputs");
        // 3,000 sat on a 111-vB transaction is 27 sat/vB; 200,000 sat on a huge input set would
        // be a high rate by share alone, so the rate is tested on its own below.
        let review = review_of(99_000);
        assert!(review.min_fee_rate().unwrap() < HIGH_FEE_RATE);

        let big = funding(&[(account.script_pubkey(Derivation::receive(0)), 1_000_000_000)]);
        let outputs = [(account.script_pubkey(change), 1_000_000_000 - 200_000, Some(change))];
        let review = super::review(&account, &spend(&account, &big, &spends, &outputs)).unwrap();
        assert!(review.min_fee_rate().unwrap() > HIGH_FEE_RATE, "0.02% of the inputs");
        assert_eq!(review.warnings, [Warning::HighFee]);
    }

    #[test]
    fn change_far_past_the_inputs_is_flagged() {
        let account = account(Kind::SegwitV0);
        let funding = funding(&[(account.script_pubkey(Derivation::receive(7)), 50_000)]);
        let spends = [Some(Derivation::receive(7))];
        for (index, flagged) in [(7 + GAP, false), (8 + GAP, true), ((1 << 31) - 1, true)] {
            let change = Derivation::change(index);
            let outputs = [(account.script_pubkey(change), 49_000, Some(change))];
            let review = review(&account, &spend(&account, &funding, &spends, &outputs)).unwrap();
            let expected: &[Warning] = match flagged {
                true => &[Warning::DistantIndex { output: 0, index }],
                false => &[],
            };
            assert_eq!(review.warnings, expected, "{index}");
        }
    }

    #[test]
    fn a_locktime_with_every_sequence_final_is_flagged() {
        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.unsigned_tx.lock_time = LockTime::from_height(850_000).unwrap();
        let review = review(&account, &psbt).unwrap();
        assert_eq!(review.lock_time, LockTime::from_height(850_000).unwrap());
        assert_eq!(review.warnings, [], "the inputs signal RBF, which enables it");
        for txin in &mut psbt.unsigned_tx.input {
            txin.sequence = bitcoin::Sequence::MAX;
        }
        assert_eq!(super::review(&account, &psbt).unwrap().warnings, [Warning::LocktimeIgnored]);
    }

    #[test]
    fn a_finalized_input_is_left_as_it_is() {
        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.inputs[0].final_script_witness = Some(bitcoin::Witness::from_slice(&[[1u8; 64]]));
        assert_eq!(sign(&account, &abandon(""), &mut psbt, &AUX_RAND).unwrap(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_none() && psbt.inputs[1].tap_key_sig.is_some());
    }

    #[test]
    fn sighash_types_that_leave_the_transaction_open_are_refused() {
        let segwit_v0 = [EcdsaSighashType::None, EcdsaSighashType::Single]
            .into_iter()
            .chain([EcdsaSighashType::AllPlusAnyoneCanPay])
            .map(|sighash| (Kind::SegwitV0, PsbtSighashType::from(sighash)));
        let taproot = [TapSighashType::None, TapSighashType::SinglePlusAnyoneCanPay]
            .map(|sighash| (Kind::Taproot, PsbtSighashType::from(sighash)));
        for (kind, sighash) in segwit_v0.chain(taproot) {
            let (account, mut psbt) = payment(kind);
            psbt.inputs[1].sighash_type = Some(sighash);
            let refused = sign(&account, &abandon(""), &mut psbt, &AUX_RAND);
            assert!(
                matches!(refused, Err(Error::UnsupportedSighash { input: 1, .. })),
                "{kind:?} {sighash}"
            );
        }
    }

    #[test]
    fn outputs_paying_more_than_the_inputs_hold_are_refused() {
        let (account, mut psbt) = payment(Kind::SegwitV0);
        psbt.unsigned_tx.output[1].value = Amount::from_sat(21_000);
        assert!(matches!(review(&account, &psbt), Err(Error::NegativeFee)));
    }
}
