//! What the signer shows before it signs, and the signing. A PSBT comes from a machine the signer
//! does not trust, so it takes nothing in it on its word: an input is the account's, and is
//! signed, only when the account's descriptor at the path the PSBT claims gives the script it
//! spends; an output is change only when the same holds for the script it pays; and the fee is
//! what the spent outputs hold less what the transaction pays, with each amount read from the
//! input's whole previous transaction, which its outpoint commits to, when the PSBT carries it.

use std::collections::BTreeMap;

use bitcoin::bip32::{self, KeySource, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::psbt::{self as bip174, Psbt, PsbtSighashType};
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{self, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Address, Amount, OutPoint, TxOut, Weight, ecdsa, taproot};

use crate::account::{Account, Derivation, Kind};
use crate::seed::Seed;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the PSBT's inputs and outputs do not match its transaction's")]
    Malformed,
    #[error("input {input} carries neither the output it spends nor that output's transaction")]
    MissingSpentOutput { input: usize },
    #[error("input {input} carries a previous transaction that is not the one it spends")]
    PreviousTxMismatch { input: usize },
    #[error("input {input} asks for sighash type {sighash}, which the signer does not sign")]
    UnsupportedSighash { input: usize, sighash: PsbtSighashType },
    #[error("the outputs pay more than the inputs spend")]
    NegativeFee,
    #[error("the amounts overflow")]
    AmountOverflow,
    #[error("the seed is not the one the account was made from (a different passphrase?)")]
    WrongSeed,
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
    #[error(transparent)]
    SegwitV0Sighash(#[from] sighash::P2wpkhError),
    #[error(transparent)]
    TaprootSighash(#[from] sighash::TaprootError),
}

/// A PSBT as the account sees it: what the signer shows before it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: Amount,
    /// The most the transaction can weigh once signed. It is known when every input is the
    /// account's, as another's input's witness is not.
    pub max_weight: Option<Weight>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub previous_output: OutPoint,
    /// The output the input spends.
    pub spent: TxOut,
    /// The account's key the input spends, when it is the account's.
    pub derivation: Option<Derivation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub txout: TxOut,
    /// The output's address, unless its script has none (an `OP_RETURN`, say).
    pub address: Option<Address>,
    /// The account's key the output pays, when it is the account's: change, or a payment to one
    /// of the account's own receive addresses.
    pub derivation: Option<Derivation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// A segwit v0 input of the account's whose PSBT carries the output it spends but not that
    /// output's transaction, so its amount is the coordinator's word. A segwit v0 signature
    /// commits to its own input's amount alone: a coordinator that understates one input's
    /// amount in one PSBT and another's in a second can combine the signatures of both into a
    /// transaction whose fee the user never saw. Taproot signatures commit to every amount.
    UnverifiedAmount { input: usize },
}

impl Review {
    /// The fee rate in sat/vB, at least: the fee over the most the signed transaction can weigh.
    pub fn min_fee_rate(&self) -> Option<f64> {
        let vsize = self.max_weight?.to_vbytes_ceil();
        Some(self.fee.to_sat() as f64 / vsize as f64)
    }
}

pub fn review(account: &Account, psbt: &Psbt) -> Result<Review, Error> {
    let tx = &psbt.unsigned_tx;
    if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
        return Err(Error::Malformed);
    }
    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut warnings = Vec::new();
    for (index, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        let spent = spent_output(index, txin.previous_output, input)?;
        let derivation = claimed_keys(&input.bip32_derivation, &input.tap_key_origins)
            .find_map(|source| account.derivation_of(source, &spent.script_pubkey));
        if derivation.is_some() {
            check_sighash(account.kind(), index, input)?;
            if account.kind() == Kind::SegwitV0 && input.non_witness_utxo.is_none() {
                warnings.push(Warning::UnverifiedAmount { input: index });
            }
        }
        inputs.push(Input { previous_output: txin.previous_output, spent, derivation });
    }
    let outputs: Vec<Output> = (tx.output.iter().zip(&psbt.outputs))
        .map(|(txout, output)| Output {
            address: Address::from_script(&txout.script_pubkey, account.network()).ok(),
            derivation: claimed_keys(&output.bip32_derivation, &output.tap_key_origins)
                .find_map(|source| account.derivation_of(source, &txout.script_pubkey)),
            txout: txout.clone(),
        })
        .collect();

    let spent = total(inputs.iter().map(|input| input.spent.value))?;
    let paid = total(outputs.iter().map(|output| output.txout.value))?;
    let fee = spent.checked_sub(paid).ok_or(Error::NegativeFee)?;
    let max_weight = inputs.iter().all(|input| input.derivation.is_some()).then(|| {
        // Unsigned, the transaction has no witness, which its weight counts as having no segwit
        // marker and flag (2 WU) and no witness stack counts (1 WU an input). Signing adds those,
        // and to each input the satisfaction weight, which counts from an empty stack.
        let inputs = inputs.len() as u64;
        tx.weight() + Weight::from_wu(2 + inputs) + account.max_satisfaction_weight() * inputs
    });
    Ok(Review { inputs, outputs, fee, max_weight, warnings })
}

/// Signs every input `review` finds to be the account's with the key `seed` derives for it, and
/// returns how many it signed. `aux_rand` is fresh randomness for BIP340, which mixes it into
/// each taproot signature's nonce to guard the key against side channels; the nonce commits to
/// the key and the message as well, so one draw serves every input. ECDSA nonces are RFC6979's.
pub fn sign(
    account: &Account,
    seed: &Seed,
    psbt: &mut Psbt,
    aux_rand: &[u8; 32],
) -> Result<usize, Error> {
    let review = review(account, psbt)?;
    let secp = Secp256k1::new();
    let master = seed.master(account.network());
    let account_key = master.derive_priv(&secp, account.path())?;
    if master.fingerprint(&secp) != account.fingerprint()
        || Xpub::from_priv(&secp, &account_key) != *account.xpub()
    {
        return Err(Error::WrongSeed);
    }

    let prevouts: Vec<TxOut> = review.inputs.iter().map(|input| input.spent.clone()).collect();
    let mut sighashes = SighashCache::new(&psbt.unsigned_tx);
    let mut signed = 0;
    for (index, input) in review.inputs.iter().enumerate() {
        let Some(derivation) = input.derivation else { continue };
        let key = account_key.derive_priv(&secp, &derivation.path())?;
        let psbt_input = &mut psbt.inputs[index];
        match account.kind() {
            Kind::SegwitV0 => {
                let sighash_type = EcdsaSighashType::All;
                let TxOut { value, script_pubkey } = &input.spent;
                let sighash =
                    sighashes.p2wpkh_signature_hash(index, script_pubkey, *value, sighash_type)?;
                let message = Message::from_digest(sighash.to_byte_array());
                let signature = secp.sign_ecdsa_low_r(&message, &key.private_key);
                let public_key = bitcoin::PublicKey::new(key.private_key.public_key(&secp));
                let signature = ecdsa::Signature { signature, sighash_type };
                psbt_input.partial_sigs.insert(public_key, signature);
            }
            Kind::Taproot => {
                let sighash_type = psbt_input.taproot_hash_ty().expect("review checked it");
                let prevouts = Prevouts::All(&prevouts);
                let sighash =
                    sighashes.taproot_key_spend_signature_hash(index, &prevouts, sighash_type)?;
                let message = Message::from_digest(sighash.to_byte_array());
                // BIP86's output key is the internal key tweaked with no script tree.
                let keypair = key.to_keypair(&secp).tap_tweak(&secp, None).to_keypair();
                let signature = secp.sign_schnorr_with_aux_rand(&message, &keypair, aux_rand);
                psbt_input.tap_key_sig = Some(taproot::Signature { signature, sighash_type });
            }
        }
        signed += 1;
    }
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
fn check_sighash(kind: Kind, index: usize, input: &bip174::Input) -> Result<(), Error> {
    let Some(sighash) = input.sighash_type else { return Ok(()) };
    let whole = match kind {
        Kind::SegwitV0 => matches!(sighash.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)),
        Kind::Taproot => {
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
    use crate::seed::tests::abandon;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Network, ScriptBuf, Sequence, Transaction, TxIn};
    use miniscript::psbt::PsbtExt;
    use std::str::FromStr;

    const AUX_RAND: [u8; 32] = [7; 32];

    fn account(kind: Kind) -> Account {
        Account::from_seed(&abandon(""), Network::Regtest, kind, 0).unwrap()
    }

    /// A script that is not the account's: another passphrase's first receive address.
    fn someone_else(kind: Kind) -> ScriptBuf {
        let other = Account::from_seed(&abandon("someone else"), Network::Regtest, kind, 0);
        other.unwrap().script_pubkey(Derivation::receive(0))
    }

    /// A transaction paying each amount to its script, for a PSBT to spend.
    fn funding(outputs: &[(ScriptBuf, u64)]) -> Transaction {
        let previous_output = OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0);
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output, ..TxIn::default() }],
            output: (outputs.iter())
                .map(|(script_pubkey, sats)| TxOut {
                    value: Amount::from_sat(*sats),
                    script_pubkey: script_pubkey.clone(),
                })
                .collect(),
        }
    }

    /// A PSBT spending every output of `funding` to `outputs`, made as the account's watch-only
    /// wallet makes one: with each input's previous transaction, and the account's keys recorded
    /// for the inputs `spends` names and the outputs that name one.
    fn spend(
        account: &Account,
        funding: &Transaction,
        spends: &[Option<Derivation>],
        outputs: &[(ScriptBuf, u64, Option<Derivation>)],
    ) -> Psbt {
        let txid = funding.compute_txid();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..spends.len() as u32)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(txid, vout),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..TxIn::default()
                })
                .collect(),
            output: (outputs.iter())
                .map(|(script_pubkey, sats, _)| TxOut {
                    value: Amount::from_sat(*sats),
                    script_pubkey: script_pubkey.clone(),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (vout, (input, derivation)) in psbt.inputs.iter_mut().zip(spends).enumerate() {
            input.witness_utxo = Some(funding.output[vout].clone());
            input.non_witness_utxo = Some(funding.clone());
            if let Some(derivation) = derivation {
                account.annotate_input(input, *derivation);
            }
        }
        for (output, (_, _, derivation)) in psbt.outputs.iter_mut().zip(outputs) {
            if let Some(derivation) = derivation {
                account.annotate_output(output, *derivation);
            }
        }
        psbt
    }

    /// Finalizes a signed PSBT and checks every input with Bitcoin Core's script interpreter.
    fn finalize_and_verify(psbt: Psbt) -> Transaction {
        let (tx, spent) = finalize(psbt);
        verify_with_core(&tx, &spent);
        tx
    }

    /// The signed transaction and the outputs it spends.
    fn finalize(mut psbt: Psbt) -> (Transaction, Vec<TxOut>) {
        let spent: Vec<TxOut> =
            (psbt.inputs.iter()).map(|input| input.witness_utxo.clone().unwrap()).collect();
        psbt.finalize_mut(&Secp256k1::verification_only()).unwrap();
        (psbt.extract_tx().unwrap(), spent)
    }

    fn verify_with_core(tx: &Transaction, spent: &[TxOut]) {
        let serialized = bitcoin::consensus::serialize(tx);
        let utxos: Vec<bitcoinconsensus::Utxo> = (spent.iter())
            .map(|txout| bitcoinconsensus::Utxo {
                script_pubkey: txout.script_pubkey.as_bytes().as_ptr(),
                script_pubkey_len: txout.script_pubkey.len() as u32,
                value: txout.value.to_sat() as i64,
            })
            .collect();
        for (index, txout) in spent.iter().enumerate() {
            let script = txout.script_pubkey.as_bytes();
            let sats = txout.value.to_sat();
            bitcoinconsensus::verify(script, sats, &serialized, Some(&utxos), index)
                .unwrap_or_else(|e| panic!("input {index} fails Core's checks: {e:?}"));
        }
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
    fn a_segwit_v0_input_without_its_previous_transaction_is_flagged() {
        let (account, mut psbt) = payment(Kind::SegwitV0);
        psbt.inputs[0].non_witness_utxo = None;
        let review = review(&account, &psbt).unwrap();
        assert_eq!(review.warnings, [Warning::UnverifiedAmount { input: 0 }]);

        let (account, mut psbt) = payment(Kind::Taproot);
        psbt.inputs[0].non_witness_utxo = None;
        assert_eq!(super::review(&account, &psbt).unwrap().warnings, [], "taproot commits to it");
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
