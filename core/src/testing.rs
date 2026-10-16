//! What the tests of PSBTs build them from: funding transactions, PSBTs made as a coordinator
//! makes them, and Bitcoin Core's script interpreter, to check what the signer signed.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use miniscript::psbt::PsbtExt;

use crate::account::Derivation;
use crate::policy::Policy;

pub(crate) const AUX_RAND: [u8; 32] = [7; 32];

/// A transaction paying each amount to its script, for a PSBT to spend.
pub(crate) fn funding(outputs: &[(ScriptBuf, u64)]) -> Transaction {
    let previous_output = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
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

/// A PSBT spending every output of `funding` to `outputs`, made as the policy's watch-only wallet
/// makes one: with each input's previous transaction, and the policy's keys recorded for the
/// inputs `spends` names and the outputs that name one.
pub(crate) fn spend(
    policy: &dyn Policy,
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
            policy.annotate_input(input, *derivation);
        }
    }
    for (output, (_, _, derivation)) in psbt.outputs.iter_mut().zip(outputs) {
        if let Some(derivation) = derivation {
            policy.annotate_output(output, *derivation);
        }
    }
    psbt
}

/// Finalizes a signed PSBT and checks every input with Bitcoin Core's script interpreter.
pub(crate) fn finalize_and_verify(psbt: Psbt) -> Transaction {
    let (tx, spent) = finalize(psbt);
    verify_with_core(&tx, &spent);
    tx
}

/// The signed transaction and the outputs it spends.
pub(crate) fn finalize(mut psbt: Psbt) -> (Transaction, Vec<TxOut>) {
    let spent: Vec<TxOut> =
        (psbt.inputs.iter()).map(|input| input.witness_utxo.clone().unwrap()).collect();
    psbt.finalize_mut(&Secp256k1::verification_only()).unwrap();
    (psbt.extract_tx().unwrap(), spent)
}

pub(crate) fn verify_with_core(tx: &Transaction, spent: &[TxOut]) {
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
