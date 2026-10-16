//! What the fuzz targets share: the wallets they review PSBTs against, made once, as making a
//! seed takes a moment; the properties every review and every signing must keep whatever the
//! PSBT; and the PSBTs the structure-aware target builds around the wallets.
//!
//! The targets build with cargo-fuzz (`cargo install cargo-fuzz`), whose sanitizer flags a stable
//! toolchain takes with `RUSTC_BOOTSTRAP=1`. From the repository's root:
//!
//! ```text
//! cargo run --manifest-path fuzz/Cargo.toml --example seed-corpus
//! RUSTC_BOOTSTRAP=1 cargo fuzz run transaction -- -fork=8 -max_total_time=600
//! ```
//!
//! `review` reads any bytes as a PSBT; `transaction` builds PSBTs around the wallets, and checks
//! what the review of each must say and what signing must do, down to Bitcoin Core's script
//! interpreter; `setup` reads multisig setup files and descriptors; `bcur` and `bcur-loop` read UR
//! parts and round-trip PSBTs through loops; `seedqr` decodes SeedQRs and dice rolls; `store`
//! reads kept wallets' files and records.

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use wallet_core::Mnemonic;
use wallet_core::account::{Account, Derivation, Kind};
use wallet_core::bitcoin::absolute::LockTime;
use wallet_core::bitcoin::hashes::Hash;
use wallet_core::bitcoin::opcodes::all::OP_RETURN;
use wallet_core::bitcoin::psbt::{Psbt, PsbtSighashType};
use wallet_core::bitcoin::script::{Builder, PushBytesBuf};
use wallet_core::bitcoin::secp256k1::Secp256k1;
use wallet_core::bitcoin::transaction::Version;
use wallet_core::bitcoin::{
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use wallet_core::miniscript::psbt::PsbtExt;
use wallet_core::multisig::{CosignerKey, Multisig};
use wallet_core::policy::{Policy, Spend};
use wallet_core::psbt::{self, Review, Warning};
use wallet_core::seed::Seed;

pub const NETWORK: Network = Network::Regtest;
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon about";
pub const AUX_RAND: [u8; 32] = [7; 32];

fn seed(passphrase: &str) -> Seed {
    Seed::new(&Mnemonic::parse(MNEMONIC).unwrap(), passphrase)
}

/// The seeds of the multisig's three signers, the first of which holds the single-key accounts.
pub static SEEDS: LazyLock<[Seed; 3]> =
    LazyLock::new(|| [seed(""), seed("TREZOR"), seed("a third")]);

pub static TAPROOT: LazyLock<Account> =
    LazyLock::new(|| Account::from_seed(&SEEDS[0], NETWORK, Kind::Taproot, 0).unwrap());

pub static SEGWIT: LazyLock<Account> =
    LazyLock::new(|| Account::from_seed(&SEEDS[0], NETWORK, Kind::SegwitV0, 0).unwrap());

/// A 2-of-3 of the three seeds, as each of them co-signs it.
pub static MULTISIG: LazyLock<[Multisig; 3]> = LazyLock::new(|| {
    let keys: Vec<String> = (SEEDS.iter())
        .map(|seed| format!("{}/<0;1>/*", CosignerKey::new(seed, NETWORK, 0).unwrap()))
        .collect();
    let descriptor = format!("wsh(sortedmulti(2,{}))", keys.join(","));
    let multisig = Multisig::from_descriptor(&descriptor, NETWORK).unwrap();
    [0, 1, 2].map(|signer| multisig.clone().with_seed(&SEEDS[signer]).unwrap())
});

/// Someone else's wallet, for scripts that are not ours.
pub static STRANGER: LazyLock<Account> =
    LazyLock::new(|| Account::from_seed(&seed("a stranger"), NETWORK, Kind::Taproot, 0).unwrap());

/// Every policy a PSBT is reviewed against, with the seed that signs for it.
pub fn policies() -> [(&'static dyn Policy, &'static Seed); 3] {
    [(&*TAPROOT, &SEEDS[0]), (&*SEGWIT, &SEEDS[0]), (&MULTISIG[0], &SEEDS[0])]
}

/// What holds of every review that succeeds, whatever the PSBT.
pub fn check_review(policy: &dyn Policy, psbt: &Psbt, review: &Review) {
    let tx = &psbt.unsigned_tx;
    assert_eq!(review.inputs.len(), tx.input.len());
    assert_eq!(review.outputs.len(), tx.output.len());
    assert_eq!(review.threshold, policy.threshold());
    assert_eq!(review.lock_time, tx.lock_time);
    for ((input, txin), psbt_input) in review.inputs.iter().zip(&tx.input).zip(&psbt.inputs) {
        assert_eq!(input.previous_output, txin.previous_output);
        assert_eq!(input.signatures, psbt::signatures(psbt_input));
        // The amount spent is the previous transaction's, which the outpoint commits to, when
        // the PSBT carries it; the witness UTXO's only when it does not.
        match &psbt_input.non_witness_utxo {
            Some(previous) => {
                assert_eq!(previous.compute_txid(), txin.previous_output.txid);
                assert_eq!(input.spent, previous.output[txin.previous_output.vout as usize]);
            }
            None => assert_eq!(Some(&input.spent), psbt_input.witness_utxo.as_ref()),
        }
        // Nothing is the policy's unless the policy's own descriptor gives its script.
        if let Some(derivation) = input.derivation {
            assert_eq!(policy.script_pubkey(derivation), input.spent.script_pubkey);
        }
    }
    for (output, txout) in review.outputs.iter().zip(&tx.output) {
        assert_eq!(output.txout, *txout);
        if let Some(derivation) = output.derivation {
            assert_eq!(policy.script_pubkey(derivation), txout.script_pubkey);
        }
    }
    // Every amount is a real one, and the fee is what the inputs hold less what the outputs pay.
    let spent: u64 = review.inputs.iter().map(|input| input.spent.value.to_sat()).sum();
    let paid: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
    assert!(review.inputs.iter().all(|input| input.spent.value <= Amount::MAX_MONEY));
    assert!(tx.output.iter().all(|output| output.value <= Amount::MAX_MONEY));
    assert_eq!(review.fee.to_sat(), spent - paid);
    let all_ours = review.inputs.iter().all(|input| input.derivation.is_some());
    assert_eq!(review.max_weight.is_some(), all_ours);
    for warning in &review.warnings {
        match warning {
            Warning::FakeChange { output } => assert!(review.outputs[*output].derivation.is_none()),
            Warning::DistantIndex { output, index } => {
                assert_eq!(review.outputs[*output].derivation.map(|d| d.index), Some(*index));
            }
            Warning::ForeignInputs { count } => {
                let others = review.inputs.iter().filter(|input| input.derivation.is_none());
                assert_eq!(others.count(), *count);
            }
            Warning::UnverifiedAmounts { inputs } => {
                assert!(inputs.len() > 1);
                for index in inputs {
                    assert!(review.inputs[*index].derivation.is_some());
                    assert!(psbt.inputs[*index].non_witness_utxo.is_none());
                }
            }
            Warning::HighFee | Warning::LocktimeIgnored => {}
        }
    }
    let _ = (review.net_spent(), review.min_fee_rate(), review.complete());
}

/// Signs `psbt` with `seed` and checks what signing must and must not do: on failure, nothing
/// changed; on success, every input of the policy's that was not finalized carries the seed's
/// signature, every other input and all else is as it was, and the signed PSBT still reviews.
/// Returns the signed PSBT.
pub fn check_sign(policy: &dyn Policy, seed: &Seed, psbt: &Psbt, review: &Review) -> Option<Psbt> {
    let mut signed = psbt.clone();
    let Ok(count) = psbt::sign(policy, seed, &mut signed, &AUX_RAND) else {
        assert_eq!(signed, *psbt, "a failed signing changes nothing");
        return None;
    };
    assert_eq!(signed.unsigned_tx, psbt.unsigned_tx);
    assert_eq!(signed.outputs, psbt.outputs);
    assert_eq!(
        (signed.version, &signed.xpub, &signed.proprietary),
        (psbt.version, &psbt.xpub, &psbt.proprietary)
    );
    let secp = Secp256k1::verification_only();
    let (_, xpub) = policy.signer().expect("signing needs the seed's key");
    let mut expected = 0;
    for (index, input) in review.inputs.iter().enumerate() {
        let (before, after) = (&psbt.inputs[index], &signed.inputs[index]);
        match input.derivation {
            Some(derivation)
                if before.final_script_witness.is_none() && before.final_script_sig.is_none() =>
            {
                expected += 1;
                let key = xpub.derive_pub(&secp, &derivation.path()).unwrap().public_key;
                match policy.spend(derivation) {
                    Spend::TaprootKey => assert!(after.tap_key_sig.is_some()),
                    _ => assert!(after.partial_sigs.contains_key(&PublicKey::new(key))),
                }
            }
            _ => assert_eq!(after, before, "input {index} is not one to sign"),
        }
    }
    assert_eq!(count, expected);
    let again = psbt::review(policy, &signed).expect("a signed PSBT still reviews");
    check_review(policy, &signed, &again);
    Some(signed)
}

/// Finalizes a PSBT every input of which carries the signatures it takes, and runs each input
/// through Bitcoin Core's script interpreter.
pub fn check_consensus(psbt: &Psbt, review: &Review) {
    let spent: Vec<TxOut> = review.inputs.iter().map(|input| input.spent.clone()).collect();
    let mut psbt = psbt.clone();
    psbt.finalize_mut(&Secp256k1::verification_only()).expect("a signed PSBT finalizes");
    let tx = psbt.extract_tx_unchecked_fee_rate();
    let serialized = wallet_core::bitcoin::consensus::serialize(&tx);
    let utxos: Vec<bitcoinconsensus::Utxo> = (spent.iter())
        .map(|txout| bitcoinconsensus::Utxo {
            script_pubkey: txout.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: txout.script_pubkey.len() as u32,
            value: txout.value.to_sat() as i64,
        })
        .collect();
    for (index, txout) in spent.iter().enumerate() {
        let script = txout.script_pubkey.as_bytes();
        bitcoinconsensus::verify(script, txout.value.to_sat(), &serialized, Some(&utxos), index)
            .unwrap_or_else(|error| panic!("input {index} fails Core's checks: {error:?}"));
    }
}

/// A PSBT for the structure-aware target to build around one of the wallets.
#[derive(Arbitrary, Debug)]
pub struct Spec {
    pub wallet: Wallet,
    pub version: i32,
    pub lock_time: u32,
    pub inputs: Vec<InputSpec>,
    pub outputs: Vec<OutputSpec>,
}

#[derive(Arbitrary, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wallet {
    Taproot,
    Segwit,
    Multisig,
}

impl Wallet {
    pub fn policy(self) -> &'static dyn Policy {
        match self {
            Wallet::Taproot => &*TAPROOT,
            Wallet::Segwit => &*SEGWIT,
            Wallet::Multisig => &MULTISIG[0],
        }
    }
}

/// A key of the wallet's: a keychain and an index below 2^31.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub struct Key {
    pub change: bool,
    pub index: u32,
}

impl Key {
    pub fn derivation(self) -> Derivation {
        let index = self.index & 0x7fff_ffff;
        if self.change { Derivation::change(index) } else { Derivation::receive(index) }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum Who {
    /// The wallet's, at this key.
    Ours(Key),
    /// Someone else's.
    Theirs(u16),
    /// Someone else's, dressed in the wallet's key origin for this key.
    Pretender(Key),
}

#[derive(Arbitrary, Debug)]
pub struct InputSpec {
    pub who: Who,
    pub amount: u64,
    pub sequence: u32,
    pub previous: Previous,
    pub sighash: Option<u32>,
    pub finalized: bool,
    pub wrong_witness_script: bool,
    /// The input to spend the same output as, if any.
    pub duplicate_of: Option<u8>,
}

/// How the PSBT carries what an input spends.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum Previous {
    WitnessUtxo,
    PreviousTx,
    Both,
    /// Both, the witness UTXO stating another amount.
    Disagreeing(u64),
    Neither,
}

#[derive(Arbitrary, Debug)]
pub struct OutputSpec {
    pub who: OutputWho,
    pub amount: u64,
}

#[derive(Arbitrary, Debug)]
pub enum OutputWho {
    Who(Who),
    OpReturn(Vec<u8>),
}

/// An amount mostly among those there can be, and sometimes just past them.
pub fn amount(raw: u64) -> Amount {
    Amount::from_sat(raw % (Amount::MAX_MONEY.to_sat() + 1_000))
}

fn script(wallet: &dyn Policy, who: Who) -> ScriptBuf {
    match who {
        Who::Ours(key) => wallet.script_pubkey(key.derivation()),
        Who::Theirs(index) => STRANGER.script_pubkey(Derivation::receive(index.into())),
        Who::Pretender(key) => STRANGER.script_pubkey(Derivation::receive(key.index & 0xffff)),
    }
}

/// The most inputs, and the most outputs, a spec's PSBT has.
const MOST: usize = 6;

impl Spec {
    pub fn inputs(&self) -> &[InputSpec] {
        &self.inputs[..self.inputs.len().min(MOST)]
    }

    pub fn outputs(&self) -> &[OutputSpec] {
        &self.outputs[..self.outputs.len().min(MOST)]
    }

    /// The input whose output input `index` spends: its own, unless it spends another's.
    pub fn spends(&self, index: usize) -> usize {
        let inputs = self.inputs().len();
        self.inputs()[index].duplicate_of.map_or(index, |other| usize::from(other) % inputs)
    }
}

/// The PSBT `spec` describes, made as a coordinator makes one, mistakes and lies included.
pub fn build(spec: &Spec) -> Psbt {
    let wallet = spec.wallet.policy();
    let (inputs, outputs) = (spec.inputs(), spec.outputs());
    // Each input spends output 0 of a transaction of its own.
    let fundings: Vec<Transaction> = (inputs.iter().enumerate())
        .map(|(index, input)| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([index as u8 + 1; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: amount(input.amount),
                script_pubkey: script(wallet, input.who),
            }],
        })
        .collect();
    let tx_inputs = (inputs.iter().enumerate())
        .map(|(index, input)| TxIn {
            previous_output: OutPoint::new(fundings[spec.spends(index)].compute_txid(), 0),
            sequence: Sequence(input.sequence),
            ..TxIn::default()
        })
        .collect();
    let tx_outputs = (outputs.iter())
        .map(|output| TxOut {
            value: amount(output.amount),
            script_pubkey: match &output.who {
                OutputWho::Who(who) => script(wallet, *who),
                OutputWho::OpReturn(data) => {
                    let data = PushBytesBuf::try_from(data[..data.len().min(80)].to_vec()).unwrap();
                    Builder::new().push_opcode(OP_RETURN).push_slice(data).into_script()
                }
            },
        })
        .collect();
    let tx = Transaction {
        version: Version(spec.version),
        lock_time: LockTime::from_consensus(spec.lock_time),
        input: tx_inputs,
        output: tx_outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("an unsigned transaction");
    for ((psbt_input, input), funding) in psbt.inputs.iter_mut().zip(inputs).zip(&fundings) {
        let spent = funding.output[0].clone();
        match input.previous {
            Previous::WitnessUtxo => psbt_input.witness_utxo = Some(spent),
            Previous::PreviousTx => psbt_input.non_witness_utxo = Some(funding.clone()),
            Previous::Both => {
                psbt_input.witness_utxo = Some(spent);
                psbt_input.non_witness_utxo = Some(funding.clone());
            }
            Previous::Disagreeing(other) => {
                psbt_input.witness_utxo = Some(TxOut { value: amount(other), ..spent });
                psbt_input.non_witness_utxo = Some(funding.clone());
            }
            Previous::Neither => {}
        }
        if let Who::Ours(key) | Who::Pretender(key) = input.who {
            wallet.annotate_input(psbt_input, key.derivation());
        }
        if input.wrong_witness_script {
            psbt_input.witness_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        }
        psbt_input.sighash_type = input.sighash.map(PsbtSighashType::from_u32);
        if input.finalized {
            psbt_input.final_script_witness = Some(Witness::from_slice(&[[1u8; 64]]));
        }
    }
    for (psbt_output, output) in psbt.outputs.iter_mut().zip(outputs) {
        if let OutputWho::Who(Who::Ours(key) | Who::Pretender(key)) = output.who {
            wallet.annotate_output(psbt_output, key.derivation());
        }
    }
    psbt
}
