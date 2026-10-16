//! PSBTs made around the wallets, as a coordinator makes them, mistakes and lies included: each
//! reviews exactly as what went into it says it must, or fails for one of the reasons in it; signs
//! every input of the wallet's and nothing else; and, every input signed, makes a transaction
//! Bitcoin Core's script interpreter accepts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_core::bitcoin::Amount;
use wallet_core::bitcoin::psbt::PsbtSighashType;
use wallet_core::bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use wallet_core::psbt::{self, Error, GAP, HIGH_FEE_PERCENT, Warning};
use wallet_fuzz::{
    MULTISIG, OutputWho, Previous, SEEDS, Spec, Wallet, Who, amount, build, check_consensus,
    check_review, check_sign,
};

/// Why a PSBT must be refused, by the error it is refused with.
#[derive(Debug, PartialEq, Eq)]
enum Cause {
    Version,
    Duplicate,
    Missing,
    Mismatch,
    Sighash,
    WitnessScript,
    Excessive,
    Negative,
}

fn cause(error: &Error) -> Cause {
    match error {
        Error::UnsupportedVersion(_) => Cause::Version,
        Error::DuplicateInput { .. } => Cause::Duplicate,
        Error::MissingSpentOutput { .. } => Cause::Missing,
        Error::PreviousTxMismatch { .. } => Cause::Mismatch,
        Error::UnsupportedSighash { .. } => Cause::Sighash,
        Error::WitnessScriptMismatch { .. } => Cause::WitnessScript,
        Error::ExcessiveAmount => Cause::Excessive,
        Error::NegativeFee => Cause::Negative,
        error => panic!("refused for no reason the spec gave: {error}"),
    }
}

/// Whether a signature of the sighash type commits to the whole transaction.
fn whole(wallet: Wallet, sighash: u32) -> bool {
    let sighash = PsbtSighashType::from_u32(sighash);
    match wallet {
        Wallet::Taproot => {
            matches!(sighash.taproot_hash_ty(), Ok(TapSighashType::Default | TapSighashType::All))
        }
        Wallet::Segwit | Wallet::Multisig => {
            matches!(sighash.ecdsa_hash_ty(), Ok(EcdsaSighashType::All))
        }
    }
}

fn ours(who: Who) -> bool {
    matches!(who, Who::Ours(_))
}

fuzz_target!(|spec: Spec| {
    let policy = spec.wallet.policy();
    let (inputs, outputs) = (spec.inputs(), spec.outputs());
    let psbt = build(&spec);

    let mut causes = Vec::new();
    if !(1..=3).contains(&spec.version) {
        causes.push(Cause::Version);
    }
    let spends: Vec<usize> = (0..inputs.len()).map(|index| spec.spends(index)).collect();
    if (1..spends.len()).any(|index| spends[..index].contains(&spends[index])) {
        causes.push(Cause::Duplicate);
    }
    for (index, input) in inputs.iter().enumerate() {
        // An input spending another's output carries its own funding transaction's output, which
        // its outpoint commits to only when the PSBT carries that transaction.
        let moved = spends[index] != index;
        match input.previous {
            Previous::Neither => causes.push(Cause::Missing),
            Previous::Disagreeing(other) if amount(other) != amount(input.amount) => {
                causes.push(Cause::Mismatch);
            }
            Previous::PreviousTx | Previous::Both | Previous::Disagreeing(_) if moved => {
                causes.push(Cause::Mismatch);
            }
            _ => {}
        }
        if ours(input.who) {
            if input.sighash.is_some_and(|sighash| !whole(spec.wallet, sighash)) {
                causes.push(Cause::Sighash);
            }
            if spec.wallet == Wallet::Multisig && input.wrong_witness_script {
                causes.push(Cause::WitnessScript);
            }
        }
    }
    let spent: Vec<Amount> = inputs.iter().map(|input| amount(input.amount)).collect();
    let paid: Vec<Amount> = outputs.iter().map(|output| amount(output.amount)).collect();
    if spent.iter().chain(&paid).any(|amount| *amount > Amount::MAX_MONEY) {
        causes.push(Cause::Excessive);
    }
    let spent: u64 = spent.iter().map(|amount| amount.to_sat()).sum();
    let paid: u64 = paid.iter().map(|amount| amount.to_sat()).sum();
    if spent < paid {
        causes.push(Cause::Negative);
    }

    let review = match psbt::review(policy, &psbt) {
        Err(error) => {
            let cause = cause(&error);
            assert!(causes.contains(&cause), "refused for {cause:?}, not for {causes:?}");
            return;
        }
        Ok(review) => {
            assert_eq!(causes, [], "reviewed despite them");
            review
        }
    };
    check_review(policy, &psbt, &review);

    // Exactly the wallet's inputs and outputs are the wallet's, at the keys they are at.
    for (input, spec) in review.inputs.iter().zip(inputs) {
        let expected = match spec.who {
            Who::Ours(key) => Some(key.derivation()),
            Who::Theirs(_) | Who::Pretender(_) => None,
        };
        assert_eq!(input.derivation, expected);
    }
    for (output, spec) in review.outputs.iter().zip(outputs) {
        let expected = match spec.who {
            OutputWho::Who(Who::Ours(key)) => Some(key.derivation()),
            _ => None,
        };
        assert_eq!(output.derivation, expected);
    }

    // And the warnings are exactly those the spec calls for.
    let mut expected = Vec::new();
    if spec.wallet != Wallet::Taproot {
        let unverified: Vec<usize> = (inputs.iter().enumerate())
            .filter(|(_, input)| ours(input.who) && matches!(input.previous, Previous::WitnessUtxo))
            .map(|(index, _)| index)
            .collect();
        if unverified.len() > 1 {
            expected.push(Warning::UnverifiedAmounts { inputs: unverified });
        }
    }
    let foreign = inputs.iter().filter(|input| !ours(input.who)).count();
    if foreign > 0 {
        expected.push(Warning::ForeignInputs { count: foreign });
    }
    let highest = (inputs.iter())
        .filter_map(|input| match input.who {
            Who::Ours(key) => Some(key.derivation().index),
            _ => None,
        })
        .max();
    for (index, output) in outputs.iter().enumerate() {
        match (&output.who, highest) {
            (OutputWho::Who(Who::Pretender(_)), _) => {
                expected.push(Warning::FakeChange { output: index });
            }
            (OutputWho::Who(Who::Ours(key)), Some(highest)) => {
                let derivation = key.derivation();
                if derivation.index > highest.saturating_add(GAP) {
                    expected.push(Warning::DistantIndex { output: index, index: derivation.index });
                }
            }
            _ => {}
        }
    }
    let final_sequences = inputs.iter().all(|input| input.sequence == u32::MAX);
    if spec.lock_time != 0 && final_sequences {
        expected.push(Warning::LocktimeIgnored);
    }
    let fee = spent - paid;
    let large_share = fee * 100 >= spent * HIGH_FEE_PERCENT && fee > 0;
    if large_share || review.min_fee_rate().is_some_and(|rate| rate > psbt::HIGH_FEE_RATE) {
        expected.push(Warning::HighFee);
    }
    assert_eq!(review.warnings, expected);

    let signed = check_sign(policy, &SEEDS[0], &psbt, &review).expect("the wallet's seed signs");
    // With every input the wallet's and none finalized beforehand, its signatures alone (and a
    // second signer's, for the multisig) make a transaction the network accepts.
    let finalized = inputs.iter().any(|input| input.finalized);
    let stray_script = inputs.iter().any(|input| input.wrong_witness_script);
    if review.max_weight.is_none() || inputs.is_empty() || finalized || stray_script {
        return;
    }
    let signed = match spec.wallet {
        Wallet::Multisig => {
            let second = &MULTISIG[1];
            let review = psbt::review(second, &signed).expect("a signed PSBT still reviews");
            check_sign(second, &SEEDS[1], &signed, &review).expect("the second seed signs")
        }
        _ => signed,
    };
    let review = psbt::review(policy, &signed).unwrap();
    assert!(review.complete());
    check_consensus(&signed, &review);
});
