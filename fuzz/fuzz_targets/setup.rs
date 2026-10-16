//! Any text, as a multisig setup file or a descriptor on the card: whatever reads must give a
//! wallet that derives its addresses, writes a descriptor that reads back as itself, and takes
//! each seed that is one of its signers' as no more than one of them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_airgap::setup;
use wallet_core::account::{Account, Derivation};
use wallet_core::bitcoin::Network;
use wallet_core::multisig::Multisig;
use wallet_core::policy::Policy;
use wallet_fuzz::SEEDS;

const NETWORKS: [Network; 2] = [Network::Bitcoin, Network::Regtest];

fn check_policy(policy: &dyn Policy) {
    for derivation in [Derivation::receive(0), Derivation::change(7), Derivation::receive(1 << 30)]
    {
        let script = policy.script_pubkey(derivation);
        assert_eq!(policy.address(derivation).script_pubkey(), script);
        let _ = (policy.spend(derivation), policy.max_satisfaction_weight());
    }
}

fuzz_target!(|text: &str| {
    let _ = setup::looks_like(text);
    for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if let Some(xpub) = setup::to_xpub(word) {
            assert_eq!(setup::to_xpub(&xpub), Some(xpub.clone()), "an xpub stays itself");
        }
    }
    if let Ok(setup) = setup::read(text) {
        for network in NETWORKS {
            let Ok(multisig) = Multisig::from_descriptor(&setup.descriptor, network) else {
                continue;
            };
            check_policy(&multisig);
            assert!(
                multisig.threshold() >= 1
                    && multisig.threshold() <= multisig.fingerprints().count()
            );
            let written = multisig.descriptor().to_string();
            let again = Multisig::from_descriptor(&written, network).expect("its own descriptor");
            assert_eq!(again.descriptor(), multisig.descriptor());
            for seed in SEEDS.iter() {
                if let Ok(cosigner) = multisig.clone().with_seed(seed) {
                    assert!(cosigner.ours().is_some());
                    // A PSBT naming the seed's key at a keychain path finds the key there.
                    let ((fingerprint, path), _) = cosigner.signer().expect("a cosigner's key");
                    let derivation = Derivation::change(3);
                    let source = (*fingerprint, path.extend(derivation.path()));
                    let script = cosigner.script_pubkey(derivation);
                    assert!(cosigner.claims(&source));
                    assert_eq!(cosigner.derivation_of(&source, &script), Some(derivation));
                }
            }
        }
    }
    for network in NETWORKS {
        if let Ok(account) = Account::from_descriptor(text, network) {
            check_policy(&account);
            let written = account.descriptor().to_string();
            let again = Account::from_descriptor(&written, network).expect("its own descriptor");
            assert_eq!(again.descriptor(), account.descriptor());
        }
    }
});
