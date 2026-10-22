//! Signing a message with one of an account's keys, to show that whoever holds the seed holds an
//! address: BIP-322's "simple" signatures, which the BIP, now final, has new proofs use for every
//! address but the legacy pay-to-pubkey-hash ones this wallet does not make. The signature is a
//! transaction input's witness, spending a virtual output to the address that commits to the
//! message, and it is written as `smp` and the witness, consensus-encoded, in base64.

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::bip32::{self, Xpub};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::key::{CompressedPublicKey, Keypair, TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, ecdsa,
    opcodes, taproot,
};

use crate::account::{Account, Derivation, Kind};
use crate::policy::Policy;
use crate::seed::Seed;

/// The prefix of a "simple" signature.
pub const SIMPLE: &str = "smp";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a simple BIP-322 signature (smp…)")]
    Variant,
    #[error("the signature is not base64")]
    Encoding,
    #[error("the signature is not a witness")]
    Witness,
    #[error("only native segwit and taproot addresses are checked here")]
    Unsupported,
    #[error("the signature is not the address's for this message")]
    Invalid,
    #[error("the seed holds no key of this account's (a different passphrase?)")]
    WrongSeed,
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
}

/// BIP-322's tagged hash of the message, as it is, with no length or terminator.
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"BIP0322-signed-message");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// The virtual transaction whose one output, to `script_pubkey`, the signature spends: its input
/// commits to the message.
pub fn to_spend(script_pubkey: &Script, message: &[u8]) -> Transaction {
    let script_sig = bitcoin::script::Builder::new()
        .push_opcode(opcodes::OP_0)
        .push_slice(message_hash(message))
        .into_script();
    Transaction {
        version: Version(0),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0xffff_ffff },
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: script_pubkey.to_owned() }],
    }
}

/// The virtual transaction that spends `to_spend`'s output with `witness`, the signature.
pub fn to_sign(to_spend: &Transaction, witness: Witness) -> Transaction {
    Transaction {
        version: Version(0),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: to_spend.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness,
        }],
        // OP_RETURN alone: `new_op_return` would push an empty slice after it.
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![opcodes::all::OP_RETURN.to_u8()]),
        }],
    }
}

/// `message` signed with the account's key at `derivation`, which pays the account's address
/// there; checked once made. `aux_rand` is BIP340's fresh randomness, for a taproot key.
pub fn sign(
    account: &Account,
    seed: &Seed,
    derivation: Derivation,
    message: &str,
    aux_rand: &[u8; 32],
) -> Result<String, Error> {
    let ((fingerprint, path), xpub) = account.signer().ok_or(Error::WrongSeed)?;
    let secp = Secp256k1::new();
    let master = seed.master(account.network());
    let account_key = master.derive_priv(&secp, path)?;
    if master.fingerprint(&secp) != *fingerprint || Xpub::from_priv(&secp, &account_key) != *xpub {
        return Err(Error::WrongSeed);
    }
    let key = account_key.derive_priv(&secp, &derivation.path())?.private_key;
    let (script_pubkey, signature) = sign_with(account.kind(), &key, message.as_bytes(), aux_rand);
    if script_pubkey != account.script_pubkey(derivation) {
        return Err(Error::WrongSeed);
    }
    verify(&script_pubkey, message.as_bytes(), &signature)?;
    Ok(signature)
}

/// The address `key` pays as `kind` does, and `message` signed for it.
fn sign_with(
    kind: Kind,
    key: &SecretKey,
    message: &[u8],
    aux_rand: &[u8; 32],
) -> (ScriptBuf, String) {
    let secp = Secp256k1::new();
    let (script_pubkey, witness) = match kind {
        Kind::SegwitV0 => {
            let public_key = CompressedPublicKey(key.public_key(&secp));
            let script_pubkey = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash());
            let to_spend = to_spend(&script_pubkey, message);
            let to_sign = to_sign(&to_spend, Witness::new());
            let sighash = SighashCache::new(&to_sign)
                .p2wpkh_signature_hash(0, &script_pubkey, Amount::ZERO, EcdsaSighashType::All)
                .expect("a p2wpkh script");
            let digest = Message::from_digest(sighash.to_byte_array());
            let signature = secp.sign_ecdsa_low_r(&digest, key);
            let signature = ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
            (script_pubkey, Witness::p2wpkh(&signature, &public_key.0))
        }
        Kind::Taproot => {
            let keypair = Keypair::from_secret_key(&secp, key);
            let internal = keypair.x_only_public_key().0;
            let script_pubkey = ScriptBuf::new_p2tr(&secp, internal, None);
            let to_spend = to_spend(&script_pubkey, message);
            let to_sign = to_sign(&to_spend, Witness::new());
            let prevouts = [to_spend.output[0].clone()];
            let sighash = SighashCache::new(&to_sign)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .expect("one input, and its output");
            let digest = Message::from_digest(sighash.to_byte_array());
            // BIP86's output key is the internal key tweaked with no script tree.
            let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
            let signature = secp.sign_schnorr_with_aux_rand(&digest, &tweaked, aux_rand);
            let signature = taproot::Signature { signature, sighash_type: TapSighashType::Default };
            (script_pubkey, Witness::p2tr_key_spend(&signature))
        }
    };
    (script_pubkey, format!("{SIMPLE}{}", STANDARD.encode(serialize(&witness))))
}

/// Whether `signature` is the simple BIP-322 signature of `message` by the address that pays
/// `script_pubkey`: a native segwit key's, or a taproot key spend's.
pub fn verify(script_pubkey: &Script, message: &[u8], signature: &str) -> Result<(), Error> {
    let encoded = signature.strip_prefix(SIMPLE).ok_or(Error::Variant)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| Error::Encoding)?;
    let witness: Witness = deserialize(&bytes).map_err(|_| Error::Witness)?;
    let to_spend = to_spend(script_pubkey, message);
    let to_sign = to_sign(&to_spend, witness.clone());
    let secp = Secp256k1::verification_only();
    if script_pubkey.is_p2wpkh() {
        let [signature, public_key] = [witness.nth(0), witness.nth(1)];
        let (Some(signature), Some(public_key), 2) = (signature, public_key, witness.len()) else {
            return Err(Error::Invalid);
        };
        let public_key = CompressedPublicKey::from_slice(public_key).map_err(|_| Error::Invalid)?;
        if ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()) != *script_pubkey {
            return Err(Error::Invalid);
        }
        let signature = ecdsa::Signature::from_slice(signature).map_err(|_| Error::Invalid)?;
        if signature.sighash_type != EcdsaSighashType::All {
            return Err(Error::Invalid);
        }
        let sighash = SighashCache::new(&to_sign)
            .p2wpkh_signature_hash(0, script_pubkey, Amount::ZERO, EcdsaSighashType::All)
            .map_err(|_| Error::Invalid)?;
        let digest = Message::from_digest(sighash.to_byte_array());
        secp.verify_ecdsa(&digest, &signature.signature, &public_key.0).map_err(|_| Error::Invalid)
    } else if script_pubkey.is_p2tr() {
        let (Some(signature), 1) = (witness.nth(0), witness.len()) else {
            return Err(Error::Invalid);
        };
        let signature = taproot::Signature::from_slice(signature).map_err(|_| Error::Invalid)?;
        if !matches!(signature.sighash_type, TapSighashType::Default | TapSighashType::All) {
            return Err(Error::Invalid);
        }
        let output_key = XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..])
            .map_err(|_| Error::Invalid)?;
        let prevouts = [to_spend.output[0].clone()];
        let sighash = SighashCache::new(&to_sign)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), signature.sighash_type)
            .map_err(|_| Error::Invalid)?;
        let digest = Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&signature.signature, &digest, &output_key).map_err(|_| Error::Invalid)
    } else {
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::tests::abandon;
    use bitcoin::hex::DisplayHex;
    use bitcoin::{Address, Network, PrivateKey};
    use serde_json::Value;

    /// BIP-322's vectors, as its repository has them: the hashes, and simple signatures of
    /// several scripts, some by keys given.
    fn vectors() -> [Value; 2] {
        let basic = include_str!("testdata/bip322-basic.json");
        let generated = include_str!("testdata/bip322-generated.json");
        [serde_json::from_str(basic).unwrap(), serde_json::from_str(generated).unwrap()]
    }

    fn script(address: &str) -> ScriptBuf {
        let address: Address<_> = address.parse().unwrap();
        address.assume_checked().script_pubkey()
    }

    /// Runs `to_sign` through Bitcoin Core's script interpreter, as BIP-322 validates a
    /// signature: the one input against the one output it spends.
    fn consensus(script_pubkey: &Script, message: &[u8], witness: Witness) -> bool {
        let to_spend = to_spend(script_pubkey, message);
        let to_sign = to_sign(&to_spend, witness);
        let spent = bitcoinconsensus::Utxo {
            script_pubkey: script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: script_pubkey.len() as u32,
            value: 0,
        };
        let tx = serialize(&to_sign);
        bitcoinconsensus::verify(script_pubkey.as_bytes(), 0, &tx, Some(&[spent]), 0).is_ok()
    }

    fn witness(signature: &str) -> Witness {
        let encoded = signature.strip_prefix(SIMPLE).unwrap_or(signature);
        deserialize(&STANDARD.decode(encoded).unwrap()).unwrap()
    }

    #[test]
    fn the_virtual_transactions_are_bip322s() {
        let [basic, _] = vectors();
        for vector in basic["tx_hashes"].as_array().unwrap() {
            let message = vector["message"].as_str().unwrap().as_bytes();
            let script_pubkey = script(vector["address"].as_str().unwrap());
            assert_eq!(message_hash(message).to_lower_hex_string(), vector["message_hash"]);
            let to_spend = to_spend(&script_pubkey, message);
            assert_eq!(to_spend.compute_txid().to_string(), vector["to_spend_tx_hash"]);
            let to_sign = to_sign(&to_spend, Witness::new());
            assert_eq!(to_sign.compute_txid().to_string(), vector["to_sign_tx_hash"]);
        }
    }

    #[test]
    fn every_simple_vector_passes_cores_interpreter_and_ours_where_we_check() {
        for vectors in vectors() {
            for vector in vectors["simple"].as_array().unwrap() {
                let message = vector["message"].as_str().unwrap().as_bytes();
                let script_pubkey = script(vector["address"].as_str().unwrap());
                for signature in vector["bip322_signatures"].as_array().unwrap() {
                    let signature = signature.as_str().unwrap();
                    assert!(consensus(&script_pubkey, message, witness(signature)), "{vector}");
                    if script_pubkey.is_p2wpkh() || script_pubkey.is_p2tr() {
                        // A signature from before the prefix, which a verifier may take as simple.
                        let signature = match signature.starts_with(SIMPLE) {
                            true => signature.to_owned(),
                            false => format!("{SIMPLE}{signature}"),
                        };
                        verify(&script_pubkey, message, &signature).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn every_bad_vector_is_refused() {
        for vectors in vectors() {
            for vector in vectors["error"].as_array().unwrap() {
                let message = vector["message"].as_str().unwrap().as_bytes();
                let Ok(address) = vector["address"].as_str().unwrap().parse::<Address<_>>() else {
                    continue;
                };
                let script_pubkey = address.assume_checked().script_pubkey();
                let signature = vector["signature"].as_str().unwrap();
                assert!(verify(&script_pubkey, message, signature).is_err(), "{vector}");
            }
        }
    }

    #[test]
    fn a_vectors_keys_sign_as_its_signatures() {
        for (file, vectors) in vectors().iter().enumerate() {
            for vector in vectors["simple"].as_array().unwrap() {
                let kind = match vector["type"].as_str().unwrap() {
                    "p2wpkh" => Kind::SegwitV0,
                    "p2tr" => Kind::Taproot,
                    _ => continue,
                };
                let message = vector["message"].as_str().unwrap();
                let key = vector["private_keys"][0].as_str().unwrap();
                let key = PrivateKey::from_wif(key).unwrap().inner;
                let (script_pubkey, signature) =
                    sign_with(kind, &key, message.as_bytes(), &[0; 32]);
                assert_eq!(script_pubkey, script(vector["address"].as_str().unwrap()));
                assert!(consensus(&script_pubkey, message.as_bytes(), witness(&signature)));
                // ECDSA's nonces are RFC6979's, ground to a low R as Bitcoin Core grinds them, so
                // a segwit key's signature is the basic vectors' own. (The generated ones are
                // btcd's, which does not grind.)
                if kind == Kind::SegwitV0 && file == 0 {
                    let signatures = vector["bip322_signatures"].as_array().unwrap();
                    assert!(signatures.iter().any(|known| *known == signature), "{signature}");
                }
            }
        }
    }

    #[test]
    fn an_account_signs_with_its_own_keys_alone() {
        let seed = abandon("");
        for kind in [Kind::SegwitV0, Kind::Taproot] {
            let account = Account::from_seed(&seed, Network::Regtest, kind, 0).unwrap();
            let derivation = Derivation::change(3);
            let signature = sign(&account, &seed, derivation, "Hello World", &[7; 32]).unwrap();
            let script_pubkey = account.script_pubkey(derivation);
            assert!(consensus(&script_pubkey, b"Hello World", witness(&signature)));
            verify(&script_pubkey, b"Hello World", &signature).unwrap();
            assert!(verify(&script_pubkey, b"Hello World!", &signature).is_err());
            let other = account.script_pubkey(Derivation::change(4));
            assert!(verify(&other, b"Hello World", &signature).is_err());
            let wrong = abandon("TREZOR");
            assert!(matches!(
                sign(&account, &wrong, derivation, "", &[7; 32]),
                Err(Error::WrongSeed)
            ));
        }
    }
}
