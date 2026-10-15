//! The watch-only wallet and the signer against a real node: a Bitcoin Core (or Knots) `bitcoind`
//! on regtest, named by the BITCOIND environment variable. Each test starts its own in a
//! directory of its own and stops it when done.
//!
//!     BITCOIND=/path/to/bitcoind cargo test -p wallet-node --features test-support -- --ignored

use std::str::FromStr;

use wallet_core::Mnemonic;
use wallet_core::account::{Account, Derivation, Keychain, Kind};
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::bitcoin::{Address, Amount, Network, SignedAmount};
use wallet_core::psbt;
use wallet_core::seed::Seed;
use wallet_node::regtest::Regtest;
use wallet_node::{Auth, Node};

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon about";

fn seed(passphrase: &str) -> Seed {
    Seed::new(&Mnemonic::parse(ABANDON).unwrap(), passphrase)
}

/// An address that is not the account's.
fn elsewhere(kind: Kind) -> Address {
    let other = Account::from_seed(&seed("someone else"), Network::Regtest, kind, 0).unwrap();
    other.address(Derivation::receive(0))
}

fn the_node_funds_a_psbt_the_signer_signs_and_the_node_broadcasts(kind: Kind) {
    let regtest = Regtest::start(&format!("{kind:?}"));
    let node = &regtest.node;
    assert_eq!(node.network().unwrap(), Network::Regtest);
    let seed = seed("");
    let account = Account::from_seed(&seed, Network::Regtest, kind, 0).unwrap();
    let wallet = node.wallet(&account, None).unwrap();
    assert_eq!(node.wallet(&account, None).unwrap().name(), wallet.name(), "found, not made again");

    let (address, derivation) = wallet.receive_address().unwrap();
    assert_eq!(derivation, Derivation::receive(0));
    assert_eq!(address, account.address(derivation), "the address the signer shows");
    assert_eq!(wallet.receive_address().unwrap().1, Derivation::receive(1));

    // 101 blocks to the account, of which the first block's 50 BTC is spendable.
    regtest.mine(101, &address);
    let balance = wallet.balance().unwrap();
    assert_eq!(balance.trusted, Amount::from_int_btc(50));
    assert_eq!(balance.total(), Amount::from_int_btc(101 * 50));

    let payee = elsewhere(kind);
    let psbt = wallet.create_psbt(&[(payee.clone(), Amount::ONE_BTC)], 2.0, None).unwrap();
    // To the signer and back, as base64.
    let mut psbt = Psbt::from_str(&psbt.to_string()).unwrap();
    let review = psbt::review(&account, &psbt).unwrap();
    assert!(review.inputs.iter().all(|input| input.derivation.is_some()), "{review:#?}");
    assert_eq!(review.warnings, [], "the node includes each input's previous transaction");
    let [payment] =
        &review.outputs.iter().filter(|o| o.derivation.is_none()).collect::<Vec<_>>()[..]
    else {
        panic!("one payment: {review:#?}");
    };
    assert_eq!((payment.address.as_ref(), payment.txout.value), (Some(&payee), Amount::ONE_BTC));
    let change = review.outputs.iter().find_map(|output| output.derivation).unwrap();
    assert_eq!(change.keychain, Keychain::Change);
    let fee_rate = review.min_fee_rate().unwrap();
    assert!((1.95..=2.0).contains(&fee_rate), "{fee_rate} sat/vB");

    let signed = psbt::sign(&account, &seed, &mut psbt, &[7; 32]).unwrap();
    assert_eq!(signed, psbt.inputs.len());
    let txid = wallet.broadcast(&psbt).unwrap();
    regtest.mine(1, &payee);

    let spent = Amount::ONE_BTC + review.fee;
    assert_eq!(wallet.balance().unwrap().total(), Amount::from_int_btc(101 * 50) - spent);
    let history = wallet.history(5).unwrap();
    assert_eq!(history[0].txid, txid, "newest first");
    assert_eq!(history[0].amount, -spent.to_signed().unwrap());
    assert_eq!(history[0].confirmations, 1);
    assert!(
        history[1..].iter().all(|entry| entry.amount == SignedAmount::from_sat(50 * 100_000_000))
    );
}

#[test]
#[ignore = "needs BITCOIND"]
fn a_segwit_v0_payment_round_trips_through_the_node() {
    the_node_funds_a_psbt_the_signer_signs_and_the_node_broadcasts(Kind::SegwitV0);
}

#[test]
#[ignore = "needs BITCOIND"]
fn a_taproot_payment_round_trips_through_the_node() {
    the_node_funds_a_psbt_the_signer_signs_and_the_node_broadcasts(Kind::Taproot);
}

#[test]
#[ignore = "needs BITCOIND"]
fn a_restored_account_finds_what_it_received_before_its_import() {
    let regtest = Regtest::start("rescan");
    let account = Account::from_seed(&seed(""), Network::Regtest, Kind::Taproot, 0).unwrap();
    regtest.mine(101, &account.address(Derivation::receive(0)));
    regtest.mine(1, &account.address(Derivation::change(5)));
    let wallet = regtest.node.wallet(&account, Some(0)).unwrap();
    assert_eq!(wallet.balance().unwrap().total(), Amount::from_int_btc(102 * 50));
}

#[test]
#[ignore = "needs BITCOIND"]
fn a_wrong_login_is_an_http_error() {
    let regtest = Regtest::start("login");
    let wrong = Auth::UserPass { user: "nobody".into(), password: "wrong".into() };
    let refused = Node::new(format!("http://127.0.0.1:{}", regtest.port), wrong).network();
    assert!(matches!(refused, Err(wallet_node::Error::Status { status: 401, .. })), "{refused:?}");
}
