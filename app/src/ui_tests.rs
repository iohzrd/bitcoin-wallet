//! The app driven as a handheld drives it, by the arrow keys, Enter and Escape alone: the events
//! the gamepad sends. `screenshots` renders the screens to PNG, for looking at by eye.

use std::path::PathBuf;
use std::str::FromStr;

use eframe::egui::{Event, Key, Role, vec2};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use wallet_core::Mnemonic;
use wallet_core::account::{Account, Derivation, Kind};
use wallet_core::bitcoin::absolute::LockTime;
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::bitcoin::secp256k1::Secp256k1;
use wallet_core::bitcoin::transaction::Version;
use wallet_core::bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};
use wallet_core::multisig::{CosignerKey, Multisig};
use wallet_core::policy::Policy;
use wallet_core::psbt::review;
use wallet_core::seed::Seed;

use crate::app::{App, Config, Screen, Wallet};

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon about";

/// The app with `dirs` for PSBTs, at the scale that fits the screen.
fn app(dirs: Vec<PathBuf>) -> App {
    let config = Config { network: Network::Regtest, dirs };
    #[cfg(feature = "online")]
    let online = {
        let auth = wallet_node::Auth::UserPass { user: String::new(), password: String::new() };
        crate::online::Online::new(
            wallet_node::Node::new("http://127.0.0.1:9", auth),
            Network::Regtest,
        )
    };
    App::new(
        config,
        None,
        #[cfg(feature = "online")]
        online,
    )
}

fn harness(app: App) -> Harness<'static, App> {
    // Enough frames for a click's hover animation to settle.
    let mut harness = Harness::builder()
        .with_size(vec2(640.0, 480.0))
        .with_max_steps(32)
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness
}

fn press(harness: &mut Harness<App>, key: Key) {
    harness.key_press(key);
    harness.run();
}

/// Types on a physical keyboard, a key at a time.
fn type_text(harness: &mut Harness<App>, text: &str) {
    for char in text.chars() {
        harness.event(Event::Text(char.to_string()));
        harness.run();
    }
}

/// Whether some label on the screen holds `text`.
fn shown(harness: &Harness<App>, text: &str) {
    assert!(harness.query_all_by_label_contains(text).next().is_some(), "{text} is not shown");
}

fn abandon() -> Wallet {
    abandon_with("")
}

/// The abandon mnemonic's wallet under `passphrase`.
fn abandon_with(passphrase: &str) -> Wallet {
    let seed = Seed::new(&Mnemonic::parse(ABANDON).unwrap(), passphrase);
    let account = Account::from_seed(&seed, Network::Regtest, Kind::Taproot, 0).unwrap();
    Wallet::signing(Mnemonic::parse(ABANDON).unwrap(), seed, account)
}

/// A 2-of-3 of three passphrases' keys, the first the abandon wallet's own.
fn two_of_three() -> String {
    let keys: Vec<String> = (["", "TREZOR", "a third"].iter())
        .map(|passphrase| {
            let seed = Seed::new(&Mnemonic::parse(ABANDON).unwrap(), passphrase);
            format!("{}/<0;1>/*", CosignerKey::new(&seed, Network::Regtest, 0).unwrap())
        })
        .collect();
    format!("wsh(sortedmulti(2,{}))", keys.join(","))
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wallet-ui-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A PSBT spending 50,000 sat of the policy's to someone else, with change, as a coordinator
/// writes one.
fn payment(account: &dyn Policy) -> Psbt {
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_str(&"11".repeat(32)).unwrap(), 0),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: account.script_pubkey(Derivation::receive(0)),
        }],
    };
    let other = Seed::new(&Mnemonic::parse(ABANDON).unwrap(), "someone else");
    let payee = Account::from_seed(&other, Network::Regtest, Kind::Taproot, 0).unwrap();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..TxIn::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: payee.script_pubkey(Derivation::receive(0)),
            },
            TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: account.script_pubkey(Derivation::change(0)),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(funding);
    account.annotate_input(&mut psbt.inputs[0], Derivation::receive(0));
    account.annotate_output(&mut psbt.outputs[1], Derivation::change(0));
    psbt
}

#[test]
fn a_new_seed_is_made_written_down_checked_and_opened_with_the_gamepad_alone() {
    let mut harness = harness(app(Vec::new()));
    press(&mut harness, Key::Enter); // Make a new seed
    press(&mut harness, Key::Enter); // 12 words
    let Screen::Generate(generate) = harness.state().screen() else { panic!("not making a seed") };
    let words = generate.shown_words().unwrap();
    assert_eq!(words.len(), 12);
    press(&mut harness, Key::Enter); // I wrote them down
    // One word of each three, among others of the seed's own.
    let mut asked = 0;
    while let Screen::Generate(generate) = harness.state().screen() {
        let (right, choices) = generate.question().expect("a question");
        assert!(choices.iter().all(|choice| words.contains(choice)), "{choices:?}");
        for _ in 0..choices.iter().position(|choice| *choice == right).unwrap() {
            press(&mut harness, Key::ArrowDown);
        }
        press(&mut harness, Key::Enter);
        asked += 1;
    }
    assert_eq!(asked, 4);
    assert!(matches!(harness.state().screen(), Screen::Setup(_)));
    press(&mut harness, Key::Enter); // Open
    assert!(matches!(harness.state().screen(), Screen::Home(_)));

    let seed = Seed::new(&Mnemonic::parse(words.join(" ")).unwrap(), "");
    let opened = harness.state_mut().shared().wallet.as_ref().unwrap().account.fingerprint();
    assert_eq!(opened, seed.fingerprint(&Secp256k1::signing_only()));
}

#[test]
fn fifty_dice_rolls_make_the_seed_seedsigner_makes_of_them() {
    let mut harness = harness(app(Vec::new()));
    press(&mut harness, Key::Enter); // New seed
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // 12 words from dice
    shown(&harness, "0 of 50");
    // The first roll with the D-pad on the faces: 1, then a 2 taken back with B.
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::ArrowRight);
    press(&mut harness, Key::Enter);
    shown(&harness, "12");
    press(&mut harness, Key::Escape);
    shown(&harness, "1 of 50");
    // The rest on a keyboard.
    type_text(&mut harness, &"1".repeat(49));
    let Screen::Generate(generate) = harness.state().screen() else { panic!("left the seed") };
    let words = generate.shown_words().expect("the words, once the rolls are in").join(" ");
    assert_eq!(words, "diet glad hat rural panther lawsuit act drop gallery urge where fit");
}

#[test]
fn a_wrong_word_in_the_check_goes_back_to_the_words() {
    let mut harness = harness(app(Vec::new()));
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::Enter);
    let Screen::Generate(generate) = harness.state().screen() else { panic!("not checking") };
    let (right, choices) = generate.question().unwrap();
    let wrong = choices.iter().position(|choice| *choice != right).unwrap();
    for _ in 0..wrong {
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter);
    let Screen::Generate(generate) = harness.state().screen() else { panic!("left the seed") };
    assert!(generate.shown_words().is_some(), "back to the words");
}

#[test]
fn a_seed_restores_from_its_words_on_the_screens_keyboard_or_a_real_one() {
    let mut harness = harness(app(Vec::new()));
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Restore a seed
    press(&mut harness, Key::Enter); // 12 words
    // The first word with the D-pad on the screen's keys: a, b to its right, a again.
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::ArrowRight);
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::ArrowLeft);
    press(&mut harness, Key::Enter); // "aba" fits only "abandon"
    harness.get_by_label_contains("1 abandon");
    // The rest on a keyboard, with a slip taken back.
    type_text(&mut harness, "abx");
    harness.key_press(Key::Backspace);
    harness.run();
    type_text(&mut harness, &"aba".repeat(10));
    type_text(&mut harness, "abou");
    assert!(matches!(harness.state().screen(), Screen::Setup(_)), "twelve words make a seed");
    press(&mut harness, Key::Enter); // Open
    let opened = harness.state_mut().shared().wallet.as_ref().unwrap().account.fingerprint();
    assert_eq!(opened.to_string(), "73c5da0a");
}

#[test]
fn escape_takes_back_a_word_at_a_time_and_then_leaves() {
    let mut harness = harness(app(Vec::new()));
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter);
    press(&mut harness, Key::Enter);
    type_text(&mut harness, "abaab");
    harness.get_by_label_contains("1 abandon");
    press(&mut harness, Key::Escape); // the letters typed of word 2
    harness.get_by_label_contains("1 abandon");
    press(&mut harness, Key::Escape); // word 1
    assert!(harness.query_by_label_contains("1 abandon").is_none());
    press(&mut harness, Key::Escape); // the word count
    press(&mut harness, Key::Escape); // the screen
    assert!(matches!(harness.state().screen(), Screen::Start));
}

#[test]
fn a_psbt_on_the_card_is_reviewed_signed_and_written_back_beside_it() {
    let dir = temp_dir("sign");
    let wallet = abandon();
    let psbt = payment(&wallet.account);
    std::fs::write(dir.join("pay.psbt"), psbt.serialize()).unwrap();
    let mut app = app(vec![dir.clone()]);
    app.open(wallet);
    let mut harness = harness(app);

    press(&mut harness, Key::Enter); // Sign a PSBT
    press(&mut harness, Key::Enter); // pay.psbt
    assert!(matches!(harness.state().screen(), Screen::Review(_)));
    shown(&harness, "0.00040000 BTC");
    shown(&harness, "Change #0");
    shown(&harness, "0.00009000 BTC");
    shown(&harness, "0.00001000 BTC");
    // Down through every line to the button.
    for _ in 0..10 {
        if harness.get_by_label("Sign").is_focused() {
            break;
        }
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Outgoing(_)));

    let signed = std::fs::read(dir.join("pay-signed.psbt")).unwrap();
    let signed = wallet_airgap::file::read_psbt(&signed).unwrap();
    assert!(signed.inputs[0].tap_key_sig.is_some());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn every_screen_past_the_first_goes_back_without_escape_or_b() {
    let mut app = app(Vec::new());
    app.open(abandon());
    let mut harness = harness(app);
    // The title bar's button, clicked.
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Export account
    assert!(matches!(harness.state().screen(), Screen::Export(_)));
    harness.get_by_role_and_label(Role::Button, "Back").click();
    harness.run();
    assert!(matches!(harness.state().screen(), Screen::Home(_)));
    // The same button, reached by the D-pad from the top of the screen.
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Addresses
    assert!(matches!(harness.state().screen(), Screen::Addresses(_)));
    for _ in 0..4 {
        press(&mut harness, Key::ArrowUp);
    }
    assert!(harness.get_by_role_and_label(Role::Button, "Back").is_focused());
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Home(_)));
    // The hint at the bottom, clicked: with no gamepad, it names the key.
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter);
    harness.get_by_label("Esc: Back").click();
    harness.run();
    assert!(matches!(harness.state().screen(), Screen::Home(_)));
    let back = harness.query_by_role_and_label(Role::Button, "Back");
    assert!(back.is_none(), "home has nowhere to go back to");
}

#[test]
fn b_cancels_a_review_from_anywhere_on_it() {
    let dir = temp_dir("cancel");
    let wallet = abandon();
    std::fs::write(dir.join("pay.psbt"), payment(&wallet.account).serialize()).unwrap();
    let mut app = app(vec![dir.clone()]);
    app.open(wallet);
    let mut harness = harness(app);
    press(&mut harness, Key::Enter); // Sign
    press(&mut harness, Key::Enter); // pay.psbt
    press(&mut harness, Key::ArrowDown);
    assert!(matches!(harness.state().screen(), Screen::Review(_)));
    press(&mut harness, Key::Escape);
    assert!(matches!(harness.state().screen(), Screen::Home(_)), "B cancels");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_backup_shows_the_words_checks_a_copy_and_draws_its_seedqr() {
    let mut app = app(Vec::new());
    app.open(abandon());
    let mut harness = harness(app);
    for _ in 0..3 {
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter); // Backup
    assert!(matches!(harness.state().screen(), Screen::Backup(_)));

    press(&mut harness, Key::Enter); // Show the words
    shown(&harness, "about");
    press(&mut harness, Key::Enter); // Done
    assert!(matches!(harness.state().screen(), Screen::Backup(_)));

    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Check a copy
    type_text(&mut harness, &"aba".repeat(11));
    type_text(&mut harness, "abou");
    assert!(matches!(harness.state().screen(), Screen::Backup(_)));
    shown(&harness, "Your copy matches the seed");

    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter);
    // "ability" where the seed has "abandon".
    type_text(&mut harness, "abi");
    type_text(&mut harness, &"aba".repeat(10));
    type_text(&mut harness, "abou");
    shown(&harness, "Word 1 of your copy is not the seed's");

    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // SeedQR
    shown(&harness, "21 × 21");
    harness.get_by_label("Standard SeedQR").click();
    harness.run();
    shown(&harness, "25 × 25");
}

#[test]
fn a_multisig_registers_from_the_card_and_its_psbt_takes_two_signers() {
    let dir = temp_dir("multisig");
    let descriptor = two_of_three();
    std::fs::write(dir.join("vault.txt"), &descriptor).unwrap();
    let watching = Multisig::from_descriptor(&descriptor, Network::Regtest).unwrap();
    std::fs::write(dir.join("pay.psbt"), payment(&watching).serialize()).unwrap();

    let sign_as = |passphrase: &str, file: &str| {
        let mut app = app(vec![dir.clone()]);
        app.open(abandon_with(passphrase));
        let mut harness = harness(app);
        for _ in 0..4 {
            press(&mut harness, Key::ArrowDown);
        }
        press(&mut harness, Key::Enter); // Multisig
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // Register a wallet
        press(&mut harness, Key::Enter); // vault.txt
        assert!(matches!(harness.state().screen(), Screen::MultisigWallet(_)));
        shown(&harness, "2 of 3 signatures");
        press(&mut harness, Key::Enter); // Sign
        harness.get_by_label(file).click();
        harness.run();
        assert!(matches!(harness.state().screen(), Screen::Review(_)));
        shown(&harness, "Change #0");
        for _ in 0..10 {
            if harness.get_by_label("Sign").is_focused() {
                break;
            }
            press(&mut harness, Key::ArrowDown);
        }
        press(&mut harness, Key::Enter);
        assert!(matches!(harness.state().screen(), Screen::Outgoing(_)));
        harness
    };

    let first = sign_as("", "pay.psbt");
    shown(&first, "1 OF 2 SIGNATURES");
    drop(first);
    let second = sign_as("a third", "pay-signed.psbt");
    shown(&second, "SIGNED");

    let signed = std::fs::read(dir.join("pay-signed-signed.psbt")).unwrap();
    let mut signed = wallet_airgap::file::read_psbt(&signed).unwrap();
    assert!(review(&watching, &signed).unwrap().complete());
    use wallet_core::miniscript::psbt::PsbtExt;
    signed.finalize_mut(&Secp256k1::verification_only()).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

/// Opens the abandon wallet and goes to Multisig, then Register a wallet.
fn registering(dir: &std::path::Path) -> Harness<'static, App> {
    let mut app = app(vec![dir.to_path_buf()]);
    app.open(abandon());
    let mut harness = harness(app);
    for _ in 0..4 {
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter); // Multisig
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Register a wallet
    harness
}

#[test]
fn a_wallet_registers_from_sparrows_descriptor_export_and_from_bsms() {
    let dir = temp_dir("sparrow");
    let descriptor = two_of_three();
    let watching = Multisig::from_descriptor(&descriptor, Network::Regtest).unwrap();
    // As Sparrow writes it, with its annotations, which the checksum covers.
    let annotated = format!("{descriptor}?bh=850123");
    let mut engine = wallet_core::miniscript::descriptor::checksum::Engine::new();
    engine.input(&annotated).unwrap();
    let sparrow = format!("# Receive and change descriptor:\n{annotated}#{}\n", engine.checksum());
    std::fs::write(dir.join("Vault.txt"), &sparrow).unwrap();
    let mut harness = registering(&dir);
    press(&mut harness, Key::Enter); // Vault.txt
    assert!(matches!(harness.state().screen(), Screen::MultisigWallet(_)));
    let first = watching.address(Derivation::receive(0)).to_string();
    shown(&harness, &crate::widgets::grouped(&first)[..14]);
    drop(harness);

    // A BSMS record whose first address is not the wallet's is refused.
    std::fs::remove_file(dir.join("Vault.txt")).unwrap();
    let bsms = |address: &str| format!("BSMS 1.0\n{descriptor}\n/0/*,/1/*\n{address}\n");
    std::fs::write(dir.join("vault.bsms"), bsms("bcrt1qnotthewallets")).unwrap();
    let mut harness = registering(&dir);
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Register(_)));
    shown(&harness, "is not the wallet's");
    drop(harness);
    std::fs::write(dir.join("vault.bsms"), bsms(&first)).unwrap();
    let mut harness = registering(&dir);
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::MultisigWallet(_)));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_psbt_with_warnings_takes_a_second_press_to_sign() {
    let dir = temp_dir("warned");
    let wallet = abandon();
    let mut psbt = payment(&wallet.account);
    // A fee of 6% of the coin: change cut from 9,000 to 6,000 sat.
    psbt.unsigned_tx.output[1].value = Amount::from_sat(6_000);
    std::fs::write(dir.join("pay.psbt"), psbt.serialize()).unwrap();
    let mut app = app(vec![dir.clone()]);
    app.open(wallet);
    let mut harness = harness(app);
    press(&mut harness, Key::Enter); // Sign
    press(&mut harness, Key::Enter); // pay.psbt
    shown(&harness, "That is a lot");
    for _ in 0..10 {
        if harness.get_by_label("Sign").is_focused() {
            break;
        }
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Review(_)), "not yet");
    assert!(harness.get_by_label("Sign anyway").is_focused());
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Outgoing(_)));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_multisig_key_saves_to_the_card_for_a_coordinator() {
    let dir = temp_dir("cosigner");
    let mut app = app(vec![dir.clone()]);
    app.open(abandon());
    let mut harness = harness(app);
    for _ in 0..4 {
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter); // Multisig
    press(&mut harness, Key::Enter); // Your key
    assert!(matches!(harness.state().screen(), Screen::CosignerKey(_)));
    press(&mut harness, Key::Enter); // Save
    let saved = std::fs::read_to_string(dir.join("73c5da0a-multisig-key.txt")).unwrap();
    assert!(saved.starts_with("[73c5da0a/48'/1'/0'/2']tpub"), "{saved}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// Renders the screens to `target/screenshots`, on a handheld's 640 by 480 and a desktop window.
#[test]
#[ignore = "renders with wgpu; run by hand to look at the screens"]
fn screenshots() {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/screenshots");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    for (device, size) in [("handheld", vec2(640.0, 480.0)), ("desktop", vec2(1000.0, 640.0))] {
        let dir = temp_dir(&format!("shots-{device}"));
        let wallet = abandon();
        std::fs::write(dir.join("pay.psbt"), payment(&wallet.account).serialize()).unwrap();
        let vault = two_of_three();
        std::fs::write(dir.join("vault.txt"), &vault).unwrap();
        let watching = Multisig::from_descriptor(&vault, Network::Regtest).unwrap();
        std::fs::write(dir.join("vault.psbt"), payment(&watching).serialize()).unwrap();
        let mut warned = payment(&wallet.account);
        warned.unsigned_tx.output[1].value = Amount::from_sat(6_000);
        warned.unsigned_tx.lock_time =
            wallet_core::bitcoin::absolute::LockTime::from_height(850_000).unwrap();
        std::fs::write(dir.join("warned.psbt"), warned.serialize()).unwrap();
        let mut harness = Harness::builder()
            .with_size(size)
            .with_max_steps(32)
            .wgpu()
            .build_ui_state(|ui, app: &mut App| app.show(ui), app(vec![dir.clone()]));
        let shot = |harness: &mut Harness<App>, name: &str| {
            harness.run_steps(4);
            let image = harness.render().unwrap();
            image.save(out.join(format!("{device}-{name}.png"))).unwrap();
        };
        harness.run();
        shot(&mut harness, "01-start");
        press(&mut harness, Key::Enter);
        shot(&mut harness, "02-length");
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // 12 words from dice
        shot(&mut harness, "02a-dice-empty");
        type_text(&mut harness, "16253416252341664312513");
        press(&mut harness, Key::ArrowRight);
        press(&mut harness, Key::ArrowRight);
        shot(&mut harness, "02b-dice");
        for _ in 0..24 {
            press(&mut harness, Key::Escape);
        }
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // 24 words
        shot(&mut harness, "03-words");
        press(&mut harness, Key::Enter);
        press(&mut harness, Key::Enter); // I wrote them down
        shot(&mut harness, "04-check");
        for _ in 0..4 {
            press(&mut harness, Key::Escape);
        }
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // Restore
        shot(&mut harness, "05-restore-count");
        press(&mut harness, Key::Enter);
        type_text(&mut harness, &"aba".repeat(4));
        type_text(&mut harness, "ab");
        shot(&mut harness, "06-restore-typing");
        type_text(&mut harness, &format!("a{}abou", "aba".repeat(6)));
        shot(&mut harness, "07-setup");
        press(&mut harness, Key::ArrowUp);
        press(&mut harness, Key::ArrowUp);
        press(&mut harness, Key::Enter); // Passphrase
        type_text(&mut harness, "correct horse");
        shot(&mut harness, "08-passphrase");
        harness.state_mut().open(wallet);
        harness.run();
        shot(&mut harness, "09-home");
        press(&mut harness, Key::Enter);
        shot(&mut harness, "10-files");
        harness.get_by_label("pay.psbt").click();
        harness.run();
        shot(&mut harness, "11-review");
        for _ in 0..10 {
            if harness.get_by_label("Sign").is_focused() {
                break;
            }
            press(&mut harness, Key::ArrowDown);
        }
        shot(&mut harness, "12-review-end");
        press(&mut harness, Key::Enter);
        shot(&mut harness, "13-signed");
        press(&mut harness, Key::Enter); // Show as QR codes
        shot(&mut harness, "14-signed-qr");
        press(&mut harness, Key::Escape);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // Export account
        shot(&mut harness, "15-export");
        press(&mut harness, Key::Escape);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // Addresses
        press(&mut harness, Key::PageDown);
        shot(&mut harness, "16-addresses");
        press(&mut harness, Key::Escape);
        for _ in 0..3 {
            press(&mut harness, Key::ArrowDown);
        }
        press(&mut harness, Key::Enter); // Backup
        shot(&mut harness, "17-backup");
        press(&mut harness, Key::Enter); // Show the words
        shot(&mut harness, "18-backup-words");
        press(&mut harness, Key::Escape);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // SeedQR
        shot(&mut harness, "19-seedqr");
        press(&mut harness, Key::Escape);
        press(&mut harness, Key::Escape);
        for _ in 0..4 {
            press(&mut harness, Key::ArrowDown);
        }
        press(&mut harness, Key::Enter); // Multisig
        shot(&mut harness, "20-multisig");
        press(&mut harness, Key::Enter); // Your key
        shot(&mut harness, "21-multisig-key");
        press(&mut harness, Key::Escape);
        press(&mut harness, Key::ArrowDown);
        press(&mut harness, Key::Enter); // Register a wallet
        shot(&mut harness, "22-register");
        press(&mut harness, Key::Enter); // vault.txt
        shot(&mut harness, "23-multisig-wallet");
        press(&mut harness, Key::Enter); // Sign
        harness.get_by_label("vault.psbt").click();
        harness.run();
        for _ in 0..5 {
            press(&mut harness, Key::ArrowDown);
        }
        shot(&mut harness, "24-multisig-review");
        for _ in 0..3 {
            press(&mut harness, Key::Escape);
        }
        press(&mut harness, Key::Enter); // Sign
        harness.get_by_label("warned.psbt").click();
        harness.run();
        for _ in 0..4 {
            press(&mut harness, Key::ArrowDown);
        }
        shot(&mut harness, "25-review-warnings");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Steps the app in real time until `done`, as the node answers on threads of its own.
#[cfg(feature = "online")]
fn wait_for(harness: &mut Harness<App>, what: &str, done: impl Fn(&mut App) -> bool) {
    let start = std::time::Instant::now();
    while !done(harness.state_mut()) {
        assert!(start.elapsed().as_secs() < 20, "waited too long for {what}");
        std::thread::sleep(std::time::Duration::from_millis(20));
        harness.step();
    }
    harness.run();
}

#[cfg(feature = "online")]
#[test]
#[ignore = "needs BITCOIND"]
fn a_hot_wallet_pays_through_the_node_and_hands_out_its_addresses() {
    use serde_json::json;
    use wallet_node::regtest::Regtest;

    let regtest = Regtest::start("ui-pay");
    let wallet = abandon();
    let account = wallet.account.clone();
    regtest.mine(101, &account.address(Derivation::receive(0)));
    let config = Config { network: Network::Regtest, dirs: Vec::new() };
    let online = crate::online::Online::new(regtest.node.clone(), Network::Regtest);
    let mut app = App::new(config, None, online);
    app.open(wallet);
    let mut harness = harness(app);
    let ctx = harness.ctx.clone();
    harness.state_mut().shared().online.open(&ctx, &account, Some(0));
    wait_for(&mut harness, "the wallet on the node", |app| app.shared().online.connected());
    shown(&harness, "50.00000000 BTC");

    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Send
    assert!(matches!(harness.state().screen(), Screen::Pay(_)));
    let other = Seed::new(&Mnemonic::parse(ABANDON).unwrap(), "someone else");
    let payee = Account::from_seed(&other, Network::Regtest, Kind::Taproot, 0).unwrap();
    type_text(&mut harness, &payee.address(Derivation::receive(0)).to_string());
    press(&mut harness, Key::Tab);
    type_text(&mut harness, "1.5");
    harness.get_by_label("Make the PSBT").click();
    wait_for(&mut harness, "the node's PSBT", |app| matches!(app.screen(), Screen::Review(_)));
    shown(&harness, "1.50000000 BTC");
    for _ in 0..10 {
        if harness.get_by_label("Sign").is_focused() {
            break;
        }
        press(&mut harness, Key::ArrowDown);
    }
    press(&mut harness, Key::Enter);
    assert!(matches!(harness.state().screen(), Screen::Outgoing(_)));
    harness.get_by_label("Broadcast").click();
    harness.run();
    let mempool = |regtest: &Regtest| regtest.node.call("getrawmempool", json!([])).unwrap();
    wait_for(&mut harness, "the broadcast", |_| {
        mempool(&regtest).as_array().is_some_and(|txs| txs.len() == 1)
    });
    let txid = mempool(&regtest)[0].as_str().unwrap().to_owned();
    harness.get_by_label(&format!("Broadcast {txid}"));

    assert!(matches!(harness.state().screen(), Screen::Home(_)));
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::ArrowDown);
    press(&mut harness, Key::Enter); // Receive
    assert!(matches!(harness.state().screen(), Screen::Receive(_)), "the focus held its place");
    wait_for(
        &mut harness,
        "an address",
        |app| matches!(app.screen(), Screen::Receive(r) if r.shown().is_some()),
    );
    let Screen::Receive(receive) = harness.state().screen() else { unreachable!() };
    let (address, derivation) = receive.shown().unwrap();
    assert_eq!(address, account.address(derivation), "the address the signer shows");
    harness.get_by_label_contains(&format!("receive address {}.", derivation.index));
}
