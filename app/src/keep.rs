//! Keeping the wallet on the device, for whoever opts into it: by default the seed lives in memory
//! and is gone when the wallet closes; kept, it is sealed under a passphrase, a FIDO2 security
//! key, or both, in a file of its own for the chain (`bitcoin.wallet`, `testnet.wallet`...), with
//! the multisig wallets registered with it, and unlocked from the start screen. The seed's BIP39 passphrase is asked for each time
//! unless kept too. `--no-store` turns keeping off, for a signer that should hold nothing once off.

use std::path::{Path, PathBuf};

use eframe::egui::{ScrollArea, Ui};
use wallet_core::account::Account;
use wallet_core::bitcoin::Network;
use wallet_core::bitcoin::secp256k1::Secp256k1;
use wallet_core::multisig::Multisig;
use wallet_core::seed::Seed;
use wallet_core::store::{
    self, Header, Kept as KeptWallet, KeptMultisig, Key, Record, SecurityKey,
};
use zeroize::Zeroizing;

use crate::app::{Registered, Screen, Shared, Wallet};
use crate::fido::{self, KeyError};
use crate::files;
use crate::home::Home;
use crate::task::Task;
use crate::theme::{DIM, FAINT, TEXT, WARN, body, mono, strong};
use crate::widgets::{
    Control, Emphasis, Hint, Keyboard, Keys, Press, back_pressed, button, card, field, menu_item,
    text,
};

const MOVE_SELECT_BACK: &[Hint] =
    &[(Control::DPad, "Move"), (Control::A, "Select"), (Control::B, "Back")];
const TYPING: &[Hint] = &[(Control::DPad, "Move"), (Control::A, "Type"), (Control::B, "Back")];

/// What a build without the `security-key` feature says of a security key.
const NO_KEYS: &str = "This build cannot use security keys: build it with --features security-key.";

/// Below this many characters a passphrase is flagged as one a copy of the card gives up.
const SHORT: usize = 12;

/// The file the wallet of `network` is kept in, in `dir`.
pub fn path(dir: &Path, network: Network) -> PathBuf {
    dir.join(format!("{network}.wallet"))
}

/// The open wallet's key, while it is kept.
pub struct Kept {
    key: Key,
    /// Whether the seed's BIP39 passphrase is kept with it, rather than asked for on unlocking.
    passphrase: bool,
}

/// Seals `wallet` under the key and writes it to `path`, over what was there.
pub fn save(path: &Path, kept: &Kept, wallet: &Wallet, network: Network) -> Result<(), String> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|error| format!("no randomness: {error}"))?;
    let file = store::seal(&kept.key, nonce, &record(wallet, kept.passphrase, network));
    files::write_private(path, &file).map_err(|error| format!("{}: {error}", path.display()))
}

fn record(wallet: &Wallet, keep_passphrase: bool, network: Network) -> Record {
    let kept = match (&wallet.mnemonic, &wallet.seed) {
        (Some(mnemonic), Some(seed)) => KeptWallet::Seed {
            mnemonic: mnemonic.clone(),
            passphrase: (keep_passphrase && !wallet.passphrase.is_empty())
                .then(|| wallet.passphrase.clone()),
            fingerprint: seed.fingerprint(&Secp256k1::signing_only()),
            kind: wallet.account.kind(),
        },
        _ => KeptWallet::Watch { descriptor: wallet.account.descriptor().to_string() },
    };
    let multisigs = (wallet.multisigs.iter())
        .map(|registered| KeptMultisig {
            descriptor: registered.multisig.descriptor().to_string(),
            name: registered.name.clone(),
        })
        .collect();
    Record { network, birthday: wallet.birthday, wallet: kept, multisigs }
}

/// The wallet `record` keeps, its seed under `passphrase`, and what of it no longer opens: a
/// multisig wallet this version refuses is left out rather than keeping the rest locked.
fn open(
    record: &Record,
    passphrase: &str,
    network: Network,
) -> Result<(Wallet, Vec<String>), String> {
    if record.network != network {
        return Err(format!("It is kept for {}, and the app is on {network}.", record.network));
    }
    let mut wallet = match &record.wallet {
        KeptWallet::Seed { mnemonic, fingerprint, kind, .. } => {
            let seed = Seed::new(mnemonic, passphrase);
            if seed.fingerprint(&Secp256k1::signing_only()) != *fingerprint {
                return Err("That passphrase opens another wallet than the one kept here.".into());
            }
            let account =
                Account::from_seed(&seed, network, *kind, 0).map_err(|e| e.to_string())?;
            let mut wallet = Wallet::signing(mnemonic.clone(), seed, account);
            wallet.passphrase = Zeroizing::new(passphrase.to_owned());
            wallet
        }
        KeptWallet::Watch { descriptor } => {
            let account = Account::from_descriptor(descriptor, network);
            Wallet::watching(account.map_err(|error| error.to_string())?)
        }
    };
    wallet.birthday = record.birthday;
    let mut problems = Vec::new();
    for KeptMultisig { descriptor, name } in &record.multisigs {
        let multisig = Multisig::from_descriptor(descriptor, network);
        let seed = wallet.seed.as_ref().ok_or(wallet_core::multisig::Error::NotACosigner);
        match multisig.and_then(|multisig| multisig.with_seed(seed?)) {
            Ok(multisig) => wallet.multisigs.push(Registered { multisig, name: name.clone() }),
            Err(error) => problems
                .push(format!("{}: {error}", name.as_deref().unwrap_or("A multisig wallet"))),
        }
    }
    Ok((wallet, problems))
}

/// A passphrase as typed, each character but the last a dot.
fn masked(typed: &str) -> String {
    let count = typed.chars().count();
    let last = typed.chars().last().map(String::from).unwrap_or_default();
    "•".repeat(count.saturating_sub(1)) + &last
}

/// A passphrase being typed on the keyboard: the dots, its length (and, if `flag_short`, whether
/// it is short), and the keys, all a handheld's screen holds. Returns whether the keyboard's Done
/// was pressed.
fn typing(
    ui: &mut Ui,
    shared: &mut Shared,
    typed: &mut Zeroizing<String>,
    keyboard: &mut Keyboard,
    flag_short: bool,
) -> bool {
    let count = typed.chars().count();
    let trailing = match flag_short && (1..SHORT).contains(&count) {
        true => (format!("{count} · short: use several words"), WARN),
        false => (count.to_string(), FAINT),
    };
    field(ui, &masked(typed), 18.0, Some((&trailing.0, trailing.1)));
    match keyboard.show(ui, Keys::Full, Some(shared.focus_flag())) {
        Some(Press::Char(char)) => typed.push(char),
        Some(Press::Backspace) => {
            typed.pop();
        }
        Some(Press::Done) => return true,
        None => {}
    }
    false
}

/// Why sealing or opening a wallet failed: at the security key, which another try can get past
/// (a wrong PIN, a key not yet plugged in), or in the sealing, which starts over.
enum Failure {
    Key(KeyError),
    Other(String),
}

/// Keeping the open wallet, or, once it is kept, sealing it again or forgetting it.
pub struct Keep {
    stage: KeepStage,
    /// Whether the seed's BIP39 passphrase is kept with it.
    keep_passphrase: bool,
    /// Whether it is sealed with a security key.
    with_key: bool,
    /// Whether "Forget it" was pressed once, and waits for a second press.
    forgetting: bool,
}

enum KeepStage {
    About,
    /// The passphrase, typed once, then again to check it; with a security key, it may be none.
    Typing {
        first: Option<Zeroizing<String>>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    /// The security key's PIN, or, for a key with none, a new one, typed twice.
    KeyPin {
        passphrase: Zeroizing<String>,
        new: bool,
        first: Option<Zeroizing<String>>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    /// The key being made: from the passphrase, and the security key's secret once touched.
    Sealing {
        task: Task<Result<Key, Failure>>,
        passphrase: Zeroizing<String>,
    },
}

impl Keep {
    pub fn new(shared: &Shared) -> Keep {
        let keep_passphrase = shared.kept.as_ref().is_some_and(|kept| kept.passphrase);
        let with_key = shared.kept.as_ref().is_some_and(|kept| kept.key.security_key().is_some());
        Keep { stage: KeepStage::About, keep_passphrase, with_key, forgetting: false }
    }

    pub fn title(&self) -> String {
        match &self.stage {
            KeepStage::About => "Keep on this device",
            KeepStage::Typing { first: None, .. } if self.with_key => "A passphrase too, or none",
            KeepStage::Typing { first: None, .. } => "Choose a passphrase",
            KeepStage::Typing { first: Some(_), .. } => "Again, to check it",
            KeepStage::KeyPin { new: false, .. } => "The key's PIN",
            KeepStage::KeyPin { first: None, .. } => "Choose the key's PIN",
            KeepStage::KeyPin { first: Some(_), .. } => "The PIN again, to check it",
            KeepStage::Sealing { .. } if self.with_key => "Touch your key",
            KeepStage::Sealing { .. } => "Sealing",
        }
        .to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.stage {
            KeepStage::Typing { .. } | KeepStage::KeyPin { .. } => TYPING,
            KeepStage::Sealing { .. } => &[],
            KeepStage::About => MOVE_SELECT_BACK,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(path) = shared.config.store.clone() else { return Some(home()) };
        let Some(wallet) = &shared.wallet else { return Some(Screen::Start) };
        let has_passphrase = !wallet.passphrase.is_empty();
        match &mut self.stage {
            KeepStage::About => return self.about(ui, shared, &path, has_passphrase),
            KeepStage::Typing { first, typed, keyboard } => {
                let done = typing(ui, shared, typed, keyboard, first.is_none() && !self.with_key);
                if done {
                    match first.take() {
                        // With a security key, the key and its PIN are enough.
                        None if typed.is_empty() && self.with_key => {
                            self.stage = key_pin(shared, Zeroizing::default());
                        }
                        _ if typed.is_empty() => shared.error("Type a passphrase first."),
                        None => *first = Some(std::mem::take(typed)),
                        Some(chosen) if chosen == *typed => {
                            self.stage = match self.with_key {
                                true => key_pin(shared, chosen),
                                false => {
                                    let task = seal(ui, shared, chosen.clone(), None);
                                    KeepStage::Sealing { task, passphrase: chosen }
                                }
                            };
                        }
                        Some(_) => {
                            typed.clear();
                            shared.error("The two differ. Choose it again.");
                        }
                    }
                    shared.refocus();
                }
            }
            KeepStage::KeyPin { passphrase, new, first, typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    let pin = std::mem::take(typed);
                    match (*new, first.take()) {
                        _ if pin.chars().count() < fido::SHORTEST_PIN => {
                            shared.error("A key's PIN is at least 4 characters.");
                        }
                        (true, None) => *first = Some(pin),
                        (true, Some(chosen)) if chosen != pin => {
                            shared.error("The two differ. Choose it again.");
                        }
                        (new, _) => {
                            let passphrase = std::mem::take(passphrase);
                            let task = seal(ui, shared, passphrase.clone(), Some((pin, new)));
                            self.stage = KeepStage::Sealing { task, passphrase };
                        }
                    }
                    shared.refocus();
                }
            }
            KeepStage::Sealing { task, passphrase } => {
                let about = match self.with_key {
                    true => {
                        "Touch your key when it blinks: once to make its credential, once to give its secret."
                    }
                    false => "Sealing the wallet under its passphrase…",
                };
                text(ui, about, body(13.0), DIM);
                let result = task.poll()?;
                let kept = result.map(|key| Kept { key, passphrase: self.keep_passphrase });
                let saved = kept.and_then(|kept| {
                    let network = shared.config.network;
                    save(&path, &kept, wallet, network).map(|()| kept).map_err(Failure::Other)
                });
                match saved {
                    Ok(kept) => {
                        shared.kept = Some(kept);
                        shared.info("Kept on this device. Unlock it from the start screen.");
                        return Some(home());
                    }
                    // Another try at the key, its PIN or a key plugged in, keeps the passphrase.
                    Err(Failure::Key(error)) if retryable(&error) => {
                        let new = error == KeyError::PinNotSet;
                        shared.error(if new {
                            "This key has no PIN yet: choose one.".into()
                        } else {
                            error.to_string()
                        });
                        self.stage = KeepStage::KeyPin {
                            passphrase: std::mem::take(passphrase),
                            new,
                            first: None,
                            typed: Zeroizing::default(),
                            keyboard: Keyboard::digits(),
                        };
                    }
                    Err(Failure::Key(error)) => {
                        shared.error(error);
                        self.stage = KeepStage::About;
                    }
                    Err(Failure::Other(error)) => {
                        shared.error(error);
                        self.stage = KeepStage::About;
                    }
                }
                shared.refocus();
                return None;
            }
        }
        if back_pressed(ui) {
            self.stage = KeepStage::About;
            shared.refocus();
        }
        None
    }

    fn about(
        &mut self,
        ui: &mut Ui,
        shared: &mut Shared,
        path: &Path,
        has_passphrase: bool,
    ) -> Option<Screen> {
        let kept = shared
            .kept
            .as_ref()
            .map(|kept| (kept.key.security_key().is_some(), kept.key.has_passphrase()));
        let mut next = None;
        let mut start = false;
        // In a scroll area, which follows the focus: the card and the items are more than a
        // handheld's screen holds.
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            card(ui, |ui| {
                match kept {
                    Some((key, passphrase)) => {
                        text(ui, "Kept on this device", strong(15.0), TEXT);
                        let sealed = match (key, passphrase) {
                            (true, true) => "Sealed under its passphrase and a security key.",
                            (true, false) => "Sealed under a security key and its PIN.",
                            _ => "Sealed under its passphrase.",
                        };
                        let about = format!(
                            "{sealed} What changes, such as the multisig wallets registered, is kept as it changes."
                        );
                        text(ui, about, body(12.5), DIM);
                    }
                    None if self.with_key => {
                        let about = "Sealed under your FIDO2 security key and its PIN, and a passphrase too if you choose one.";
                        text(ui, about, body(12.5), TEXT);
                        let key = "A copy of this device's storage is no use without the key, which locks after eight wrong PINs. Lose the key, and you restore the wallet from its words.";
                        text(ui, key, body(11.5), DIM);
                    }
                    None => {
                        let about = "Sealed under a passphrase you choose, and unlocked with it from the start screen.";
                        text(ui, about, body(12.5), TEXT);
                        let guessing = match shared.config.keys {
                            Some(_) => "Anyone who copies this device's storage can try passphrases as fast as their computers allow: a PIN or one word falls in hours. Use several words, or a security key.",
                            None => "Anyone who copies this device's storage can try passphrases as fast as their computers allow: a PIN or one word falls in hours. Use several words.",
                        };
                        text(ui, guessing, body(11.5), WARN);
                    }
                }
                if kept.is_none() {
                    if path.exists() {
                        text(ui, "This replaces the wallet kept here now.", body(11.5), WARN);
                    }
                    if shared.seed().is_some() {
                        text(ui, "It is no backup: keep your recovery words.", body(11.5), DIM);
                    }
                }
                text(ui, path.display().to_string(), mono(10.5), FAINT);
            });
            if kept.is_some() {
                let again =
                    menu_item(ui, "Seal it again", Some("A new passphrase, security key, or both"));
                shared.autofocus(&again);
                start = again.clicked();
            }
            if shared.config.keys.is_some() {
                let detail = match self.with_key {
                    true => "A FIDO2 key, with its PIN. Press to go without",
                    false => "None. Press to add a FIDO2 key",
                };
                let key = menu_item(ui, "Security key", Some(detail));
                shared.autofocus(&key);
                if key.clicked() {
                    self.with_key = !self.with_key;
                }
            }
            if has_passphrase {
                let detail = match self.keep_passphrase {
                    true => "Kept with the seed. Press to ask for it each time",
                    false => "Asked for each time. Press to keep it too",
                };
                if menu_item(ui, "Seed passphrase", Some(detail)).clicked() {
                    self.keep_passphrase = !self.keep_passphrase;
                    if let Some(kept) = &mut shared.kept {
                        kept.passphrase = self.keep_passphrase;
                        shared.save();
                    }
                }
            }
            if kept.is_some() {
                let detail = match self.forgetting {
                    true => "Press again: the file is erased",
                    false => "The wallet stays open until closed",
                };
                let forget = menu_item(ui, "Forget it on this device", Some(detail));
                if forget.clicked() {
                    if self.forgetting {
                        match files::erase(path) {
                            Ok(()) => {
                                shared.kept = None;
                                shared.info("Forgotten on this device.");
                                next = Some(home());
                            }
                            Err(error) => shared.error(format!("{}: {error}", path.display())),
                        }
                    }
                    self.forgetting = true;
                }
                if !forget.has_focus() {
                    self.forgetting = false;
                }
            } else {
                let label = if self.with_key { "Continue" } else { "Choose a passphrase" };
                start = button(ui, label, Emphasis::Primary, ui.available_width()).clicked();
            }
        });
        if start {
            self.stage = KeepStage::Typing {
                first: None,
                typed: Zeroizing::default(),
                keyboard: Keyboard::default(),
            };
            shared.refocus();
        }
        next.or_else(|| back_pressed(ui).then(home))
    }
}

fn home() -> Screen {
    Screen::Home(Home::default())
}

/// Whether another try can get past a security key's error: the PIN, or the key, again.
fn retryable(error: &KeyError) -> bool {
    !matches!(error, KeyError::NotFido2 | KeyError::NoHmacSecret | KeyError::PinBlocked)
}

/// The PIN stage for the security key plugged in: a new PIN for a key with none.
fn key_pin(shared: &mut Shared, passphrase: Zeroizing<String>) -> KeepStage {
    let state = shared.config.keys.as_ref().map(|keys| keys.state());
    let new = match state.unwrap_or(Err(KeyError::Other(NO_KEYS.into()))) {
        Ok(state) => !state.pin_set,
        // A key not plugged in yet, or not one that makes secrets: said now, and again when its
        // PIN is tried, by then plugged in or not.
        Err(error) => {
            shared.error(error);
            false
        }
    };
    let (first, typed, keyboard) = (None, Zeroizing::default(), Keyboard::digits());
    KeepStage::KeyPin { passphrase, new, first, typed, keyboard }
}

/// Makes the key of `passphrase` under a fresh salt, and with a security key, `(pin, new)`, of a
/// credential made on it (once its PIN is set, if `new`) for the wallet, on a thread: it takes a
/// handheld seconds, and the key a touch.
fn seal(
    ui: &Ui,
    shared: &Shared,
    passphrase: Zeroizing<String>,
    security_key: Option<(Zeroizing<String>, bool)>,
) -> Task<Result<Key, Failure>> {
    let (params, keys) = (shared.config.kdf, shared.config.keys.clone());
    let keys = keys.ok_or(Failure::Other(NO_KEYS.into()));
    Task::spawn(ui.ctx(), move || {
        let mut salt = [0; 16];
        getrandom::fill(&mut salt)
            .map_err(|error| Failure::Other(format!("no randomness: {error}")))?;
        let Some((pin, new)) = security_key else {
            return Key::derive(&passphrase, salt, params)
                .map_err(|error| Failure::Other(error.to_string()));
        };
        let keys = keys?;
        if new {
            keys.set_pin(&pin).map_err(Failure::Key)?;
        }
        let mut key_salt = [0; 32];
        getrandom::fill(&mut key_salt)
            .map_err(|error| Failure::Other(format!("no randomness: {error}")))?;
        let (credential, secret) = keys.enroll(&pin, &key_salt).map_err(Failure::Key)?;
        let security_key = SecurityKey { credential, salt: key_salt };
        Key::derive_with(&passphrase, salt, params, security_key, &secret)
            .map_err(|error| Failure::Other(error.to_string()))
    })
}

/// Unlocking the wallet kept on the device.
pub struct Unlock {
    file: Vec<u8>,
    header: Header,
    stage: UnlockStage,
}

enum UnlockStage {
    Passphrase {
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    KeyPin {
        passphrase: Zeroizing<String>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    /// The file being opened: the security key's secret asked for, then the key made.
    Opening {
        task: Task<Result<(Key, Record), Failure>>,
        passphrase: Zeroizing<String>,
    },
    /// The seed's BIP39 passphrase, which was not kept with it.
    SeedPassphrase {
        opened: Option<Box<(Key, Record)>>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
}

impl Unlock {
    /// Unlocking the file `shared`'s config keeps the wallet in, as its header says to.
    pub fn new(shared: &Shared) -> Result<Unlock, String> {
        let path = shared.config.store.as_ref().ok_or("Keeping is off.")?;
        let file = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let header = Header::read(&file).map_err(|error| format!("{}: {error}", path.display()))?;
        if header.security_key.is_some() && shared.config.keys.is_none() {
            return Err(format!("It is sealed with a security key. {NO_KEYS}"));
        }
        let stage = first_stage(&header);
        Ok(Unlock { file, header, stage })
    }

    pub fn title(&self) -> String {
        match self.stage {
            UnlockStage::KeyPin { .. } => "The key's PIN",
            UnlockStage::Opening { .. } if self.header.security_key.is_some() => "Touch your key",
            UnlockStage::SeedPassphrase { .. } => "Seed passphrase",
            _ => "Unlock",
        }
        .to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.stage {
            UnlockStage::Opening { .. } => &[],
            _ => TYPING,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        match &mut self.stage {
            UnlockStage::Passphrase { typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    let passphrase = std::mem::take(typed);
                    self.stage = match self.header.security_key {
                        Some(_) => key_pin_stage(passphrase),
                        None => self.opening(ui, shared, passphrase, None),
                    };
                    shared.refocus();
                }
            }
            UnlockStage::KeyPin { passphrase, typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    let (passphrase, pin) = (std::mem::take(passphrase), std::mem::take(typed));
                    self.stage = self.opening(ui, shared, passphrase, Some(pin));
                    shared.refocus();
                }
            }
            UnlockStage::Opening { task, passphrase } => {
                let about = match self.header.security_key {
                    Some(_) => "Touch your key when it blinks.",
                    None => "Unlocking…",
                };
                text(ui, about, body(13.0), DIM);
                match task.poll()? {
                    Ok((key, record)) => match &record.wallet {
                        // A seed whose passphrase was not kept: its fingerprint says it has one.
                        KeptWallet::Seed { mnemonic, passphrase: None, fingerprint, .. }
                            if Seed::new(mnemonic, "").fingerprint(&Secp256k1::signing_only())
                                != *fingerprint =>
                        {
                            self.stage = UnlockStage::SeedPassphrase {
                                opened: Some(Box::new((key, record))),
                                typed: Zeroizing::default(),
                                keyboard: Keyboard::default(),
                            };
                        }
                        KeptWallet::Seed { passphrase, .. } => {
                            let passphrase = passphrase.clone().unwrap_or_default();
                            return self.unlock(ui, shared, key, &record, &passphrase);
                        }
                        KeptWallet::Watch { .. } => {
                            return self.unlock(ui, shared, key, &record, "");
                        }
                    },
                    // The PIN again, or the key plugged in: the passphrase stays typed.
                    Err(Failure::Key(error)) if retryable(&error) => {
                        shared.error(error);
                        self.stage = key_pin_stage(std::mem::take(passphrase));
                    }
                    Err(Failure::Key(error)) => {
                        shared.error(error);
                        self.stage = first_stage(&self.header);
                    }
                    Err(Failure::Other(error)) => {
                        shared.error(error);
                        self.stage = first_stage(&self.header);
                    }
                }
                shared.refocus();
                return None;
            }
            UnlockStage::SeedPassphrase { opened, typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    // Checked here rather than in unlocking, which takes the key: a passphrase
                    // mistyped leaves it for another try.
                    let right = match opened.as_deref().map(|(_, record)| &record.wallet) {
                        Some(KeptWallet::Seed { mnemonic, fingerprint, .. }) => {
                            let seed = Seed::new(mnemonic, typed);
                            seed.fingerprint(&Secp256k1::signing_only()) == *fingerprint
                        }
                        _ => false,
                    };
                    if !right {
                        typed.clear();
                        shared
                            .error("That passphrase opens another wallet than the one kept here.");
                        shared.refocus();
                    } else if let Some(opened) = opened.take() {
                        let (key, record) = *opened;
                        let passphrase = std::mem::take(typed);
                        return self.unlock(ui, shared, key, &record, &passphrase);
                    }
                }
            }
        }
        back_pressed(ui).then_some(Screen::Start)
    }

    /// Opens the file on a thread: the security key's secret, under `pin`, a touch away, and
    /// Argon2's seconds.
    fn opening(
        &self,
        ui: &Ui,
        shared: &Shared,
        passphrase: Zeroizing<String>,
        pin: Option<Zeroizing<String>>,
    ) -> UnlockStage {
        let (keys, file, security_key) =
            (shared.config.keys.clone(), self.file.clone(), self.header.security_key.clone());
        let typed = passphrase.clone();
        let task = Task::spawn(ui.ctx(), move || {
            let secret = match (&security_key, &pin) {
                (Some(SecurityKey { credential, salt }), Some(pin)) => {
                    let keys = keys.ok_or(Failure::Other(NO_KEYS.into()))?;
                    Some(keys.secret(pin, credential, salt).map_err(Failure::Key)?)
                }
                _ => None,
            };
            let secret = secret.as_deref();
            store::open(&typed, secret, &file).map_err(|error| Failure::Other(error.to_string()))
        });
        UnlockStage::Opening { task, passphrase }
    }

    /// Opens the wallet `record` keeps with its seed under `passphrase`, and goes to it; or, if
    /// it does not open, starts over.
    fn unlock(
        &mut self,
        ui: &Ui,
        shared: &mut Shared,
        key: Key,
        record: &Record,
        passphrase: &str,
    ) -> Option<Screen> {
        let network = shared.config.network;
        match open(record, passphrase, network) {
            Ok((wallet, problems)) => {
                #[cfg(feature = "online")]
                shared.online.open(ui.ctx(), &wallet.account, Some(wallet.birthday));
                #[cfg(not(feature = "online"))]
                let _ = ui;
                let kept_passphrase =
                    matches!(&record.wallet, KeptWallet::Seed { passphrase: Some(_), .. });
                shared.kept = Some(Kept { key, passphrase: kept_passphrase });
                shared.wallet = Some(wallet);
                if !problems.is_empty() {
                    shared.error(format!("Not opened: {}", problems.join("; ")));
                }
                Some(home())
            }
            Err(error) => {
                shared.error(error);
                self.stage = first_stage(&self.header);
                shared.refocus();
                None
            }
        }
    }
}

/// Where unlocking a file starts: its passphrase, or, sealed with a security key alone, the
/// key's PIN.
fn first_stage(header: &Header) -> UnlockStage {
    match header.passphrase {
        true => {
            UnlockStage::Passphrase { typed: Zeroizing::default(), keyboard: Keyboard::default() }
        }
        false => key_pin_stage(Zeroizing::default()),
    }
}

fn key_pin_stage(passphrase: Zeroizing<String>) -> UnlockStage {
    UnlockStage::KeyPin { passphrase, typed: Zeroizing::default(), keyboard: Keyboard::digits() }
}
