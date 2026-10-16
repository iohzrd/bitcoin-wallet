//! Keeping the wallet on the device, for whoever opts into it: by default the seed lives in memory
//! and is gone when the wallet closes; kept, it is sealed under a passphrase in a file of its own
//! for the chain (`bitcoin.wallet`, `testnet.wallet`...), with the multisig wallets registered
//! with it, and unlocked from the start screen. The seed's BIP39 passphrase is asked for each time
//! unless kept too. `--no-store` turns keeping off, for a signer that should hold nothing once off.

use std::path::{Path, PathBuf};

use eframe::egui::Ui;
use wallet_core::account::Account;
use wallet_core::bitcoin::Network;
use wallet_core::bitcoin::secp256k1::Secp256k1;
use wallet_core::multisig::Multisig;
use wallet_core::seed::Seed;
use wallet_core::store::{self, Kept as KeptWallet, KeptMultisig, Key, Record};
use zeroize::Zeroizing;

use crate::app::{Registered, Screen, Shared, Wallet};
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

/// Keeping the open wallet, or, once it is kept, changing its passphrase or forgetting it.
pub struct Keep {
    stage: KeepStage,
    /// Whether the seed's BIP39 passphrase is kept with it.
    keep_passphrase: bool,
    /// Whether "Forget it" was pressed once, and waits for a second press.
    forgetting: bool,
}

enum KeepStage {
    About,
    /// The passphrase, typed once, then again to check it.
    Typing {
        first: Option<Zeroizing<String>>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    /// Its key being made.
    Sealing(Task<Result<Key, String>>),
}

impl Keep {
    pub fn new(shared: &Shared) -> Keep {
        let keep_passphrase = shared.kept.as_ref().is_some_and(|kept| kept.passphrase);
        Keep { stage: KeepStage::About, keep_passphrase, forgetting: false }
    }

    pub fn title(&self) -> String {
        match &self.stage {
            KeepStage::About => "Keep on this device",
            KeepStage::Typing { first: None, .. } => "Choose a passphrase",
            KeepStage::Typing { first: Some(_), .. } => "Again, to check it",
            KeepStage::Sealing(_) => "Sealing",
        }
        .to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.stage {
            KeepStage::Typing { .. } => TYPING,
            KeepStage::Sealing(_) => &[],
            KeepStage::About => MOVE_SELECT_BACK,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(path) = shared.config.store.clone() else { return Some(home()) };
        let Some(wallet) = &shared.wallet else { return Some(Screen::Start) };
        let has_passphrase = !wallet.passphrase.is_empty();
        match &mut self.stage {
            KeepStage::About => self.about(ui, shared, &path, has_passphrase),
            KeepStage::Typing { first, typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, first.is_none()) {
                    match first.take() {
                        _ if typed.is_empty() => shared.error("Type a passphrase first."),
                        None => {
                            *first = Some(std::mem::take(typed));
                            shared.refocus();
                        }
                        Some(chosen) if chosen == *typed => {
                            self.stage = KeepStage::Sealing(seal(ui, shared, chosen));
                        }
                        Some(_) => {
                            typed.clear();
                            shared.error("The two differ. Choose it again.");
                            shared.refocus();
                        }
                    }
                }
                if back_pressed(ui) {
                    self.stage = KeepStage::About;
                    shared.refocus();
                }
                None
            }
            KeepStage::Sealing(task) => {
                text(ui, "Sealing the wallet under its passphrase…", body(13.0), DIM);
                let result = task.poll()?;
                let kept = result.map(|key| Kept { key, passphrase: self.keep_passphrase });
                let saved = kept.and_then(|kept| {
                    save(&path, &kept, wallet, shared.config.network).map(|()| kept)
                });
                match saved {
                    Ok(kept) => {
                        shared.kept = Some(kept);
                        shared.info("Kept on this device. Unlock it from the start screen.");
                        Some(home())
                    }
                    Err(error) => {
                        shared.error(error);
                        self.stage = KeepStage::About;
                        None
                    }
                }
            }
        }
    }

    fn about(
        &mut self,
        ui: &mut Ui,
        shared: &mut Shared,
        path: &Path,
        has_passphrase: bool,
    ) -> Option<Screen> {
        let kept = shared.kept.is_some();
        card(ui, |ui| {
            if kept {
                text(ui, "Kept on this device", strong(15.0), TEXT);
                let about = "Sealed under its passphrase. What changes, such as the multisig wallets registered, is kept as it changes.";
                text(ui, about, body(12.5), DIM);
            } else {
                let about = "Sealed under a passphrase you choose, and unlocked with it from the start screen.";
                text(ui, about, body(12.5), TEXT);
                let guessing = "Anyone who copies this device's storage can try passphrases as fast as their computers allow: a PIN or one word falls in hours. Use several words.";
                text(ui, guessing, body(11.5), WARN);
                if path.exists() {
                    text(ui, "This replaces the wallet kept here now.", body(11.5), WARN);
                }
                if shared.seed().is_some() {
                    text(ui, "It is no backup: keep your recovery words.", body(11.5), DIM);
                }
            }
            text(ui, path.display().to_string(), mono(10.5), FAINT);
        });
        let mut next = None;
        if kept {
            let change = menu_item(ui, "Change the passphrase", Some("Seal it under another"));
            shared.autofocus(&change);
            if change.clicked() {
                self.stage = typing_stage();
            }
        }
        if has_passphrase {
            let detail = match self.keep_passphrase {
                true => "Kept with the seed. Press to ask for it each time",
                false => "Asked for each time. Press to keep it too",
            };
            let item = menu_item(ui, "Seed passphrase", Some(detail));
            if !kept {
                shared.autofocus(&item);
            }
            if item.clicked() {
                self.keep_passphrase = !self.keep_passphrase;
                if let Some(kept) = &mut shared.kept {
                    kept.passphrase = self.keep_passphrase;
                    shared.save();
                }
            }
        }
        if kept {
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
            let choose = button(ui, "Choose a passphrase", Emphasis::Primary, ui.available_width());
            shared.autofocus(&choose);
            if choose.clicked() {
                self.stage = typing_stage();
            }
        }
        if matches!(self.stage, KeepStage::Typing { .. }) {
            shared.refocus();
        }
        next.or_else(|| back_pressed(ui).then(home))
    }
}

fn home() -> Screen {
    Screen::Home(Home::default())
}

fn typing_stage() -> KeepStage {
    KeepStage::Typing { first: None, typed: Zeroizing::default(), keyboard: Keyboard::default() }
}

/// Makes the key of `passphrase` under a fresh salt, on a thread, as it takes a handheld seconds.
fn seal(ui: &Ui, shared: &Shared, passphrase: Zeroizing<String>) -> Task<Result<Key, String>> {
    let params = shared.config.kdf;
    Task::spawn(ui.ctx(), move || {
        let mut salt = [0; 16];
        getrandom::fill(&mut salt).map_err(|error| format!("no randomness: {error}"))?;
        Key::derive(&passphrase, salt, params).map_err(|error| error.to_string())
    })
}

/// Unlocking the wallet kept on the device.
pub struct Unlock {
    stage: UnlockStage,
}

enum UnlockStage {
    Typing {
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
    /// The file being opened under the passphrase typed.
    Opening(Task<Result<(Key, Record), String>>),
    /// The seed's BIP39 passphrase, which was not kept with it.
    SeedPassphrase {
        opened: Option<(Key, Record)>,
        typed: Zeroizing<String>,
        keyboard: Keyboard,
    },
}

impl Default for Unlock {
    fn default() -> Unlock {
        Unlock {
            stage: UnlockStage::Typing {
                typed: Zeroizing::default(),
                keyboard: Keyboard::default(),
            },
        }
    }
}

impl Unlock {
    pub fn title(&self) -> String {
        match self.stage {
            UnlockStage::SeedPassphrase { .. } => "Seed passphrase",
            _ => "Unlock",
        }
        .to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.stage {
            UnlockStage::Opening(_) => &[],
            _ => TYPING,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(path) = shared.config.store.clone() else { return Some(Screen::Start) };
        match &mut self.stage {
            UnlockStage::Typing { typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    match std::fs::read(&path) {
                        Ok(file) => {
                            let passphrase = std::mem::take(typed);
                            self.stage = UnlockStage::Opening(Task::spawn(ui.ctx(), move || {
                                store::open(&passphrase, &file).map_err(|error| error.to_string())
                            }));
                        }
                        Err(error) => shared.error(format!("{}: {error}", path.display())),
                    }
                }
            }
            UnlockStage::Opening(task) => {
                text(ui, "Unlocking…", body(13.0), DIM);
                match task.poll()? {
                    Ok((key, record)) => match &record.wallet {
                        // A seed whose passphrase was not kept: its fingerprint says it has one.
                        KeptWallet::Seed { mnemonic, passphrase: None, fingerprint, .. }
                            if Seed::new(mnemonic, "").fingerprint(&Secp256k1::signing_only())
                                != *fingerprint =>
                        {
                            self.stage = UnlockStage::SeedPassphrase {
                                opened: Some((key, record)),
                                typed: Zeroizing::default(),
                                keyboard: Keyboard::default(),
                            };
                            shared.refocus();
                        }
                        KeptWallet::Seed { passphrase, .. } => {
                            let passphrase = passphrase.clone().unwrap_or_default();
                            return self.unlock(ui, shared, key, &record, &passphrase);
                        }
                        KeptWallet::Watch { .. } => {
                            return self.unlock(ui, shared, key, &record, "");
                        }
                    },
                    Err(error) => {
                        shared.error(error);
                        *self = Unlock::default();
                        shared.refocus();
                    }
                }
                return None;
            }
            UnlockStage::SeedPassphrase { opened, typed, keyboard } => {
                if typing(ui, shared, typed, keyboard, false) {
                    // Checked here rather than in unlocking, which takes the key: a passphrase
                    // mistyped leaves it for another try.
                    let right = match opened.as_ref().map(|(_, record)| &record.wallet) {
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
                    } else if let Some((key, record)) = opened.take() {
                        let passphrase = std::mem::take(typed);
                        return self.unlock(ui, shared, key, &record, &passphrase);
                    }
                }
            }
        }
        back_pressed(ui).then_some(Screen::Start)
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
                *self = Unlock::default();
                shared.refocus();
                None
            }
        }
    }
}
