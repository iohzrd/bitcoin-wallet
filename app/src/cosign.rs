//! Co-signing multisig wallets. The seed's part in one is its BIP48 key, which this exports for a
//! coordinator (Sparrow, Nunchuk, Liana) to make the wallet with, beside the other signers' keys.
//! The wallet's descriptor then comes back on the card and is registered here, for as long as the
//! wallet is open: that is what lets the signer tell the wallet's change from a payment, sign its
//! PSBTs, and show its addresses.

use std::path::PathBuf;

use eframe::egui::{Align, Layout, ScrollArea, Ui};
use wallet_airgap::qr::Qr;
use wallet_core::account::Derivation;
use wallet_core::multisig::{CosignerKey, Multisig};
use wallet_core::policy::Policy;

use crate::app::{Registered, Screen, Shared};
use crate::files;
use crate::home::{Addresses, Home};
use crate::sign::{Files, Purpose, Which};
use crate::theme::{ACCENT, DIM, FAINT, TEXT, body, mono, strong};
use crate::widgets::{
    Emphasis, back_pressed, beside_qr, button, card, chip, grouped, menu_item, text,
};

/// The multisig menu: the seed's key, registering a wallet, and the wallets registered.
pub struct Cosign;

impl Cosign {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(wallet) = &shared.wallet else { return Some(Screen::Start) };
        let summaries: Vec<(String, String)> = wallet.multisigs.iter().map(summary).collect();
        let mut next = None;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let about = "Make the wallet in a coordinator with this key and the other signers', then register its descriptor here.";
            text(ui, about, body(12.5), DIM);
            let key = menu_item(ui, "Your key", Some("BIP48, for the coordinator"));
            shared.autofocus(&key);
            if key.clicked() {
                next = KeyExport::new(shared).map(Screen::CosignerKey);
            }
            if menu_item(ui, "Register a wallet", Some("Its descriptor, from the card")).clicked() {
                next = Some(Screen::Register(Register::new(shared)));
            }
            for (index, (title, keys)) in summaries.iter().enumerate() {
                if menu_item(ui, title, Some(keys)).clicked() {
                    next = Some(Screen::MultisigWallet(WalletScreen::new(index)));
                }
            }
        });
        next.or_else(|| back_pressed(ui).then(|| Screen::Home(Home::default())))
    }
}

/// A registered wallet in a line, and its signers' fingerprints in another.
fn summary(registered: &Registered) -> (String, String) {
    let multisig = &registered.multisig;
    let signers = multisig.fingerprints().count();
    let name = registered.name.clone().unwrap_or_else(|| multisig.checksum());
    let title = format!("{name} · {} of {signers}", multisig.threshold());
    let keys: Vec<String> = (multisig.fingerprints().enumerate())
        .map(|(index, fingerprint)| match multisig.ours() == Some(index) {
            true => format!("{fingerprint} (this seed)"),
            false => fingerprint.to_string(),
        })
        .collect();
    (title, keys.join(", "))
}

/// The seed's BIP48 key, as a QR code and a file, for a coordinator.
pub struct KeyExport {
    text: String,
    file: String,
    qr: Option<Qr>,
}

impl KeyExport {
    fn new(shared: &mut Shared) -> Option<KeyExport> {
        let wallet = shared.wallet.as_ref()?;
        match CosignerKey::new(wallet.seed.as_ref()?, shared.config.network, 0) {
            Ok(key) => {
                let text = key.to_string();
                let file = format!("{}-multisig-key.txt", key.origin.0);
                Some(KeyExport { qr: Qr::new(&text).ok(), text, file })
            }
            Err(error) => {
                shared.error(error);
                None
            }
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let dirs = shared.config.dirs.clone();
        let mut save = None;
        beside_qr(ui, self.qr.as_ref(), |ui| {
            let about = "Scan it into the coordinator, or save it to the card, as one of the wallet's keys.";
            text(ui, about, body(12.5), DIM);
            text(ui, &self.text, mono(10.5), FAINT);
            ScrollArea::vertical().show(ui, |ui| {
                for dir in &dirs {
                    let label = dir.file_name().map_or_else(
                        || dir.display().to_string(),
                        |name| name.to_string_lossy().into_owned(),
                    );
                    let width = ui.available_width();
                    let button =
                        button(ui, &format!("Save to {label}"), Emphasis::Secondary, width);
                    shared.autofocus(&button);
                    if button.clicked() {
                        save = Some(dir.join(&self.file));
                    }
                }
            });
        });
        if let Some(path) = save {
            // No newline after it: Sparrow's importer reads one as part of the key.
            match files::write(&path, self.text.as_bytes()) {
                Ok(()) => shared.info(format!("Saved {}", path.display())),
                Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
            }
        }
        back_pressed(ui).then_some(Screen::Cosign(Cosign))
    }
}

/// Registering a wallet from a descriptor file on the card.
pub struct Register {
    files: Vec<PathBuf>,
}

impl Register {
    fn new(shared: &Shared) -> Register {
        Register { files: files::setup_files(&shared.config.dirs) }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let mut chosen = None;
        let mut look_again = false;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            if self.files.is_empty() {
                card(ui, |ui| {
                    text(ui, "No multisig setups here", strong(15.0), TEXT);
                    let about = "Export the wallet from the coordinator to the card (a descriptor, BSMS or Coldcard file), then look again. Looked in:";
                    text(ui, about, body(12.5), DIM);
                    for dir in &shared.config.dirs {
                        text(ui, dir.display().to_string(), mono(11.0), FAINT);
                    }
                });
            }
            for path in &self.files {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let dir = path.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
                let item = menu_item(ui, &name, Some(&dir));
                shared.autofocus(&item);
                if item.clicked() {
                    chosen = Some(path.clone());
                }
            }
            let again = button(ui, "Look again", Emphasis::Secondary, ui.available_width());
            shared.autofocus(&again);
            look_again = again.clicked();
        });
        if look_again {
            *self = Register::new(shared);
            shared.refocus();
        }
        if let Some(path) = chosen {
            match register(shared, &path) {
                Ok(index) => {
                    shared.save();
                    return Some(Screen::MultisigWallet(WalletScreen::new(index)));
                }
                Err(error) => shared.error(format!("{}: {error}", path.display())),
            }
        }
        back_pressed(ui).then_some(Screen::Cosign(Cosign))
    }
}

/// Registers the wallet the setup file at `path` describes, if the seed is one of its signers,
/// and returns its place among the registered; the same place again for one already registered.
/// A BSMS record's first address must be the wallet's, as BIP-129 has the signer check.
fn register(shared: &mut Shared, path: &PathBuf) -> Result<usize, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let setup = wallet_airgap::setup::read(&text).map_err(|error| error.to_string())?;
    let network = shared.config.network;
    let wallet = shared.wallet.as_mut().ok_or("No wallet is open.")?;
    let seed = wallet.seed.as_ref().ok_or("A watch-only wallet signs nothing.")?;
    let multisig = Multisig::from_descriptor(&setup.descriptor, network);
    let multisig = multisig.and_then(|multisig| multisig.with_seed(seed));
    let multisig = multisig.map_err(|error| error.to_string())?;
    let first = multisig.address(Derivation::receive(0)).to_string();
    if let Some(stated) = setup.first_address.filter(|stated| *stated != first) {
        return Err(format!("its first address, {stated}, is not the wallet's, {first}"));
    }
    let known = (wallet.multisigs.iter())
        .position(|known| known.multisig.descriptor() == multisig.descriptor());
    Ok(known.unwrap_or_else(|| {
        wallet.multisigs.push(Registered { multisig, name: setup.name });
        wallet.multisigs.len() - 1
    }))
}

/// A registered wallet: its signers, and what to do with it.
pub struct WalletScreen {
    index: usize,
    /// Whether "Forget this wallet" was pressed once, and waits for a second press.
    forgetting: bool,
}

impl WalletScreen {
    pub fn new(index: usize) -> WalletScreen {
        WalletScreen { index, forgetting: false }
    }

    pub fn title(&self) -> String {
        "Multisig wallet".to_owned()
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let registered = shared.wallet.as_ref().and_then(|wallet| wallet.multisigs.get(self.index));
        let Some(Registered { multisig, name }) = registered else {
            return Some(Screen::Cosign(Cosign));
        };
        let label = name.clone().unwrap_or_else(|| multisig.checksum());
        let first = multisig.address(Derivation::receive(0)).to_string();
        let signers: Vec<(String, bool)> = (multisig.fingerprints().enumerate())
            .map(|(index, fingerprint)| (fingerprint.to_string(), multisig.ours() == Some(index)))
            .collect();
        let threshold = multisig.threshold();
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let title = format!("{threshold} of {} signatures", signers.len());
                text(ui, title, strong(15.0), TEXT);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    text(ui, label, mono(11.5), FAINT);
                });
            });
            ui.horizontal_wrapped(|ui| {
                for (fingerprint, ours) in &signers {
                    let color = if *ours { ACCENT } else { DIM };
                    chip(ui, fingerprint, mono(11.5), color);
                }
            });
            // What BIP-129 has a signer show: the coordinator shows the same, or it is not this
            // wallet.
            text(ui, format!("First address {}", grouped(&first)), mono(11.0), FAINT);
        });
        let mut next = None;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let sign = menu_item(ui, "Sign", Some("Review a PSBT of this wallet's and sign it"));
            shared.autofocus(&sign);
            if sign.clicked() {
                let which = Which::Multisig(self.index);
                next = Some(Screen::Files(Files::new(shared, Purpose::Sign, which)));
            }
            if menu_item(ui, "Addresses", Some("Check one the coordinator shows")).clicked() {
                next = Some(Screen::Addresses(Addresses::new(Which::Multisig(self.index))));
            }
            let forget = match (self.forgetting, shared.kept.is_some()) {
                (true, _) => "Press again to forget it",
                (false, true) => "Off this device too; register it again to sign",
                (false, false) => "Register it again to sign for it",
            };
            let forget = menu_item(ui, "Forget this wallet", Some(forget));
            if forget.clicked() {
                if self.forgetting {
                    if let Some(wallet) = shared.wallet.as_mut() {
                        wallet.multisigs.remove(self.index);
                    }
                    shared.save();
                    next = Some(Screen::Cosign(Cosign));
                }
                self.forgetting = true;
            }
            if !forget.has_focus() {
                self.forgetting = false;
            }
        });
        next.or_else(|| back_pressed(ui).then_some(Screen::Cosign(Cosign)))
    }
}
