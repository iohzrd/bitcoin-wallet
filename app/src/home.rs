//! The open wallet: what it can do, its account's descriptor to give the watch-only wallet, and
//! its addresses, to check one another wallet shows against the one the signer derives.

use eframe::egui::{Align, Key, Layout, ScrollArea, Ui};
use wallet_airgap::qr::Qr;
use wallet_core::account::{Derivation, Keychain, Kind};

use crate::app::{Screen, Shared};
use crate::backup::Backup;
use crate::cosign::Cosign;
use crate::files;
use crate::sign::{Files, Purpose, Which};
use crate::theme::{ACCENT, DIM, FAINT, TEXT, WARN, body, mono, strong};
use crate::widgets::{
    Emphasis, address, back_pressed, beside_qr, button, button_row, card, chip, menu_item, text,
};

#[derive(Default)]
pub struct Home {
    /// Whether "Close wallet" was pressed once, and waits for a second press.
    closing: bool,
}

impl Home {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(wallet) = &shared.wallet else { return Some(Screen::Start) };
        let account = &wallet.account;
        let signer = wallet.seed.is_some();
        let kind = match account.kind() {
            Kind::Taproot => "Taproot account",
            Kind::SegwitV0 => "Native segwit account",
        };
        let path = format!("m/{}", account.path());
        // In an id scope, as the balance and its lines come and go above the menu.
        ui.push_id("account", |ui| {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    text(ui, kind, strong(15.0), TEXT);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        text(ui, &path, mono(11.5), FAINT);
                    });
                });
                #[cfg(feature = "online")]
                shared.online.summary(ui);
                #[cfg(not(feature = "online"))]
                text(ui, "Offline signer: PSBTs come and go on the card.", body(12.5), DIM);
            });
        });

        let mut next = None;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            if signer {
                let sign = menu_item(ui, "Sign", Some("Review a PSBT from the card and sign it"));
                shared.autofocus(&sign);
                if sign.clicked() {
                    next = Some(Screen::Files(Files::new(shared, Purpose::Sign, Which::Account)));
                }
            }
            #[cfg(feature = "online")]
            if shared.online.connected() {
                let send = menu_item(ui, "Send", Some("Make a payment for the signer"));
                shared.autofocus(&send);
                if send.clicked() {
                    next = Some(Screen::Pay(crate::online::Pay::default()));
                }
                if menu_item(ui, "Receive", Some("Show a new address")).clicked() {
                    next = Some(Screen::Receive(crate::online::Receive::new(ui.ctx(), shared)));
                }
                let broadcast =
                    menu_item(ui, "Broadcast", Some("Send a signed PSBT to the network"));
                if broadcast.clicked() {
                    next =
                        Some(Screen::Files(Files::new(shared, Purpose::Broadcast, Which::Account)));
                }
            }
            let export =
                menu_item(ui, "Export account", Some("Its descriptor, for a watch-only wallet"));
            shared.autofocus(&export);
            if export.clicked() {
                next = Some(Screen::Export(Export::new(shared)));
            }
            let addresses = menu_item(ui, "Addresses", Some("Check one another screen shows"));
            if addresses.clicked() {
                next = Some(Screen::Addresses(Addresses::new(Which::Account)));
            }
            if signer {
                let backup = menu_item(ui, "Backup", Some("Show, check or SeedQR the words"));
                if backup.clicked() {
                    next = Some(Screen::Backup(Backup));
                }
                let cosign = menu_item(ui, "Multisig", Some("Co-sign wallets with other devices"));
                if cosign.clicked() {
                    next = Some(Screen::Cosign(Cosign));
                }
            }
            let close = match (self.closing, signer) {
                (true, true) => "Press again: the seed will be forgotten",
                (true, false) => "Press again to close",
                (false, _) => "Back to the start",
            };
            let close = menu_item(ui, "Close wallet", Some(close));
            if close.clicked() {
                if self.closing {
                    // Dropping the seed wipes it.
                    shared.wallet = None;
                    #[cfg(feature = "online")]
                    shared.online.close();
                    next = Some(Screen::Start);
                }
                self.closing = true;
            }
            if !close.has_focus() {
                self.closing = false;
            }
        });
        next
    }
}

/// The account's descriptor, as a QR code and a file, for a watch-only wallet to import.
pub struct Export {
    text: String,
    qr: Option<Qr>,
}

impl Export {
    fn new(shared: &Shared) -> Export {
        let text = shared.wallet.as_ref().map(|w| w.account.descriptor().to_string());
        let text = text.unwrap_or_default();
        Export { qr: Qr::new(&text).ok(), text }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(wallet) = &shared.wallet else { return Some(Screen::Start) };
        let kind = match wallet.account.kind() {
            Kind::Taproot => "taproot",
            Kind::SegwitV0 => "segwit",
        };
        let name = format!("{}-{kind}.txt", wallet.account.fingerprint());
        let dirs = shared.config.dirs.clone();
        let mut save = None;
        beside_qr(ui, self.qr.as_ref(), |ui| {
            text(ui, "Scan it, or save it to the card, to watch this account.", body(12.5), DIM);
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
                        save = Some(dir.join(&name));
                    }
                }
            });
        });
        if let Some(path) = save {
            match files::write(&path, self.text.as_bytes()) {
                Ok(()) => shared.info(format!("Saved {}", path.display())),
                Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
            }
        }
        back_pressed(ui).then(|| Screen::Home(Home::default()))
    }
}

/// The addresses of the account or of a multisig it co-signs, one at a time with its QR code,
/// stepped through with the buttons or the shoulder buttons.
pub struct Addresses {
    which: Which,
    derivation: Derivation,
    shown: Option<(Derivation, String, Option<Qr>)>,
}

impl Addresses {
    pub fn new(which: Which) -> Addresses {
        Addresses { which, derivation: Derivation::receive(0), shown: None }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let wallet = shared.wallet.as_ref();
        let Some(policy) = wallet.and_then(|wallet| self.which.policy(wallet)) else {
            return Some(Screen::Start);
        };
        if self.shown.as_ref().is_none_or(|(shown, ..)| *shown != self.derivation) {
            let address = policy.address(self.derivation).to_string();
            // Capitals, which a bech32 address may be written in, make the QR code smaller.
            let qr = Qr::new(&address.to_uppercase()).ok();
            self.shown = Some((self.derivation, address, qr));
        }
        let (_, shown, qr) = self.shown.as_ref().expect("just made");
        let Derivation { keychain, index } = self.derivation;
        let (previous, next) =
            ui.input(|input| (input.key_pressed(Key::PageUp), input.key_pressed(Key::PageDown)));
        let mut step: i64 = (next as i64) - (previous as i64);
        let mut switch = false;
        beside_qr(ui, qr.as_ref(), |ui| {
            ui.horizontal(|ui| {
                let (name, color) = match keychain {
                    Keychain::Receive => ("RECEIVE", ACCENT),
                    Keychain::Change => ("CHANGE", WARN),
                };
                chip(ui, name, strong(10.0), color);
                text(ui, format!("#{index}"), strong(20.0), TEXT);
            });
            address(ui, shown, 15.0);
            ui.add_space(2.0);
            let steps = [("Previous", Emphasis::Secondary), ("Next", Emphasis::Secondary)];
            let buttons = button_row(ui, &steps);
            shared.autofocus(&buttons[1]);
            if buttons[0].clicked() {
                step = -1;
            }
            if buttons[1].clicked() {
                step = 1;
            }
            let other = match keychain {
                Keychain::Receive => "Change addresses",
                Keychain::Change => "Receive addresses",
            };
            switch = button(ui, other, Emphasis::Secondary, ui.available_width()).clicked();
        });
        if switch {
            let keychain = match keychain {
                Keychain::Receive => Keychain::Change,
                Keychain::Change => Keychain::Receive,
            };
            self.derivation = Derivation { keychain, index: 0 };
        }
        // Below 2^31, BIP32's unhardened range.
        let index = self.derivation.index as i64 + step;
        self.derivation.index = index.clamp(0, (1 << 31) - 1) as u32;
        back_pressed(ui).then(|| self.which.home())
    }
}
