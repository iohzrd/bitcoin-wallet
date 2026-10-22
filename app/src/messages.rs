//! Signing a message with one of the account's addresses, to show whoever asks that the seed
//! holds it: a request from the card, as Coldcard reads one, or a message typed on the keyboard.
//! The message and the address are shown before anything is signed; the signature (BIP-322's
//! simple one) comes back as a QR code, and as the signed message in its armor on the card.

use std::path::PathBuf;

use eframe::egui::{ScrollArea, Ui};
use wallet_airgap::message::{self, KeyRef, Request};
use wallet_airgap::qr::Qr;
use wallet_core::account::{Account, Derivation, Keychain};
use wallet_core::bitcoin::Address;

use crate::app::{Screen, Shared};
use crate::files;
use crate::home::Home;
use crate::theme::{DIM, FAINT, TEXT, WARN, body, mono};
use crate::widgets::{
    Control, Emphasis, Hint, Keyboard, Keys, Press, back_pressed, beside_qr, button, field,
    focus_row, grouped, menu_item, text,
};

/// The message in pieces of about this many characters, at spaces, a row of the review each.
const PIECE: usize = 120;

/// How far into each keychain an address a request names is looked for.
const SEARCH: u32 = 1000;

pub const TYPING: &[Hint] = &[(Control::DPad, "Move"), (Control::A, "Type"), (Control::B, "Back")];
pub const READING: &[Hint] =
    &[(Control::DPad, "Read on"), (Control::A, "Select"), (Control::B, "Back")];

fn home() -> Screen {
    Screen::Home(Home::default())
}

/// The requests on the card, and typing one.
pub struct Messages {
    files: Vec<PathBuf>,
}

impl Messages {
    pub fn new(shared: &Shared) -> Messages {
        Messages { files: files::message_files(&shared.config.dirs) }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let mut next = None;
        let mut chosen = None;
        let mut look_again = false;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let about = "Sign a message with one of this account's addresses, to show that you hold it.";
            text(ui, about, body(12.5), DIM);
            let typed = menu_item(ui, "Type a message", Some("On the keyboard, for the first address"));
            shared.autofocus(&typed);
            if typed.clicked() {
                next = Some(Screen::TypeMessage(Typing::default()));
            }
            for path in &self.files {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let dir = path.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
                if menu_item(ui, &name, Some(&dir)).clicked() {
                    chosen = Some(path.clone());
                }
            }
            if self.files.is_empty() {
                let none = "Or put a .txt file on the card: the message on its first line, and the address or its path (m/84h/0h/0h/0/5) on the second.";
                text(ui, none, body(11.5), FAINT);
            }
            look_again = button(ui, "Look again", Emphasis::Secondary, ui.available_width()).clicked();
        });
        if look_again {
            *self = Messages::new(shared);
            shared.refocus();
        }
        if let Some(path) = chosen {
            let request = std::fs::read_to_string(&path).map_err(|error| error.to_string());
            let request = request.and_then(|text| message::read(&text).map_err(|e| e.to_string()));
            match request.and_then(|request| Review::new(shared, request, Some(path.clone()))) {
                Ok(review) => return Some(Screen::MessageReview(review)),
                Err(error) => shared.error(format!("{}: {error}", path.display())),
            }
        }
        next.or_else(|| back_pressed(ui).then(home))
    }
}

/// A message typed on the keyboard.
#[derive(Default)]
pub struct Typing {
    typed: String,
    keyboard: Keyboard,
}

impl Typing {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let count = self.typed.chars().count();
        field(ui, &self.typed, 16.0, Some((&count.to_string(), FAINT)));
        match self.keyboard.show(ui, Keys::Full, Some(shared.focus_flag())) {
            Some(Press::Char(char)) => self.typed.push(char),
            Some(Press::Backspace) => {
                self.typed.pop();
            }
            Some(Press::Done) => {
                let message = self.typed.trim().to_owned();
                let request = message::check(&message).map(|()| Request { message, key: None });
                let review = request.map_err(|error| error.to_string());
                match review.and_then(|request| Review::new(shared, request, None)) {
                    Ok(review) => return Some(Screen::MessageReview(review)),
                    Err(error) => shared.error(error),
                }
            }
            None => {}
        }
        back_pressed(ui).then(|| Screen::Messages(Messages::new(shared)))
    }
}

/// The message and the address it is to be signed with, before it is.
pub struct Review {
    message: String,
    derivation: Derivation,
    /// The request's file, beside which the signed message is written.
    file: Option<PathBuf>,
}

impl Review {
    /// The review of `request`, its key found among the account's: the path or address it names,
    /// or the first receive address.
    fn new(shared: &Shared, request: Request, file: Option<PathBuf>) -> Result<Review, String> {
        let wallet = shared.wallet.as_ref().ok_or("No wallet is open.")?;
        let derivation = derivation(&wallet.account, request.key.as_ref())?;
        Ok(Review { message: request.message, derivation, file })
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let wallet = shared.wallet.as_ref()?;
        let address = wallet.account.address(self.derivation).to_string();
        let which = match self.derivation.keychain {
            Keychain::Receive => format!("Receive address #{}", self.derivation.index),
            Keychain::Change => format!("Change address #{}", self.derivation.index),
        };
        let mut sign = false;
        // As a PSBT's review: rows the D-pad reads down through, the message from its start, to
        // the button under them.
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for (index, piece) in pieces(&self.message).into_iter().enumerate() {
                let row = focus_row(ui, "Message", |ui| {
                    if index == 0 {
                        text(ui, "Message", body(12.0), DIM);
                    }
                    text(ui, piece, mono(14.0), TEXT);
                });
                if index == 0 {
                    shared.autofocus(&row.response);
                }
            }
            focus_row(ui, &which, |ui| {
                text(ui, &which, body(12.0), DIM);
                text(ui, grouped(&address), mono(13.0), TEXT);
            });
            let caution =
                "Sign only what you mean to: a signed message can be shown to anyone, as yours.";
            text(ui, caution, body(11.5), WARN);
            sign = button(ui, "Sign", Emphasis::Primary, ui.available_width()).clicked();
        });
        if sign {
            return self.sign(shared);
        }
        back_pressed(ui).then(|| Screen::Messages(Messages::new(shared)))
    }

    fn sign(&self, shared: &mut Shared) -> Option<Screen> {
        let wallet = shared.wallet.as_ref()?;
        let seed = wallet.seed.as_ref()?;
        let mut aux_rand = [0; 32];
        if let Err(error) = getrandom::fill(&mut aux_rand) {
            shared.error(format!("No randomness: {error}"));
            return None;
        }
        let account = &wallet.account;
        let signed =
            wallet_core::message::sign(account, seed, self.derivation, &self.message, &aux_rand);
        let signature = match signed {
            Ok(signature) => signature,
            Err(error) => {
                shared.error(error);
                return None;
            }
        };
        let address = account.address(self.derivation).to_string();
        let armored = message::armor(&self.message, &address, &signature);
        let saved = self.file.as_ref().map(|file| files::signed_text_path(file));
        if let Some(path) = &saved {
            match files::write(path, armored.as_bytes()) {
                Ok(()) => shared.info(format!("Saved {}", path.display())),
                Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
            }
        }
        let qr = Qr::new(&signature).ok();
        Some(Screen::MessageSigned(Signed { address, signature, armored, qr }))
    }
}

/// `message` cut at spaces into pieces of about `PIECE` characters, for rows the D-pad steps
/// through. A word longer than a piece is a piece of its own.
fn pieces(message: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut start = 0;
    while message.len() - start > PIECE {
        let window = &message[start..start + PIECE];
        let cut = window.rfind(' ').filter(|&cut| cut > 0).unwrap_or(PIECE);
        pieces.push(message[start..start + cut].trim());
        start += cut;
    }
    pieces.push(message[start..].trim());
    pieces
}

/// The key a request names, among the account's: by its path, or by the address it pays, among
/// the first `SEARCH` of each keychain; with none named, the first receive address.
fn derivation(account: &Account, key: Option<&KeyRef>) -> Result<Derivation, String> {
    match key {
        None => Ok(Derivation::receive(0)),
        Some(KeyRef::Path(path)) => account.derivation_at(path).ok_or_else(|| {
            format!("{path} is not one of this account's addresses, under m/{}", account.path())
        }),
        Some(KeyRef::Address(text)) => {
            let address: Address<_> =
                text.parse().map_err(|_| format!("{text} is not an address"))?;
            let address = (address.require_network(account.network()))
                .map_err(|_| format!("{text} is not an address on {}", account.network()))?;
            account.find(&address.script_pubkey(), SEARCH).ok_or_else(|| {
                format!("{text} is not among this account's first {SEARCH} addresses")
            })
        }
    }
}

/// The signature, as a QR code, and the armored message, which signing saved beside its request
/// if it came on the card, to save on the card.
pub struct Signed {
    address: String,
    signature: String,
    armored: String,
    qr: Option<Qr>,
}

impl Signed {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let dirs = shared.config.dirs.clone();
        let mut save = None;
        beside_qr(ui, self.qr.as_ref(), |ui| {
            text(ui, "Signed by", body(12.0), DIM);
            text(ui, grouped(&self.address), mono(11.5), TEXT);
            text(ui, &self.signature, mono(10.0), FAINT);
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
                        save = Some(dir.join("signed-message.txt"));
                    }
                }
            });
        });
        if let Some(path) = save {
            match files::write(&path, self.armored.as_bytes()) {
                Ok(()) => shared.info(format!("Saved {}", path.display())),
                Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
            }
        }
        back_pressed(ui).then(home)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use wallet_core::account::Kind;
    use wallet_core::bitcoin::Network;
    use wallet_core::bitcoin::bip32::DerivationPath;

    #[test]
    fn a_long_message_is_cut_at_spaces() {
        let message = "word ".repeat(100);
        let message = message.trim();
        let cut = pieces(message);
        assert!(cut.len() > 3 && cut.iter().all(|piece| piece.len() <= PIECE));
        assert_eq!(cut.join(" "), message);
        let long = "x".repeat(300);
        assert_eq!(pieces(&long).concat(), long);
        assert_eq!(pieces("Hello World"), ["Hello World"]);
    }

    #[test]
    fn a_request_names_its_key_by_path_or_address() {
        let seed = wallet_core::seed::Seed::new(
            &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            "",
        );
        let account = Account::from_seed(&seed, Network::Regtest, Kind::SegwitV0, 0).unwrap();
        assert_eq!(derivation(&account, None), Ok(Derivation::receive(0)));
        let path = DerivationPath::from_str("m/84h/1h/0h/1/7").unwrap();
        assert_eq!(derivation(&account, Some(&KeyRef::Path(path))), Ok(Derivation::change(7)));
        let other = DerivationPath::from_str("m/84h/1h/1h/0/0").unwrap();
        assert!(derivation(&account, Some(&KeyRef::Path(other))).is_err());
        let address = account.address(Derivation::receive(12)).to_string();
        let found = derivation(&account, Some(&KeyRef::Address(address)));
        assert_eq!(found, Ok(Derivation::receive(12)));
        let mainnet = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l".to_owned();
        assert!(derivation(&account, Some(&KeyRef::Address(mainnet))).is_err());
    }
}
