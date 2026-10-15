//! A PSBT's way through the signer: chosen from the files on a card, reviewed line by line, signed,
//! and written back beside the one it came from or shown as a loop of QR codes.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use eframe::egui::{Align, Label, Layout, RichText, ScrollArea, Ui};
use wallet_airgap::bcur::{FRAGMENT_LEN, PsbtEncoder};
use wallet_airgap::qr::Qr;
use wallet_core::account::Keychain;
use wallet_core::bitcoin::Amount;
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::psbt::{self, Warning};

use crate::app::{Screen, Shared};
use crate::files::{self, PsbtFile};
use crate::home::Home;
use crate::theme::{BAD, DIM, FAINT, GOOD, TEXT, WARN, body, mono, strong};
use crate::widgets::{
    Emphasis, address, amount, back_pressed, beside_qr, button, card, chip, focus_row, menu_item,
    text,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    #[cfg(feature = "online")]
    Broadcast,
}

pub struct Files {
    purpose: Purpose,
    files: Vec<PsbtFile>,
}

impl Files {
    pub fn new(shared: &Shared, purpose: Purpose) -> Files {
        Files { purpose, files: files::list_psbts(&shared.config.dirs) }
    }

    pub fn title(&self) -> String {
        match self.purpose {
            Purpose::Sign => "Choose a PSBT",
            #[cfg(feature = "online")]
            Purpose::Broadcast => "Choose a signed PSBT",
        }
        .to_owned()
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let mut chosen = None;
        let mut look_again = false;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            if self.files.is_empty() {
                card(ui, |ui| {
                    text(ui, "No PSBT files here", strong(15.0), TEXT);
                    text(
                        ui,
                        "Put a .psbt file on the card, then look again. Looked in:",
                        body(12.5),
                        DIM,
                    );
                    for dir in &shared.config.dirs {
                        text(ui, dir.display().to_string(), mono(11.0), FAINT);
                    }
                });
            }
            for file in &self.files {
                let name = file.path.file_name().unwrap_or_default().to_string_lossy();
                let dir = file.path.parent().unwrap_or(&file.path).display();
                let item = menu_item(ui, &name, Some(&format!("{} · {dir}", ago(file.modified))));
                shared.autofocus(&item);
                if item.clicked() {
                    chosen = Some(file.path.clone());
                }
            }
            let again = button(ui, "Look again", Emphasis::Secondary, ui.available_width());
            shared.autofocus(&again);
            look_again = again.clicked();
        });
        if look_again {
            self.files = files::list_psbts(&shared.config.dirs);
            shared.refocus();
        }
        if let Some(path) = chosen {
            let read = std::fs::read(&path).map_err(|error| error.to_string());
            let psbt = read
                .and_then(|data| wallet_airgap::file::read_psbt(&data).map_err(|e| e.to_string()));
            match psbt {
                Ok(psbt) => {
                    return Some(Screen::Review(Review::new(psbt, Origin::File(path), shared)));
                }
                Err(error) => shared.error(format!("{}: {error}", path.display())),
            }
        }
        back_pressed(ui).then(|| Screen::Home(Home::default()))
    }
}

/// How long ago, roughly.
fn ago(time: SystemTime) -> String {
    let secs = SystemTime::now().duration_since(time).unwrap_or_default().as_secs();
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86_400 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// Where a PSBT came from, which decides where it goes once signed.
#[derive(Clone, Debug)]
pub enum Origin {
    /// A file, which the signed PSBT is written beside.
    File(PathBuf),
    /// The node, which funded it for this wallet to sign or to export for the signer.
    #[cfg(feature = "online")]
    Node,
}

pub struct Review {
    psbt: Psbt,
    origin: Origin,
    review: Result<psbt::Review, String>,
}

/// What the review screen's buttons do.
enum Action {
    Sign,
    #[cfg(feature = "online")]
    Broadcast,
    #[cfg(feature = "online")]
    Export,
    Cancel,
}

impl Review {
    pub fn new(psbt: Psbt, origin: Origin, shared: &Shared) -> Review {
        let review = match &shared.wallet {
            Some(wallet) => psbt::review(&wallet.account, &psbt).map_err(|error| error.to_string()),
            None => Err("No wallet is open.".to_owned()),
        };
        Review { psbt, origin, review }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let review = match &self.review {
            Ok(review) => review,
            Err(error) => {
                card(ui, |ui| {
                    text(ui, "This PSBT cannot be signed", strong(15.0), BAD);
                    text(ui, error.as_str(), body(13.0), TEXT);
                });
                let back = button(ui, "Back", Emphasis::Secondary, ui.available_width());
                shared.autofocus(&back);
                return (back.clicked() || back_pressed(ui)).then(|| Screen::Home(Home::default()));
            }
        };
        let unsigned = unsigned_inputs(&self.psbt);
        let signable = shared.seed().is_some()
            && (review.inputs.iter().enumerate())
                .any(|(i, input)| input.derivation.is_some() && !has_signature(&self.psbt, i));
        // The step forward first, so the D-pad reaches it first on its way down past the lines;
        // B cancels anywhere.
        let mut actions: Vec<(&str, Emphasis, Action)> = Vec::new();
        if signable {
            actions.push(("Sign", Emphasis::Primary, Action::Sign));
        }
        #[cfg(feature = "online")]
        {
            if unsigned == 0 && shared.online.connected() {
                actions.push(("Broadcast", Emphasis::Primary, Action::Broadcast));
            }
            if matches!(self.origin, Origin::Node) && !signable && unsigned > 0 {
                actions.push(("Export for the signer", Emphasis::Primary, Action::Export));
            }
        }
        actions.push(("Cancel", Emphasis::Secondary, Action::Cancel));
        let mut chosen = None;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            // The lines first, so the D-pad passes every one on its way down to the buttons.
            for (index, line) in lines(review).into_iter().enumerate() {
                let row = focus_row(ui, &line.name, |ui| line.show(ui));
                if index == 0 {
                    shared.autofocus(&row.response);
                }
            }
            if !signable && unsigned > 0 && shared.seed().is_some() {
                text(ui, "Nothing in it is this wallet's to sign.", body(12.5), DIM);
            }
            for (label, emphasis, action) in &actions {
                if button(ui, label, *emphasis, ui.available_width()).clicked() {
                    chosen = Some(action);
                }
            }
        });
        let next = match chosen? {
            Action::Sign => self.sign(shared),
            #[cfg(feature = "online")]
            Action::Broadcast => {
                shared.online.broadcast(ui.ctx(), &self.psbt);
                Some(Screen::Home(Home::default()))
            }
            #[cfg(feature = "online")]
            Action::Export => {
                let psbt = self.psbt.clone();
                Some(Screen::Outgoing(Outgoing::new(psbt, self.origin.clone(), shared)))
            }
            Action::Cancel => Some(Screen::Home(Home::default())),
        };
        next.or_else(|| back_pressed(ui).then(|| Screen::Home(Home::default())))
    }

    fn sign(&mut self, shared: &mut Shared) -> Option<Screen> {
        let wallet = shared.wallet.as_ref()?;
        let seed = wallet.seed.as_ref()?;
        let mut aux_rand = [0u8; 32];
        if let Err(error) = getrandom::fill(&mut aux_rand) {
            shared.error(format!("No randomness: {error}"));
            return None;
        }
        match psbt::sign(&wallet.account, seed, &mut self.psbt, &aux_rand) {
            Ok(signed) => {
                let mut outgoing = Outgoing::new(self.psbt.clone(), self.origin.clone(), shared);
                match &self.origin {
                    Origin::File(path) => outgoing.save(files::signed_path(path), shared),
                    #[cfg(feature = "online")]
                    Origin::Node => {}
                }
                if outgoing.saved.is_none() {
                    let plural = if signed == 1 { "" } else { "s" };
                    shared.info(format!("Signed {signed} input{plural}."));
                }
                Some(Screen::Outgoing(outgoing))
            }
            Err(error) => {
                shared.error(error);
                None
            }
        }
    }
}

/// A block of the review.
struct Line {
    /// What a screen reader calls the block.
    name: String,
    kind: LineKind,
}

enum LineKind {
    /// The total paid to others, at the top.
    Total(Amount),
    Payment {
        amount: Amount,
        to: Option<String>,
        script: String,
    },
    Kept {
        amount: Amount,
        keychain: Keychain,
        index: u32,
    },
    Fee {
        amount: Amount,
        rate: Option<f64>,
        high: bool,
    },
    Spends {
        ours: usize,
        total: Amount,
        others: usize,
    },
    Warning(String),
}

impl Line {
    fn show(&self, ui: &mut Ui) {
        let sides = |ui: &mut Ui, label: &str, color, value: Amount, value_color| {
            ui.horizontal(|ui| {
                text(ui, label, body(12.5), color);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(amount(value, 14.0, value_color));
                });
            });
        };
        match &self.kind {
            LineKind::Total(total) => {
                text(ui, "You send", body(12.5), DIM);
                ui.label(amount(*total, 24.0, TEXT));
            }
            LineKind::Payment { amount, to: Some(to), .. } => {
                sides(ui, "To", DIM, *amount, TEXT);
                address(ui, to, 14.0);
            }
            LineKind::Payment { amount, to: None, script } => {
                sides(ui, "To a script with no address", WARN, *amount, TEXT);
                text(ui, script.as_str(), mono(11.0), WARN);
            }
            LineKind::Kept { amount, keychain, index } => {
                let label = match keychain {
                    Keychain::Change => format!("Change #{index}"),
                    Keychain::Receive => format!("Back to this wallet, receive #{index}"),
                };
                sides(ui, &label, DIM, *amount, DIM);
            }
            LineKind::Fee { amount, rate, high } => {
                let color = if *high { WARN } else { TEXT };
                sides(ui, "Fee", DIM, *amount, color);
                let rate = match rate {
                    Some(rate) => format!("at least {rate:.1} sat/vB"),
                    None => "rate unknown: not every input is this wallet's".to_owned(),
                };
                text(ui, rate, body(11.5), FAINT);
                if *high {
                    text(ui, "More than a tenth of the payment. Is that right?", body(12.0), WARN);
                }
            }
            LineKind::Spends { ours, total, others } => {
                let coins = if *ours == 1 { "coin" } else { "coins" };
                sides(ui, &format!("Spends {ours} {coins} of this wallet"), DIM, *total, DIM);
                if *others > 0 {
                    let plural = if *others == 1 { "" } else { "s" };
                    let text_ =
                        format!("and {others} input{plural} of others, which it does not sign");
                    text(ui, text_, body(12.0), WARN);
                }
            }
            LineKind::Warning(warning) => {
                text(ui, warning.as_str(), body(12.5), WARN);
            }
        }
    }
}

/// The review in blocks: what is sent, each payment, the change, the fee, the coins spent, and any
/// warnings.
fn lines(review: &psbt::Review) -> Vec<Line> {
    let mut lines = Vec::new();
    let paid: Amount =
        (review.outputs.iter()).filter(|o| o.derivation.is_none()).map(|o| o.txout.value).sum();
    lines.push(Line { name: "Total".into(), kind: LineKind::Total(paid) });
    for (index, output) in review.outputs.iter().enumerate() {
        let amount = output.txout.value;
        let kind = match output.derivation {
            None => LineKind::Payment {
                amount,
                to: output.address.as_ref().map(|address| address.to_string()),
                script: output.txout.script_pubkey.to_string(),
            },
            Some(derivation) => {
                LineKind::Kept { amount, keychain: derivation.keychain, index: derivation.index }
            }
        };
        lines.push(Line { name: format!("Output {}", index + 1), kind });
    }
    // A fee of more than a tenth of what the transaction pays out is a mistake more often than not.
    let high = review.fee > paid / 10 && paid > Amount::ZERO;
    let fee = LineKind::Fee { amount: review.fee, rate: review.min_fee_rate(), high };
    lines.push(Line { name: "Fee".into(), kind: fee });
    let ours: Vec<_> = review.inputs.iter().filter(|input| input.derivation.is_some()).collect();
    let total = ours.iter().map(|input| input.spent.value).sum::<Amount>();
    let others = review.inputs.len() - ours.len();
    lines.push(Line {
        name: "Inputs".into(),
        kind: LineKind::Spends { ours: ours.len(), total, others },
    });
    for warning in &review.warnings {
        let Warning::UnverifiedAmount { input } = warning;
        let text = format!(
            "Input {input}'s amount comes without its previous transaction, so it is the coordinator's word. Sign only once for these coins."
        );
        lines.push(Line {
            name: format!("Warning about input {input}"),
            kind: LineKind::Warning(text),
        });
    }
    lines
}

fn has_signature(psbt: &Psbt, index: usize) -> bool {
    let input = &psbt.inputs[index];
    !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || input.final_script_witness.is_some()
        || input.final_script_sig.is_some()
}

/// The inputs with no signature yet.
fn unsigned_inputs(psbt: &Psbt) -> usize {
    (0..psbt.inputs.len()).filter(|&index| !has_signature(psbt, index)).count()
}

/// A PSBT on its way out of the signer (signed) or the watch-only wallet (for the signer): saved
/// to a file, shown as QR codes, or (online) broadcast.
pub struct Outgoing {
    psbt: Psbt,
    origin: Origin,
    saved: Option<PathBuf>,
    animation: Option<Animation>,
}

/// The QR codes of a PSBT, one after another.
struct Animation {
    encoder: PsbtEncoder,
    qr: Option<Qr>,
    shown: Instant,
    /// How many parts were shown.
    parts: usize,
}

/// How long each QR code of a loop stays up: long enough for a camera to focus on it.
const FRAME: Duration = Duration::from_millis(250);

impl Outgoing {
    pub fn new(psbt: Psbt, origin: Origin, _shared: &Shared) -> Outgoing {
        Outgoing { psbt, origin, saved: None, animation: None }
    }

    pub fn title(&self) -> String {
        if unsigned_inputs(&self.psbt) == 0 { "Signed" } else { "For the signer" }.to_owned()
    }

    fn save(&mut self, path: PathBuf, shared: &mut Shared) {
        match files::write(&path, &wallet_airgap::file::write_psbt(&self.psbt)) {
            // The screen shows where, in place of a notice.
            Ok(()) => self.saved = Some(path),
            Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let complete = unsigned_inputs(&self.psbt) == 0;
        if let Some(animation) = &mut self.animation {
            if animation.qr.is_none() || animation.shown.elapsed() >= FRAME {
                animation.qr = Qr::new(&animation.encoder.next_part()).ok();
                animation.shown = Instant::now();
                animation.parts += 1;
            }
            ui.ctx().request_repaint_after(FRAME);
        }
        let qr = self.animation.as_ref().and_then(|animation| animation.qr.as_ref());
        let mut next = None;
        let mut toggle = false;
        let mut save = None;
        beside_qr(ui, qr, |ui| {
            // In an id scope, as what it says comes and goes above the buttons.
            ui.push_id("about", |ui| {
                ui.horizontal(|ui| {
                    match complete {
                        true => chip(ui, "SIGNED", strong(10.0), GOOD),
                        false => chip(ui, "NOT SIGNED", strong(10.0), WARN),
                    };
                    if let Some(animation) = &self.animation {
                        let fragments = animation.encoder.fragment_count();
                        let part = (animation.parts - 1) % fragments + 1;
                        text(ui, format!("part {part} of {fragments}"), mono(11.5), FAINT);
                    }
                });
                if let Some(path) = &self.saved {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    text(ui, name, strong(14.0), TEXT);
                    let dir =
                        path.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
                    let dir = RichText::new(dir).font(mono(11.0)).color(FAINT);
                    ui.add(Label::new(dir).truncate());
                }
            });
            let width = ui.available_width();
            let qr = if self.animation.is_some() { "Hide QR codes" } else { "Show as QR codes" };
            let qr = button(ui, qr, Emphasis::Secondary, width);
            shared.autofocus(&qr);
            toggle = qr.clicked();
            if self.saved.is_none() {
                for dir in &shared.config.dirs {
                    let label = dir.file_name().map_or_else(
                        || dir.display().to_string(),
                        |name| name.to_string_lossy().into_owned(),
                    );
                    if button(ui, &format!("Save to {label}"), Emphasis::Secondary, width).clicked()
                    {
                        save = Some(dir.clone());
                    }
                }
            }
            #[cfg(feature = "online")]
            if complete
                && shared.online.connected()
                && button(ui, "Broadcast", Emphasis::Primary, width).clicked()
            {
                shared.online.broadcast(ui.ctx(), &self.psbt);
                next = Some(Screen::Home(Home::default()));
            }
            if button(ui, "Done", Emphasis::Primary, width).clicked() {
                next = Some(Screen::Home(Home::default()));
            }
        });
        if toggle {
            self.animation = match self.animation {
                Some(_) => None,
                None => Some(Animation {
                    encoder: PsbtEncoder::new(&self.psbt, FRAGMENT_LEN),
                    qr: None,
                    shown: Instant::now(),
                    parts: 0,
                }),
            };
        }
        if let Some(dir) = save {
            let name = self.file_name(shared);
            self.save(dir.join(name), shared);
        }
        next.or_else(|| back_pressed(ui).then(|| Screen::Home(Home::default())))
    }

    /// The file a PSBT saved by hand goes to: beside the one it was signed from, or for one the
    /// node made, named for the wallet and the time.
    #[cfg_attr(not(feature = "online"), allow(unused_variables))]
    fn file_name(&self, shared: &Shared) -> String {
        match &self.origin {
            Origin::File(path) => {
                let signed = files::signed_path(path);
                signed.file_name().unwrap_or_default().to_string_lossy().into_owned()
            }
            #[cfg(feature = "online")]
            Origin::Node => {
                let wallet = shared.wallet.as_ref();
                let fingerprint =
                    wallet.map(|w| w.account.fingerprint().to_string()).unwrap_or_default();
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
                format!("{fingerprint}-{}.psbt", now.unwrap_or_default().as_secs())
            }
        }
    }
}
