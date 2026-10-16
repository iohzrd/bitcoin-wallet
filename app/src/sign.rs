//! A PSBT's way through the signer: chosen from the files on a card, reviewed line by line, signed,
//! and written back beside the one it came from or shown as a loop of QR codes.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use eframe::egui::{Align, Label, Layout, RichText, ScrollArea, Ui};
use wallet_airgap::bcur::{FRAGMENT_LEN, PsbtEncoder};
use wallet_airgap::qr::Qr;
use wallet_core::account::Keychain;
use wallet_core::bitcoin::absolute::LockTime;
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::bitcoin::{Amount, SignedAmount};
use wallet_core::policy::Policy;
use wallet_core::psbt::{self, Warning};

use crate::app::{Screen, Shared, Wallet};
use crate::cosign::WalletScreen;
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

/// Which of the open wallet's policies a PSBT is for: its account, or a multisig it co-signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Account,
    Multisig(usize),
}

impl Which {
    pub fn policy(self, wallet: &Wallet) -> Option<&dyn Policy> {
        match self {
            Which::Account => Some(&wallet.account),
            Which::Multisig(index) => {
                wallet.multisigs.get(index).map(|registered| &registered.multisig as _)
            }
        }
    }

    /// The screen the policy's screens go back to.
    pub fn home(self) -> Screen {
        match self {
            Which::Account => Screen::Home(Home::default()),
            Which::Multisig(index) => Screen::MultisigWallet(WalletScreen::new(index)),
        }
    }
}

pub struct Files {
    purpose: Purpose,
    which: Which,
    files: Vec<PsbtFile>,
}

impl Files {
    pub fn new(shared: &Shared, purpose: Purpose, which: Which) -> Files {
        Files { purpose, which, files: files::list_psbts(&shared.config.dirs) }
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
                    let review = Review::new(psbt, Origin::File(path), self.which, shared);
                    return Some(Screen::Review(review));
                }
                Err(error) => shared.error(format!("{}: {error}", path.display())),
            }
        }
        back_pressed(ui).then(|| self.which.home())
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
    which: Which,
    review: Result<psbt::Review, String>,
    /// Whether Sign was pressed once with warnings showing, and waits for a second press.
    confirming: bool,
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
    pub fn new(psbt: Psbt, origin: Origin, which: Which, shared: &Shared) -> Review {
        let review = match shared.wallet.as_ref().and_then(|wallet| which.policy(wallet)) {
            Some(policy) => psbt::review(policy, &psbt).map_err(|error| error.to_string()),
            None => Err("No wallet is open.".to_owned()),
        };
        Review { psbt, origin, which, review, confirming: false }
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
                return (back.clicked() || back_pressed(ui)).then(|| self.which.home());
            }
        };
        #[cfg_attr(not(feature = "online"), allow(unused_variables))]
        let complete = review.complete();
        let ours = review.inputs.iter().any(|input| input.derivation.is_some());
        let signable = shared.seed().is_some()
            && (review.inputs.iter())
                .any(|input| input.derivation.is_some() && input.signatures < review.threshold);
        // The step forward first, so the D-pad reaches it first on its way down past the lines;
        // B cancels anywhere.
        let mut actions: Vec<(&str, Emphasis, Action)> = Vec::new();
        // With warnings above, Sign takes a second press.
        let warned = !review.warnings.is_empty();
        if signable {
            let label = if self.confirming { "Sign anyway" } else { "Sign" };
            actions.push((label, Emphasis::Primary, Action::Sign));
        }
        #[cfg(feature = "online")]
        {
            if complete && shared.online.connected() {
                actions.push(("Broadcast", Emphasis::Primary, Action::Broadcast));
            }
            if matches!(self.origin, Origin::Node) && !signable && !complete {
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
            if !ours && shared.seed().is_some() {
                text(ui, "Nothing in it is this wallet's to sign.", body(12.5), DIM);
            }
            for (label, emphasis, action) in &actions {
                if button(ui, label, *emphasis, ui.available_width()).clicked() {
                    chosen = Some(action);
                }
            }
        });
        let next = match chosen {
            None => None,
            Some(Action::Sign) if warned && !self.confirming => {
                self.confirming = true;
                None
            }
            Some(Action::Sign) => self.sign(shared),
            #[cfg(feature = "online")]
            Some(Action::Broadcast) => {
                shared.online.broadcast(ui.ctx(), &self.psbt);
                Some(Screen::Home(Home::default()))
            }
            #[cfg(feature = "online")]
            Some(Action::Export) => {
                let (psbt, origin) = (self.psbt.clone(), self.origin.clone());
                Some(Screen::Outgoing(Outgoing::new(psbt, origin, self.which, shared)))
            }
            Some(Action::Cancel) => Some(self.which.home()),
        };
        next.or_else(|| back_pressed(ui).then(|| self.which.home()))
    }

    fn sign(&mut self, shared: &mut Shared) -> Option<Screen> {
        let wallet = shared.wallet.as_ref()?;
        let seed = wallet.seed.as_ref()?;
        let mut aux_rand = [0u8; 32];
        if let Err(error) = getrandom::fill(&mut aux_rand) {
            shared.error(format!("No randomness: {error}"));
            return None;
        }
        let policy = self.which.policy(wallet)?;
        match psbt::sign(policy, seed, &mut self.psbt, &aux_rand) {
            Ok(signed) => {
                let (psbt, origin) = (self.psbt.clone(), self.origin.clone());
                let mut outgoing = Outgoing::new(psbt, origin, self.which, shared);
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
        /// Whether it claims to be the wallet's change, which it is not.
        fake_change: bool,
    },
    Kept {
        amount: Amount,
        keychain: Keychain,
        index: u32,
        /// Whether it is further past the inputs than a restored wallet looks.
        distant: bool,
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
        /// What leaves the wallet, when others' inputs are in it too.
        net: SignedAmount,
    },
    /// A multisig's signatures: the fewest any of its inputs carries, of the threshold.
    Signatures {
        have: usize,
        need: usize,
    },
    Locktime {
        lock_time: LockTime,
        ignored: bool,
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
            LineKind::Payment { amount, to, script, fake_change } => {
                match to {
                    Some(to) => {
                        sides(ui, "To", DIM, *amount, TEXT);
                        address(ui, to, 14.0);
                    }
                    None => {
                        sides(ui, "To a script with no address", WARN, *amount, TEXT);
                        text(ui, script.as_str(), mono(11.0), WARN);
                    }
                }
                if *fake_change {
                    let warning = "It claims to be this wallet's change but pays another script. Unless you are paying another wallet that shares this key, it is not yours.";
                    text(ui, warning, body(12.0), WARN);
                }
            }
            LineKind::Kept { amount, keychain, index, distant } => {
                let label = match keychain {
                    Keychain::Change => format!("Change #{index}"),
                    Keychain::Receive => format!("Back to this wallet, receive #{index}"),
                };
                sides(ui, &label, if *distant { WARN } else { DIM }, *amount, DIM);
                if *distant {
                    let warning = "Far past the inputs' addresses: a wallet restored from the seed may not look that far.";
                    text(ui, warning, body(12.0), WARN);
                }
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
                    let warning = format!(
                        "That is a lot: {}% or more of what is spent, or over {} sat/vB. Is it right?",
                        psbt::HIGH_FEE_PERCENT,
                        psbt::HIGH_FEE_RATE
                    );
                    text(ui, warning, body(12.0), WARN);
                }
            }
            LineKind::Spends { ours, total, others, net } => {
                let coins = if *ours == 1 { "coin" } else { "coins" };
                sides(ui, &format!("Spends {ours} {coins} of this wallet"), DIM, *total, DIM);
                if *others > 0 {
                    let plural = if *others == 1 { "" } else { "s" };
                    let note = format!(
                        "and {others} input{plural} of others, which it does not sign, and whose amounts its signatures do not cover"
                    );
                    text(ui, note, body(12.0), WARN);
                    let net = Amount::from_sat(net.to_sat().max(0) as u64);
                    sides(ui, "Leaves this wallet", DIM, net, TEXT);
                }
            }
            LineKind::Signatures { have, need } => {
                ui.horizontal(|ui| {
                    text(ui, "Signatures", body(12.5), DIM);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let color = if have >= need { GOOD } else { TEXT };
                        text(ui, format!("{have} of {need}"), mono(14.0), color);
                    });
                });
            }
            LineKind::Locktime { lock_time, ignored } => {
                let when = match lock_time {
                    LockTime::Blocks(height) => format!("block {}", height.to_consensus_u32()),
                    LockTime::Seconds(time) => utc(time.to_consensus_u32()),
                };
                ui.horizontal(|ui| {
                    text(ui, "Not valid before", body(12.5), DIM);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        text(ui, when, mono(13.0), TEXT);
                    });
                });
                if *ignored {
                    let note = "No input's sequence enables it, so it does nothing.";
                    text(ui, note, body(12.0), WARN);
                }
            }
            LineKind::Warning(warning) => {
                text(ui, warning.as_str(), body(12.5), WARN);
            }
        }
    }
}

/// A Unix time as a UTC date and time, by the proleptic Gregorian calendar.
fn utc(time: u32) -> String {
    let (days, seconds) = (i64::from(time) / 86_400, i64::from(time) % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year}-{month:02}-{day:02} {:02}:{:02} UTC", seconds / 3600, seconds % 3600 / 60)
}

/// The review in blocks: what is sent, each payment, the change, the fee, the coins spent, any
/// locktime, and any warnings the blocks do not carry themselves.
fn lines(review: &psbt::Review) -> Vec<Line> {
    let mut lines = Vec::new();
    let warned = |wanted: &dyn Fn(&Warning) -> bool| review.warnings.iter().any(wanted);
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
                fake_change: warned(&|w| *w == Warning::FakeChange { output: index }),
            },
            Some(derivation) => LineKind::Kept {
                amount,
                keychain: derivation.keychain,
                index: derivation.index,
                distant: warned(
                    &|w| matches!(w, Warning::DistantIndex { output, .. } if *output == index),
                ),
            },
        };
        lines.push(Line { name: format!("Output {}", index + 1), kind });
    }
    let high = warned(&|w| *w == Warning::HighFee);
    let fee = LineKind::Fee { amount: review.fee, rate: review.min_fee_rate(), high };
    lines.push(Line { name: "Fee".into(), kind: fee });
    let ours: Vec<_> = review.inputs.iter().filter(|input| input.derivation.is_some()).collect();
    let total = ours.iter().map(|input| input.spent.value).sum::<Amount>();
    let others = review.inputs.len() - ours.len();
    let net = review.net_spent();
    lines.push(Line {
        name: "Inputs".into(),
        kind: LineKind::Spends { ours: ours.len(), total, others, net },
    });
    if review.threshold > 1 {
        let need = review.threshold;
        let have = ours.iter().map(|input| input.signatures.min(need)).min().unwrap_or_default();
        lines.push(Line { name: "Signatures".into(), kind: LineKind::Signatures { have, need } });
    }
    if review.lock_time != LockTime::ZERO {
        let ignored = warned(&|w| *w == Warning::LocktimeIgnored);
        let kind = LineKind::Locktime { lock_time: review.lock_time, ignored };
        lines.push(Line { name: "Locktime".into(), kind });
    }
    for warning in &review.warnings {
        if let Warning::UnverifiedAmounts { inputs } = warning {
            let inputs: Vec<String> = inputs.iter().map(usize::to_string).collect();
            let text = format!(
                "Inputs {} come without their previous transactions, so their amounts are the coordinator's word. Sign this payment once only.",
                inputs.join(", ")
            );
            lines.push(Line { name: "Unverified amounts".into(), kind: LineKind::Warning(text) });
        }
    }
    lines
}

/// A PSBT on its way out of the signer (signed) or the watch-only wallet (for the signer): saved
/// to a file, shown as QR codes, or (online) broadcast.
pub struct Outgoing {
    psbt: Psbt,
    origin: Origin,
    which: Which,
    /// How signed it is: the fewest signatures any of the policy's inputs carries, the threshold,
    /// and whether the whole transaction is signed.
    signatures: (usize, usize, bool),
    saved: Option<PathBuf>,
    animation: Option<Animation>,
}

/// The QR codes of a PSBT, one after another.
struct Animation {
    density: usize,
    encoder: PsbtEncoder,
    qr: Option<Qr>,
    shown: Instant,
    /// How many parts were shown.
    parts: usize,
}

/// How long each QR code of a loop stays up: long enough for a camera to focus on it. Jade shows
/// its parts for 450 ms, SeedSigner for 167.
const FRAME: Duration = Duration::from_millis(300);

/// The loop's densities, by the bytes of PSBT in each code: fewer bytes make a simpler code that a
/// phone's camera reads from further off, in more parts. SeedSigner's medium is 30, Jade's about
/// 65; 120 is a code of about 60 modules a side.
const DENSITIES: [(&str, usize); 3] = [("Low", 30), ("Medium", 60), ("High", FRAGMENT_LEN)];

impl Outgoing {
    pub fn new(psbt: Psbt, origin: Origin, which: Which, shared: &Shared) -> Outgoing {
        let policy = shared.wallet.as_ref().and_then(|wallet| which.policy(wallet));
        let review = policy.and_then(|policy| psbt::review(policy, &psbt).ok());
        let signatures = review.map_or((0, 1, false), |review| {
            let ours = review.inputs.iter().filter(|input| input.derivation.is_some());
            let fewest = ours.map(|input| input.signatures).min().unwrap_or_default();
            (fewest.min(review.threshold), review.threshold, review.complete())
        });
        Outgoing { psbt, origin, which, signatures, saved: None, animation: None }
    }

    pub fn title(&self) -> String {
        match self.signatures {
            (.., true) => "Signed",
            (0, ..) => "For the signer",
            _ => "Partly signed",
        }
        .to_owned()
    }

    fn save(&mut self, path: PathBuf, shared: &mut Shared) {
        match files::write(&path, &wallet_airgap::file::write_psbt(&self.psbt)) {
            // The screen shows where, in place of a notice.
            Ok(()) => self.saved = Some(path),
            Err(error) => shared.error(format!("Saving {}: {error}", path.display())),
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let (have, need, complete) = self.signatures;
        if let Some(animation) = &mut self.animation {
            if animation.qr.is_none() || animation.shown.elapsed() >= FRAME {
                animation.qr = Qr::for_loop(&animation.encoder.next_part()).ok();
                animation.shown = Instant::now();
                animation.parts += 1;
            }
            ui.ctx().request_repaint_after(FRAME);
        }
        let qr = self.animation.as_ref().and_then(|animation| animation.qr.as_ref());
        let mut next = None;
        let mut toggle = false;
        let mut denser = false;
        let mut save = None;
        beside_qr(ui, qr, |ui| {
            // In an id scope, as what it says comes and goes above the buttons.
            ui.push_id("about", |ui| {
                ui.horizontal(|ui| {
                    match (complete, have) {
                        (true, _) => chip(ui, "SIGNED", strong(10.0), GOOD),
                        (false, 0) => chip(ui, "NOT SIGNED", strong(10.0), WARN),
                        (false, _) => {
                            chip(ui, &format!("{have} OF {need} SIGNATURES"), strong(10.0), WARN)
                        }
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
            if let Some(animation) = &self.animation {
                let label = format!("Density: {}", DENSITIES[animation.density].0);
                denser = button(ui, &label, Emphasis::Secondary, width).clicked();
            }
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
                next = Some(self.which.home());
            }
        });
        if toggle {
            self.animation = match self.animation {
                Some(_) => None,
                None => Some(self.animation(1)),
            };
        }
        if denser && let Some(animation) = &self.animation {
            self.animation = Some(self.animation((animation.density + 1) % DENSITIES.len()));
        }
        if let Some(dir) = save {
            let name = self.file_name(shared);
            self.save(dir.join(name), shared);
        }
        next.or_else(|| back_pressed(ui).then(|| self.which.home()))
    }

    /// The loop of QR codes at `density`. Once signed, a PSBT goes back as its signatures alone,
    /// which the coordinator combines with its own copy; unsigned, it goes whole to the signer.
    fn animation(&self, density: usize) -> Animation {
        let psbt = match self.signatures.0 {
            0 => self.psbt.clone(),
            _ => wallet_airgap::file::signatures_only(&self.psbt),
        };
        let encoder = PsbtEncoder::new(&psbt, DENSITIES[density].1);
        Animation { density, encoder, qr: None, shown: Instant::now(), parts: 0 }
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
