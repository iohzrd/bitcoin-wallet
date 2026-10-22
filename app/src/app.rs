//! The app: one screen at a time, each a step of making, opening or using the wallet. The arrow
//! keys (or the D-pad) move between a screen's buttons, Enter (or A) presses one, and Escape (or
//! B) goes back.

use std::fmt::Display;
use std::path::PathBuf;

use eframe::egui::{
    self, Align, CentralPanel, Frame, Key, Layout, Margin, Panel, RawInput, Rect, Stroke, Ui,
    UiBuilder, pos2, vec2,
};
use wallet_core::Mnemonic;
use wallet_core::account::Account;
use wallet_core::bitcoin::Network;
use wallet_core::multisig::Multisig;
use wallet_core::seed::Seed;
use wallet_core::store::Params;
use zeroize::Zeroizing;

use crate::gamepad::Gamepad;
use crate::theme::{
    self, ACCENT, BAD, BG, DIM, GOOD, RADIUS, TEST_NETWORK, TEXT, body, mono, strong,
};
use crate::widgets::{Control, Hint, back_button, back_id, chip, hint_bar, text};
use crate::{backup, cosign, create, home, keep, messages, sign};

/// The widest the screens' column grows, on a desktop's window.
const MAX_WIDTH: f32 = 560.0;

pub struct Config {
    pub network: Network,
    /// Where PSBTs and descriptors are read from and written to.
    pub dirs: Vec<PathBuf>,
    /// The file a wallet is kept in, for whoever asks to keep one; `None` where keeping is off.
    pub store: Option<PathBuf>,
    /// What a kept wallet's key costs to make.
    pub kdf: Params,
    /// The security keys a kept wallet can be sealed with: none in a build without the
    /// `security-key` feature.
    pub keys: crate::fido::Keys,
}

/// The open wallet: an account, and the seed it derives from unless it is watch-only.
pub struct Wallet {
    pub seed: Option<Seed>,
    /// The seed's words, for the backup screens.
    pub mnemonic: Option<Mnemonic>,
    /// The seed's BIP39 passphrase, empty for none, for keeping the wallet with it.
    pub passphrase: Zeroizing<String>,
    pub account: Account,
    /// The multisig wallets the seed co-signs, registered for as long as the wallet is open, or
    /// kept with it.
    pub multisigs: Vec<Registered>,
    /// The earliest its coins could have come, in Unix time: 0 for a restored seed, whose coins
    /// a node must look back through the whole chain for.
    pub birthday: u64,
}

/// A multisig wallet registered from a coordinator's setup file, and the name the file gave it.
pub struct Registered {
    pub multisig: Multisig,
    pub name: Option<String>,
}

impl Wallet {
    pub fn signing(mnemonic: Mnemonic, seed: Seed, account: Account) -> Wallet {
        Wallet {
            seed: Some(seed),
            mnemonic: Some(mnemonic),
            passphrase: Zeroizing::default(),
            account,
            multisigs: Vec::new(),
            birthday: 0,
        }
    }

    pub fn watching(account: Account) -> Wallet {
        Wallet {
            seed: None,
            mnemonic: None,
            passphrase: Zeroizing::default(),
            account,
            multisigs: Vec::new(),
            birthday: 0,
        }
    }
}

enum Notice {
    Info(String),
    Error(String),
}

/// What every screen reads or changes besides its own state.
pub struct Shared {
    pub config: Config,
    pub wallet: Option<Wallet>,
    /// The key the open wallet is kept under, when it is kept on the device.
    pub kept: Option<keep::Kept>,
    #[cfg(feature = "online")]
    pub online: crate::online::Online,
    /// A message for the top of the screen, and the frame it was set in.
    notice: Option<(Notice, u64)>,
    /// Set on entering a screen, so the first widget to ask takes the keyboard focus and the
    /// D-pad has somewhere to move from.
    focus: bool,
    /// `focus` for the next frame. A screen that changes in place asks for it once its widgets
    /// are drawn: set at once, the next widget drawn in the same frame would take the focus.
    refocus: bool,
    frame: u64,
}

impl Shared {
    /// Gives `response`'s widget the keyboard focus, if it is the first to ask on a screen
    /// just entered.
    pub fn autofocus(&mut self, response: &egui::Response) {
        if self.focus {
            response.request_focus();
            self.focus = false;
        }
    }

    /// The flag `autofocus` reads, for a widget made of many to take it with its first.
    pub fn focus_flag(&mut self) -> &mut bool {
        &mut self.focus
    }

    /// Focuses the first widget to ask in the next frame, for a screen whose widgets change.
    pub fn refocus(&mut self) {
        self.refocus = true;
    }

    pub fn info(&mut self, text: impl Into<String>) {
        self.notice = Some((Notice::Info(text.into()), self.frame));
    }

    pub fn error(&mut self, error: impl Display) {
        self.notice = Some((Notice::Error(error.to_string()), self.frame));
    }

    /// Writes the open wallet to its file again, when it is kept, for a change to it to last.
    pub fn save(&mut self) {
        let (Some(kept), Some(wallet), Some(path)) = (&self.kept, &self.wallet, &self.config.store)
        else {
            return;
        };
        if let Err(error) = keep::save(path, kept, wallet, self.config.network) {
            self.error(format!("Keeping the wallet: {error}"));
        }
    }

    /// The open wallet's seed, when it has one.
    pub fn seed(&self) -> Option<&Seed> {
        self.wallet.as_ref().and_then(|wallet| wallet.seed.as_ref())
    }
}

pub enum Screen {
    Start,
    Generate(create::Generate),
    Restore(create::Restore),
    Setup(create::Setup),
    Home(home::Home),
    Export(home::Export),
    Addresses(home::Addresses),
    Files(sign::Files),
    Review(sign::Review),
    Outgoing(sign::Outgoing),
    Backup(backup::Backup),
    BackupWords(backup::Words),
    SeedQr(backup::SeedQr),
    Cosign(cosign::Cosign),
    CosignerKey(cosign::KeyExport),
    Register(cosign::Register),
    MultisigWallet(cosign::WalletScreen),
    Keep(keep::Keep),
    Unlock(keep::Unlock),
    Messages(messages::Messages),
    TypeMessage(messages::Typing),
    MessageReview(messages::Review),
    MessageSigned(messages::Signed),
    #[cfg(feature = "online")]
    Import(crate::online::Import),
    #[cfg(feature = "online")]
    Pay(crate::online::Pay),
    #[cfg(feature = "online")]
    Receive(crate::online::Receive),
}

const MOVE_SELECT_BACK: &[Hint] =
    &[(Control::DPad, "Move"), (Control::A, "Select"), (Control::B, "Back")];

impl Screen {
    fn title(&self) -> String {
        match self {
            Screen::Start | Screen::Home(_) => "Wallet".to_owned(),
            Screen::Generate(screen) => screen.title(),
            Screen::Restore(screen) => screen.title(),
            Screen::Setup(screen) => screen.title(),
            Screen::Export(_) => "Export account".to_owned(),
            Screen::Addresses(_) => "Addresses".to_owned(),
            Screen::Files(screen) => screen.title(),
            Screen::Review(_) => "Review".to_owned(),
            Screen::Outgoing(screen) => screen.title(),
            Screen::Backup(_) => "Backup".to_owned(),
            Screen::BackupWords(_) => "Recovery words".to_owned(),
            Screen::SeedQr(_) => "SeedQR".to_owned(),
            Screen::Cosign(_) => "Multisig".to_owned(),
            Screen::CosignerKey(_) => "Your multisig key".to_owned(),
            Screen::Register(_) => "Register a wallet".to_owned(),
            Screen::MultisigWallet(screen) => screen.title(),
            Screen::Keep(screen) => screen.title(),
            Screen::Unlock(screen) => screen.title(),
            Screen::Messages(_) => "Sign a message".to_owned(),
            Screen::TypeMessage(_) => "Type the message".to_owned(),
            Screen::MessageReview(_) => "Review the message".to_owned(),
            Screen::MessageSigned(_) => "Signed message".to_owned(),
            #[cfg(feature = "online")]
            Screen::Import(_) => "Watch an account".to_owned(),
            #[cfg(feature = "online")]
            Screen::Pay(_) => "Send".to_owned(),
            #[cfg(feature = "online")]
            Screen::Receive(_) => "Receive".to_owned(),
        }
    }

    /// Whether there is anywhere to go back to: everywhere but the two screens a wallet starts
    /// from.
    fn has_back(&self) -> bool {
        !matches!(self, Screen::Start | Screen::Home(_))
    }

    /// What the buttons do here, for the bar at the bottom.
    fn hints(&self) -> &'static [Hint] {
        match self {
            Screen::Start => &[(Control::DPad, "Move"), (Control::A, "Select")],
            Screen::Generate(screen) => screen.hints(),
            Screen::Restore(screen) => screen.hints(),
            Screen::Setup(screen) => screen.hints(),
            Screen::Keep(screen) => screen.hints(),
            Screen::Unlock(screen) => screen.hints(),
            Screen::TypeMessage(_) => messages::TYPING,
            Screen::MessageReview(_) => messages::READING,
            Screen::Addresses(_) => &[
                (Control::Shoulders, "Previous / next"),
                (Control::A, "Select"),
                (Control::B, "Back"),
            ],
            Screen::Review(_) => {
                &[(Control::DPad, "Read on"), (Control::A, "Select"), (Control::B, "Cancel")]
            }
            _ => MOVE_SELECT_BACK,
        }
    }

    /// Shows the screen and returns the one to move to, if any.
    fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        match self {
            Screen::Start => create::start(ui, shared),
            Screen::Generate(screen) => screen.show(ui, shared),
            Screen::Restore(screen) => screen.show(ui, shared),
            Screen::Setup(screen) => screen.show(ui, shared),
            Screen::Home(screen) => screen.show(ui, shared),
            Screen::Export(screen) => screen.show(ui, shared),
            Screen::Addresses(screen) => screen.show(ui, shared),
            Screen::Files(screen) => screen.show(ui, shared),
            Screen::Review(screen) => screen.show(ui, shared),
            Screen::Outgoing(screen) => screen.show(ui, shared),
            Screen::Backup(screen) => screen.show(ui, shared),
            Screen::BackupWords(screen) => screen.show(ui, shared),
            Screen::SeedQr(screen) => screen.show(ui, shared),
            Screen::Cosign(screen) => screen.show(ui, shared),
            Screen::CosignerKey(screen) => screen.show(ui, shared),
            Screen::Register(screen) => screen.show(ui, shared),
            Screen::MultisigWallet(screen) => screen.show(ui, shared),
            Screen::Keep(screen) => screen.show(ui, shared),
            Screen::Unlock(screen) => screen.show(ui, shared),
            Screen::Messages(screen) => screen.show(ui, shared),
            Screen::TypeMessage(screen) => screen.show(ui, shared),
            Screen::MessageReview(screen) => screen.show(ui, shared),
            Screen::MessageSigned(screen) => screen.show(ui, shared),
            #[cfg(feature = "online")]
            Screen::Import(screen) => screen.show(ui, shared),
            #[cfg(feature = "online")]
            Screen::Pay(screen) => screen.show(ui, shared),
            #[cfg(feature = "online")]
            Screen::Receive(screen) => screen.show(ui, shared),
        }
    }
}

pub struct App {
    shared: Shared,
    screen: Screen,
    /// The widget focused when the D-pad last went up, to tell whether it moved.
    climbing: Option<egui::Id>,
    /// The zoom: as given, or `None` to fit the layouts' height to the screen's.
    scale: Option<f32>,
    styled: bool,
    gamepad: Option<Gamepad>,
}

impl App {
    pub fn new(
        config: Config,
        scale: Option<f32>,
        #[cfg(feature = "online")] online: crate::online::Online,
    ) -> App {
        let shared = Shared {
            config,
            wallet: None,
            kept: None,
            #[cfg(feature = "online")]
            online,
            notice: None,
            focus: true,
            refocus: false,
            frame: 0,
        };
        App { shared, screen: Screen::Start, climbing: None, scale, styled: false, gamepad: None }
    }

    /// Reads the gamepads into `ctx`'s input; see [`Gamepad::start`] for `swap_ab`.
    pub fn start_gamepad(&mut self, ctx: &egui::Context, swap_ab: bool) {
        self.gamepad = Some(Gamepad::start(ctx.clone(), swap_ab));
    }

    #[cfg(feature = "online")]
    pub fn open_watch_only(&mut self, account: Account, ctx: &egui::Context) {
        self.shared.online.open(ctx, &account, Some(0));
        self.shared.wallet = Some(Wallet::watching(account));
        self.screen = Screen::Home(home::Home::default());
    }

    pub fn show(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if !self.styled {
            theme::install(&ctx);
            self.styled = true;
        }
        self.fit(&ctx);
        self.shared.frame = ctx.cumulative_frame_nr();
        if std::mem::take(&mut self.shared.refocus) {
            self.shared.focus = true;
        }
        #[cfg(feature = "online")]
        for notice in self.shared.online.poll() {
            match notice {
                Ok(text) => self.shared.info(text),
                Err(error) => self.shared.error(error),
            }
        }
        // A direction pressed with nothing focused (after a click elsewhere, or Escape) puts the
        // focus back on the screen's first widget.
        let arrow = ctx.input(|input| {
            [Key::ArrowUp, Key::ArrowDown, Key::ArrowLeft, Key::ArrowRight]
                .iter()
                .any(|key| input.key_pressed(*key))
        });
        let focused = ctx.memory(|memory| memory.focused());
        if arrow && focused.is_none() {
            self.shared.focus = true;
        }
        // Up from a widget with nothing above it goes to the back button, which egui's own
        // direction finding misses from anywhere but the left edge. egui moves the focus at the
        // end of a frame, so a press shows its effect, or its lack, in the next.
        if let Some(from) = self.climbing.take()
            && focused == Some(from)
            && self.screen.has_back()
        {
            ctx.memory_mut(|memory| memory.request_focus(back_id()));
        }
        if ctx.input(|input| input.key_pressed(Key::ArrowUp)) {
            self.climbing = focused;
        }

        let bar = || Frame::new().fill(BG).inner_margin(Margin::symmetric(14, 0));
        let title = self.screen.title();
        let back = self.screen.has_back();
        let gamepad = self.gamepad.as_ref().is_some_and(Gamepad::connected);
        Panel::top("title")
            .exact_size(38.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(bar())
            .show(ui, |ui| title_bar(ui, &title, back, &self.shared));
        Panel::bottom("hints")
            .exact_size(28.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(bar())
            .show(ui, |ui| hint_bar(ui, self.screen.hints(), gamepad));
        let margin = Margin { left: 14, right: 14, top: 2, bottom: 4 };
        CentralPanel::default().frame(Frame::new().fill(BG).inner_margin(margin)).show(ui, |ui| {
            let available = ui.available_rect_before_wrap();
            let width = available.width().min(MAX_WIDTH);
            let left = available.center().x - width / 2.0;
            let column =
                Rect::from_min_size(pos2(left, available.top()), vec2(width, available.height()));
            ui.scope_builder(UiBuilder::new().max_rect(column), |ui| {
                // Each in an id scope of its own, as are the parts of a screen that come and go:
                // egui numbers widgets in the order drawn, so a notice appearing above the screen
                // would renumber the widgets below it, and the keyboard focus, held by number,
                // would jump.
                ui.push_id("notice", |ui| notice(ui, &self.shared));
                let next = ui.push_id("screen", |ui| self.screen.show(ui, &mut self.shared)).inner;
                if let Some(next) = next {
                    self.screen = next;
                    self.shared.focus = true;
                    // A notice from this frame is about the move; one from before it is stale.
                    let shared = &mut self.shared;
                    if shared.notice.as_ref().is_some_and(|(_, frame)| *frame < shared.frame) {
                        shared.notice = None;
                    }
                    ctx.request_repaint();
                }
            });
        });
    }

    /// Zooms so the layouts' height fills the screen's, unless a scale was given: a handheld's
    /// 480 pixels and a desktop's window show the same screens, as large as they can be.
    fn fit(&self, ctx: &egui::Context) {
        let zoom = self.scale.unwrap_or_else(|| {
            let native = ctx.native_pixels_per_point().unwrap_or(1.0);
            let pixels = ctx.content_rect().height() * ctx.pixels_per_point();
            (pixels / native / theme::DESIGN_HEIGHT).clamp(1.0, 2.5)
        });
        if (ctx.zoom_factor() - zoom).abs() > 0.01 {
            ctx.set_zoom_factor(zoom);
        }
    }

    #[cfg(test)]
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    #[cfg(test)]
    pub fn screen_title(&self) -> String {
        self.screen.title()
    }

    #[cfg(test)]
    pub fn shared(&mut self) -> &mut Shared {
        &mut self.shared
    }

    #[cfg(test)]
    pub fn open(&mut self, wallet: Wallet) {
        self.shared.wallet = Some(wallet);
        self.screen = Screen::Home(home::Home::default());
        self.shared.focus = true;
    }
}

impl eframe::App for App {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, input: &mut RawInput) {
        if let Some(gamepad) = &self.gamepad {
            gamepad.feed(input);
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

/// The bar at the top: the way back, the screen's title, and which wallet is open on which chain.
fn title_bar(ui: &mut Ui, title: &str, back: bool, shared: &Shared) {
    ui.horizontal_centered(|ui| {
        if back {
            ui.spacing_mut().item_spacing.x = 4.0;
            back_button(ui);
        }
        text(ui, title, strong(16.0), TEXT);
        // Right to left: the first chip drawn is the rightmost.
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            #[cfg(feature = "online")]
            shared.online.status(ui);
            if let Some(wallet) = &shared.wallet {
                if wallet.seed.is_none() {
                    chip(ui, "WATCH-ONLY", strong(10.0), DIM);
                }
                chip(ui, &wallet.account.fingerprint().to_string(), mono(11.5), TEXT);
            }
            match shared.config.network {
                Network::Bitcoin => chip(ui, "MAINNET", strong(10.0), ACCENT),
                network => {
                    chip(ui, &network.to_string().to_uppercase(), strong(10.0), TEST_NETWORK)
                }
            };
        });
    });
}

fn notice(ui: &mut Ui, shared: &Shared) {
    let Some((notice, _)) = &shared.notice else { return };
    let (color, message) = match notice {
        Notice::Info(message) => (GOOD, message),
        Notice::Error(message) => (BAD, message),
    };
    Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(RADIUS)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            text(ui, message.as_str(), body(13.0), color);
        });
    ui.add_space(2.0);
}
