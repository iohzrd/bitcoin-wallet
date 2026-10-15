//! The online half, compiled only with the `online` feature: the account's watch-only wallet on a
//! node, its balance and history, the PSBTs it funds for the signer, and broadcasting what the
//! signer signed. Calls to the node run on threads of their own, so a slow node or a long rescan
//! never stalls the screen.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, channel};

use eframe::egui::{self, Align, Layout, Margin, TextEdit, Ui};
use wallet_airgap::qr::Qr;
use wallet_core::account::{Account, Derivation};
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::bitcoin::{Address, Amount, Denomination, Network, Txid};
use wallet_node::{Auth, Balance, Entry, Node};

use crate::app::{Screen, Shared, Wallet};
use crate::home::Home;
use crate::sign::{Origin, Review};
use crate::theme::{ACCENT, BAD, DIM, FAINT, GOOD, TEXT, WARN, body, mono, strong};
use crate::widgets::{
    Emphasis, address, amount, back_pressed, beside_qr, button, chip, menu_item, text,
};

#[derive(clap::Args, Debug)]
pub struct NodeArgs {
    /// The node's RPC server [default: 127.0.0.1 at the network's RPC port]
    #[arg(long)]
    rpc_url: Option<String>,
    /// The node's cookie file [default: .cookie in the network's directory under ~/.bitcoin]
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
    /// An RPC login, instead of the cookie
    #[arg(long, requires = "rpc_password")]
    rpc_user: Option<String>,
    /// The password of --rpc-user
    #[arg(long, requires = "rpc_user")]
    rpc_password: Option<String>,
    /// A watch-only account to open at start: its descriptor, or a file holding it
    #[arg(long)]
    pub watch: Option<String>,
}

impl NodeArgs {
    pub fn node(&self, network: Network) -> Node {
        let port = match network {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Testnet4 => 48332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        };
        let url = self.rpc_url.clone().unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
        let auth = match (&self.rpc_user, &self.rpc_password) {
            (Some(user), Some(password)) => {
                Auth::UserPass { user: user.clone(), password: password.clone() }
            }
            _ => Auth::Cookie(self.rpc_cookie.clone().unwrap_or_else(|| {
                let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
                let dir = match network {
                    Network::Bitcoin => "",
                    Network::Testnet => "testnet3",
                    Network::Testnet4 => "testnet4",
                    Network::Signet => "signet",
                    Network::Regtest => "regtest",
                };
                home.join(".bitcoin").join(dir).join(".cookie")
            })),
        };
        Node::new(url, auth)
    }

    /// The account `--watch` names, read from the file it names if it names one.
    pub fn watch(&self, network: Network) -> Option<Result<Account, String>> {
        let watch = self.watch.as_ref()?;
        let text = std::fs::read_to_string(watch).unwrap_or_else(|_| watch.clone());
        Some(Account::from_descriptor(text.trim(), network).map_err(|error| error.to_string()))
    }
}

/// A call to the node on a thread of its own.
pub struct Task<T> {
    result: Receiver<T>,
}

impl<T: Send + 'static> Task<T> {
    pub fn spawn(ctx: &egui::Context, call: impl FnOnce() -> T + Send + 'static) -> Task<T> {
        let (send, result) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = send.send(call());
            ctx.request_repaint();
        });
        Task { result }
    }

    pub fn poll(&self) -> Option<T> {
        self.result.try_recv().ok()
    }
}

type Opened = Result<(wallet_node::Wallet, Balance, Vec<Entry>), String>;

/// The node, and the open account's wallet on it.
pub struct Online {
    node: Node,
    network: Network,
    wallet: Option<wallet_node::Wallet>,
    balance: Option<Balance>,
    history: Vec<Entry>,
    opening: Option<Task<Opened>>,
    broadcasting: Option<Task<Result<Txid, String>>>,
    /// The node's last failure, shown until it next answers.
    problem: Option<String>,
    /// For refreshing the balance after a broadcast, which ends on another thread.
    ctx: Option<egui::Context>,
}

const HISTORY: usize = 8;

impl Online {
    pub fn new(node: Node, network: Network) -> Online {
        Online {
            node,
            network,
            wallet: None,
            balance: None,
            history: Vec::new(),
            opening: None,
            broadcasting: None,
            problem: None,
            ctx: None,
        }
    }

    /// Opens the account's wallet on the node, making it if the node has none; see
    /// [`Node::wallet`] for `rescan_since`. Then reads its balance and history.
    pub fn open(&mut self, ctx: &egui::Context, account: &Account, rescan_since: Option<u64>) {
        let (node, account, network) = (self.node.clone(), account.clone(), self.network);
        self.wallet = None;
        self.ctx = Some(ctx.clone());
        self.opening = Some(Task::spawn(ctx, move || {
            let chain = node.network().map_err(|error| error.to_string())?;
            if chain != network {
                return Err(format!("The node is on {chain}, the wallet on {network}."));
            }
            let wallet = node.wallet(&account, rescan_since).map_err(|error| error.to_string())?;
            let balance = wallet.balance().map_err(|error| error.to_string())?;
            let history = wallet.history(HISTORY).map_err(|error| error.to_string())?;
            Ok((wallet, balance, history))
        }));
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        let Some(wallet) = self.wallet.clone() else { return };
        self.opening = Some(Task::spawn(ctx, move || {
            let balance = wallet.balance().map_err(|error| error.to_string())?;
            let history = wallet.history(HISTORY).map_err(|error| error.to_string())?;
            Ok((wallet, balance, history))
        }));
    }

    pub fn close(&mut self) {
        *self = Online::new(self.node.clone(), self.network);
    }

    pub fn connected(&self) -> bool {
        self.wallet.is_some()
    }

    pub fn wallet(&self) -> Option<&wallet_node::Wallet> {
        self.wallet.as_ref()
    }

    pub fn broadcast(&mut self, ctx: &egui::Context, psbt: &Psbt) {
        let (Some(wallet), psbt) = (self.wallet.clone(), psbt.clone()) else { return };
        self.broadcasting = Some(Task::spawn(ctx, move || {
            wallet.broadcast(&psbt).map_err(|error| error.to_string())
        }));
    }

    /// Takes in what the node's calls have answered, and returns what to tell the user.
    pub fn poll(&mut self) -> Vec<Result<String, String>> {
        let mut notices = Vec::new();
        if let Some(opened) = self.opening.as_ref().and_then(Task::poll) {
            self.opening = None;
            match opened {
                Ok((wallet, balance, history)) => {
                    self.wallet = Some(wallet);
                    self.balance = Some(balance);
                    self.history = history;
                    self.problem = None;
                }
                Err(error) => self.problem = Some(error),
            }
        }
        if let Some(broadcast) = self.broadcasting.as_ref().and_then(Task::poll) {
            self.broadcasting = None;
            notices.push(broadcast.map(|txid| format!("Broadcast {txid}")));
            if let Some(ctx) = &self.ctx {
                self.refresh(&ctx.clone());
            }
        }
        notices
    }

    /// The node's chip in the title bar.
    pub fn status(&self, ui: &mut Ui) {
        let (label, color) = match (&self.problem, &self.wallet, &self.opening) {
            (Some(_), ..) => ("NODE ERROR", BAD),
            (None, _, Some(_)) => ("SYNCING", WARN),
            (None, Some(_), None) => ("NODE", GOOD),
            (None, None, None) => return,
        };
        chip(ui, label, strong(10.0), color);
    }

    /// The balance and the latest transactions, for the home screen's account card.
    pub fn summary(&mut self, ui: &mut Ui) {
        if let Some(problem) = &self.problem {
            text(ui, problem.as_str(), body(12.5), BAD);
        }
        if self.opening.is_some() && self.wallet.is_none() {
            text(ui, "Opening the wallet on the node. A rescan can take a while.", body(12.5), DIM);
        }
        let Some(balance) = self.balance else { return };
        ui.horizontal(|ui| {
            ui.label(amount(balance.trusted, 22.0, TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let idle = self.wallet.is_some() && self.opening.is_none();
                if ui.add_enabled(idle, egui::Button::new("Refresh").small()).clicked() {
                    self.refresh(ui.ctx());
                }
            });
        });
        for (more, label) in [(balance.pending, "unconfirmed"), (balance.immature, "maturing")] {
            if more > Amount::ZERO {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(amount(more, 12.0, DIM));
                    text(ui, label, body(12.0), FAINT);
                });
            }
        }
        for entry in self.history.iter().take(HOME_HISTORY) {
            let sats = entry.amount.to_sat();
            let (sign, color) = if sats >= 0 { ("+", GOOD) } else { ("−", TEXT) };
            let confirmations = match entry.confirmations {
                ..0 => "replaced".to_owned(),
                0 => "unconfirmed".to_owned(),
                1 => "1 confirmation".to_owned(),
                n => format!("{n} confirmations"),
            };
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                text(ui, sign, mono(12.0), color);
                ui.label(amount(Amount::from_sat(sats.unsigned_abs()), 12.0, color));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    text(ui, confirmations, body(11.5), FAINT);
                });
            });
        }
    }
}

/// Transactions the home screen lists under the balance, as many as leave room for the menu.
const HOME_HISTORY: usize = 3;

/// A text field as the online screens' forms have it: a label above, and a margin a thumb can find.
fn form_field(
    ui: &mut Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    mono_font: bool,
) -> egui::Response {
    let label = text(ui, label, body(12.0), DIM);
    let mut edit = TextEdit::singleline(value)
        .desired_width(f32::INFINITY)
        .margin(Margin::symmetric(10, 8))
        .hint_text(hint);
    if mono_font {
        edit = edit.font(mono(14.0));
    }
    ui.add(edit).labelled_by(label.id)
}

/// Opening a watch-only account from its descriptor, pasted or from a file.
pub struct Import {
    text: String,
    /// The descriptor files in the directories, found once on entering.
    files: Vec<PathBuf>,
}

impl Import {
    pub fn new(shared: &Shared) -> Import {
        Import { text: String::new(), files: descriptor_files(&shared.config.dirs) }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let about = "Its descriptor, as the signer exports it: wpkh(…) or tr(…) ending /<0;1>/*.";
        let label = text(ui, about, body(12.5), DIM);
        let edit = ui.add(
            TextEdit::multiline(&mut self.text)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8))
                .font(mono(12.0)),
        );
        shared.autofocus(&edit.labelled_by(label.id));
        let network = shared.config.network;
        let watch = button(ui, "Watch", Emphasis::Primary, ui.available_width()).clicked();
        let mut chosen = None;
        for path in &self.files {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let dir = path.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
            if menu_item(ui, &format!("From {name}"), Some(&dir)).clicked() {
                match std::fs::read_to_string(path) {
                    Ok(text) => chosen = Some(text),
                    Err(error) => shared.error(format!("{}: {error}", path.display())),
                }
            }
        }
        let text = chosen.unwrap_or_else(|| self.text.clone());
        if watch || text != self.text {
            match Account::from_descriptor(text.trim(), network) {
                Ok(account) => {
                    shared.online.open(ui.ctx(), &account, Some(0));
                    shared.wallet = Some(Wallet { seed: None, account });
                    return Some(Screen::Home(Home::default()));
                }
                Err(error) => shared.error(error),
            }
        }
        back_pressed(ui).then_some(Screen::Start)
    }
}

/// The `.txt` files in `dirs`, where the signer saves descriptors.
fn descriptor_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = (dirs.iter())
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .filter(|path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let text = text.trim_start();
            text.starts_with("wpkh(") || text.starts_with("tr(")
        })
        .collect();
    files.sort();
    files
}

/// A payment: the node funds it as a PSBT for the review screen.
pub struct Pay {
    address: String,
    amount: String,
    fee_rate: String,
    creating: Option<Task<Result<Psbt, String>>>,
}

impl Default for Pay {
    fn default() -> Pay {
        Pay { address: String::new(), amount: String::new(), fee_rate: "2".into(), creating: None }
    }
}

impl Pay {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        if let Some(created) = self.creating.as_ref().and_then(Task::poll) {
            self.creating = None;
            match created {
                Ok(psbt) => return Some(Screen::Review(Review::new(psbt, Origin::Node, shared))),
                Err(error) => shared.error(error),
            }
        }
        let address = form_field(ui, "To", &mut self.address, "bc1…", true);
        shared.autofocus(&address);
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 8.0) / 2.0;
            ui.vertical(|ui| {
                ui.set_width(width);
                form_field(ui, "Amount, BTC", &mut self.amount, "0.001", true);
            });
            ui.vertical(|ui| {
                ui.set_width(width);
                form_field(ui, "Fee rate, sat/vB", &mut self.fee_rate, "2", true);
            });
        });
        ui.add_space(4.0);
        let busy = self.creating.is_some();
        let label = if busy { "Asking the node…" } else { "Make the PSBT" };
        let make = ui
            .add_enabled_ui(!busy, |ui| button(ui, label, Emphasis::Primary, ui.available_width()));
        if make.inner.clicked() {
            match self.payment(shared.config.network) {
                Ok((address, amount, fee_rate)) => {
                    if let Some(wallet) = shared.online.wallet().cloned() {
                        self.creating = Some(Task::spawn(ui.ctx(), move || {
                            wallet
                                .create_psbt(&[(address, amount)], fee_rate, None)
                                .map_err(|error| error.to_string())
                        }));
                    }
                }
                Err(error) => shared.error(error),
            }
        }
        back_pressed(ui).then(|| Screen::Home(Home::default()))
    }

    fn payment(&self, network: Network) -> Result<(Address, Amount, f64), String> {
        let address = Address::from_str(self.address.trim())
            .map_err(|error| format!("The address: {error}"))?
            .require_network(network)
            .map_err(|error| format!("The address: {error}"))?;
        let amount = Amount::from_str_in(self.amount.trim(), Denomination::Bitcoin)
            .map_err(|error| format!("The amount: {error}"))?;
        let fee_rate: f64 =
            self.fee_rate.trim().parse().map_err(|_| "The fee rate: not a number".to_owned())?;
        if !(1.0..=10_000.0).contains(&fee_rate) {
            return Err("The fee rate: from 1 to 10000 sat/vB".to_owned());
        }
        Ok((address, amount, fee_rate))
    }
}

/// The node's next receive address, with the index to find it under on the signer.
pub struct Receive {
    asking: Option<Task<Result<(Address, Derivation), String>>>,
    shown: Option<(Address, Derivation, Option<Qr>)>,
}

impl Receive {
    #[cfg(test)]
    pub fn shown(&self) -> Option<(Address, Derivation)> {
        self.shown.as_ref().map(|(address, derivation, _)| (address.clone(), *derivation))
    }

    pub fn new(ctx: &egui::Context, shared: &Shared) -> Receive {
        let asking = shared.online.wallet().cloned().map(|wallet| {
            Task::spawn(ctx, move || wallet.receive_address().map_err(|error| error.to_string()))
        });
        Receive { asking, shown: None }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        if let Some(answer) = self.asking.as_ref().and_then(Task::poll) {
            self.asking = None;
            match answer {
                Ok((address, derivation)) => {
                    let qr = Qr::new(&address.to_string().to_uppercase()).ok();
                    self.shown = Some((address, derivation, qr));
                }
                Err(error) => shared.error(error),
            }
        }
        let mut done = false;
        let Some((shown, derivation, qr)) = &self.shown else {
            text(ui, "Asking the node for an address…", body(13.0), DIM);
            return back_pressed(ui).then(|| Screen::Home(Home::default()));
        };
        beside_qr(ui, qr.as_ref(), |ui| {
            ui.horizontal(|ui| {
                chip(ui, "RECEIVE", strong(10.0), ACCENT);
                text(ui, format!("#{}", derivation.index), strong(20.0), TEXT);
            });
            address(ui, &shown.to_string(), 15.0);
            let check =
                format!("Check it on the signer: Addresses, receive address {}.", derivation.index);
            text(ui, check, body(12.0), DIM);
            ui.add_space(2.0);
            let button = button(ui, "Done", Emphasis::Primary, ui.available_width());
            shared.autofocus(&button);
            done = button.clicked();
        });
        (done || back_pressed(ui)).then(|| Screen::Home(Home::default()))
    }
}
