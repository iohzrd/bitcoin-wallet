//! The wallet: a signer that keeps its seed in memory, and on the device, encrypted, only if asked
//! to, and takes PSBTs in and out as files and QR codes, and, built with the `online` feature, the watch-only wallet that funds them through a
//! node and broadcasts them signed. The same screens run on a desktop with a mouse and keyboard and
//! on a handheld with a D-pad.

mod app;
mod backup;
mod cosign;
mod create;
mod files;
mod gamepad;
mod home;
mod keep;
#[cfg(feature = "online")]
mod online;
mod sign;
mod task;
mod theme;
#[cfg(test)]
mod ui_tests;
mod widgets;

use std::path::PathBuf;

use clap::Parser;
use eframe::egui;
use wallet_core::bitcoin::Network;
use wallet_core::store::Params;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The chain: bitcoin, testnet, testnet4, signet or regtest
    #[arg(long, default_value = "bitcoin")]
    network: Network,
    /// A directory to read PSBTs from and write them to; repeat for more [default: home and
    /// every mounted removable volume]
    #[arg(long = "dir")]
    dirs: Vec<PathBuf>,
    /// Where a wallet kept on the device is kept, encrypted [default: $XDG_DATA_HOME/wallet, or
    /// ~/.local/share/wallet]
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Never keep a wallet on the device, as a signer that should hold nothing once it is off
    #[arg(long, conflicts_with = "data_dir")]
    no_store: bool,
    /// Fill the screen, as on a handheld
    #[arg(long)]
    fullscreen: bool,
    /// The size of everything [default: as large as the screen's height fits]
    #[arg(long)]
    scale: Option<f32>,
    /// Make the right face button A, as on Nintendo's layout, rather than the bottom one
    #[arg(long)]
    swap_ab: bool,
    #[cfg(feature = "online")]
    #[command(flatten)]
    node: online::NodeArgs,
}

fn main() -> eframe::Result {
    let args = Args::parse();
    let dirs = if args.dirs.is_empty() { files::default_dirs() } else { args.dirs.clone() };
    let data_dir = args.data_dir.clone().or_else(files::default_data_dir);
    let store = data_dir.filter(|_| !args.no_store).map(|dir| keep::path(&dir, args.network));
    let config = app::Config { network: args.network, dirs, store, kdf: Params::DEFAULT };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Wallet")
            .with_inner_size([640.0, 480.0])
            .with_fullscreen(args.fullscreen),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "wallet",
        options,
        Box::new(move |cc| {
            #[cfg(feature = "online")]
            let online = online::Online::new(args.node.node(args.network), args.network);
            let mut app = app::App::new(
                config,
                args.scale,
                #[cfg(feature = "online")]
                online,
            );
            app.start_gamepad(&cc.egui_ctx, args.swap_ab);
            #[cfg(feature = "online")]
            match args.node.watch(args.network) {
                Some(Ok(account)) => app.open_watch_only(account, &cc.egui_ctx),
                Some(Err(error)) => return Err(format!("--watch: {error}").into()),
                None => {}
            }
            Ok(Box::new(app))
        }),
    )
}
