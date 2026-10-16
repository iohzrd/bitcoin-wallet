//! The seed's backup, any time after it was made: its words again, to make another copy; a copy
//! checked word by word against the seed; and its SeedQR, to copy onto paper as a code that
//! SeedSigner, Sparrow or this wallet scans back in.

use eframe::egui::{Align, Layout, Ui};
use wallet_airgap::qr::Qr;
use wallet_airgap::seedqr::{self, Format};
use wallet_core::Mnemonic;

use crate::app::{Screen, Shared};
use crate::create::{PAGE, Restore, word_grid};
use crate::home::Home;
use crate::theme::{DIM, FAINT, TEXT, WARN, body, strong};
use crate::widgets::{
    Emphasis, back_pressed, button, chip, menu_item, page_dots, qr_grid_card, text,
};

/// What the screens that show the seed say first.
const SECRET: &str = "Anyone who sees this can take the coins. Look around first.";

fn mnemonic(shared: &Shared) -> Option<Mnemonic> {
    shared.wallet.as_ref().and_then(|wallet| wallet.mnemonic.clone())
}

pub struct Backup;

impl Backup {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(mnemonic) = mnemonic(shared) else { return Some(Screen::Home(Home::default())) };
        text(ui, "The words are the wallet. Keep copies apart, and check them.", body(12.5), DIM);
        let show = menu_item(ui, "Show the words", Some("To make another copy"));
        shared.autofocus(&show);
        if show.clicked() {
            return Some(Screen::BackupWords(Words { page: 0 }));
        }
        if menu_item(ui, "Check a copy", Some("Type it in, to compare with the seed")).clicked() {
            return Some(Screen::Restore(Restore::check(mnemonic)));
        }
        if menu_item(ui, "SeedQR", Some("The words as a QR code, to copy onto paper")).clicked() {
            return Some(Screen::SeedQr(SeedQr::new(&mnemonic, Format::Compact)));
        }
        back_pressed(ui).then(|| Screen::Home(Home::default()))
    }
}

/// The words, a page at a time, as they were shown when the seed was made.
pub struct Words {
    page: usize,
}

impl Words {
    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(mnemonic) = mnemonic(shared) else { return Some(Screen::Home(Home::default())) };
        let words: Vec<&str> = mnemonic.words().collect();
        let pages = words.len().div_ceil(PAGE);
        text(ui, SECRET, body(12.5), WARN);
        word_grid(ui, &words, self.page * PAGE);
        let last = self.page + 1 == pages;
        let next = ui
            .horizontal(|ui| {
                page_dots(ui, self.page, pages);
                let width = (ui.available_width() - 4.0).min(220.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    button(ui, if last { "Done" } else { "Next words" }, Emphasis::Primary, width)
                })
                .inner
            })
            .inner;
        shared.autofocus(&next);
        match (next.clicked(), back_pressed(ui)) {
            (true, _) if last => Some(Screen::Backup(Backup)),
            (true, _) => {
                self.page += 1;
                shared.refocus();
                None
            }
            (false, true) if self.page > 0 => {
                self.page -= 1;
                shared.refocus();
                None
            }
            (false, true) => Some(Screen::Backup(Backup)),
            (false, false) => None,
        }
    }
}

/// The SeedQR, with a grid to copy it onto a paper template by, in either of its forms.
pub struct SeedQr {
    format: Format,
    qr: Qr,
}

impl SeedQr {
    pub fn new(mnemonic: &Mnemonic, format: Format) -> SeedQr {
        SeedQr { format, qr: seedqr::qr(mnemonic, format) }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(mnemonic) = mnemonic(shared) else { return Some(Screen::Home(Home::default())) };
        let (name, other, other_format) = match self.format {
            Format::Compact => ("COMPACT", "Standard SeedQR", Format::Standard),
            Format::Standard => ("STANDARD", "Compact SeedQR", Format::Compact),
        };
        let width = self.qr.width();
        let mut next = None;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            let side = ui.available_height().min(ui.available_width() * 0.55);
            qr_grid_card(ui, &self.qr, side);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    chip(ui, name, strong(10.0), TEXT);
                    text(ui, format!("{width} × {width}"), strong(16.0), TEXT);
                });
                text(ui, "Anyone who sees it can take the coins.", body(12.0), WARN);
                let about = "Copy it onto a SeedQR template; SeedSigner and Sparrow scan it.";
                text(ui, about, body(12.0), FAINT);
                let width = ui.available_width();
                if button(ui, other, Emphasis::Secondary, width).clicked() {
                    next = Some(Screen::SeedQr(SeedQr::new(&mnemonic, other_format)));
                }
                let done = button(ui, "Done", Emphasis::Primary, width);
                shared.autofocus(&done);
                if done.clicked() {
                    next = Some(Screen::Backup(Backup));
                }
            });
        });
        next.or_else(|| back_pressed(ui).then_some(Screen::Backup(Backup)))
    }
}
