//! Opening a wallet: making a new seed or restoring one from its words, then choosing its
//! passphrase and its kind of account. The seed lives in memory only; nothing here writes it
//! anywhere, so closing the app or the wallet forgets it.

use eframe::egui::{Button, Event, Grid, Key, RichText, ScrollArea, Ui, vec2};
use wallet_core::Mnemonic;
use wallet_core::account::{Account, Kind};
use wallet_core::bitcoin::bip32::Fingerprint;
use wallet_core::bitcoin::secp256k1::Secp256k1;
use wallet_core::dice;
use wallet_core::seed::Seed;
use zeroize::Zeroizing;

use crate::app::{Screen, Shared, Wallet};
use crate::backup::Backup;
use crate::theme::{ACCENT, DIM, FAINT, TEXT, WARN, body, mono, strong};
use crate::widgets::{
    Control, Emphasis, Hint, Keyboard, Keys, Press, back_pressed, button, button_row, card,
    die_button, field, menu_item, page_dots, progress, text,
};

pub fn start(ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
    ui.add_space(6.0);
    text(ui, "Open a wallet", strong(20.0), TEXT);
    let kept = shared.config.store.as_ref().is_some_and(|path| path.exists());
    let about = match (&shared.config.store, kept) {
        (_, true) => "A wallet is kept on this device, sealed under its passphrase.",
        (Some(_), false) => "The seed lives in memory only, unless you choose to keep it.",
        (None, false) => "The seed lives in memory only. Nothing writes it to disk.",
    };
    text(ui, about, body(13.0), DIM);
    ui.add_space(6.0);
    if kept {
        let unlock = menu_item(ui, "Unlock", Some("The wallet kept on this device"));
        shared.autofocus(&unlock);
        if unlock.clicked() {
            match crate::keep::Unlock::new(shared) {
                Ok(unlock) => return Some(Screen::Unlock(unlock)),
                Err(error) => shared.error(error),
            }
        }
    }
    let new = menu_item(ui, "New seed", Some("Make 12 or 24 recovery words"));
    shared.autofocus(&new);
    if new.clicked() {
        return Some(Screen::Generate(Generate::default()));
    }
    if menu_item(ui, "Restore", Some("Type in your recovery words")).clicked() {
        return Some(Screen::Restore(Restore::default()));
    }
    #[cfg(feature = "online")]
    if menu_item(ui, "Watch-only", Some("Follow an account by its descriptor")).clicked() {
        return Some(Screen::Import(crate::online::Import::new(shared)));
    }
    None
}

#[derive(Default)]
pub struct Generate {
    stage: Stage,
}

#[derive(Default)]
enum Stage {
    #[default]
    Length,
    /// Taking dice rolls, until there are `needed`.
    Dice { rolls: Zeroizing<Vec<u8>>, needed: usize },
    /// The words, a page of `PAGE` at a time.
    Words { mnemonic: Mnemonic, page: usize },
    /// Asking for some of the words back, to know they were written down.
    Check { mnemonic: Mnemonic, questions: Vec<Question>, asked: usize },
}

/// Which word is at `position`, of `choices`, one of which is it.
struct Question {
    position: usize,
    choices: [&'static str; 4],
}

/// Words shown at once: as many as a handheld's screen fits legibly.
pub(crate) const PAGE: usize = 12;
/// Words asked back: one of each group of this many, as Jade asks.
const GROUP: usize = 3;

impl Generate {
    pub fn title(&self) -> String {
        match self.stage {
            Stage::Length => "New seed",
            Stage::Dice { .. } => "Dice rolls",
            Stage::Words { .. } => "Recovery words",
            Stage::Check { .. } => "Check your copy",
        }
        .to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.stage {
            Stage::Dice { .. } => {
                &[(Control::DPad, "Move"), (Control::A, "Enter roll"), (Control::B, "Undo")]
            }
            _ => &[(Control::DPad, "Move"), (Control::A, "Select"), (Control::B, "Back")],
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        // The stage to move to, set while the current one is borrowed and moved to after.
        let mut stage = None;
        let screen = match &mut self.stage {
            Stage::Length => {
                ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    let about = "Dice spare you trusting this device's randomness.";
                    text(ui, about, body(12.5), DIM);
                    for (words, entropy) in [(12, 16), (24, 32)] {
                        let title = format!("{words} words");
                        let button = menu_item(ui, &title, Some("From this device's randomness"));
                        shared.autofocus(&button);
                        if button.clicked() {
                            match new_mnemonic(entropy) {
                                Ok(mnemonic) => stage = Some(Stage::Words { mnemonic, page: 0 }),
                                Err(error) => shared.error(error),
                            }
                        }
                    }
                    for words in [12, 24] {
                        let needed = dice::rolls_for(words).expect("12 and 24 words take rolls");
                        let title = format!("{words} words from dice");
                        let about = format!("Roll a die {needed} times");
                        if menu_item(ui, &title, Some(&about)).clicked() {
                            stage = Some(Stage::Dice { rolls: Zeroizing::default(), needed });
                        }
                    }
                });
                back_pressed(ui).then_some(Screen::Start)
            }
            Stage::Dice { rolls, needed } => {
                ui.spacing_mut().item_spacing.y = 6.0;
                progress(ui, rolls.len() as f32 / *needed as f32);
                ui.horizontal(|ui| {
                    text(ui, "Roll a die and enter the face it shows.", body(12.5), DIM);
                    ui.with_layout(
                        eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                        |ui| text(ui, format!("{} of {needed}", rolls.len()), mono(12.5), TEXT),
                    );
                });
                // In an id scope, as its lines grow above the faces.
                ui.push_id("rolls", |ui| {
                    card(ui, |ui| match rolls.is_empty() {
                        true => {
                            let about = "The rolls show here in fives, to check against paper.";
                            text(ui, about, body(12.5), FAINT)
                        }
                        false => text(ui, in_fives(rolls), mono(15.0), TEXT),
                    });
                });
                let mut rolled = None;
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let side = ((ui.available_width() - 5.0 * 8.0) / 6.0).min(60.0);
                    // Centered, when a wide window leaves room on either side.
                    let room = ui.available_width() - 6.0 * side - 5.0 * 8.0;
                    if room > 0.0 {
                        ui.add_space(room / 2.0);
                    }
                    for face in 1..=6 {
                        let button = die_button(ui, face, side);
                        shared.autofocus(&button);
                        if button.clicked() {
                            rolled = Some(face);
                        }
                    }
                });
                let typed = ui.input(|input| {
                    let mut faces = input.events.iter().filter_map(|event| match event {
                        Event::Text(text) => text.chars().find(|c| ('1'..='6').contains(c)),
                        _ => None,
                    });
                    faces.next_back().map(|face| face as u8 - b'0')
                });
                let undo = ui.add_enabled_ui(!rolls.is_empty(), |ui| {
                    button(ui, "Undo the last roll", Emphasis::Secondary, ui.available_width())
                });
                let about = "SeedSigner and Coldcard make the same words from the same rolls.";
                text(ui, about, body(11.5), FAINT);
                let backspace = ui.input(|input| input.key_pressed(Key::Backspace));
                if let Some(face) = rolled.or(typed) {
                    rolls.push(face);
                    if rolls.len() == *needed {
                        match dice::mnemonic(rolls) {
                            Ok(mnemonic) => stage = Some(Stage::Words { mnemonic, page: 0 }),
                            Err(error) => shared.error(error),
                        }
                    }
                } else if undo.inner.clicked() || backspace || back_pressed(ui) {
                    if rolls.pop().is_none() {
                        stage = Some(Stage::Length);
                    }
                    // B is Escape, which takes the focus away; give it back to the faces.
                    shared.refocus();
                }
                None
            }
            Stage::Words { mnemonic, page } => {
                let words: Vec<&str> = mnemonic.words().collect();
                let pages = words.len().div_ceil(PAGE);
                text(
                    ui,
                    "Write them on paper, in order. Whoever has them has the coins.",
                    body(12.5),
                    DIM,
                );
                word_grid(ui, &words, *page * PAGE);
                let last = *page + 1 == pages;
                let label = if last { "I wrote them down" } else { "Next words" };
                let next = ui
                    .horizontal(|ui| {
                        page_dots(ui, *page, pages);
                        let width = ui.available_width() - 4.0;
                        ui.with_layout(
                            eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                            |ui| button(ui, label, Emphasis::Primary, width.min(220.0)),
                        )
                        .inner
                    })
                    .inner;
                shared.autofocus(&next);
                let page = match (next.clicked(), back_pressed(ui)) {
                    (true, _) if last => {
                        let questions = questions(&words);
                        stage =
                            Some(Stage::Check { mnemonic: mnemonic.clone(), questions, asked: 0 });
                        None
                    }
                    (true, _) => Some(*page + 1),
                    (false, true) if *page == 0 => {
                        stage = Some(Stage::Length);
                        None
                    }
                    (false, true) => Some(*page - 1),
                    (false, false) => None,
                };
                if let Some(page) = page {
                    stage = Some(Stage::Words { mnemonic: mnemonic.clone(), page });
                }
                None
            }
            Stage::Check { mnemonic, questions, asked } => {
                let question = &questions[*asked];
                ui.horizontal(|ui| {
                    text(
                        ui,
                        format!("Which is word {}?", question.position + 1),
                        strong(18.0),
                        TEXT,
                    );
                    ui.with_layout(
                        eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                        |ui| {
                            let total = questions.len();
                            text(ui, format!("{} of {total}", *asked + 1), body(12.5), DIM);
                        },
                    );
                });
                let right = mnemonic.words().nth(question.position).expect("a word of the seed");
                let mut screen = None;
                for choice in question.choices {
                    let button = menu_item(ui, choice, None);
                    shared.autofocus(&button);
                    if !button.clicked() {
                        continue;
                    }
                    if choice != right {
                        let position = question.position + 1;
                        shared.error(format!(
                            "That is not word {position}. Compare your copy with the words again."
                        ));
                        let page = question.position / PAGE;
                        stage = Some(Stage::Words { mnemonic: mnemonic.clone(), page });
                    } else if *asked + 1 < questions.len() {
                        *asked += 1;
                        shared.refocus();
                    } else {
                        screen = Some(Screen::Setup(Setup::new(mnemonic.clone(), false)));
                    }
                }
                if back_pressed(ui) {
                    stage = Some(Stage::Words { mnemonic: mnemonic.clone(), page: 0 });
                }
                screen
            }
        };
        if let Some(stage) = stage {
            self.stage = stage;
            shared.refocus();
        }
        screen
    }
}

#[cfg(test)]
impl Generate {
    /// The words, while they are shown.
    pub fn shown_words(&self) -> Option<Vec<&'static str>> {
        match &self.stage {
            Stage::Words { mnemonic, .. } => Some(mnemonic.words().collect()),
            _ => None,
        }
    }

    /// The word asked for and the choices, in their order, while one is asked for.
    pub fn question(&self) -> Option<(&'static str, [&'static str; 4])> {
        let Stage::Check { mnemonic, questions, asked } = &self.stage else { return None };
        let question = &questions[*asked];
        Some((mnemonic.words().nth(question.position)?, question.choices))
    }
}

/// Rolls as their digits in groups of five, the way they are easiest to check against paper.
fn in_fives(rolls: &[u8]) -> String {
    let groups: Vec<String> = rolls
        .chunks(5)
        .map(|group| group.iter().map(|roll| char::from(b'0' + roll)).collect())
        .collect();
    groups.join(" ")
}

/// A seed of `bytes` bytes of the operating system's randomness.
fn new_mnemonic(bytes: usize) -> Result<Mnemonic, String> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut entropy[..bytes]).map_err(|error| format!("no randomness: {error}"))?;
    Mnemonic::from_entropy(&entropy[..bytes]).map_err(|error| error.to_string())
}

/// A position in each group of `GROUP` words, each with the word there and three others in a
/// random order. The others are the seed's own words where it has enough, as Jade picks them: a
/// word from the whole list is easy to rule out as one never written down.
fn questions(words: &[&str]) -> Vec<Question> {
    let list = wallet_core::bip39::Language::English.word_list();
    let listed = |word: &str| list.iter().copied().find(|listed| *listed == word).expect("listed");
    (0..words.len().div_ceil(GROUP))
        .map(|group| {
            let start = group * GROUP;
            let position = start + random_below(GROUP.min(words.len() - start));
            let right = listed(words[position]);
            let mut choices = vec![right];
            let mut others: Vec<&'static str> = words.iter().map(|word| listed(word)).collect();
            shuffle(&mut others);
            for other in
                others.into_iter().chain(std::iter::repeat_with(|| list[random_below(list.len())]))
            {
                if choices.len() == 4 {
                    break;
                }
                if !choices.contains(&other) {
                    choices.push(other);
                }
            }
            shuffle(&mut choices);
            Question { position, choices: choices.try_into().expect("four choices") }
        })
        .collect()
}

fn random_below(n: usize) -> usize {
    // The bias of a 64-bit draw modulo a few thousand is far below anything that matters here.
    getrandom::u64().expect("randomness") as usize % n
}

fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        items.swap(i, random_below(i + 1));
    }
}

/// `words` from `from`, a page of them, numbered and in columns read top to bottom.
pub(crate) fn word_grid(ui: &mut Ui, words: &[&str], from: usize) {
    let page = &words[from..(from + PAGE).min(words.len())];
    let rows = page.len().div_ceil(3);
    card(ui, |ui| {
        let column = (ui.available_width() - 2.0 * 12.0) / 3.0;
        Grid::new("words").spacing(vec2(12.0, 7.0)).min_col_width(column).show(ui, |ui| {
            for row in 0..rows {
                for column in 0..3 {
                    if let Some(word) = page.get(column * rows + row) {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let number = from + column * rows + row + 1;
                            text(ui, format!("{number:>2}"), mono(12.0), FAINT);
                            text(ui, *word, mono(16.0), TEXT);
                        });
                    }
                }
                ui.end_row();
            }
        });
    });
}

#[derive(Default)]
pub struct Restore {
    count: Option<usize>,
    words: Vec<&'static str>,
    prefix: String,
    keyboard: Keyboard,
    /// The seed a copy of whose words is being checked, rather than restored.
    check: Option<Mnemonic>,
}

/// Words entered at once, as the restore screen's line of them shows.
const SHOWN: usize = 3;
/// Candidate words shown for a prefix: as many as fit one row.
const CANDIDATES: usize = 5;

impl Restore {
    /// Checks a copy of `mnemonic`'s words: they are typed in as they are restored, and compared
    /// with the seed's word by word.
    pub fn check(mnemonic: Mnemonic) -> Restore {
        Restore { count: Some(mnemonic.word_count()), check: Some(mnemonic), ..Restore::default() }
    }

    pub fn title(&self) -> String {
        match (self.count, &self.check) {
            (None, _) => "Restore".to_owned(),
            (Some(count), None) => format!("Word {} of {count}", self.words.len() + 1),
            (Some(count), Some(_)) => format!("Check word {} of {count}", self.words.len() + 1),
        }
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.count {
            None => &[(Control::DPad, "Move"), (Control::A, "Select"), (Control::B, "Back")],
            Some(_) => &[(Control::DPad, "Move"), (Control::A, "Type"), (Control::B, "Undo")],
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        let Some(count) = self.count else {
            ui.add_space(6.0);
            text(ui, "How many words?", strong(18.0), TEXT);
            text(ui, "As many as your backup has.", body(13.0), DIM);
            ui.add_space(6.0);
            let counts = [12, 15, 18, 21, 24].map(|count| count.to_string());
            let labels: Vec<(&str, Emphasis)> =
                counts.iter().map(|count| (count.as_str(), Emphasis::Secondary)).collect();
            for (count, button) in [12, 15, 18, 21, 24].into_iter().zip(button_row(ui, &labels)) {
                shared.autofocus(&button);
                if button.clicked() {
                    self.count = Some(count);
                    shared.refocus();
                }
            }
            return back_pressed(ui).then_some(Screen::Start);
        };

        ui.spacing_mut().item_spacing.y = 6.0;
        progress(ui, self.words.len() as f32 / count as f32);
        let skipped = self.words.len().saturating_sub(SHOWN);
        let entered: Vec<String> = (self.words.iter().enumerate().skip(skipped))
            .map(|(i, word)| format!("{} {word}", i + 1))
            .collect();
        let entered = match skipped {
            0 => entered.join("  "),
            _ => format!("…  {}", entered.join("  ")),
        };
        field(ui, &self.prefix, 20.0, Some((&entered, FAINT)));
        let english = wallet_core::bip39::Language::English;
        let candidates: Vec<&'static str> = match self.prefix.as_str() {
            "" => Vec::new(),
            prefix => english.words_by_prefix_iter(prefix).collect(),
        };
        let mut chosen = None;
        ui.horizontal(|ui| {
            ui.set_min_height(30.0);
            let mut shown = 0;
            for word in candidates.iter().take(CANDIDATES) {
                // As many as fit the row, with room left for the count of the rest.
                let width =
                    ui.painter().layout_no_wrap(word.to_string(), mono(14.0), TEXT).size().x;
                let width =
                    width + 2.0 * ui.spacing().button_padding.x + ui.spacing().item_spacing.x;
                if width > ui.available_width() - 30.0 {
                    break;
                }
                let button = ui.add(Button::new(RichText::new(*word).font(mono(14.0))));
                shared.autofocus(&button);
                if button.clicked() {
                    chosen = Some(*word);
                }
                shown += 1;
            }
            if candidates.len() > shown {
                text(ui, format!("+{}", candidates.len() - shown), body(12.0), FAINT);
            } else if candidates.is_empty() {
                text(ui, "Type the word's first letters.", body(12.5), FAINT);
            }
        });
        match self.keyboard.show(ui, Keys::Letters, Some(shared.focus_flag())) {
            Some(Press::Char(char)) => {
                let prefix = format!("{}{char}", self.prefix);
                let fits: Vec<&'static str> = english.words_by_prefix_iter(&prefix).collect();
                match fits[..] {
                    // A word is settled once its letters fit no other.
                    [word] => chosen = Some(word),
                    [] => {}
                    _ => self.prefix = prefix,
                }
            }
            Some(Press::Backspace) => {
                if self.prefix.pop().is_none() {
                    self.words.pop();
                }
            }
            Some(Press::Done) | None => {}
        }
        if let Some(word) = chosen {
            self.words.push(word);
            self.prefix.clear();
            shared.refocus();
            if let (true, Some(seed)) = (self.words.len() == count, &self.check) {
                // Word by word: a copy whose words are a valid seed of their own can still
                // be wrong.
                let wrong: Vec<String> = (seed.words().zip(&self.words).enumerate())
                    .filter(|(_, (right, copied))| right != *copied)
                    .map(|(index, _)| (index + 1).to_string())
                    .collect();
                match wrong.len() {
                    0 => shared.info("Your copy matches the seed, word for word."),
                    1 => shared.error(format!("Word {} of your copy is not the seed's.", wrong[0])),
                    _ => shared.error(format!(
                        "Words {} of your copy are not the seed's.",
                        wrong.join(", ")
                    )),
                }
                return Some(Screen::Backup(Backup));
            }
            if self.words.len() == count {
                match Mnemonic::parse_in_normalized(english, &self.words.join(" ")) {
                    Ok(mnemonic) => return Some(Screen::Setup(Setup::new(mnemonic, true))),
                    Err(_) => shared.error("These words are not a seed: one is wrong or out of place. Go back over them with Delete."),
                }
            }
        }
        if back_pressed(ui) {
            if !self.prefix.is_empty() {
                self.prefix.clear();
            } else if self.words.pop().is_none() {
                if self.check.is_some() {
                    return Some(Screen::Backup(Backup));
                }
                self.count = None;
            }
            shared.refocus();
        }
        None
    }
}

pub struct Setup {
    mnemonic: Mnemonic,
    /// Whether the seed is an old one, whose coins the node must look back through the chain for.
    restored: bool,
    passphrase: Zeroizing<String>,
    entering: bool,
    keyboard: Keyboard,
    kind: Kind,
    /// The fingerprint under the passphrase, which takes a moment to compute.
    fingerprint: Option<Fingerprint>,
}

impl Setup {
    pub fn title(&self) -> String {
        if self.entering { "Passphrase" } else { "Open wallet" }.to_owned()
    }

    pub fn hints(&self) -> &'static [Hint] {
        match self.entering {
            true => &[(Control::DPad, "Move"), (Control::A, "Type"), (Control::B, "Done")],
            false => &[(Control::DPad, "Move"), (Control::A, "Select"), (Control::B, "Back")],
        }
    }

    fn new(mnemonic: Mnemonic, restored: bool) -> Setup {
        Setup {
            mnemonic,
            restored,
            passphrase: Zeroizing::default(),
            entering: false,
            keyboard: Keyboard::default(),
            kind: Kind::Taproot,
            fingerprint: None,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, shared: &mut Shared) -> Option<Screen> {
        if self.entering {
            let count = self.passphrase.chars().count();
            field(ui, &self.passphrase, 18.0, Some((&format!("{count}"), FAINT)));
            match self.keyboard.show(ui, Keys::Full, Some(shared.focus_flag())) {
                Some(Press::Char(char)) => self.passphrase.push(char),
                Some(Press::Backspace) => {
                    self.passphrase.pop();
                }
                Some(Press::Done) => self.entering = false,
                None => {}
            }
            self.fingerprint = None;
            if back_pressed(ui) {
                self.entering = false;
                shared.refocus();
            }
            return None;
        }

        let (mnemonic, passphrase) = (&self.mnemonic, self.passphrase.as_str());
        let fingerprint = *self.fingerprint.get_or_insert_with(|| {
            Seed::new(mnemonic, passphrase).fingerprint(&Secp256k1::signing_only())
        });
        // In an id scope, as its warning comes and goes above the buttons.
        ui.push_id("fingerprint", |ui| {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    text(ui, "Fingerprint", body(13.0), DIM);
                    ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                        text(ui, fingerprint.to_string(), mono(20.0), ACCENT);
                    });
                });
                if !self.passphrase.is_empty() {
                    let warning = "Check it against yours: a passphrase off by one letter opens another, empty wallet.";
                    text(ui, warning, body(11.5), WARN);
                }
            });
        });
        let passphrase = match self.passphrase.chars().count() {
            0 => "None. Add one".to_owned(),
            1 => "1 character. Change it".to_owned(),
            n => format!("{n} characters. Change it"),
        };
        if menu_item(ui, "Passphrase", Some(&passphrase)).clicked() {
            self.entering = true;
            shared.refocus();
        }
        let kind = match self.kind {
            Kind::Taproot => "Taproot, bc1p…",
            Kind::SegwitV0 => "Native segwit, bc1q…",
        };
        if menu_item(ui, "Address type", Some(kind)).clicked() {
            self.kind = match self.kind {
                Kind::Taproot => Kind::SegwitV0,
                Kind::SegwitV0 => Kind::Taproot,
            };
        }
        let open = button(ui, "Open wallet", Emphasis::Primary, ui.available_width());
        shared.autofocus(&open);
        if open.clicked() {
            let seed = Seed::new(&self.mnemonic, &self.passphrase);
            let network = shared.config.network;
            match Account::from_seed(&seed, network, self.kind, 0) {
                Ok(account) => {
                    #[cfg(feature = "online")]
                    shared.online.open(ui.ctx(), &account, self.restored.then_some(0));
                    #[cfg(not(feature = "online"))]
                    let _ = self.restored;
                    let mut wallet = Wallet::signing(self.mnemonic.clone(), seed, account);
                    wallet.passphrase = self.passphrase.clone();
                    // A new seed's coins can come no earlier than now; a restored one's, whenever.
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
                    let now = now.map_or(0, |since| since.as_secs());
                    wallet.birthday = if self.restored { 0 } else { now };
                    shared.wallet = Some(wallet);
                    return Some(Screen::Home(Default::default()));
                }
                Err(error) => shared.error(error),
            }
        }
        back_pressed(ui).then_some(Screen::Start)
    }
}
