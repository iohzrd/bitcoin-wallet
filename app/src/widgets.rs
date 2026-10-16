//! What the screens are built of: menu rows, buttons, cards, the rows a review is read through,
//! amounts and addresses set for reading, the QR code painter, the button hints, and the
//! on-screen keyboard a gamepad types with.

use std::sync::Arc;

use eframe::egui::text::{LayoutJob, TextFormat, TextWrapping};
use eframe::egui::{
    self, Align2, Button, Color32, CornerRadius, Event, FontId, Frame, Galley, Id, InnerResponse,
    Key, Margin, Modifiers, Painter, Rect, Response, RichText, Role, Sense, Shape, Stroke,
    StrokeKind, Ui, Vec2, WidgetInfo, pos2, vec2,
};
use wallet_airgap::qr::{QUIET_ZONE, Qr};
use wallet_core::bitcoin::Amount;

use crate::theme::{
    ACCENT, BORDER, DIM, FAINT, HOVER, ON_ACCENT, RADIUS, RAISED, SURFACE, TEXT, body, mono, strong,
};

pub fn back_pressed(ui: &Ui) -> bool {
    ui.input(|input| input.key_pressed(Key::Escape))
}

/// Presses Escape, which every screen answers as back: what the back button and the back hint do,
/// for a mouse, a touchscreen, or a gamepad with no B.
pub fn press_back(ctx: &egui::Context) {
    let modifiers = Modifiers::NONE;
    let escape = Event::Key {
        key: Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    };
    ctx.input_mut(|input| input.events.push(escape));
}

/// The title bar's back button's id, by which the app focuses it when the D-pad goes up past the
/// top of a screen.
pub fn back_id() -> Id {
    Id::unique("back button")
}

/// The title bar's back button: clickable, and focusable, so the D-pad reaches it from the top
/// of the screen.
pub fn back_button(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(30.0, 30.0), Sense::hover());
    let response = ui.interact(rect, back_id(), Sense::click());
    response.widget_info(|| WidgetInfo::labeled(Role::Button, true, "Back"));
    let (fill, fg) = match (response.has_focus(), response.hovered()) {
        (true, _) => (ACCENT, ON_ACCENT),
        (false, true) => (HOVER, TEXT),
        (false, false) => (Color32::TRANSPARENT, TEXT),
    };
    ui.painter().rect_filled(rect, RADIUS, fill);
    let chevron = rect.center() - vec2(1.0, 2.0);
    ui.painter().text(chevron, Align2::CENTER_CENTER, "‹", strong(24.0), fg);
    if response.clicked() {
        press_back(ui.ctx());
    }
}

/// A line of text, as large and as colored as given.
pub fn text(ui: &mut Ui, text: impl Into<String>, font: FontId, color: Color32) -> Response {
    ui.label(RichText::new(text).font(font).color(color))
}

/// `text` laid out on one line no wider than `width`, cut short with an ellipsis if it is not.
fn one_line(
    painter: &Painter,
    text: &str,
    font: FontId,
    color: Color32,
    width: f32,
) -> Arc<Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_owned(), font, color);
    job.wrap = TextWrapping::truncate_at_width(width);
    painter.layout_job(job)
}

/// Scrolls `response`'s widget into view when it has just taken the keyboard focus. egui moves
/// the focus for the arrow keys between frames, which `Response::gained_focus` does not see, so
/// the widget last scrolled to is kept here instead.
fn follow_focus(response: &Response) {
    if !response.has_focus() {
        return;
    }
    let followed = Id::unique("followed focus");
    if response.ctx.data(|data| data.get_temp::<Id>(followed)) != Some(response.id) {
        response.ctx.data_mut(|data| data.insert_temp(followed, response.id));
        response.scroll_to_me(None);
    }
}

/// A row of a menu: a title, what choosing it does below it, and the accent behind it while the
/// D-pad is on it.
pub fn menu_item(ui: &mut Ui, title: &str, subtitle: Option<&str>) -> Response {
    let height = if subtitle.is_some() { 50.0 } else { 40.0 };
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(Role::Button, enabled, title));
    follow_focus(&response);
    if ui.is_rect_visible(rect) {
        let focused = response.has_focus();
        let (fill, fg, sub) = match (focused, response.hovered()) {
            (true, _) => (ACCENT, ON_ACCENT, ON_ACCENT),
            (false, true) => (HOVER, TEXT, DIM),
            (false, false) => (RAISED, TEXT, DIM),
        };
        let painter = ui.painter();
        painter.rect_filled(rect, RADIUS, fill);
        let left = rect.left() + 14.0;
        let width = rect.width() - 44.0;
        let title = one_line(painter, title, strong(15.0), fg, width);
        let sub = subtitle.map(|subtitle| one_line(painter, subtitle, body(12.0), sub, width));
        let lines = title.size().y + sub.as_ref().map_or(0.0, |sub| sub.size().y + 1.0);
        let top = rect.center().y - lines / 2.0;
        painter.galley(pos2(left, top), title.clone(), fg);
        if let Some(sub) = sub {
            painter.galley(pos2(left, top + title.size().y + 1.0), sub, fg);
        }
        let chevron = if focused { ON_ACCENT } else { FAINT };
        painter.text(
            pos2(rect.right() - 14.0, rect.center().y),
            Align2::RIGHT_CENTER,
            "›",
            strong(20.0),
            chevron,
        );
    }
    response
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emphasis {
    /// The step forward: signing, opening, going on.
    Primary,
    Secondary,
}

pub fn button(ui: &mut Ui, label: &str, emphasis: Emphasis, width: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(width, 38.0), Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(Role::Button, enabled, label));
    follow_focus(&response);
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let (fill, stroke, fg) = match (response.has_focus(), emphasis, enabled) {
            (_, _, false) => (RAISED.gamma_multiply(0.5), Stroke::NONE, FAINT),
            (true, ..) => (ACCENT, Stroke::NONE, ON_ACCENT),
            (false, Emphasis::Primary, _) => {
                (ACCENT.gamma_multiply(0.12), Stroke::new(1.5, ACCENT), ACCENT)
            }
            (false, Emphasis::Secondary, _) => {
                (if response.hovered() { HOVER } else { RAISED }, Stroke::NONE, TEXT)
            }
        };
        painter.rect(rect, RADIUS, fill, stroke, StrokeKind::Inside);
        let label = one_line(painter, label, strong(14.0), fg, rect.width() - 16.0);
        painter.galley(rect.center() - label.size() / 2.0, label, fg);
    }
    response
}

/// Buttons side by side, sharing the width.
pub fn button_row(ui: &mut Ui, buttons: &[(&str, Emphasis)]) -> Vec<Response> {
    let gap = 8.0;
    let width = (ui.available_width() - gap * (buttons.len() - 1) as f32) / buttons.len() as f32;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        buttons.iter().map(|(label, emphasis)| button(ui, label, *emphasis, width)).collect()
    })
    .inner
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A block of a review the D-pad stops on: nothing happens when it is pressed, but stepping from
/// one to the next scrolls the review, so the buttons under it are reached only past every line.
/// `name` is what a screen reader calls it.
pub fn focus_row<R>(ui: &mut Ui, name: &str, add: impl FnOnce(&mut Ui) -> R) -> InnerResponse<R> {
    let background = ui.painter().add(Shape::Noop);
    let inner = Frame::new().inner_margin(Margin::symmetric(12, 9)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui)
    });
    let rect = inner.response.rect;
    let response =
        ui.interact(rect, inner.response.id.with("row"), Sense::focusable_noninteractive());
    response.widget_info(|| WidgetInfo::labeled(Role::Group, true, name));
    follow_focus(&response);
    let focused = response.has_focus();
    ui.painter()
        .set(background, Shape::rect_filled(rect, RADIUS, if focused { RAISED } else { SURFACE }));
    if focused {
        let bar = Rect::from_min_size(rect.min, vec2(3.0, rect.height()));
        ui.painter().rect_filled(
            bar,
            CornerRadius { nw: RADIUS, sw: RADIUS, ne: 0, se: 0 },
            ACCENT,
        );
    }
    InnerResponse::new(inner.inner, response)
}

/// An amount in bitcoin to eight decimals, the trailing zeros faint, so the digits that count
/// stand out and no amount is misread by a factor of ten.
pub fn amount(amount: Amount, size: f32, color: Color32) -> LayoutJob {
    let sats = amount.to_sat();
    let fraction = format!("{:08}", sats % 100_000_000);
    let significant = fraction.trim_end_matches('0');
    let mut job = LayoutJob::default();
    let format =
        |font: FontId, color: Color32| TextFormat { font_id: font, color, ..Default::default() };
    job.append(&format!("{}.{significant}", sats / 100_000_000), 0.0, format(mono(size), color));
    job.append(&"0".repeat(8 - significant.len()), 0.0, format(mono(size), FAINT));
    job.append(" BTC", 0.0, format(body(size * 0.8), DIM));
    job
}

/// Text in groups of four characters, which is how an address is compared with another
/// screen's: group by group.
pub fn grouped(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let groups: Vec<String> = chars.chunks(4).map(|group| group.iter().collect()).collect();
    groups.join(" ")
}

/// An address in its groups of four, wrapping at the width it is given.
pub fn address(ui: &mut Ui, address: &str, size: f32) -> Response {
    ui.label(RichText::new(grouped(address)).font(mono(size)).color(TEXT))
}

/// A text field drawn for the on-screen keyboard to type into: what is typed so far, the caret,
/// and `trailing` faint at its right.
pub fn field(ui: &mut Ui, value: &str, size: f32, trailing: Option<(&str, Color32)>) {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(RADIUS)
        .inner_margin(Margin::symmetric(12, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                let typed = text(ui, value, mono(size), TEXT);
                let caret = Rect::from_min_size(
                    pos2(typed.rect.right() + 1.0, typed.rect.top() + 2.0),
                    vec2(2.0, typed.rect.height().max(size) - 4.0),
                );
                ui.painter().rect_filled(caret, 1.0, ACCENT);
                if let Some((trailing, color)) = trailing {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        text(ui, trailing, mono(12.0), color);
                    });
                }
            });
        });
}

/// How far along, as a thin bar.
pub fn progress(ui: &mut Ui, fraction: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.0, RAISED);
    let done = Rect::from_min_size(rect.min, vec2(rect.width() * fraction.clamp(0.0, 1.0), 4.0));
    ui.painter().rect_filled(done, 2.0, ACCENT);
}

/// A die's face as a button, its pips drawn, for entering the face a roll showed.
pub fn die_button(ui: &mut Ui, face: u8, side: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::click());
    response.widget_info(|| WidgetInfo::labeled(Role::Button, true, face.to_string()));
    follow_focus(&response);
    if ui.is_rect_visible(rect) {
        let (fill, pip) = match (response.has_focus(), response.hovered()) {
            (true, _) => (ACCENT, ON_ACCENT),
            (false, true) => (HOVER, TEXT),
            (false, false) => (RAISED, TEXT),
        };
        let painter = ui.painter();
        painter.rect_filled(rect, side * 0.18, fill);
        let pips = rect.shrink(side * 0.24);
        // Each pip's place on a 3 by 3 grid, as a die has them.
        let places: &[(f32, f32)] = match face {
            1 => &[(0.5, 0.5)],
            2 => &[(0.0, 0.0), (1.0, 1.0)],
            3 => &[(0.0, 0.0), (0.5, 0.5), (1.0, 1.0)],
            4 => &[(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)],
            5 => &[(0.0, 0.0), (1.0, 0.0), (0.5, 0.5), (0.0, 1.0), (1.0, 1.0)],
            _ => &[(0.0, 0.0), (1.0, 0.0), (0.0, 0.5), (1.0, 0.5), (0.0, 1.0), (1.0, 1.0)],
        };
        for &(x, y) in places {
            painter.circle_filled(pips.lerp_inside(vec2(x, y)), side * 0.085, pip);
        }
    }
    response
}

/// A small label on a tinted pill.
pub fn chip(ui: &mut Ui, text: &str, font: FontId, color: Color32) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let size = galley.size() + vec2(14.0, 6.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(Role::Label, true, text));
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(255), color.gamma_multiply(0.14));
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    response
}

/// Which page of `count` this is, as dots.
pub fn page_dots(ui: &mut Ui, page: usize, count: usize) {
    let (rect, _) = ui.allocate_exact_size(vec2(count as f32 * 14.0, 10.0), Sense::hover());
    for index in 0..count {
        let center = pos2(rect.left() + 5.0 + index as f32 * 14.0, rect.center().y);
        let color = if index == page { ACCENT } else { FAINT };
        ui.painter().circle_filled(center, if index == page { 4.0 } else { 3.0 }, color);
    }
}

/// Paints `qr` on a white card as large as fits a square of `side` points, each module a whole
/// number of pixels wide and on the pixel grid, as a blurred module edge is what makes a camera
/// misread one.
pub fn qr_card(ui: &mut Ui, qr: &Qr, side: f32) -> Response {
    paint_qr(ui, qr, side, false)
}

/// `qr_card` with lines between the modules, darker every fifth, for copying the code onto a
/// paper template square by square, as a SeedQR is.
pub fn qr_grid_card(ui: &mut Ui, qr: &Qr, side: f32) -> Response {
    paint_qr(ui, qr, side, true)
}

fn paint_qr(ui: &mut Ui, qr: &Qr, side: f32, grid: bool) -> Response {
    let modules = qr.width() + 2 * QUIET_ZONE;
    let pixels_per_point = ui.ctx().pixels_per_point();
    let module_px = ((side * pixels_per_point) / modules as f32).floor().max(1.0);
    let module = module_px / pixels_per_point;
    let size = module * modules as f32;
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side.max(size)), Sense::hover());
    let painter = ui.painter();
    let origin = rect.center() - Vec2::splat(size / 2.0);
    let origin = ((origin.to_vec2() * pixels_per_point).round() / pixels_per_point).to_pos2();
    painter.rect_filled(Rect::from_min_size(origin, Vec2::splat(size)), 6.0, Color32::WHITE);
    let mut mesh = egui::Mesh::default();
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr.is_dark(x, y) {
                let min = origin + vec2((x + QUIET_ZONE) as f32, (y + QUIET_ZONE) as f32) * module;
                mesh.add_colored_rect(
                    Rect::from_min_size(min, Vec2::splat(module)),
                    Color32::BLACK,
                );
            }
        }
    }
    painter.add(mesh);
    if grid {
        let code = Rect::from_min_size(
            origin + Vec2::splat(QUIET_ZONE as f32 * module),
            Vec2::splat(qr.width() as f32 * module),
        );
        for line in 0..=qr.width() {
            let at = line as f32 * module;
            let color =
                if line % 5 == 0 { Color32::from_gray(150) } else { Color32::from_gray(205) };
            let stroke = Stroke::new(1.0 / pixels_per_point, color);
            painter.vline(code.left() + at, code.y_range(), stroke);
            painter.hline(code.x_range(), code.top() + at, stroke);
        }
    }
    response
}

/// Two columns: `qr` on the left, as large as the screen allows, and `add` on the right; or `add`
/// alone, across the screen, when there is no code to show.
pub fn beside_qr<R>(ui: &mut Ui, qr: Option<&Qr>, add: impl FnOnce(&mut Ui) -> R) -> R {
    let Some(qr) = qr else { return ui.vertical(add).inner };
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        let side = ui.available_height().min(ui.available_width() * 0.5);
        qr_card(ui, qr, side);
        ui.vertical(add).inner
    })
    .inner
}

/// A control, as the hints at the bottom of the screen draw it: a gamepad's button, or the key
/// that does the same on a keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    A,
    B,
    /// The shoulder buttons, as a pair.
    Shoulders,
    DPad,
}

impl Control {
    fn glyph(self, gamepad: bool) -> &'static str {
        match (self, gamepad) {
            (Control::A, true) => "A",
            (Control::B, true) => "B",
            (Control::Shoulders, true) => "L R",
            (Control::DPad, true) => "",
            (Control::A, false) => "Enter",
            (Control::B, false) => "Esc",
            (Control::Shoulders, false) => "PgUp PgDn",
            (Control::DPad, false) => "←↑↓→",
        }
    }
}

pub type Hint = (Control, &'static str);

/// What the controls do on this screen, drawn as the gamepad's buttons when one is connected
/// and as keys when not. The back hint is a button too, for a mouse or a touchscreen.
pub fn hint_bar(ui: &mut Ui, hints: &[Hint], gamepad: bool) {
    ui.horizontal_centered(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        for (index, (control, label)) in hints.iter().enumerate() {
            if index > 0 {
                ui.add_space(10.0);
            }
            let hint = ui.horizontal(|ui| {
                let glyph = control.glyph(gamepad);
                let galley = ui.painter().layout_no_wrap(glyph.to_owned(), strong(10.5), TEXT);
                let size = vec2((galley.size().x + 10.0).max(17.0), 17.0);
                let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
                let painter = ui.painter();
                if *control == Control::DPad && gamepad {
                    // A plus, as the D-pad's cross.
                    let (center, long, short) = (rect.center(), 13.0, 4.5);
                    painter.rect_filled(
                        Rect::from_center_size(center, vec2(long, short)),
                        1.0,
                        HOVER,
                    );
                    painter.rect_filled(
                        Rect::from_center_size(center, vec2(short, long)),
                        1.0,
                        HOVER,
                    );
                } else {
                    let round = matches!(control, Control::A | Control::B) && gamepad;
                    let radius = if round { 255 } else { 4 };
                    painter.rect_filled(rect, CornerRadius::same(radius), HOVER);
                    painter.galley(rect.center() - galley.size() / 2.0, galley, TEXT);
                }
                text(ui, *label, body(12.0), DIM);
            });
            if *control == Control::B {
                let rect = hint.response.rect;
                let back = ui.interact(rect, hint.response.id.with("press"), Sense::CLICK);
                let name = format!("{}: {label}", control.glyph(gamepad));
                back.widget_info(|| WidgetInfo::labeled(Role::Button, true, &name));
                if back.hovered() {
                    ui.painter().rect_stroke(
                        rect.expand(3.0),
                        4.0,
                        Stroke::new(1.0, FAINT),
                        StrokeKind::Outside,
                    );
                }
                if back.clicked() {
                    press_back(ui.ctx());
                }
            }
        }
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    Char(char),
    Backspace,
    Done,
}

/// The keys a keyboard can type: the letters alone, for the words of a seed, or letters, digits
/// and symbols, for a passphrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keys {
    Letters,
    Full,
}

/// A keyboard on the screen, for the handhelds, which have none. A physical keyboard types too.
#[derive(Default)]
pub struct Keyboard {
    shift: bool,
    symbols: bool,
}

const LETTERS: &str = "abcdefghijklmnopqrstuvwxyz";
const SYMBOLS: &str = "1234567890-_=+.,:;!?@#$%&*/\\|'\"()[]{}<>~`^";
const COLUMNS: usize = 9;

impl Keyboard {
    /// A keyboard open on its digits and symbols, for a PIN.
    pub fn digits() -> Keyboard {
        Keyboard { shift: false, symbols: true }
    }

    /// Shows the keys and returns the one pressed, on the screen or on a physical keyboard.
    pub fn show(&mut self, ui: &mut Ui, keys: Keys, first: Option<&mut bool>) -> Option<Press> {
        let mut pressed = typed(ui, keys);
        let chars: Vec<char> = match (keys, self.symbols) {
            (Keys::Full, true) => SYMBOLS.chars().collect(),
            _ if self.shift => LETTERS.to_uppercase().chars().collect(),
            _ => LETTERS.chars().collect(),
        };
        let gap = 4.0;
        let control = vec2(70.0, 32.0);
        let key =
            ((ui.available_width() - control.x - gap) / COLUMNS as f32 - gap).clamp(26.0, 46.0);
        let key = vec2(key, 32.0);
        let mut first = first;
        // The controls in a column beside the keys rather than a row below them, which a
        // handheld's 320 points of height have no room for under the word's candidates.
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing = vec2(gap, gap);
            // A key is one character: the usual padding would make it wider than its cell.
            ui.spacing_mut().button_padding = vec2(2.0, 4.0);
            let grid = egui::Grid::new("keyboard").spacing(vec2(gap, gap)).min_col_width(key.x);
            grid.show(ui, |ui| {
                for (index, &char) in chars.iter().enumerate() {
                    let label = RichText::new(char).font(mono(16.0));
                    let response = ui.add_sized(key, Button::new(label));
                    if let Some(first) = first.as_deref_mut().filter(|first| **first) {
                        response.request_focus();
                        *first = false;
                    }
                    if response.clicked() {
                        pressed = Some(Press::Char(char));
                    }
                    if (index + 1) % COLUMNS == 0 {
                        ui.end_row();
                    }
                }
            });
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = gap;
                if ui.add_sized(control, Button::new("Delete")).clicked() {
                    pressed = Some(Press::Backspace);
                }
                if keys == Keys::Letters {
                    return;
                }
                if ui.add_sized(control, Button::new("Space")).clicked() {
                    pressed = Some(Press::Char(' '));
                }
                if ui.add_sized(control, Button::new("Shift").selected(self.shift)).clicked() {
                    self.shift = !self.shift;
                    self.symbols = false;
                }
                if ui.add_sized(control, Button::new("123").selected(self.symbols)).clicked() {
                    self.symbols = !self.symbols;
                }
                if ui.add_sized(control, Button::new("Done")).clicked() {
                    pressed = Some(Press::Done);
                }
            });
        });
        pressed
    }
}

/// What a physical keyboard typed since the last frame.
fn typed(ui: &Ui, keys: Keys) -> Option<Press> {
    ui.input(|input| {
        input.events.iter().find_map(|event| match event {
            Event::Text(text) => text
                .chars()
                .find(|char| match keys {
                    Keys::Letters => char.is_ascii_lowercase(),
                    Keys::Full => !char.is_control(),
                })
                .map(Press::Char),
            Event::Key { key: Key::Backspace, pressed: true, .. } => Some(Press::Backspace),
            _ => None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_amounts_trailing_zeros_are_set_apart() {
        let pieces = |sats| {
            let job = amount(Amount::from_sat(sats), 14.0, TEXT);
            let piece = |section: &egui::text::LayoutSection| {
                job.text[section.byte_range.start.0..section.byte_range.end.0].to_owned()
            };
            job.sections.iter().map(piece).collect::<Vec<_>>()
        };
        assert_eq!(pieces(40_000), ["0.0004", "0000", " BTC"]);
        assert_eq!(pieces(100_000_000), ["1.", "00000000", " BTC"]);
        assert_eq!(pieces(123_456_789), ["1.23456789", "", " BTC"]);
        assert_eq!(pieces(1), ["0.00000001", "", " BTC"]);
    }

    #[test]
    fn text_groups_by_four() {
        assert_eq!(grouped("bc1qcr8te4kr60"), "bc1q cr8t e4kr 60");
        assert_eq!(grouped(""), "");
    }
}
