//! The look: Inter for text and JetBrains Mono for what is read character by character (amounts,
//! addresses, words, fingerprints), on near-black with one accent. The accent marks where the
//! D-pad is, so nothing else on the screen is filled with it.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke,
    TextStyle, Visuals, vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x0e, 0x0f, 0x11);
pub const SURFACE: Color32 = Color32::from_rgb(0x17, 0x19, 0x1d);
pub const RAISED: Color32 = Color32::from_rgb(0x22, 0x25, 0x2b);
pub const HOVER: Color32 = Color32::from_rgb(0x2c, 0x30, 0x37);
pub const BORDER: Color32 = Color32::from_rgb(0x2a, 0x2e, 0x35);
pub const TEXT: Color32 = Color32::from_rgb(0xec, 0xed, 0xef);
pub const DIM: Color32 = Color32::from_rgb(0x9a, 0xa0, 0xa8);
pub const FAINT: Color32 = Color32::from_rgb(0x5e, 0x64, 0x6d);
pub const ACCENT: Color32 = Color32::from_rgb(0xf7, 0x93, 0x1a);
pub const ON_ACCENT: Color32 = Color32::from_rgb(0x16, 0x11, 0x08);
pub const GOOD: Color32 = Color32::from_rgb(0x3f, 0xb9, 0x50);
pub const WARN: Color32 = Color32::from_rgb(0xe3, 0xb3, 0x41);
pub const BAD: Color32 = Color32::from_rgb(0xf8, 0x51, 0x49);
/// The test networks' color, so a test wallet never passes for a real one.
pub const TEST_NETWORK: Color32 = Color32::from_rgb(0x58, 0xa6, 0xff);

pub const RADIUS: u8 = 8;

/// The height, in points, the layouts are drawn for: a 480-pixel handheld screen at 1.5 pixels a
/// point. Other screens scale to show as much.
pub const DESIGN_HEIGHT: f32 = 320.0;

const SEMIBOLD: &str = "semibold";

pub fn body(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

pub fn strong(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    ctx.set_visuals_of(egui::Theme::Dark, visuals());
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, body(11.5)),
            (TextStyle::Body, body(14.0)),
            (TextStyle::Button, body(14.0)),
            (TextStyle::Heading, strong(18.0)),
            (TextStyle::Monospace, mono(13.0)),
        ]
        .into();
        style.spacing.item_spacing = vec2(8.0, 8.0);
        style.spacing.button_padding = vec2(12.0, 7.0);
        // Rows no taller than their text: the screens' buttons set their own heights.
        style.spacing.interact_size.y = 22.0;
        style.spacing.window_margin = Margin::same(12);
    });
}

fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let mut add = |name: &str, data: &'static [u8]| {
        fonts.font_data.insert(name.to_owned(), Arc::new(FontData::from_static(data)));
    };
    add("Inter", include_bytes!("../assets/fonts/Inter-Regular.ttf"));
    add("Inter SemiBold", include_bytes!("../assets/fonts/Inter-SemiBold.ttf"));
    add("JetBrains Mono", include_bytes!("../assets/fonts/JetBrainsMono-Medium.ttf"));
    // egui's own fonts stay behind each as fallbacks, for the glyphs these lack.
    let fallbacks = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let family = |first: &str| [vec![first.to_owned()], fallbacks.clone()].concat();
    fonts.families.insert(FontFamily::Proportional, family("Inter"));
    fonts.families.insert(FontFamily::Name(SEMIBOLD.into()), family("Inter SemiBold"));
    fonts.families.insert(FontFamily::Monospace, family("JetBrains Mono"));
    fonts
}

fn visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = SURFACE;
    visuals.faint_bg_color = SURFACE;
    visuals.code_bg_color = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.warn_fg_color = WARN;
    visuals.error_fg_color = BAD;
    visuals.hyperlink_color = ACCENT;
    visuals.selection.bg_fill = ACCENT.linear_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.5, ACCENT);
    visuals.text_cursor.stroke = Stroke::new(2.0, ACCENT);
    let radius = CornerRadius::same(RADIUS);
    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.noninteractive.corner_radius = radius;
    for (state, fill, text) in [
        (&mut widgets.inactive, RAISED, TEXT),
        (&mut widgets.hovered, HOVER, TEXT),
        (&mut widgets.open, HOVER, TEXT),
        // egui draws the focused widget as active: that is where the D-pad is.
        (&mut widgets.active, ACCENT, ON_ACCENT),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::NONE;
        state.fg_stroke = Stroke::new(1.5, text);
        state.corner_radius = radius;
        state.expansion = 0.0;
    }
    visuals
}
