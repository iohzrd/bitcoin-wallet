//! The handhelds' buttons, as the keys egui already answers to: the D-pad (or the left stick)
//! moves the keyboard focus as the arrow keys do, A presses the focused button as Enter does,
//! B goes back as Escape does, and the shoulder buttons step as Page Up and Page Down do. A held
//! direction repeats, as a held key does.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use eframe::egui::{self, Event, Key, Modifiers, RawInput};
use gilrs::{Axis, Button, EventType, Gilrs};

/// How long a direction is held before it repeats, and how often it repeats then.
const REPEAT_DELAY: Duration = Duration::from_millis(400);
const REPEAT_EVERY: Duration = Duration::from_millis(110);

/// A stick past this is pushed; back under the lower one, released.
const PUSHED: f32 = 0.6;
const RELEASED: f32 = 0.3;

pub struct Gamepad {
    keys: Receiver<Press>,
    connected: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Press {
    key: Key,
    pressed: bool,
    repeat: bool,
}

impl Gamepad {
    /// Reads every gamepad there is, or comes to be, on a thread of its own. `swap_ab` makes the
    /// right face button A, as on Nintendo's layout, where it is otherwise the bottom one.
    pub fn start(ctx: egui::Context, swap_ab: bool) -> Gamepad {
        let (send, keys) = channel();
        let connected = Arc::new(AtomicBool::new(false));
        let reader = connected.clone();
        let spawned = std::thread::Builder::new()
            .name("gamepad".into())
            .spawn(move || read(&ctx, &send, &reader, swap_ab));
        if let Err(error) = spawned {
            eprintln!("no gamepad: {error}");
        }
        Gamepad { keys, connected }
    }

    /// Whether a gamepad is plugged in, for the screen to show its buttons rather than keys.
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Adds the presses since the last frame to its input.
    pub fn feed(&self, input: &mut RawInput) {
        for Press { key, pressed, repeat } in self.keys.try_iter() {
            let modifiers = Modifiers::NONE;
            input.events.push(Event::Key { key, physical_key: None, pressed, repeat, modifiers });
        }
    }
}

fn read(ctx: &egui::Context, send: &Sender<Press>, connected: &AtomicBool, swap_ab: bool) {
    let mut gilrs = match Gilrs::new() {
        Ok(gilrs) => gilrs,
        Err(error) => return eprintln!("no gamepad: {error}"),
    };
    connected.store(gilrs.gamepads().next().is_some(), Ordering::Relaxed);
    ctx.request_repaint();
    let mut keys = Keys::default();
    loop {
        let timeout = keys.held.map(|(_, next)| next.saturating_duration_since(Instant::now()));
        let presses = match gilrs.next_event_blocking(timeout) {
            Some(event) => {
                if matches!(event.event, EventType::Connected | EventType::Disconnected) {
                    connected.store(gilrs.gamepads().next().is_some(), Ordering::Relaxed);
                    ctx.request_repaint();
                }
                keys.translate(event.event, swap_ab)
            }
            None => keys.repeat(),
        };
        for press in presses {
            if send.send(press).is_err() {
                return;
            }
            ctx.request_repaint();
        }
    }
}

#[derive(Default)]
struct Keys {
    /// The direction held, and when it next repeats.
    held: Option<(Key, Instant)>,
    /// Each axis's direction while pushed, by axis.
    axes: Vec<(Axis, Key)>,
}

impl Keys {
    fn translate(&mut self, event: EventType, swap_ab: bool) -> Vec<Press> {
        match event {
            EventType::ButtonPressed(button, _) => {
                button_key(button, swap_ab).map(|key| self.press(key)).into_iter().collect()
            }
            EventType::ButtonReleased(button, _) => {
                button_key(button, swap_ab).map(|key| self.release(key)).into_iter().collect()
            }
            EventType::AxisChanged(axis, value, _) => self.axis(axis, value),
            EventType::Disconnected => {
                self.axes.clear();
                self.held.take().map(|(key, _)| self.release(key)).into_iter().collect()
            }
            _ => Vec::new(),
        }
    }

    fn axis(&mut self, axis: Axis, value: f32) -> Vec<Press> {
        let pushed = self.axes.iter().position(|(held, _)| *held == axis);
        match (pushed, axis_key(axis, value)) {
            (None, Some(key)) if value.abs() > PUSHED => {
                self.axes.push((axis, key));
                vec![self.press(key)]
            }
            (Some(index), _) if value.abs() < RELEASED => {
                let (_, key) = self.axes.remove(index);
                vec![self.release(key)]
            }
            _ => Vec::new(),
        }
    }

    fn press(&mut self, key: Key) -> Press {
        if is_direction(key) {
            self.held = Some((key, Instant::now() + REPEAT_DELAY));
        }
        Press { key, pressed: true, repeat: false }
    }

    fn release(&mut self, key: Key) -> Press {
        if self.held.is_some_and(|(held, _)| held == key) {
            self.held = None;
        }
        Press { key, pressed: false, repeat: false }
    }

    fn repeat(&mut self) -> Vec<Press> {
        let Some((key, next)) = &mut self.held else { return Vec::new() };
        if Instant::now() < *next {
            return Vec::new();
        }
        *next += REPEAT_EVERY;
        vec![Press { key: *key, pressed: true, repeat: true }]
    }
}

fn button_key(button: Button, swap_ab: bool) -> Option<Key> {
    let (confirm, back) =
        if swap_ab { (Button::East, Button::South) } else { (Button::South, Button::East) };
    Some(match button {
        Button::DPadUp => Key::ArrowUp,
        Button::DPadDown => Key::ArrowDown,
        Button::DPadLeft => Key::ArrowLeft,
        Button::DPadRight => Key::ArrowRight,
        Button::LeftTrigger => Key::PageUp,
        Button::RightTrigger => Key::PageDown,
        button if button == confirm => Key::Enter,
        button if button == back => Key::Escape,
        _ => return None,
    })
}

/// The arrow a stick or hat axis points, up and right being positive as gilrs has them.
fn axis_key(axis: Axis, value: f32) -> Option<Key> {
    match axis {
        Axis::LeftStickX | Axis::DPadX => {
            Some(if value > 0.0 { Key::ArrowRight } else { Key::ArrowLeft })
        }
        Axis::LeftStickY | Axis::DPadY => {
            Some(if value > 0.0 { Key::ArrowUp } else { Key::ArrowDown })
        }
        _ => None,
    }
}

fn is_direction(key: Key) -> bool {
    matches!(key, Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pressed(key: Key) -> Press {
        Press { key, pressed: true, repeat: false }
    }

    fn released(key: Key) -> Press {
        Press { key, pressed: false, repeat: false }
    }

    #[test]
    fn a_is_enter_and_b_is_escape_on_either_layout() {
        assert_eq!(button_key(Button::South, false), Some(Key::Enter));
        assert_eq!(button_key(Button::East, false), Some(Key::Escape));
        assert_eq!(button_key(Button::East, true), Some(Key::Enter));
        assert_eq!(button_key(Button::South, true), Some(Key::Escape));
        assert_eq!(button_key(Button::Mode, false), None);
    }

    #[test]
    fn a_stick_presses_past_its_threshold_and_releases_back_near_center() {
        let mut keys = Keys::default();
        assert_eq!(keys.axis(Axis::LeftStickY, 0.4), []);
        assert_eq!(keys.axis(Axis::LeftStickY, 0.9), [pressed(Key::ArrowUp)]);
        assert_eq!(keys.axis(Axis::LeftStickY, 0.5), [], "between the thresholds");
        assert_eq!(keys.axis(Axis::LeftStickY, 0.1), [released(Key::ArrowUp)]);
        assert_eq!(keys.axis(Axis::LeftStickX, -0.9), [pressed(Key::ArrowLeft)]);
        assert_eq!(keys.axis(Axis::RightStickX, 1.0), [], "only the left stick steers");
    }

    #[test]
    fn a_held_direction_repeats_after_a_delay_until_released() {
        let mut keys = Keys::default();
        keys.press(Key::ArrowDown);
        assert_eq!(keys.repeat(), [], "not yet");
        keys.held.as_mut().unwrap().1 = Instant::now();
        assert_eq!(keys.repeat(), [Press { key: Key::ArrowDown, pressed: true, repeat: true }]);
        keys.release(Key::ArrowDown);
        assert_eq!(keys.held, None);
        keys.press(Key::Enter);
        assert_eq!(keys.held, None, "buttons do not repeat");
    }
}
