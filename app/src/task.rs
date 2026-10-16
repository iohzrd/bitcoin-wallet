//! Work that takes longer than a frame, on a thread of its own: a call to the node, or the
//! key of a kept wallet, which Argon2 takes seconds to make on a handheld.

use std::sync::mpsc::{Receiver, channel};

use eframe::egui;

pub struct Task<T> {
    result: Receiver<T>,
}

impl<T: Send + 'static> Task<T> {
    /// Runs `work`, and has `ctx` draw a frame when it is done, for the screen to take its result.
    pub fn spawn(ctx: &egui::Context, work: impl FnOnce() -> T + Send + 'static) -> Task<T> {
        let (send, result) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = send.send(work());
            ctx.request_repaint();
        });
        Task { result }
    }

    pub fn poll(&self) -> Option<T> {
        self.result.try_recv().ok()
    }
}
