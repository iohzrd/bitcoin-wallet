//! Security keys: FIDO2 authenticators whose hmac-secret seals a kept wallet, beside its
//! passphrase or in its place. A credential is made on the key for the wallet, under the key's
//! PIN; the key gives the credential's secret under the file's salt only when touched and given
//! the PIN again, and locks itself after eight wrong PINs, which no copy of the file can get
//! around. The credential is not discoverable: its ID lives in the file, and it takes none of the
//! key's slots.
//!
//! Talking to keys over USB takes the `security-key` feature, and a FIDO2 library with it; this
//! much, what the screens need of a key, is in every build, as are the screens.

// Without the feature, only the tests' key makes these errors.
#![cfg_attr(not(feature = "security-key"), allow(dead_code))]

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

/// The keys plugged in over USB, in a build with the `security-key` feature.
#[cfg(feature = "security-key")]
mod hid;
#[cfg(feature = "security-key")]
pub use hid::Hid;

/// The FIDO2 PIN's shortest, by the standard.
pub const SHORTEST_PIN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    NoKey,
    SeveralKeys,
    NotFido2,
    NoHmacSecret,
    PinNotSet,
    WrongPin {
        retries: Option<u32>,
    },
    PinBlocked,
    /// Three wrong PINs in a row, after which the key takes no more until plugged in again.
    PinPaused,
    /// The key holds no such credential: another key than the one the wallet was sealed with.
    NotThisKey,
    Timeout,
    Other(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyError::NoKey => write!(f, "Plug in your security key."),
            KeyError::SeveralKeys => write!(f, "Unplug every security key but the one to use."),
            KeyError::NotFido2 => write!(
                f,
                "This key speaks U2F only. It takes a FIDO2 key, such as a YubiKey 5 or a Security Key."
            ),
            KeyError::NoHmacSecret => {
                write!(f, "This key cannot make secrets (it lacks FIDO2's hmac-secret).")
            }
            KeyError::PinNotSet => write!(f, "This key has no PIN yet."),
            KeyError::WrongPin { retries: Some(retries) } => {
                write!(f, "Wrong PIN: {retries} tries left before the key locks.")
            }
            KeyError::WrongPin { retries: None } => write!(f, "Wrong PIN."),
            KeyError::PinBlocked => write!(
                f,
                "The key's PIN is locked after too many wrong tries. Resetting the key erases its credentials: restore the wallet from its words."
            ),
            KeyError::PinPaused => {
                write!(f, "Three wrong PINs in a row: unplug the key and plug it in again.")
            }
            KeyError::NotThisKey => write!(f, "This is not the key the wallet was kept with."),
            KeyError::Timeout => write!(f, "The key was not touched in time."),
            KeyError::Other(error) => write!(f, "Security key: {error}"),
        }
    }
}

/// Whether the key plugged in has its PIN set, and how many tries it has left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyState {
    pub pin_set: bool,
    pub retries: Option<u32>,
}

pub trait SecurityKeys: Send + Sync {
    /// The key plugged in, which must be one: a FIDO2 key with hmac-secret.
    fn state(&self) -> Result<KeyState, KeyError>;

    /// Sets the PIN of a key that has none.
    fn set_pin(&self, pin: &str) -> Result<(), KeyError>;

    /// Makes a credential for a wallet, and its secret under `salt`: two touches.
    fn enroll(
        &self,
        pin: &str,
        salt: &[u8; 32],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), KeyError>;

    /// The secret of `credential` under `salt`: a touch.
    fn secret(
        &self,
        pin: &str,
        credential: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, KeyError>;
}

/// The security keys a build can use: none, without the `security-key` feature.
pub type Keys = Option<Arc<dyn SecurityKeys>>;

/// A key in software, for the tests: it keeps its PIN and counts wrong tries as a key does, and
/// its secrets are an HMAC of the credential and salt under a secret of its own.
#[cfg(test)]
pub struct Fake {
    state: std::sync::Mutex<FakeState>,
}

#[cfg(test)]
struct FakeState {
    plugged: bool,
    pin: Option<String>,
    retries: u32,
    credentials: Vec<Vec<u8>>,
}

#[cfg(test)]
impl Fake {
    pub fn new(pin: Option<&str>) -> Fake {
        let state = FakeState {
            plugged: true,
            pin: pin.map(str::to_owned),
            retries: 8,
            credentials: Vec::new(),
        };
        Fake { state: std::sync::Mutex::new(state) }
    }

    pub fn plug(&self, plugged: bool) {
        self.state.lock().unwrap().plugged = plugged;
    }

    fn check(state: &mut FakeState, pin: &str) -> Result<(), KeyError> {
        if !state.plugged {
            return Err(KeyError::NoKey);
        }
        let Some(set) = &state.pin else { return Err(KeyError::PinNotSet) };
        if state.retries == 0 {
            return Err(KeyError::PinBlocked);
        }
        if set != pin {
            state.retries -= 1;
            return Err(match state.retries {
                0 => KeyError::PinBlocked,
                retries => KeyError::WrongPin { retries: Some(retries) },
            });
        }
        state.retries = 8;
        Ok(())
    }

    fn hmac(parts: &[&[u8]]) -> [u8; 32] {
        use wallet_core::bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
        let mut engine = HmacEngine::<sha256::Hash>::new(b"the fake key's own secret");
        for part in parts {
            engine.input(part);
        }
        Hmac::from_engine(engine).to_byte_array()
    }
}

#[cfg(test)]
impl SecurityKeys for Fake {
    fn state(&self) -> Result<KeyState, KeyError> {
        let state = self.state.lock().unwrap();
        if !state.plugged {
            return Err(KeyError::NoKey);
        }
        let pin_set = state.pin.is_some();
        Ok(KeyState { pin_set, retries: pin_set.then_some(state.retries) })
    }

    fn set_pin(&self, pin: &str) -> Result<(), KeyError> {
        let mut state = self.state.lock().unwrap();
        if !state.plugged {
            return Err(KeyError::NoKey);
        }
        state.pin = Some(pin.to_owned());
        Ok(())
    }

    fn enroll(
        &self,
        pin: &str,
        salt: &[u8; 32],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), KeyError> {
        let mut state = self.state.lock().unwrap();
        Fake::check(&mut state, pin)?;
        let credential =
            Fake::hmac(&[b"credential", &(state.credentials.len() as u32).to_le_bytes()]).to_vec();
        state.credentials.push(credential.clone());
        let secret = Zeroizing::new(Fake::hmac(&[&credential, salt]));
        Ok((credential, secret))
    }

    fn secret(
        &self,
        pin: &str,
        credential: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let mut state = self.state.lock().unwrap();
        Fake::check(&mut state, pin)?;
        if !state.credentials.iter().any(|made| made == credential) {
            return Err(KeyError::NotThisKey);
        }
        Ok(Zeroizing::new(Fake::hmac(&[credential, salt])))
    }
}
