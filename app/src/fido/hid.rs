//! FIDO2 security keys over USB HID, through Linux's hidraw, which systemd's udev rules open to
//! the user at the seat for any device that says it is one.

use std::fmt;

use ctap_hid_fido2::fidokey::get_assertion::{
    Extension as AssertionExtension, GetAssertionArgsBuilder,
};
use ctap_hid_fido2::fidokey::make_credential::{
    Extension as CredentialExtension, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHid, LibCfg, get_fidokey_devices};
use zeroize::Zeroizing;

use super::{KeyError, KeyState, SecurityKeys};

/// The relying party the credentials are made for. A credential that is no website's takes any
/// name; this one says whose it is in a key's management tools.
const RP_ID: &str = "wallet";

/// The security keys plugged in over USB.
pub struct Hid;

impl Hid {
    fn open() -> Result<FidoKeyHid, KeyError> {
        let devices = get_fidokey_devices();
        let device = match devices.as_slice() {
            [] => return Err(KeyError::NoKey),
            [device] => device,
            _ => return Err(KeyError::SeveralKeys),
        };
        let mut cfg = LibCfg::init();
        // It would print to stdout while it waits for a touch, which the screen says instead.
        cfg.enable_keep_alive_msg = false;
        FidoKeyHid::new(std::slice::from_ref(&device.param), &cfg)
            .map_err(|error| classify(None, error))
    }

    /// The key plugged in, checked to be one that makes secrets, and whether its PIN is set.
    fn checked() -> Result<(FidoKeyHid, bool), KeyError> {
        let key = Hid::open()?;
        let info = key.get_info().map_err(|error| classify(None, error))?;
        if !info.extensions.iter().any(|extension| extension == "hmac-secret") {
            return Err(KeyError::NoHmacSecret);
        }
        let pin_set = info.options.iter().any(|(option, set)| option == "clientPin" && *set);
        Ok((key, pin_set))
    }

    fn assert(
        key: &FidoKeyHid,
        pin: &str,
        credential: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let challenge = random()?;
        let args = GetAssertionArgsBuilder::new(RP_ID, challenge.as_ref())
            .pin(pin)
            .credential_id(credential)
            .extensions(&[AssertionExtension::HmacSecret(Some(*salt))])
            .build();
        let assertions =
            key.get_assertion_with_args(&args).map_err(|error| classify(Some(key), error))?;
        let extensions = assertions.first().map(|assertion| assertion.extensions.as_slice());
        (extensions.unwrap_or_default().iter())
            .find_map(|extension| match extension {
                AssertionExtension::HmacSecret(Some(secret)) => Some(Zeroizing::new(*secret)),
                _ => None,
            })
            .ok_or(KeyError::NoHmacSecret)
    }
}

impl SecurityKeys for Hid {
    fn state(&self) -> Result<KeyState, KeyError> {
        let (key, pin_set) = Hid::checked()?;
        let retries = if pin_set { key.get_pin_retries().ok() } else { None };
        Ok(KeyState { pin_set, retries: retries.map(|retries| retries.max(0) as u32) })
    }

    fn set_pin(&self, pin: &str) -> Result<(), KeyError> {
        let (key, _) = Hid::checked()?;
        key.set_new_pin(pin).map_err(|error| classify(Some(&key), error))
    }

    fn enroll(
        &self,
        pin: &str,
        salt: &[u8; 32],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), KeyError> {
        let (key, pin_set) = Hid::checked()?;
        if !pin_set {
            return Err(KeyError::PinNotSet);
        }
        let challenge = random()?;
        // Some keys refuse a credential without a user; this one is the wallet.
        let user_id = random()?;
        let user = PublicKeyCredentialUserEntity::new(
            Some(user_id.as_ref()),
            Some("wallet"),
            Some("Wallet"),
        );
        let args = MakeCredentialArgsBuilder::new(RP_ID, challenge.as_ref())
            .pin(pin)
            .user_entity(&user)
            .extensions(&[CredentialExtension::HmacSecret(Some(true))])
            .build();
        let attestation =
            key.make_credential_with_args(&args).map_err(|error| classify(Some(&key), error))?;
        let made = (attestation.extensions.iter())
            .any(|extension| matches!(extension, CredentialExtension::HmacSecret(Some(true))));
        if !made {
            return Err(KeyError::NoHmacSecret);
        }
        let credential = attestation.credential_descriptor.id;
        let secret = Hid::assert(&key, pin, &credential, salt)?;
        Ok((credential, secret))
    }

    fn secret(
        &self,
        pin: &str,
        credential: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let (key, _) = Hid::checked()?;
        Hid::assert(&key, pin, credential, salt)
    }
}

fn random() -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|error| KeyError::Other(format!("no randomness: {error}")))?;
    Ok(bytes)
}

/// What a key's error means, from the CTAP status the library writes into it.
fn classify(key: Option<&FidoKeyHid>, error: impl fmt::Display) -> KeyError {
    let message = format!("{error:#}");
    let says = |status: &str| message.contains(status);
    if says("CTAP2_ERR_PIN_INVALID") {
        let retries = key.and_then(|key| key.get_pin_retries().ok());
        KeyError::WrongPin { retries: retries.map(|retries| retries.max(0) as u32) }
    } else if says("CTAP2_ERR_PIN_BLOCKED") {
        KeyError::PinBlocked
    } else if says("CTAP2_ERR_PIN_AUTH_BLOCKED") {
        KeyError::PinPaused
    } else if says("CTAP2_ERR_PIN_NOT_SET") {
        KeyError::PinNotSet
    } else if says("CTAP2_ERR_NO_CREDENTIALS") {
        KeyError::NotThisKey
    } else if says("TIMEOUT") {
        KeyError::Timeout
    } else if says("CTAP1_ERR_INVALID_COMMAND") {
        KeyError::NotFido2
    } else {
        KeyError::Other(message)
    }
}

/// Against the security key plugged in. `the_key_plugged_in` says what it is and needs no touch;
/// `a_real_key_gives_one_secret_a_salt` makes a credential and asks it for secrets, which takes
/// the key's PIN (in `FIDO_PIN`) and three touches:
/// `FIDO_PIN=… cargo test -p wallet --features security-key -- --ignored --nocapture real_key`.
#[cfg(test)]
mod hardware {
    use super::*;

    #[test]
    #[ignore = "needs a security key plugged in"]
    fn the_key_plugged_in() {
        println!("{:?}", Hid.state());
    }

    #[test]
    #[ignore = "needs a FIDO2 key plugged in, its PIN in FIDO_PIN, and three touches"]
    fn a_real_key_gives_one_secret_a_salt() {
        let pin = std::env::var("FIDO_PIN").expect("the key's PIN in FIDO_PIN");
        println!("Touch the key, twice: a credential, then its secret.");
        let (credential, secret) = Hid.enroll(&pin, &[1; 32]).unwrap();
        // A wrong PIN is refused before any touch, and counted.
        let wrong = Hid.secret("not the PIN", &credential, &[1; 32]);
        assert!(matches!(wrong, Err(KeyError::WrongPin { retries: Some(7) })), "{wrong:?}");
        println!("Touch it once more.");
        assert_eq!(Hid.secret(&pin, &credential, &[1; 32]).unwrap(), secret, "the same again");
        assert_eq!(Hid.state().unwrap().retries, Some(8), "the right PIN restores the count");
    }
}
