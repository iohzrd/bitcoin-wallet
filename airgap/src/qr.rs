//! QR codes for the screen. The signer only shows them (the handhelds have no camera), so this
//! makes the modules and the UI paints them.

use qrcode::{Color, EcLevel, QrCode};

#[derive(Debug, thiserror::Error)]
#[error("too long for a QR code")]
pub struct TooLong;

/// A QR code's modules, row by row, without its quiet zone. It is made at error correction
/// level M, which recovers 15% of the code: a screen does not smudge, but glare does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qr {
    width: usize,
    dark: Vec<bool>,
}

impl Qr {
    /// The smallest QR code that holds `text`, in alphanumeric mode where it can be (a UR part in
    /// capitals) and byte mode where it cannot (a descriptor).
    pub fn new(text: &str) -> Result<Qr, TooLong> {
        let code = QrCode::with_error_correction_level(text, EcLevel::M).map_err(|_| TooLong)?;
        Ok(Qr::from_code(&code))
    }

    /// A QR code for one part of a loop, at error correction level L, as SeedSigner, Jade and
    /// Krux show theirs: a smaller code reads more easily, and a part the camera misses comes
    /// round again.
    pub fn for_loop(text: &str) -> Result<Qr, TooLong> {
        let code = QrCode::with_error_correction_level(text, EcLevel::L).map_err(|_| TooLong)?;
        Ok(Qr::from_code(&code))
    }

    pub(crate) fn from_code(code: &QrCode) -> Qr {
        let dark = code.to_colors().into_iter().map(|color| color == Color::Dark).collect();
        Qr { width: code.width(), dark }
    }

    /// The modules a side.
    pub fn width(&self) -> usize {
        self.width
    }

    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.width + x]
    }
}

/// The white margin a reader needs around a QR code, in modules.
pub const QUIET_ZONE: usize = 4;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bcur::{FRAGMENT_LEN, PsbtDecoder, PsbtEncoder};
    use crate::file::tests::example;
    use wallet_core::bitcoin::{Amount, TxOut};

    /// What a camera reads off `qr` drawn `scale` pixels a module with its quiet zone.
    fn scan(qr: &Qr, scale: usize) -> String {
        String::from_utf8(scan_bytes(qr, scale)).unwrap()
    }

    /// The bytes a camera reads off `qr`, which need not be text.
    pub(crate) fn scan_bytes(qr: &Qr, scale: usize) -> Vec<u8> {
        let side = (qr.width() + 2 * QUIET_ZONE) * scale;
        let mut image = rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| {
            let (x, y) = (x / scale, y / scale);
            let inside = QUIET_ZONE..QUIET_ZONE + qr.width();
            let dark = inside.contains(&x)
                && inside.contains(&y)
                && qr.is_dark(x - QUIET_ZONE, y - QUIET_ZONE);
            if dark { 0 } else { 255 }
        });
        let grids = image.detect_grids();
        assert_eq!(grids.len(), 1);
        let mut bytes = Vec::new();
        grids[0].decode_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn an_animated_psbt_scans_back_off_its_qr_codes() {
        let mut psbt = example();
        let previous = TxOut { value: Amount::from_sat(1), script_pubkey: vec![0x51; 200].into() };
        psbt.inputs[0].witness_utxo = Some(previous);
        let mut encoder = PsbtEncoder::new(&psbt, FRAGMENT_LEN);
        assert!(encoder.fragment_count() > 1);
        let mut decoder = PsbtDecoder::default();
        let decoded = loop {
            let qr = Qr::new(&encoder.next_part()).unwrap();
            assert!(qr.width() <= 61, "version 11 at most: {} modules", qr.width());
            if let Some(psbt) = decoder.receive(&scan(&qr, 3)).unwrap() {
                break psbt;
            }
        };
        assert_eq!(decoded, psbt);
    }

    #[test]
    fn capitals_make_a_ur_part_a_smaller_code() {
        let part = PsbtEncoder::new(&example(), FRAGMENT_LEN).next_part();
        let upper = Qr::new(&part).unwrap();
        let lower = Qr::new(&part.to_lowercase()).unwrap();
        assert!(upper.width() < lower.width(), "{} vs {}", upper.width(), lower.width());
    }

    #[test]
    fn a_descriptor_scans_back_as_its_text() {
        let descriptor = "tr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)";
        assert_eq!(scan(&Qr::new(descriptor).unwrap(), 3), descriptor);
    }

    #[test]
    fn text_past_a_qr_codes_capacity_is_refused() {
        assert!(Qr::new(&"a".repeat(3000)).is_err());
    }
}
