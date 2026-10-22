# Wallet

A Bitcoin wallet that works as an offline signer on Linux handhelds and single-board computers
(D-pad and face buttons, a 640×480 screen) and on air-gapped laptops and desktops alike, and,
built with the `online` feature, as the watch-only wallet that funds and broadcasts what the
signer signs, through your own Bitcoin Core node.

The signer reviews a PSBT before signing it and takes nothing in it on its word: an input or a
change output is the wallet's only when the wallet's own descriptor gives its script, amounts come
from the previous transactions, and it warns of fake change, high fees, foreign inputs and the
rest of what Coldcard, Ledger, Trezor and Jade warn of.

## Building

```sh
cargo build --release -p wallet                          # the offline signer
cargo build --release -p wallet --features online        # with the watch-only wallet
cargo build --release -p wallet --features security-key  # with FIDO2 security keys
```

It needs libudev (`libudev-dev` on Debian), for gamepads and security keys, and OpenGL ES 2 or
later, which handhelds' Mali GPUs run under Mesa's Panfrost.

For arm64 handhelds and boards, `scripts/build-aarch64.sh` builds it in a Debian trixie
container (Docker), against the glibc and libudev their images ship, to
`target/aarch64/aarch64-unknown-linux-gnu/release/wallet`. rugix-handheld's `apps/wallet.sh`
runs it for its signer images. The offline build links no HTTP,
TLS or RPC client; CI checks that it does not.

| Feature        | Adds                                                                      |
| -------------- | ------------------------------------------------------------------------- |
| `online`       | The watch-only wallet: balance, receive, send and broadcast through Bitcoin Core's RPC |
| `security-key` | Sealing a kept wallet with a FIDO2 key's hmac-secret, over USB            |

## Running

```sh
wallet --network testnet --dir /media/card
```

| Flag                        | What it does                                                       |
| --------------------------- | ------------------------------------------------------------------ |
| `--network`                 | `bitcoin` (the default), `testnet`, `testnet4`, `signet` or `regtest` |
| `--dir <DIR>`               | Where PSBTs and other files are read and written; repeat for more. Default: home and every mounted removable volume |
| `--data-dir <DIR>`          | Where a kept wallet is kept. Default: `$XDG_DATA_HOME/wallet`      |
| `--no-store`                | Never keep a wallet on the device                                  |
| `--fullscreen`, `--scale`   | For handhelds, and for the size of everything                      |
| `--swap-ab`                 | Nintendo's face-button layout                                      |
| `--rpc-url`, `--rpc-cookie`, `--rpc-user`, `--rpc-password` | The node (`online`)            |
| `--watch <DESCRIPTOR>`      | A watch-only account to open at start (`online`)                   |

A gamepad drives every screen: the D-pad moves, A selects, B goes back, the shoulders page. So
do the arrow keys, Enter and Escape, and the mouse.

## What it does

- **Seeds**: 12 or 24 words, from the system's randomness or from dice rolls (as SeedSigner and
  Coldcard make them), or restored; a BIP39 passphrase; backups shown word by word, checked, or
  drawn as a SeedQR to copy by hand.
- **Accounts**: BIP86 taproot or BIP84 native segwit, exported as a `crypto-account` UR or as a
  descriptor, by QR code or on the card.
- **Signing**: PSBTs (binary, base64 or hex) from the card; the signed one is written beside
  it, and shown as a `crypto-psbt` QR loop holding its signatures alone.
- **Multisig**: the seed's BIP48 key for a coordinator; wallets registered from Sparrow's
  descriptor export, BSMS, a Coldcard setup file or Specter's `addwallet`, then co-signed.
- **Messages**: BIP-322 simple signatures (`smp…`), from a request on the card (Coldcard's
  format: the message, then the key's path or address) or typed, written back armored.
- **Addresses**: shown to check against what another wallet shows.

## Keeping a wallet on the device

By default the seed lives in memory and is gone when the wallet closes. Keeping it is opt-in,
from the wallet's home screen: the seed (or a watch-only account) and the multisig wallets
registered with it are sealed in a file of their own for the chain, with XChaCha20-Poly1305
under a key from Argon2id (64 MiB, 3 passes, 4 lanes), and unlocked from the start screen. The
seed's BIP39 passphrase is asked for each time unless you keep it too.

A copy of the file can be attacked offline, as fast as the attacker's hardware allows, so a
passphrase must be strong: several words. With the `security-key` feature, the file can instead
be sealed with a FIDO2 key (YubiKey 5, Security Key, Nitrokey 3…) and its PIN, with or without a
passphrase: the key's secret never leaves it, and it locks after eight wrong PINs.

The kept file is no backup. Keep your recovery words.

## Hardening

At start the process makes itself non-dumpable (no core dumps, no `ptrace` or `/proc/<pid>/mem`
by your other processes). Where the locked-memory limit allows (`ulimit -l unlimited`, or
`LimitMEMLOCK=infinity` in a systemd service), it locks all of its memory out of swap; otherwise
it locks the app's own state, where the open wallet's seed, words and key live, and says on
stderr that the rest is not. Secrets are wiped from memory as they are dropped.

## Testing

```sh
cargo test --workspace --all-features
```

Every signature the signer makes in the tests is run through Bitcoin Core's script interpreter
(`bitcoinconsensus`). The UI tests drive the app by the keys a gamepad sends. Further:

```sh
# Against a real bitcoind on regtest:
BITCOIND=/path/to/bitcoind cargo test --workspace --all-features -- --ignored --skip screenshots
# Every screen rendered to target/screenshots, to look at:
cargo test -p wallet -- --ignored screenshots
# A FIDO2 key plugged in (its PIN, and three touches):
FIDO_PIN=… cargo test -p wallet --features security-key -- --ignored --nocapture real_key
# Fuzzing (cargo install cargo-fuzz; stable takes its flags with RUSTC_BOOTSTRAP=1):
cargo run --manifest-path fuzz/Cargo.toml --example seed-corpus
RUSTC_BOOTSTRAP=1 cargo fuzz run transaction -- -fork=8 -max_total_time=600
```

## Layout

| Crate    | What it holds                                                                  |
| -------- | ------------------------------------------------------------------------------ |
| `core`   | Seeds, accounts, multisig, PSBT review and signing, messages, the kept-wallet format; no I/O, no randomness of its own |
| `airgap` | What crosses the air gap: PSBT files, BC-UR, QR codes, SeedQR, setup files, message requests, account export |
| `node`   | Bitcoin Core's RPC, for the watch-only wallet                                   |
| `app`    | The egui app                                                                    |
| `fuzz`   | cargo-fuzz targets, a workspace of their own                                    |

## Status

Not audited. The handheld images (an aarch64 build and a signer image for the RG35XX and
others) are not yet built. No license has been chosen yet.
