//! Writes what the byte-reading targets start from into `fuzz/corpus/<target>/`: PSBTs of each
//! wallet's, unsigned, partly and fully signed, in each encoding the signer reads; setup files in
//! each format it reads; the parts of UR loops; and SeedSigner's SeedQR vectors. The fuzzer
//! mutates these into what a hostile coordinator could hand the signer, far faster than it could
//! find their structure from nothing.

use std::fs;
use std::path::Path;

use wallet_airgap::bcur::PsbtEncoder;
use wallet_airgap::file::write_psbt;
use wallet_core::account::{Account, Kind};
use wallet_core::bitcoin::base58;
use wallet_core::bitcoin::hex::DisplayHex;
use wallet_core::bitcoin::psbt::Psbt;
use wallet_core::miniscript::descriptor::checksum::Engine;
use wallet_core::multisig::CosignerKey;
use wallet_core::policy::Policy;
use wallet_core::{Mnemonic, psbt};
use wallet_fuzz::{
    AUX_RAND, InputSpec, Key, MULTISIG, OutputSpec, OutputWho, Previous, SEEDS, Spec, Wallet, Who,
    build,
};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    psbts(&root.join("review"), &root.join("bcur"));
    setups(&root.join("setup"));
    seedqrs(&root.join("seedqr"));
    stores(&root.join("store"));
}

/// Records as a kept wallet holds them, and a file sealing one at Argon2's least cost.
fn stores(dir: &Path) {
    use wallet_core::store::{self, Kept, KeptMultisig, Key, Params, Record};
    let seed = Record {
        network: wallet_fuzz::NETWORK,
        birthday: 1_700_000_000,
        wallet: Kept::Seed {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".parse().unwrap(),
            passphrase: Some(zeroize::Zeroizing::new("TREZOR".to_owned())),
            fingerprint: "73c5da0a".parse().unwrap(),
            kind: Kind::Taproot,
        },
        multisigs: vec![KeptMultisig {
            descriptor: MULTISIG[0].descriptor().to_string(),
            name: Some("Vault".to_owned()),
        }],
    };
    let watch = Record {
        wallet: Kept::Watch { descriptor: wallet_fuzz::TAPROOT.descriptor().to_string() },
        multisigs: Vec::new(),
        ..seed.clone()
    };
    write(dir, "seed", seed.encode().as_bytes());
    write(dir, "watch", watch.encode().as_bytes());
    let cheap = Params { memory_kib: 8, passes: 1, lanes: 1 };
    let key = Key::derive("passphrase", [1; 16], cheap).unwrap();
    write(dir, "sealed", store::seal(&key, [2; 24], &seed));
    let security_key = store::SecurityKey { credential: vec![9; 48], salt: [3; 32] };
    let keyed = Key::derive_with("", [1; 16], cheap, security_key, &[5; 32]).unwrap();
    write(dir, "sealed-with-a-key", store::seal(&keyed, [2; 24], &seed));
}

fn write(dir: &Path, name: &str, data: impl AsRef<[u8]>) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), data).unwrap();
}

fn input(who: Who, amount: u64, previous: Previous) -> InputSpec {
    InputSpec {
        who,
        amount,
        sequence: 0xffff_fffd,
        previous,
        sighash: None,
        finalized: false,
        wrong_witness_script: false,
        duplicate_of: None,
    }
}

fn ours(change: bool, index: u32) -> Who {
    Who::Ours(Key { change, index })
}

/// A wallet's spend of two of its outputs to a payment and its change, and variations of it.
fn specs(wallet: Wallet) -> Vec<(&'static str, Spec)> {
    let payment = |amount| OutputSpec { who: OutputWho::Who(Who::Theirs(5)), amount };
    let change = |amount| OutputSpec { who: OutputWho::Who(ours(true, 2)), amount };
    let spend = Spec {
        wallet,
        version: 2,
        lock_time: 850_000,
        inputs: vec![
            input(ours(false, 0), 60_000, Previous::Both),
            input(ours(true, 1), 40_000, Previous::Both),
        ],
        outputs: vec![payment(70_000), change(29_000)],
    };
    let witness_only = Spec {
        inputs: vec![
            input(ours(false, 3), 60_000, Previous::WitnessUtxo),
            input(ours(false, 4), 40_000, Previous::WitnessUtxo),
        ],
        outputs: vec![payment(99_000)],
        ..spec(wallet)
    };
    let mixed = Spec {
        inputs: vec![
            input(ours(false, 0), 60_000, Previous::PreviousTx),
            input(Who::Theirs(9), 40_000, Previous::WitnessUtxo),
        ],
        outputs: vec![
            payment(50_000),
            OutputSpec {
                who: OutputWho::Who(Who::Pretender(Key { change: true, index: 0 })),
                amount: 20_000,
            },
            OutputSpec { who: OutputWho::OpReturn(b"hello".to_vec()), amount: 0 },
            change(29_000),
        ],
        ..spec(wallet)
    };
    vec![("spend", spend), ("witness-only", witness_only), ("mixed", mixed)]
}

fn spec(wallet: Wallet) -> Spec {
    Spec { wallet, version: 2, lock_time: 0, inputs: Vec::new(), outputs: Vec::new() }
}

/// Each PSBT as a file holds it, binary, base64 and hex; and as the parts of UR loops.
fn psbts(review: &Path, bcur: &Path) {
    for wallet in [Wallet::Taproot, Wallet::Segwit, Wallet::Multisig] {
        for (name, spec) in specs(wallet) {
            let unsigned = build(&spec);
            let mut stages = vec![("unsigned", unsigned.clone())];
            let mut signed = unsigned.clone();
            if psbt::sign(wallet.policy(), &SEEDS[0], &mut signed, &AUX_RAND).is_ok() {
                stages.push(("signed", signed.clone()));
                if wallet == Wallet::Multisig {
                    let mut both = signed;
                    psbt::sign(&MULTISIG[1], &SEEDS[1], &mut both, &AUX_RAND).unwrap();
                    stages.push(("cosigned", both));
                }
            }
            for (stage, psbt) in stages {
                let name = format!("{wallet:?}-{name}-{stage}").to_lowercase();
                write(review, &format!("{name}.psbt"), write_psbt(&psbt));
                write(review, &format!("{name}.base64"), psbt.to_string());
                write(review, &format!("{name}.hex"), write_psbt(&psbt).to_lower_hex_string());
                write(bcur, &name, loop_parts(&psbt));
            }
        }
    }
}

/// A loop's first parts, a line each: enough to decode, at a fragment length that cuts the PSBT
/// into a few.
fn loop_parts(psbt: &Psbt) -> String {
    let mut encoder = PsbtEncoder::new(psbt, 200);
    let count = encoder.fragment_count();
    (0..count + 2).map(|_| encoder.next_part() + "\n").collect()
}

fn checksummed(line: &str) -> String {
    let mut engine = Engine::new();
    engine.input(line).unwrap();
    format!("{line}#{}", engine.checksum())
}

fn slip132(xpub: &str, version: [u8; 4]) -> String {
    let mut data = base58::decode_check(xpub).unwrap();
    data[..4].copy_from_slice(&version);
    base58::encode_check(&data)
}

/// The fuzz wallets' 2-of-3 in each format a coordinator writes one, and single-key accounts'
/// descriptors.
fn setups(dir: &Path) {
    let network = wallet_fuzz::NETWORK;
    let keys: Vec<CosignerKey> =
        SEEDS.iter().map(|seed| CosignerKey::new(seed, network, 0).unwrap()).collect();
    let with =
        |suffix: &str| -> Vec<String> { keys.iter().map(|key| format!("{key}{suffix}")).collect() };
    let multipath = format!("wsh(sortedmulti(2,{}))", with("/<0;1>/*").join(","));
    let sparrow = format!(
        "# Receive and change descriptor:\n{}\n\n# Receive descriptor:\n{}\n\n# Change descriptor:\n{}\n",
        checksummed(&format!("{multipath}?bh=850123")),
        checksummed(&multipath.replace("<0;1>", "0")),
        checksummed(&multipath.replace("<0;1>", "1")),
    );
    write(dir, "sparrow", sparrow);
    write(dir, "multipath", checksummed(&multipath));
    let receive = format!("wsh(multi(2,{}))", with("/0/*").join(","));
    write(dir, "pair", format!("{receive}\n{}\n", receive.replace("/0/*", "/1/*")));
    let first = MULTISIG[0].address(wallet_core::account::Derivation::receive(0));
    let bsms =
        format!("BSMS 1.0\nwsh(sortedmulti(2,{}))\n/0/*,/1/*\n{first}\n", with("/**").join(","));
    write(dir, "bsms", bsms);
    write(dir, "specter", format!("addwallet Vault&wsh(sortedmulti(2,{}))", with("").join(",")));
    let mut coldcard = String::from(
        "# Coldcard Multisig setup file (created by Sparrow)\n#\nName: Vault\nPolicy: 2 of 3\nDerivation: m/48'/1'/0'/2'\nFormat: P2WSH\n\n",
    );
    for (index, key) in keys.iter().enumerate() {
        let xpub = key.xpub.to_string();
        // Vpub, as Sparrow writes testnet keys for a Coldcard.
        let xpub = if index == 1 { slip132(&xpub, [0x02, 0x57, 0x54, 0x83]) } else { xpub };
        coldcard.push_str(&format!("{}: {xpub}\n", key.origin.0.to_string().to_uppercase()));
    }
    write(dir, "coldcard", coldcard);
    for kind in [Kind::Taproot, Kind::SegwitV0] {
        let account = Account::from_seed(&SEEDS[0], network, kind, 0).unwrap();
        write(dir, &format!("{kind:?}").to_lowercase(), account.descriptor().to_string());
    }
}

/// SeedSigner's SeedQR vectors (docs/seed_qr/README.md), in both forms, and dice rolls.
fn seedqrs(dir: &Path) {
    let mnemonics = [
        "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire",
        "atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid meadow quick medal plate wisdom swap noble shallow",
        "forum undo fragile fade shy sign arrest garment culture tube off merit",
        "good battle boil exact add seed angle hurry success glad carbon whisper",
    ];
    for (index, words) in mnemonics.iter().enumerate() {
        let mnemonic: Mnemonic = words.parse().unwrap();
        write(
            dir,
            &format!("standard-{index}"),
            wallet_airgap::seedqr::standard_digits(&mnemonic).as_bytes(),
        );
        write(dir, &format!("compact-{index}"), mnemonic.to_entropy());
    }
    let rolls: Vec<u8> =
        (0..wallet_core::dice::ROLLS_24).map(|roll| (roll % 6 + 1) as u8).collect();
    write(dir, "dice-24", &rolls);
    write(dir, "dice-12", &rolls[..wallet_core::dice::ROLLS_12]);
}
