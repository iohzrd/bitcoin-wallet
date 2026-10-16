//! The watch-only wallet's view of the chain, through a Bitcoin Core or Knots node's own wallet: a
//! wallet with no private keys that holds the account's receive and change descriptors. The node
//! keeps it in sync, picks the coins and sizes the fee of the PSBTs it funds, and broadcasts them
//! once the signer has signed them; the keys never reach it.

#[cfg(feature = "test-support")]
pub mod regtest;

use std::path::PathBuf;
use std::str::FromStr;

use serde_json::{Map, Value, json};
use wallet_core::account::{Account, Derivation, Keychain, Kind};
use wallet_core::bitcoin::base64::Engine;
use wallet_core::bitcoin::base64::engine::general_purpose::STANDARD as BASE64;
use wallet_core::bitcoin::bip32::KeySource;
use wallet_core::bitcoin::psbt::{Psbt, PsbtParseError};
use wallet_core::bitcoin::{Address, Amount, Denomination, Network, SignedAmount, Txid};
use wallet_core::miniscript::Descriptor;
use wallet_core::miniscript::descriptor::DescriptorPublicKey;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reaching the node: {0}")]
    Http(#[from] minreq::Error),
    #[error("reading the node's cookie file {path}: {source}")]
    Cookie { path: PathBuf, source: std::io::Error },
    #[error("the node answered HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("{method}: {message} ({code})")]
    Rpc { method: String, code: i64, message: String },
    #[error("{method} answered what the wallet does not understand: {reply}")]
    Unexpected { method: String, reply: String },
    #[error("importing the account's {keychain:?} descriptor: {reply}")]
    Import { keychain: Keychain, reply: String },
    #[error("the node gave an address that is not the account's: {0}")]
    ForeignAddress(String),
    #[error("the node could not finalize the PSBT, which is missing signatures")]
    Incomplete,
    #[error(transparent)]
    Psbt(#[from] PsbtParseError),
}

/// Bitcoin Core's code for a wallet it does not have on disk.
const RPC_WALLET_NOT_FOUND: i64 = -18;

/// How long a call may take, in seconds. Importing an account with a rescan takes as long as
/// the rescan does, which is hours on mainnet, and has none.
const TIMEOUT: u64 = 60;

/// How the node knows the caller.
#[derive(Clone, Debug)]
pub enum Auth {
    /// The `.cookie` file the node writes into its data directory when it starts, read for each
    /// call as the node writes a new one every start.
    Cookie(PathBuf),
    /// An `rpcauth` or `rpcuser` login.
    UserPass { user: String, password: String },
}

impl Auth {
    fn header(&self) -> Result<String, Error> {
        let login = match self {
            Auth::Cookie(path) => std::fs::read_to_string(path)
                .map_err(|source| Error::Cookie { path: path.clone(), source })?,
            Auth::UserPass { user, password } => format!("{user}:{password}"),
        };
        Ok(format!("Basic {}", BASE64.encode(login.trim())))
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    url: String,
    auth: Auth,
}

impl Node {
    /// The node at `url`, its RPC server's address: `http://127.0.0.1:8332` for a mainnet node
    /// on this machine.
    pub fn new(url: impl Into<String>, auth: Auth) -> Node {
        Node { url: url.into().trim_end_matches('/').to_owned(), auth }
    }

    /// The chain the node follows.
    pub fn network(&self) -> Result<Network, Error> {
        let info = self.call("getblockchaininfo", json!([]))?;
        info["chain"]
            .as_str()
            .and_then(|chain| Network::from_core_arg(chain).ok())
            .ok_or_else(|| unexpected("getblockchaininfo", &info))
    }

    /// The account's wallet on the node, which this loads if the node has it on disk and makes
    /// otherwise: a blank wallet with no private keys, into which it imports the account's
    /// descriptors. The node then scans the chain from `rescan_since`, the Unix time before which
    /// the account received nothing (0 for an account restored from its words, which may be any
    /// age); `None` scans nothing, for an account made just now.
    pub fn wallet(&self, account: &Account, rescan_since: Option<u64>) -> Result<Wallet, Error> {
        let wallet =
            Wallet { node: self.clone(), name: wallet_name(account), account: account.clone() };
        let loaded = self.call("listwallets", json!([]))?;
        if loaded
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == wallet.name.as_str()))
        {
            return Ok(wallet);
        }
        match self.call("loadwallet", json!([wallet.name])) {
            Ok(_) => return Ok(wallet),
            Err(Error::Rpc { code: RPC_WALLET_NOT_FOUND, .. }) => {}
            Err(error) => return Err(error),
        }
        let options = json!({ "wallet_name": wallet.name, "disable_private_keys": true, "blank": true, "load_on_startup": true });
        self.call("createwallet", options)?;
        let timestamp = rescan_since.map_or(json!("now"), |time| json!(time));
        let imports: Vec<Value> = [Keychain::Receive, Keychain::Change]
            .map(|keychain| {
                json!({
                    "desc": account.keychain_descriptor(keychain).to_string(),
                    "active": true,
                    "internal": keychain == Keychain::Change,
                    "timestamp": timestamp,
                })
            })
            .into();
        let results = wallet.call_with_timeout("importdescriptors", json!([imports]), None)?;
        for (keychain, result) in
            [Keychain::Receive, Keychain::Change].into_iter().zip(results_of(&results))
        {
            if result["success"] != true {
                return Err(Error::Import { keychain, reply: result.to_string() });
            }
        }
        Ok(wallet)
    }

    /// Calls `method` on the node, outside any wallet.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        self.call_at(&self.url, method, params, Some(TIMEOUT))
    }

    /// Calls `method` on the node's wallet named `wallet`.
    pub fn call_wallet(&self, wallet: &str, method: &str, params: Value) -> Result<Value, Error> {
        self.call_at(&format!("{}/wallet/{wallet}", self.url), method, params, Some(TIMEOUT))
    }

    fn call_at(
        &self,
        url: &str,
        method: &str,
        params: Value,
        timeout: Option<u64>,
    ) -> Result<Value, Error> {
        let body = json!({ "jsonrpc": "1.0", "id": method, "method": method, "params": params });
        let mut request = minreq::post(url)
            .with_header("Authorization", self.auth.header()?)
            .with_header("Content-Type", "application/json")
            .with_body(body.to_string());
        if let Some(timeout) = timeout {
            request = request.with_timeout(timeout);
        }
        let response = request.send()?;
        let text = response.as_str().unwrap_or_default();
        // An RPC error comes back in a JSON reply as HTTP 500 (or 404, for a wallet the node does
        // not have loaded); a failed login comes back as HTTP 401 with no JSON at all.
        let Ok(mut reply) = serde_json::from_str::<Value>(text) else {
            let body = text.chars().take(200).collect();
            return Err(Error::Status { status: response.status_code, body });
        };
        let error = &reply["error"];
        if !error.is_null() {
            return Err(Error::Rpc {
                method: method.to_owned(),
                code: error["code"].as_i64().unwrap_or_default(),
                message: error["message"].as_str().unwrap_or_default().to_owned(),
            });
        }
        Ok(reply["result"].take())
    }
}

/// The name the account's wallet goes by on the node: its master key's fingerprint and its
/// descriptor's checksum, which tell apart two accounts of one seed.
fn wallet_name(account: &Account) -> String {
    let descriptor = account.descriptor().to_string();
    let checksum = descriptor.rsplit('#').next().unwrap_or_default();
    format!("{}-{checksum}", account.fingerprint())
}

fn results_of(reply: &Value) -> impl Iterator<Item = &Value> {
    reply.as_array().into_iter().flatten()
}

fn unexpected(method: &str, reply: &Value) -> Error {
    Error::Unexpected { method: method.to_owned(), reply: reply.to_string() }
}

/// An amount the node writes as a number of bitcoin.
fn amount(method: &str, reply: &Value) -> Result<Amount, Error> {
    reply
        .as_f64()
        .and_then(|btc| Amount::from_btc(btc).ok())
        .ok_or_else(|| unexpected(method, reply))
}

fn signed_amount(method: &str, reply: &Value) -> Result<SignedAmount, Error> {
    reply
        .as_f64()
        .and_then(|btc| SignedAmount::from_btc(btc).ok())
        .ok_or_else(|| unexpected(method, reply))
}

/// The account's watch-only wallet on the node.
#[derive(Clone, Debug)]
pub struct Wallet {
    node: Node,
    name: String,
    account: Account,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// Confirmed, and unconfirmed change of the account's own.
    pub trusted: Amount,
    /// Unconfirmed, from others.
    pub pending: Amount,
    /// Mined to the account, and not yet 100 blocks deep.
    pub immature: Amount,
}

impl Balance {
    pub fn total(&self) -> Amount {
        self.trusted + self.pending + self.immature
    }
}

/// A transaction of the account's, by what it did to the balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub txid: Txid,
    /// What the transaction added to the balance, fee included; negative for a payment.
    pub amount: SignedAmount,
    /// 0 while unconfirmed, and negative for a transaction a conflicting one has replaced.
    pub confirmations: i64,
    /// When the node first saw it, in Unix time.
    pub time: u64,
}

impl Wallet {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn balance(&self) -> Result<Balance, Error> {
        const METHOD: &str = "getbalances";
        let reply = self.call(METHOD, json!([]))?;
        let mine = &reply["mine"];
        Ok(Balance {
            trusted: amount(METHOD, &mine["trusted"])?,
            pending: amount(METHOD, &mine["untrusted_pending"])?,
            immature: amount(METHOD, &mine["immature"])?,
        })
    }

    /// The next receive address the node has not handed out, and the key it is. The derivation
    /// is checked against the account, so the address the watch-only wallet shows is one the
    /// signer will show under the same index.
    pub fn receive_address(&self) -> Result<(Address, Derivation), Error> {
        let reply = self.call("getnewaddress", json!(["", self.address_type()]))?;
        let address = reply.as_str().ok_or_else(|| unexpected("getnewaddress", &reply))?;
        let info = self.call("getaddressinfo", json!([address]))?;
        let foreign = || Error::ForeignAddress(address.to_owned());
        let address = Address::from_str(address)
            .ok()
            .and_then(|address| address.require_network(self.account.network()).ok())
            .ok_or_else(foreign)?;
        // The address's own descriptor, `wpkh([fingerprint/path]key)` or `tr(...)`, names its key.
        let descriptor = info["desc"].as_str().and_then(|desc| desc.parse().ok());
        let source = match descriptor {
            Some(Descriptor::<DescriptorPublicKey>::Wpkh(wpkh)) => origin(wpkh.as_inner()),
            Some(Descriptor::Tr(tr)) => origin(tr.internal_key()),
            _ => None,
        };
        let derivation = source
            .and_then(|source| self.account.derivation_of(&source, &address.script_pubkey()))
            .ok_or_else(foreign)?;
        Ok((address, derivation))
    }

    /// A PSBT paying each address its amount, funded from the account's coins with change back to
    /// it at `fee_rate` sat/vB, with the account's key origins on its inputs and change for the
    /// signer to find. `subtract_fee_from` names a payment to take the fee out of instead, as
    /// sweeping the account to one address does.
    pub fn create_psbt(
        &self,
        payments: &[(Address, Amount)],
        fee_rate: f64,
        subtract_fee_from: Option<usize>,
    ) -> Result<Psbt, Error> {
        const METHOD: &str = "walletcreatefundedpsbt";
        // As strings, which the node reads exactly, where a JSON number would be a float.
        let outputs: Vec<Value> = (payments.iter())
            .map(|(address, amount)| {
                let btc = amount.to_string_in(Denomination::Bitcoin);
                Value::Object(Map::from_iter([(address.to_string(), Value::String(btc))]))
            })
            .collect();
        let change_type = self.address_type();
        let mut options =
            json!({ "fee_rate": fee_rate, "replaceable": true, "change_type": change_type });
        if let Some(output) = subtract_fee_from {
            options["subtractFeeFromOutputs"] = json!([output]);
        }
        let reply = self.call(METHOD, json!([[], outputs, 0, options, true]))?;
        let psbt = reply["psbt"].as_str().ok_or_else(|| unexpected(METHOD, &reply))?;
        Ok(Psbt::from_str(psbt)?)
    }

    /// Finalizes a signed PSBT and broadcasts its transaction.
    pub fn broadcast(&self, psbt: &Psbt) -> Result<Txid, Error> {
        let reply = self.node.call("finalizepsbt", json!([psbt.to_string()]))?;
        let (true, Some(hex)) = (reply["complete"] == true, reply["hex"].as_str()) else {
            return Err(Error::Incomplete);
        };
        let reply = self.node.call("sendrawtransaction", json!([hex]))?;
        let txid = reply.as_str().and_then(|txid| Txid::from_str(txid).ok());
        txid.ok_or_else(|| unexpected("sendrawtransaction", &reply))
    }

    /// The account's latest transactions, newest first. The node lists one entry for each
    /// output a transaction moves, and on each of a payment's the whole fee; an entry here sums
    /// a transaction's outputs and counts its fee once.
    pub fn history(&self, count: usize) -> Result<Vec<Entry>, Error> {
        const METHOD: &str = "listtransactions";
        // The node counts entries, not transactions; enough of them for `count` transactions of
        // a payment and its change each.
        let reply = self.call(METHOD, json!(["*", count * 3, 0, true]))?;
        let mut history: Vec<(Entry, bool)> = Vec::new();
        // Oldest first, as the node lists them.
        for item in results_of(&reply) {
            let txid = item["txid"].as_str().and_then(|txid| Txid::from_str(txid).ok());
            let txid = txid.ok_or_else(|| unexpected(METHOD, item))?;
            let amount = signed_amount(METHOD, &item["amount"])?;
            let fee = match &item["fee"] {
                Value::Null => None,
                fee => Some(signed_amount(METHOD, fee)?),
            };
            let index = match history.iter().position(|(entry, _)| entry.txid == txid) {
                Some(index) => index,
                None => {
                    let entry = Entry {
                        txid,
                        amount: SignedAmount::ZERO,
                        confirmations: item["confirmations"].as_i64().unwrap_or_default(),
                        time: item["time"].as_u64().unwrap_or_default(),
                    };
                    history.push((entry, false));
                    history.len() - 1
                }
            };
            let (entry, fee_counted) = &mut history[index];
            entry.amount += amount;
            if let (Some(fee), false) = (fee, *fee_counted) {
                entry.amount += fee;
                *fee_counted = true;
            }
        }
        Ok(history.into_iter().rev().take(count).map(|(entry, _)| entry).collect())
    }

    /// The node's name for the account's addresses, which it hands out only when asked by name:
    /// it defaults to segwit v0's.
    fn address_type(&self) -> &'static str {
        match self.account.kind() {
            Kind::SegwitV0 => "bech32",
            Kind::Taproot => "bech32m",
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        self.call_with_timeout(method, params, Some(TIMEOUT))
    }

    fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Option<u64>,
    ) -> Result<Value, Error> {
        let url = format!("{}/wallet/{}", self.node.url, self.name);
        self.node.call_at(&url, method, params, timeout)
    }
}

/// The key origin of a key in a descriptor the node wrote for one address.
fn origin(key: &DescriptorPublicKey) -> Option<KeySource> {
    match key {
        DescriptorPublicKey::Single(single) => single.origin.clone(),
        _ => None,
    }
}
