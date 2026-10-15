//! A Bitcoin Core (or Knots) node on regtest for tests: the `bitcoind` the BITCOIND environment
//! variable names, in a directory and on a port of its own, stopped and removed when dropped.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use wallet_core::bitcoin::Address;

use crate::{Auth, Node};

pub struct Regtest {
    bitcoind: Child,
    dir: PathBuf,
    pub port: u16,
    pub node: Node,
}

impl Regtest {
    /// Starts a node and waits for its RPC server. `name` keeps apart the directories of tests
    /// that run at once.
    pub fn start(name: &str) -> Regtest {
        let bitcoind = std::env::var("BITCOIND").expect("BITCOIND names a bitcoind to run");
        let dir = std::env::temp_dir().join(format!("wallet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let bitcoind = Command::new(bitcoind)
            .arg("-regtest")
            .arg(format!("-datadir={}", dir.display()))
            .arg(format!("-rpcport={port}"))
            .args(["-listen=0", "-printtoconsole=0"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let url = format!("http://127.0.0.1:{port}");
        let node = Node::new(url, Auth::Cookie(dir.join("regtest/.cookie")));
        let regtest = Regtest { bitcoind, dir, port, node };
        let start = Instant::now();
        while regtest.node.network().is_err() {
            assert!(start.elapsed() < Duration::from_secs(30), "bitcoind did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        regtest
    }

    pub fn mine(&self, blocks: u32, to: &Address) {
        self.node.call("generatetoaddress", json!([blocks, to.to_string()])).unwrap();
    }
}

impl Drop for Regtest {
    fn drop(&mut self) {
        let _ = self.node.call("stop", json!([]));
        let start = Instant::now();
        while !matches!(self.bitcoind.try_wait(), Ok(Some(_))) {
            if start.elapsed() > Duration::from_secs(10) {
                let _ = self.bitcoind.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
