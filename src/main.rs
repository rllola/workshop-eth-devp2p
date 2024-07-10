use byteorder::{BigEndian, ReadBytesExt};
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::types::{Block, Transaction};

pub mod eth;
pub mod mac;
pub mod message;
pub mod networks;
pub mod types;
pub mod utils;

// max value seems to be 1024 (https://github.com/ethereum/go-ethereum/blob/master/eth/protocols/eth/handler.go#L40)
const BLOCK_NUM: usize = 1024;

fn main() {
    println!("Lets go");

    // Fill the IP here
    let ip = "2a01:e0a:46a:2780:ca1f:66ff:fec3:5924";
    let port = 30304;
    // Fill the remote_id here
    let remote_id = hex::decode("883a7c135a8c9da475423110f48258a4ab8b9c9f88d8a6091bce3502aa88a94d3610e363520af944a07e34357b9d9dc4538803d1af584d98bceab5fdbf32ba08").unwrap();

    let network = networks::Network::find("ethereum_rinkeby").unwrap();

    loop {


        if current_height == 0 {
            println!("Data fully synced");
            break;
        }

        break;
    }
}
