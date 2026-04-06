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
    let ip = "65.109.90.251";
    let port = 30303;
    // Fill the remote_id here
    let remote_id = hex::decode("dd9fca568f82e037ffec72c4c1ef59295f2a3dd873cbe1fa166ae7af1d2f93e5bacf63db5c137bfabacece7587461315bc4cebbd23f2a0de4fc7aa1108fdc97e").unwrap();

    let network = networks::Network::find("ethereum_hoodi").unwrap();

    loop {


        // if current_height == 0 {
        //     println!("Data fully synced");
        //     break;
        // }

        break;
    }
}
