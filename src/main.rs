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

    // Feel the IP here
    let ip = "184.174.36.104";
    let port = 50303;
    // Feel the remote_id here
    let remote_id = hex::decode("a73c411ac2aa8092b961d934109302548f276916001bb24d36715d8894215b3b2a93d4e00790a6d565334bb4860a3c211d64881e3fde4ed96be77dc86b9f6784").unwrap();

    let network = networks::Network::find("ethereum_sepolia").unwrap();

    /******************
     *
     *  Connect to peer
     *
     ******************/
     let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).unwrap();

     let private_key = SecretKey::new(&mut rand::thread_rng())
         .secret_bytes()
         .to_vec();
     let mut nonce = vec![0; 32];
     rand::thread_rng().fill_bytes(&mut nonce);
     let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
         .secret_bytes()
         .to_vec();
     let pad = vec![0; 100]; // should be generated randomly but we don't really care


    loop {


        // if current_height == 0 {
        //     println!("Data fully synced");
        //     break;
        // }

        break;
    }
}
