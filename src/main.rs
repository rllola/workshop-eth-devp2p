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


    /******************
     *
     *  Create Auth message (EIP8 supported)
     *
     ******************/
    println!("Creating EIP8 Auth message");
    let init_msg =
        utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // send the message
    println!("Sending EIP8 Auth message");
    utils::send_eip8_auth_message(&init_msg, &mut stream);

    loop {


        // if current_height == 0 {
        //     println!("Data fully synced");
        //     break;
        // }

        break;
    }
}
