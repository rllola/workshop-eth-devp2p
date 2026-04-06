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

    /******************
     *
     *  Handle Ack message
     *
     ******************/

    println!("waiting for answer (ACK message)...");
    let (payload, shared_mac_data) = utils::read_ack_message(&mut stream);

    println!("Received Ack");
    let (_remote_public_key, remote_nonce, ephemeral_shared_secret) = utils::handle_ack_message(&payload, &shared_mac_data, &private_key, &ephemeral_privkey);

    /******************
     *
     *  Setup Frame
     *
     ******************/

    println!("Setup frame for sending and reading message");
    let remote_data = [shared_mac_data, payload].concat();
    let (mut ingress_aes, mut ingress_mac, egress_aes, egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
    );

    let egress_aes = Arc::new(Mutex::new(egress_aes));
    let egress_mac = Arc::new(Mutex::new(egress_mac));

    println!("Frame setup done !");

    /******************
     *
     *  Handle HELLO
     *
     ******************/

    println!("Waiting for HELLO message...");
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]).unwrap();

    dbg!(&payload);

    loop {


        // if current_height == 0 {
        //     println!("Data fully synced");
        //     break;
        // }

        break;
    }
}
