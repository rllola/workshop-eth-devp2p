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

    /******************
     *
     *  Create HELLO
     *
     ******************/

    println!("Sending HELLO message");
    let hello = message::create_hello_message(&private_key);
    utils::send_message(hello, &mut stream, &egress_mac, &egress_aes);


    loop {


        // if current_height == 0 {
        //     println!("Data fully synced");
        //     break;
        // }

        break;
    }
}
