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

    println!("waiting for answer (ACK message)...");
    let (payload, shared_mac_data) = utils::read_ack_message(&mut stream);

    /******************
     *
     *  Handle Ack message
     *
     ******************/

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

    /******************
     *
     *  Send STATUS message
     *
     ******************/

    println!("Sending STATUS message");

    let genesis_hash = network.genesis_hash.to_vec();
    let head_td = 0;
    let fork_id = network.fork_id.to_vec();
    let network_id = network.network_id;

    let status = eth::create_status_message(
        &genesis_hash,
        &genesis_hash,
        &head_td,
        &fork_id,
        &network_id,
    );
    utils::send_message(status, &mut stream, &egress_mac, &egress_aes);

    /******************
     *
     *  Handle STATUS message
     *
     ******************/

    println!("Handling STATUS message");
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
    let mut current_hash = eth::parse_status_message(uncrypted_body[1..].to_vec());

    /****************************
     *
     *  START FETCHING BLOCKS
     *
     ****************************/
    let mut thread_stream = stream.try_clone().unwrap();
    let thread_egress_mac = Arc::clone(&egress_mac);
    let thread_egress_aes = Arc::clone(&egress_aes);

    let (tx, rx) = channel();

    let _handle = thread::spawn(move || {
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body =
                utils::read_message(&mut thread_stream, &mut ingress_mac, &mut ingress_aes);

            // handle RLPx message
            if uncrypted_body[0] < 16 {
                println!("Code {}", uncrypted_body[0]);
                println!("{}", hex::encode(&uncrypted_body));
                code = uncrypted_body[0];

                if code == 2 {
                    // send pong
                    let pong = message::create_pong_message();

                    utils::send_message(
                        pong,
                        &mut thread_stream,
                        &thread_egress_mac,
                        &thread_egress_aes,
                    );
                }
                continue;
            }

            tx.send(uncrypted_body).unwrap();
        }
    });

    loop {
        /******************
         *
         *  Send GetBlockHeaders message
         *
         ******************/

        println!("Sending GetBlockHeaders message");
        let get_blocks_headers =
            eth::create_get_block_headers_message(&current_hash, BLOCK_NUM, 0, true);
        utils::send_message(get_blocks_headers, &mut stream, &egress_mac, &egress_aes);

        /******************
         *
         *  Handle BlockHeader message
         *
         ******************/

        println!("Handling BlockHeaders message");
        let mut uncrypted_body: Vec<u8>;
        let mut code;
        loop {
            uncrypted_body = rx.recv().unwrap();

            code = uncrypted_body[0] - 16;
            if code == 4 {
                break;
            }
        }

        assert_eq!(code, 4);

        let block_headers = eth::parse_block_headers(uncrypted_body[1..].to_vec());

        // update block hash
        current_hash = block_headers.last().unwrap().parenthash.to_vec();

        /******************
         *
         *  Send GetBlockBodies message
         *
         ******************/
        println!("Sending GetBlockBodies message");
        let hashes = block_headers
            .iter()
            .map(|b| b.hash.clone())
            .collect::<Vec<Vec<u8>>>();

        let mut transactions: Vec<Vec<Transaction>> = vec![];

        while transactions.len() < hashes.len() {
            let get_blocks_bodies =
                eth::create_get_block_bodies_message(&hashes[transactions.len()..].to_vec());
            utils::send_message(get_blocks_bodies, &mut stream, &egress_mac, &egress_aes);

            /******************
             *
             *  Handle BlockHeader message
             *
             ******************/

            println!(
                "Handling BlockBodies message ({}/{BLOCK_NUM} blocks received)",
                transactions.len()
            );
            let mut uncrypted_body: Vec<u8>;
            let mut code;
            loop {
                uncrypted_body = rx.recv().unwrap();

                code = uncrypted_body[0] - 16;
                if code == 6 {
                    break;
                }
            }
            assert_eq!(code, 6);

            let tmp_txs = eth::parse_block_bodies(uncrypted_body[1..].to_vec());
            transactions.extend(tmp_txs);
        }

        let mut blocks: Vec<(Block, Vec<Transaction>)> = vec![];
        let t_iter = transactions.iter();
        t_iter.enumerate().for_each(|(i, txs)| {
            blocks.push((block_headers[i].clone(), txs.to_vec()));
        });

        let current_height = blocks.last().unwrap().0.number;
        println!("Blocks n° {}", current_height);

        if current_height == 0 {
            println!("Data fully synced");
            break;
        }
    }
}
