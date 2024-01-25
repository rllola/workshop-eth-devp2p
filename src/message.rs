use crate::types::{CapabilityMessage, CapabilityName, HelloMessage, Transaction};
use arrayvec::ArrayString;
use sha3::{Digest, Keccak256};

const BASE_PROTOCOL_VERSION: usize = 5;

pub fn create_pong_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x03];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_transaction(payload: Vec<u8>) -> Transaction {
    let transaction = rlp::Rlp::new(&payload);

    if !transaction.is_list() {
        let eip_tx: Vec<u8> = transaction.as_val().unwrap();

        match eip_tx[0] {
            1 => {
                let t = rlp::Rlp::new(&eip_tx[1..]);
                assert!(t.is_list());

                // let chain_id: u32 = t.at(0).unwrap().as_val().unwrap();
                let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
                let gas_price: u64 = t.at(2).unwrap().as_val().unwrap();
                let gas_limit: u64 = t.at(3).unwrap().as_val().unwrap();
                let to: Vec<u8> = t.at(4).unwrap().as_val().unwrap();
                let value: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
                let data: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
                let v: u32 = t.at(8).unwrap().as_val().unwrap();
                let r: Vec<u8> = t.at(9).unwrap().as_val().unwrap();
                let s: Vec<u8> = t.at(10).unwrap().as_val().unwrap();

                let mut hasher = Keccak256::new();
                hasher.update(&eip_tx);

                return Transaction {
                    txid: hasher.finalize().to_vec(),
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    value,
                    data,
                    v,
                    r,
                    s,
                    raw: eip_tx,
                };
            }
            2 => {
                let t = rlp::Rlp::new(&eip_tx[1..]);
                assert!(t.is_list());

                // let chain_id: u32 = t.at(0).unwrap().as_val().unwrap();
                let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
                // let max_priority_fee_per_gas: u64 = t.at(2).unwrap().as_val().unwrap();
                // let max_fee_per_gas: u64 = t.at(3).unwrap().as_val().unwrap();
                let gas_limit: u64 = t.at(4).unwrap().as_val().unwrap();
                let to: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
                let value: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
                let data: Vec<u8> = t.at(7).unwrap().as_val().unwrap();
                let v: u32 = t.at(9).unwrap().as_val().unwrap();
                let r: Vec<u8> = t.at(10).unwrap().as_val().unwrap();
                let s: Vec<u8> = t.at(11).unwrap().as_val().unwrap();

                let mut hasher = Keccak256::new();
                hasher.update(&eip_tx);

                return Transaction {
                    txid: hasher.finalize().to_vec(),
                    nonce,
                    // we don't have gas_price but max_fee_per_gas and max_priority_fee_per_gas instead...
                    gas_price: 0,
                    gas_limit,
                    to,
                    value,
                    data,
                    v,
                    r,
                    s,
                    raw: eip_tx,
                };
            }
            _ => {
                dbg!(hex::encode(&payload));
                todo!("others type not supported yet");
            }
        }
    }

    let nonce: u32 = transaction.at(0).unwrap().as_val().unwrap();
    let gas_price: u64 = transaction.at(1).unwrap().as_val().unwrap();
    let gas_limit: u64 = transaction.at(2).unwrap().as_val().unwrap();
    let to: Vec<u8> = transaction.at(3).unwrap().as_val().unwrap();
    let value: Vec<u8> = transaction.at(4).unwrap().as_val().unwrap();
    let data: Vec<u8> = transaction.at(5).unwrap().as_val().unwrap();
    let v: u32 = transaction.at(6).unwrap().as_val().unwrap();
    let r: Vec<u8> = transaction.at(7).unwrap().as_val().unwrap();
    let s: Vec<u8> = transaction.at(8).unwrap().as_val().unwrap();

    let mut hasher = Keccak256::new();
    hasher.update(&transaction.as_raw());

    Transaction {
        txid: hasher.finalize().to_vec(),
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        v,
        r,
        s,
        raw: vec![],
    }
}

pub fn create_hello_message(private_key: &Vec<u8>) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello = HelloMessage {
        protocol_version: BASE_PROTOCOL_VERSION,
        client_version: String::from("deadbrain corp."),
        capabilities: vec![
            //CapabilityMessage{ name: CapabilityName(ArrayString::from("eth").unwrap()), version: 66 },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 67,
            },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 68,
            },
        ],
        // capabilities: vec![types::CapabilityMessage{ name: types::CapabilityName(ArrayString::from("les").unwrap()), version: 4 }],
        port: 0,
        id: primitive_types::H512::from_slice(
            &secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
                [1..],
        ),
    };

    let payload = rlp::encode(&hello);
    let code: Vec<u8> = vec![0x80];
    // Add HELLO code in front
    let message = [code.to_vec(), payload.to_vec()].concat();

    return message;
}
