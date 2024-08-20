use crate::types::{CapabilityMessage, CapabilityName, HelloMessage, Transaction, AccessList, Hash};
use arrayvec::ArrayString;
use sha3::{Digest, Keccak256};
use num::BigUint;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use crate::utils;

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

    let mut hasher = Keccak256::new();

    if transaction.is_list() {
        // Transaction legacy

        hasher.update(&transaction.as_raw());
        let txid = hasher.finalize().to_vec();

        let nonce: u32 = transaction.at(0).unwrap().as_val().unwrap();
        // NOTE: there is a transaction in Ropsten where gas_price is bigger than u64
        let gas_price: Vec<u8> = transaction.at(1).unwrap().as_val().unwrap();
        let gas_limit: u64 = transaction.at(2).unwrap().as_val().unwrap();
        let to: Vec<u8> = transaction.at(3).unwrap().as_val().unwrap();
        let value: Vec<u8> = transaction.at(4).unwrap().as_val().unwrap();
        let data: Vec<u8> = transaction.at(5).unwrap().as_val().unwrap();
        let v: u64 = transaction.at(6).unwrap().as_val().unwrap();
        let r: Vec<u8> = transaction.at(7).unwrap().as_val().unwrap();
        let s: Vec<u8> = transaction.at(8).unwrap().as_val().unwrap();

        // Calculate from address
        let mut rlps = rlp::RlpStream::new();
        rlps.begin_unbounded_list();
        for n in 0..=5 {
            rlps.append_raw(transaction.at(n).unwrap().as_raw(), 1);
        }
        if v > 28 {
            // TODO: This is not right...
            let chain_id = v / 2;

            rlps.append(&chain_id);
            rlps.append(&0_u8);
            rlps.append(&0_u8);
        }
        rlps.finalize_unbounded_list();

        let mut hasher = Keccak256::new();
        hasher.update(&rlps.as_raw());
        let digest = hasher.finalize();

        // Get public key here and therefore address
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let recid = match v {
            0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
            27 => RecoveryId::from_i32(0).unwrap(),
            28 => RecoveryId::from_i32(1).unwrap(),
            _ => {
                let v = (v - 35) % 2;
                RecoveryId::from_i32(v as i32).unwrap()
            }
        };
        let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
        let pubkey = sig.recover(&msg).unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize_uncompressed()[1..]);
        let from: Vec<u8> = hasher.finalize()[12..].to_vec();

        return Transaction {
            chain_id: None,
            nonce,
            gas_price: Some(BigUint::from_bytes_be(&gas_price)),
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            gas_limit,
            to,
            value: BigUint::from_bytes_be(&value),
            data,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            v,
            r,
            s,
            txid,
            from,
            tx_type: 0,
        };
    }

    let eip_tx: Vec<u8> = transaction.as_val().unwrap();
    let t = rlp::Rlp::new(&eip_tx[1..]);
    assert!(t.is_list());

    hasher.update(&eip_tx);
    let txid = hasher.finalize().to_vec();

    match eip_tx[0] {
        1 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let gas_price: Vec<u8> = t.at(2).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(3).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(4).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(7).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let v: u64 = t.at(8).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(9).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(10).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=7 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x01u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: Some(BigUint::from_bytes_be(&gas_price)),
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                v,
                r,
                s,
                txid,
                from,
                tx_type: 1,
            }
        }
        2 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let max_priority_fee_per_gas: u64 = t.at(2).unwrap().as_val().unwrap();
            let max_fee_per_gas: u64 = t.at(3).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(4).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(7).unwrap().as_val().unwrap();

            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(8).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let v: u64 = t.at(9).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(10).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(11).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=8 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x02u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: None,
                max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
                max_fee_per_gas: Some(max_fee_per_gas),
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                v,
                r,
                s,
                txid,
                from,
                tx_type: 2,
            }
        }
        3 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let max_priority_fee_per_gas: u64 = t.at(2).unwrap().as_val().unwrap();
            let max_fee_per_gas: u64 = t.at(3).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(4).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(7).unwrap().as_val().unwrap();

            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(8).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let max_fee_per_blob_gas: u64 = t.at(9).unwrap().as_val().unwrap(); // This is UINT256 https://github.com/ethereum/go-ethereum/blob/master/core/types/tx_blob.go#L42 but putting u64 for now. Hoping it doesn't overflow.
            let blob_versioned_hashes: Vec<Hash> = t
                .at(10)
                .unwrap()
                .as_list::<Vec<u8>>()
                .unwrap()
                .iter()
                .map(|h| {
                    // See https://github.com/ethereum/go-ethereum/blob/master/core/types/tx_blob.go#L43
                    // let h = rlp::Rlp::new(&h);
                    // assert!(h.is_list());

                    // let hash: Vec<u8> = h.as_val().unwrap();
                    Hash(h.to_owned())
                })
                .collect();
            let v: u64 = t.at(11).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(12).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(13).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=10 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x03u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: None,
                max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
                max_fee_per_gas: Some(max_fee_per_gas),
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
                blob_versioned_hashes: Some(blob_versioned_hashes),
                v,
                r,
                s,
                txid,
                from,
                tx_type: 3,
            }
        }
        _ => {
            dbg!(hex::encode(&payload));
            todo!("others type not supported yet");
        }
    }
}

pub fn create_hello_message(private_key: &Vec<u8>) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello = HelloMessage {
        protocol_version: BASE_PROTOCOL_VERSION,
        client_version: String::from("Geth/v1.14.5-stable-0dd173a7/linux-amd64/go1.22.2"),
        capabilities: vec![
            //CapabilityMessage{ name: CapabilityName(ArrayString::from("eth").unwrap()), version: 66 },
            // CapabilityMessage {
            //     name: CapabilityName(ArrayString::from("eth").unwrap()),
            //     version: 67,
            // },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 68,
            },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("snap").unwrap()),
                version: 1,
            },
        ],
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
