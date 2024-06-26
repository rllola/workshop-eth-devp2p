use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::ByteOrder;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use hmac_sha256::{Hash, HMAC};
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Keccak256};
use std::borrow::BorrowMut;
use std::io::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::mac;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;
const READ_MESSAGE_TIME_MS: u64 = 1;

pub fn ecdh_x(pubkey: &Vec<u8>, privkey: &Vec<u8>) -> Vec<u8> {
    let sk = k256::ecdsa::SigningKey::from_slice(privkey).unwrap();
    let pk = k256::PublicKey::from_sec1_bytes(pubkey).unwrap();
    let shared_secret =
        k256::elliptic_curve::ecdh::diffie_hellman(sk.as_nonzero_scalar(), pk.as_affine());

    shared_secret.raw_secret_bytes().to_vec()
}

pub fn concat_kdf(key_material: Vec<u8>, key_length: usize) -> Vec<u8> {
    const SHA256_BLOCK_SIZE: usize = 64;
    let reps = ((key_length + 7) * 8) / (SHA256_BLOCK_SIZE * 8);
    let mut counter = 0;

    let mut buffers: Vec<Vec<u8>> = vec![];

    while counter <= reps {
        counter += 1;
        let mut tmp: Vec<u8> = vec![];
        let _ = tmp.write_u32::<BigEndian>(counter as u32);
        let mut hash = Hash::new();
        hash.update(tmp);
        hash.update(&key_material);
        buffers.push(hash.finalize().into());
    }

    let mut result: Vec<u8> = vec![];
    buffers.iter().for_each(|x| result.extend(x));

    return result[0..key_length].to_vec();
}

pub fn encrypt_message(
    remote_public: &Vec<u8>,
    mut data: Vec<u8>,
    shared_mac_data: &Vec<u8>,
) -> Vec<u8> {
    let privkey = k256::SecretKey::random(&mut OsRng);
    let x = ecdh_x(remote_public, &privkey.to_bytes().to_vec());
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // encrypt
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let mut cipher = Aes128Ctr64BE::new(e_key.into(), &iv.into());
    cipher.apply_keystream(&mut data);

    let mut data_iv: Vec<u8> = vec![];
    data_iv.extend(iv);
    data_iv.extend(data);

    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let tag = HMAC::mac(input, m_key);

    let public_key = privkey.public_key();
    let vkey = k256::ecdsa::VerifyingKey::from(public_key);
    let uncompressed_pubkey_bytes = vkey.to_encoded_point(false).to_bytes();

    let mut result: Vec<u8> = vec![];

    result.extend(uncompressed_pubkey_bytes.to_vec());
    result.extend(data_iv);
    result.extend(tag);

    return result;
}

pub fn decrypt_message(
    payload: &Vec<u8>,
    shared_mac_data: &Vec<u8>,
    private_key: &Vec<u8>,
) -> Vec<u8> {
    assert_eq!(payload[0], 0x04);

    let public_key = payload[0..65].to_vec();
    let data_iv = payload[65..(payload.len() - 32)].to_vec();
    let tag = payload[(payload.len() - 32)..].to_vec();

    // derive keys
    let x = ecdh_x(&public_key, private_key);
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // check the tag
    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let _tag = HMAC::mac(input, m_key).to_vec();

    assert_eq!(_tag, tag);

    // decrypt data
    let iv = &data_iv[0..16];
    let mut encrypted_data = data_iv[16..].to_vec();
    let mut decipher = Aes128Ctr64BE::new(e_key.into(), iv.into());
    // decipher encrypted_data and return result in encrypted_data variable
    decipher.apply_keystream(&mut encrypted_data);

    return encrypted_data;
}

pub fn create_auth_eip8(
    remote_id: &Vec<u8>,
    private_key: &Vec<u8>,
    nonce: &Vec<u8>,
    ephemeral_privkey: &Vec<u8>,
    pad: &Vec<u8>,
) -> Vec<u8> {
    let mut auth_message: Vec<u8> = vec![];
    // Add 04 to the remote ID to get the remote public key
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    // ECDH stuff
    let shared_secret = ecdh_x(&remote_public_key, &private_key);

    // XOR pubkey and nonce
    let msg_hash: Vec<u8> = shared_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    // sign message
    let ephemeral_signing_key = secp256k1::SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let (recid, sig) = secp256k1::SECP256K1
        .sign_ecdsa_recoverable(
            &secp256k1::Message::from_slice(&msg_hash).unwrap(),
            &ephemeral_signing_key,
        )
        .serialize_compact();

    // convert to RSV
    let mut rsv_sig = sig.to_vec();

    // adding signing id
    rsv_sig.push(recid.to_i32() as u8);

    // Initialize array with empty vectors
    let sk = k256::ecdsa::SigningKey::from_slice(&private_key).unwrap();
    let vkey = sk.verifying_key();
    let uncompressed_pubkey_bytes = vkey.to_encoded_point(false).to_bytes();

    let data = vec![
        rsv_sig,
        uncompressed_pubkey_bytes[1..].to_vec(),
        nonce.to_vec(),
        vec![0x04],
    ];

    // Encoded RLP data
    let encoded_data = rlp::encode_list::<Vec<u8>, _>(&data);

    // Concat padding to the encoded data
    auth_message.extend(encoded_data.to_vec());
    auth_message.extend(pad);

    let overhead_length = 113;
    let mut shared_mac_data: Vec<u8> = vec![];
    let _ = shared_mac_data.write_u16::<BigEndian>((auth_message.len() + overhead_length) as u16);

    // Encrypt message
    let enrcyped_auth_message = encrypt_message(&remote_public_key, auth_message, &shared_mac_data);

    let init_msg = [shared_mac_data, enrcyped_auth_message].concat();

    return init_msg;
}

pub fn setup_frame(
    remote_nonce: Vec<u8>,
    nonce: Vec<u8>,
    ephemeral_shared_secret: Vec<u8>,
    remote_data: Vec<u8>,
    init_msg: Vec<u8>,
) -> (Aes256Ctr64BE, mac::MAC, Aes256Ctr64BE, mac::MAC) {
    let nonce_material = [remote_nonce.clone(), nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize();

    let iv = [0u8; 16];
    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(h_nonce);
    let shared_secret = hasher.finalize();

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(shared_secret);
    let aes_secret = hasher.finalize();

    let ingress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());
    let egress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(aes_secret);
    let mac_secret = hasher.finalize();

    // The MAC thingy is actually keccak256

    // let remote_data = [shared_mac_data, &payload].concat();

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut ingress_mac = mac::MAC::new(mac_secret.to_vec());
    ingress_mac.update(&[xor_result, remote_data].concat());

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(remote_nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut egress_mac = mac::MAC::new(mac_secret.to_vec());
    egress_mac.update(&[xor_result, init_msg].concat());

    return (ingress_aes, ingress_mac, egress_aes, egress_mac);
}

// NOTE: could be [u8; 32]
pub fn parse_header(
    data: &Vec<u8>,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> usize {
    let mut header = data[0..16].to_vec();
    let mac = &data[16..32];

    ingress_mac.update_header(&mut header);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut header);
    let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3).unwrap()).unwrap();
    return body_size;
}

pub fn parse_body(
    data: &Vec<u8>,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
    body_size: usize,
) -> Vec<u8> {
    let mut body = data[0..data.len() - 16].to_vec();
    let mac = &data[data.len() - 16..];

    /* Something about mac that we are missing */
    ingress_mac.update_body(&mut body);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut body);

    return body[0..body_size].to_vec();
}

pub fn get_body_len(size: usize) -> usize {
    (if size % 16 == 0 {
        size
    } else {
        (size / 16 + 1) * 16
    }) + 16
}

pub fn create_header(
    length: usize,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let mut buf = [0; 8];
    BigEndian::write_uint(&mut buf, length as u64, 3);
    let mut header = [0_u8; 16];
    header[0..3].copy_from_slice(&buf[0..3]);

    egress_aes.apply_keystream(&mut header);
    egress_mac.update_header(&mut header.to_vec());

    let tag = egress_mac.digest();

    return [header.to_vec(), tag].concat().to_vec();
}

pub fn create_body(
    body: Vec<u8>,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let body_len = get_body_len(body.len()) - 16;

    let mut body_message = vec![0; body_len];
    body_message[..body.len()].clone_from_slice(&body);

    egress_aes.apply_keystream(&mut body_message);
    egress_mac.update_body(&mut body_message.to_vec());
    let tag = egress_mac.digest();

    return [body_message.to_vec(), tag].concat().to_vec();
}

pub fn send_eip8_auth_message(
    msg: &Vec<u8>,
    stream: &mut std::net::TcpStream,
) {
    stream.write(&msg).unwrap();
    stream.flush().unwrap();
}

pub fn read_ack_message(
    stream: &mut std::net::TcpStream
) -> (Vec<u8>, Vec<u8>) {
    let mut buf = [0u8; 2];
    let _size = stream.read(&mut buf);

    let size_expected = buf.as_slice().read_u16::<BigEndian>().unwrap() as usize;
    let shared_mac_data = &buf[0..2];

    let mut payload = vec![0u8; size_expected.into()];
    let size = stream.read(&mut payload).unwrap();

    assert_eq!(size, size_expected);

    return (payload, shared_mac_data.to_vec());
}

pub fn handle_ack_message(
    payload: &Vec<u8>,
    shared_mac_data: &Vec<u8>,
    private_key: &Vec<u8>,
    ephemeral_privkey: &Vec<u8>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let decrypted = decrypt_message(payload, shared_mac_data, private_key);

    // decode RPL data
    let rlp = rlp::Rlp::new(&decrypted);
    let mut rlp = rlp.into_iter();

    // id to pubkey
    let remote_public_key: Vec<u8> = [vec![0x04], rlp.next().unwrap().as_val().unwrap()].concat();
    let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();

    let ephemeral_shared_secret = ecdh_x(&remote_public_key, ephemeral_privkey);

    return (remote_public_key, remote_nonce, ephemeral_shared_secret);
}

pub fn send_message(
    msg: Vec<u8>,
    stream: &mut std::net::TcpStream,
    egress_mac: &Arc<Mutex<mac::MAC>>,
    egress_aes: &Arc<Mutex<Aes256Ctr64BE>>,
) {
    let mut egress_aes = egress_aes.lock().unwrap();
    let mut egress_mac = egress_mac.lock().unwrap();

    let header = create_header(msg.len(), egress_mac.borrow_mut(), egress_aes.borrow_mut());

    stream.write(&header).unwrap();
    stream.flush().unwrap();

    let body = create_body(msg, egress_mac.borrow_mut(), egress_aes.borrow_mut());

    stream.write(&body).unwrap();
    stream.flush().unwrap();

    drop(egress_aes);
    drop(egress_mac);
}

pub fn read_message(
    stream: &mut std::net::TcpStream,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let mut buf = [0u8; 32];
    let mut size = stream.read(&mut buf).unwrap();

    while size == 0 {
        thread::sleep(Duration::from_millis(READ_MESSAGE_TIME_MS));
        size = stream.read(&mut buf).unwrap();
    }

    assert_eq!(size, 32);

    let next_size = parse_header(&buf.to_vec(), ingress_mac, ingress_aes);

    // Message payload
    let mut body: Vec<u8> = vec![];
    let body_size = get_body_len(next_size);

    // we have this loop to be sure we have received the complete payload
    while body.len() < body_size {
        let mut buf: Vec<u8> = vec![0; body_size - body.len()];
        let l = stream.read(&mut buf).unwrap();

        body.extend(&buf[0..l]);
        thread::sleep(Duration::from_millis(READ_MESSAGE_TIME_MS));
    }

    assert_eq!(body.len(), body_size);

    let uncrypted_body = parse_body(&body, ingress_mac, ingress_aes, next_size);

    return uncrypted_body;
}
