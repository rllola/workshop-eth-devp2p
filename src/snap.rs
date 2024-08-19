

pub fn create_get_account_range_message(root_hash: &Vec<u8>, starting_hash: &Vec<u8>, limit_hash: &Vec<u8>) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // req ID
    s.append(&0x42_u8);

    s.append(root_hash);
    s.append(starting_hash);
    s.append(limit_hash);
    s.append(&10000_u32);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + 32];

    dbg!(hex::encode(payload));

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}
