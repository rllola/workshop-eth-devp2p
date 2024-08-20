

pub fn create_get_account_range_message(root_hash: &Vec<u8>, starting_hash: &Vec<u8>, limit_hash: &Vec<u8>) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // req ID
    s.append(&0x42_u8);

    s.append(root_hash);
    s.append(starting_hash);
    s.append(limit_hash);
    s.append(&4000_u32);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + 33];

    dbg!(hex::encode(payload));

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_account_range(payload: Vec<u8>) {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    let _reqid: u64 = r.at(0).unwrap().as_val().unwrap();
    let accounts = r.at(1).unwrap(); 
    // let proof

    assert!(accounts.is_list());

    let count = accounts.item_count().unwrap();

    for i in 0..count {
        let acc = accounts.at(i).unwrap();

        assert!(acc.is_list());
        assert_eq!(acc.item_count().unwrap(), 2);

        let _acc_hash: Vec<u8> = acc.at(0).unwrap().as_val().unwrap();
        let acc_body: Vec<u8> = acc.at(1).unwrap().as_raw().to_vec();
    
        dbg!(hex::encode(acc_body));
    }



    return;
}