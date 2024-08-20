use arrayvec::ArrayString;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use num::BigUint;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<CapabilityMessage>,
    pub port: u16,
    pub id: primitive_types::H512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMessage {
    pub name: CapabilityName,
    pub version: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityName(pub ArrayString<[u8; 4]>);

impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);
        s.append(&self.id);
    }
}

impl Decodable for CapabilityMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

impl Encodable for CapabilityMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl rlp::Decodable for CapabilityName {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self(
            ArrayString::from(
                std::str::from_utf8(rlp.data()?)
                    .map_err(|_| DecoderError::Custom("should be a UTF-8 string"))?,
            )
            .map_err(|_| DecoderError::RlpIsTooBig)?,
        ))
    }
}

impl rlp::Encodable for CapabilityName {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.as_bytes().rlp_append(s);
    }
}

#[derive(Serialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Hash(#[serde(with = "hex::serde")] pub Vec<u8>);

#[derive(Serialize, Clone, Debug)]
pub struct AccessList(pub Vec<(Hash, Vec<Hash>)>);

#[derive(Clone, Debug)]
pub struct Transaction {
    pub chain_id: Option<u64>,
    pub nonce: u32,
    pub gas_price: Option<BigUint>, // Only present in legacy and type1 transactions
    pub max_priority_fee_per_gas: Option<u64>, // Introduce in type 2 transactions
    pub max_fee_per_gas: Option<u64>, // Introduce in type 2 transactions
    pub gas_limit: u64,
    pub to: Vec<u8>,
    pub value: BigUint,
    pub data: Vec<u8>,
    pub access_list: Option<AccessList>, // Introduce in type 2 transactions
    pub max_fee_per_blob_gas: Option<u64>, // Introduce in type 3 transactions
    pub blob_versioned_hashes: Option<Vec<Hash>>, // Introduce in type 3 transactions
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    // extra info deducted from transaction
    pub txid: Vec<u8>,
    pub from: Vec<u8>,
    pub tx_type: u8,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub ommers_hash: Vec<u8>,
    pub coinbase: Vec<u8>,
    pub state_root: Vec<u8>,
    pub txs_root: Vec<u8>,
    pub receipts_root: Vec<u8>,
    pub bloom: Vec<u8>,
    pub difficulty: u64,
    pub number: u32,
    pub gas_limit: u32,
    pub gas_used: u32,
    pub time: u32,
    pub extradata: Vec<u8>,
    pub mix_digest: Vec<u8>,
    pub block_nonce: Vec<u8>,
    pub basefee_per_gas: u64,
    pub withdrawals_root: Vec<u8>,
}