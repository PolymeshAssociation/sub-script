use parity_scale_codec::{Compact, Decode, Encode};
use sp_core::{hashing::blake2_256, H256};
use sp_runtime::{
  generic::{self, Era},
  traits, MultiSignature,
};

use serde::{Deserialize, Serialize};

use rhai::serde::from_dynamic;
use rhai::{Dynamic, Engine, EvalAltResult, Map as RMap, INT};

use crate::metadata::EncodedCall;
use crate::types::TypeRef;
use crate::users::AccountId;

pub type TxHash = H256;
pub type BlockHash = H256;

pub fn hash_from_dynamic(val: Dynamic) -> Option<BlockHash> {
  if val.is::<BlockHash>() {
    val.try_cast::<BlockHash>()
  } else {
    from_dynamic(&val).ok()
  }
}

// Re-impl MultiAddress to support serde
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "polymesh_v2"), derive(Encode, Decode))]
pub enum MultiAddress<AccountId, AccountIndex> {
  /// It's an account ID (pubkey).
  Id(AccountId),
  /// It's an account index.
  Index(#[cfg_attr(not(feature = "polymesh_v2"), codec(compact))] AccountIndex),
  /// It's some arbitrary raw bytes.
  Raw(Vec<u8>),
  /// It's a 32 byte representation.
  Address32([u8; 32]),
  /// Its a 20 byte representation.
  Address20([u8; 20]),
}

#[cfg(feature = "polymesh_v2")]
impl<AccountId: Encode, AccountIndex> Encode for MultiAddress<AccountId, AccountIndex> {
  fn encode(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32);
    match self {
      MultiAddress::Id(id) => {
        buf.push(0xff);
        id.encode_to(&mut buf);
      }
      _ => {
        unimplemented!("Index accounts are not supported.");
      }
    }
    buf
  }
}

#[cfg(feature = "polymesh_v2")]
impl<AccountId: Decode, AccountIndex> Decode for MultiAddress<AccountId, AccountIndex> {
  fn decode<I: parity_scale_codec::Input>(
    input: &mut I,
  ) -> Result<Self, parity_scale_codec::Error> {
    if input.read_byte()? == 0xff {
      Ok(Self::Id(AccountId::decode(input)?))
    } else {
      unimplemented!("Index accounts are not supported.");
    }
  }
}

impl<AccountId: Clone, AccountIndex> From<&AccountId> for MultiAddress<AccountId, AccountIndex> {
  fn from(other: &AccountId) -> Self {
    Self::Id(other.clone())
  }
}

impl<AccountId, AccountIndex> From<AccountId> for MultiAddress<AccountId, AccountIndex> {
  fn from(other: AccountId) -> Self {
    Self::Id(other)
  }
}

impl<AccountId, AccountIndex> From<sp_runtime::MultiAddress<AccountId, AccountIndex>>
  for MultiAddress<AccountId, AccountIndex>
{
  fn from(other: sp_runtime::MultiAddress<AccountId, AccountIndex>) -> Self {
    match other {
      sp_runtime::MultiAddress::Id(v) => Self::Id(v),
      sp_runtime::MultiAddress::Index(v) => Self::Index(v),
      sp_runtime::MultiAddress::Raw(v) => Self::Raw(v),
      sp_runtime::MultiAddress::Address32(v) => Self::Address32(v),
      sp_runtime::MultiAddress::Address20(v) => Self::Address20(v),
    }
  }
}

impl<AccountId: Clone, AccountIndex: Clone> From<&sp_runtime::MultiAddress<AccountId, AccountIndex>>
  for MultiAddress<AccountId, AccountIndex>
{
  fn from(other: &sp_runtime::MultiAddress<AccountId, AccountIndex>) -> Self {
    Self::from(other.clone())
  }
}

pub type GenericAddress = MultiAddress<AccountId, ()>;

pub type AdditionalSigned = (u32, u32, BlockHash, BlockHash, (), (), ());

#[derive(Clone, Debug, Encode, Decode)]
pub struct Extra(Era, Compact<u32>, Compact<u128>);

impl Extra {
  pub fn new(era: Era, nonce: u32) -> Self {
    Self(era, nonce.into(), 0u128.into())
  }

  pub fn nonce(&self) -> u32 {
    self.1.into()
  }

  pub fn tip(&self) -> u128 {
    self.2.into()
  }
}

pub struct SignedPayload<'a>((&'a EncodedCall, &'a Extra, AdditionalSigned));

impl<'a> SignedPayload<'a> {
  pub fn new(call: &'a EncodedCall, extra: &'a Extra, additional: AdditionalSigned) -> Self {
    Self((call, extra, additional))
  }
}

impl<'a> Encode for SignedPayload<'a> {
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    self.0.using_encoded(|payload| {
      if payload.len() > 256 {
        f(&blake2_256(payload)[..])
      } else {
        f(payload)
      }
    })
  }
}

/// Current version of the `UncheckedExtrinsic` format.
pub const EXTRINSIC_VERSION: u8 = 4;

#[derive(Clone, Debug)]
pub struct ExtrinsicDetails {
  signature: Option<(GenericAddress, MultiSignature, Extra)>,
  xt: Vec<u8>,
  call: Dynamic,
}

impl ExtrinsicDetails {
  pub fn is_signed(&mut self) -> bool {
    self.signature.is_some()
  }

  pub fn signed_by(&mut self) -> Dynamic {
    match &self.signature {
      Some((MultiAddress::Id(addr), _, _)) => {
        let raw: &[u8] = addr.as_ref();
        Dynamic::from(hex::encode(raw))
      }
      _ => Dynamic::UNIT,
    }
  }

  pub fn nonce(&mut self) -> Dynamic {
    match &self.signature {
      Some((_, _, extra)) => Dynamic::from(extra.nonce() as INT),
      _ => Dynamic::UNIT,
    }
  }

  pub fn len(&mut self) -> i64 {
    let len: Compact<u32> = Decode::decode(&mut &self.xt[..]).unwrap_or(0.into());
    len.0 as i64
  }

  pub fn hash(&mut self) -> String {
    let hash = blake2_256(self.xt.as_slice());
    hex::encode(hash)
  }

  pub fn call(&mut self) -> Dynamic {
    self.call.clone()
  }

  pub fn to_string(&mut self) -> String {
    format!("{:?}", self)
  }
}

#[derive(Clone)]
pub struct ExtrinsicV4 {
  pub signature: Option<(GenericAddress, MultiSignature, Extra)>,
  pub call: EncodedCall,
}

impl ExtrinsicV4 {
  pub fn signed(account: AccountId, sig: MultiSignature, extra: Extra, call: EncodedCall) -> Self {
    Self {
      signature: Some((GenericAddress::from(account), sig, extra)),
      call,
    }
  }

  pub fn unsigned(call: EncodedCall) -> Self {
    Self {
      signature: None,
      call,
    }
  }

  pub fn to_hex(&self) -> String {
    let mut hex = hex::encode(self.encode());
    hex.insert_str(0, "0x");
    hex
  }

  pub fn decode_call(call_ty: &TypeRef, xt: &mut &[u8]) -> Result<Dynamic, Box<EvalAltResult>> {
    let full_xt = xt.to_vec();
    // Decode Vec length.
    let _len: Compact<u32> = Decode::decode(xt).map_err(|e| e.to_string())?;
    // Version and signed flag.
    let version: u8 = Decode::decode(xt).map_err(|e| e.to_string())?;
    let is_signed = version & 0b1000_0000 != 0;
    if (version & 0b0111_1111) != EXTRINSIC_VERSION {
      Err("Invalid EXTRINSIC_VERSION")?;
    }

    let signature = if is_signed {
      let sig: (GenericAddress, MultiSignature, Extra) =
        Decode::decode(xt).map_err(|e| e.to_string())?;
      Some(sig)
    } else {
      None
    };

    Ok(Dynamic::from(ExtrinsicDetails {
      signature,
      xt: full_xt,
      call: call_ty.decode(xt.to_vec())?,
    }))
  }
}

impl Encode for ExtrinsicV4 {
  fn encode(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // 1 byte version id and signature if signed.
    match &self.signature {
      Some(sig) => {
        buf.push(EXTRINSIC_VERSION | 0b1000_0000);
        sig.encode_to(&mut buf);
      }
      None => {
        buf.push(EXTRINSIC_VERSION & 0b0111_1111);
      }
    }
    self.call.encode_to(&mut buf);

    buf.encode()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccountInfo {
  pub nonce: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionStatus {
  Future,
  Ready,
  Broadcast(Vec<String>),
  InBlock(BlockHash),
  Retracted(BlockHash),
  FinalityTimeout(BlockHash),
  Finalized(BlockHash),
  Usurped(TxHash),
  Dropped,
  Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBlock {
  pub block: Block,
  // Ignore justifications field.
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
  extrinsics: Vec<String>,
  header: generic::Header<u32, traits::BlakeTwo256>,
  #[serde(skip)]
  pub call_ty: Option<TypeRef>,
}

impl Block {
  pub fn find_extrinsic(&self, xthex: &str) -> Option<usize> {
    self.extrinsics.iter().position(|xt| xt == xthex)
  }

  fn decode_xthex(&self, xthex: &String) -> Option<Dynamic> {
    self.call_ty.as_ref().map_or_else(
      || Some(Dynamic::from(xthex.clone())),
      |call_ty| {
        if xthex.starts_with("0x") {
          hex::decode(&xthex[2..])
            .ok()
            .map(|xt| {
              ExtrinsicV4::decode_call(call_ty, &mut &xt[..])
                .map_err(|e| eprintln!("Call decode failed: {:?}", e))
                .ok()
            })
            .flatten()
        } else {
          None
        }
      },
    )
  }

  pub fn extrinsics(&mut self) -> Dynamic {
    Dynamic::from(
      self
        .extrinsics
        .iter()
        .filter_map(|xthex| self.decode_xthex(xthex))
        .collect::<Vec<_>>(),
    )
  }

  pub fn extrinsics_filtered(&mut self, xthex_partial: &str) -> Dynamic {
    Dynamic::from(
      self
        .extrinsics
        .iter()
        .filter_map(|xthex| {
          if xthex.contains(xthex_partial) {
            self.decode_xthex(xthex)
          } else {
            None
          }
        })
        .collect::<Vec<_>>(),
    )
  }

  pub fn parent(&mut self) -> BlockHash {
    self.header.parent_hash
  }

  pub fn state_root(&mut self) -> BlockHash {
    self.header.state_root
  }

  pub fn extrinsics_root(&mut self) -> BlockHash {
    self.header.extrinsics_root
  }

  pub fn block_number(&mut self) -> i64 {
    self.header.number as i64
  }

  pub fn to_string(&mut self) -> String {
    format!("{:?}", self)
  }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Phase {
  ApplyExtrinsic(u32),
  Finalization,
  Initialization,
}

#[derive(Clone, Debug)]
pub struct EventRecord {
  pub phase: Phase,
  pub name: String,
  pub args: Dynamic,
  pub topics: Vec<BlockHash>,
}

impl EventRecord {
  pub fn name(&mut self) -> String {
    self.name.clone()
  }

  pub fn args(&mut self) -> Dynamic {
    self.args.clone()
  }

  pub fn to_string(&mut self) -> String {
    format!("{:#?}", self)
  }

  pub fn from_dynamic(val: Dynamic) -> Result<Self, Box<EvalAltResult>> {
    let mut map = val.try_cast::<RMap>().ok_or("Expected Map")?;

    // Decod event name and args from two nested maps,
    // should only have one item in each map.
    let event = map
      .remove("event")
      .ok_or("Missing field 'event'")?
      .try_cast::<RMap>()
      .ok_or("Expected Map")?;
    let (name, args) = match event.into_iter().next() {
      Some((mod_name, map2)) => {
        let map2 = map2.try_cast::<RMap>().ok_or("Expected Map")?;
        match map2.into_iter().next() {
          Some((name, args)) => (format!("{}.{}", mod_name, name), args),
          None => (format!("{}", mod_name), Dynamic::UNIT),
        }
      }
      None => ("()".into(), Dynamic::UNIT),
    };

    Ok(Self {
      phase: from_dynamic(map.get("phase").ok_or("Missing field 'phase'")?)?,
      name,
      args,
      topics: from_dynamic(map.get("topics").ok_or("Missing field 'topics'")?)?,
    })
  }
}

#[derive(Clone, Debug, Default)]
pub struct EventRecords(Vec<EventRecord>);

impl EventRecords {
  pub fn filter(&mut self, phase: Phase) {
    self.0.retain(|ev| ev.phase == phase);
  }

  pub fn prefix_filtered(&self, prefix: &str) -> Vec<Dynamic> {
    self
      .0
      .iter()
      .filter(|ev| ev.name.starts_with(prefix))
      .cloned()
      .map(|ev| Dynamic::from(ev))
      .collect::<Vec<_>>()
  }

  pub fn to_string(&mut self) -> String {
    format!("{:#?}", self.0)
  }

  pub fn from_dynamic(val: Dynamic) -> Result<Self, Box<EvalAltResult>> {
    let arr = val.try_cast::<Vec<Dynamic>>().ok_or("Expected Array")?;
    Ok(Self(
      arr
        .into_iter()
        .map(EventRecord::from_dynamic)
        .collect::<Result<Vec<EventRecord>, _>>()?,
    ))
  }
}

pub fn init_engine(engine: &mut Engine) -> Result<(), Box<EvalAltResult>> {
  engine
    .register_type_with_name::<BlockHash>("BlockHash")
    .register_fn("to_string", |hash: &mut BlockHash| hash.to_string())
    .register_fn("to_debug", |hash: &mut BlockHash| format!("{:?}", hash))
    .register_type_with_name::<Block>("Block")
    .register_get("extrinsics", Block::extrinsics)
    .register_fn("extrinsics_filtered", Block::extrinsics_filtered)
    .register_get("parent", Block::parent)
    .register_get("state_root", Block::state_root)
    .register_get("extrinsics_root", Block::extrinsics_root)
    .register_get("block_number", Block::block_number)
    .register_fn("to_string", Block::to_string)
    .register_type_with_name::<ExtrinsicDetails>("ExtrinsicDetails")
    .register_get("is_signed", ExtrinsicDetails::is_signed)
    .register_get("signed_by", ExtrinsicDetails::signed_by)
    .register_get("nonce", ExtrinsicDetails::nonce)
    .register_get("len", ExtrinsicDetails::len)
    .register_get("hash", ExtrinsicDetails::hash)
    .register_get("decoded_call", ExtrinsicDetails::call)
    .register_fn("to_string", ExtrinsicDetails::to_string)
    .register_type_with_name::<EventRecords>("EventRecords")
    .register_fn("to_string", EventRecords::to_string)
    .register_type_with_name::<EventRecord>("EventRecord")
    .register_get("name", EventRecord::name)
    .register_get("args", EventRecord::args)
    .register_fn("to_string", EventRecord::to_string);

  Ok(())
}
