use std::any::TypeId;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

use parity_scale_codec::{Compact, Decode, Encode};
use sp_core::{
  crypto::{set_default_ss58_version, Ss58AddressFormat},
  storage::{StorageData, StorageKey},
  Pair,
};
use sp_runtime::generic::Era;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dashmap::DashMap;

use rust_decimal::{prelude::{ToPrimitive, FromPrimitive}, Decimal};

use rhai::serde::{from_dynamic, to_dynamic};
use rhai::{Dynamic, Engine, EvalAltResult, INT};

pub use crate::block::*;
use crate::metadata::{EncodedCall, Metadata};
use crate::rpc::*;
use crate::types::{TypeLookup, TypeRef, TypesRegistry};
use crate::users::{AccountId, User};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeVersion {
  pub spec_name: String,
  pub impl_name: String,
  pub authoring_version: u32,
  pub spec_version: u32,
  pub impl_version: u32,
  #[serde(default)]
  pub transaction_version: u32,

  #[serde(flatten)]
  pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainProperties {
  #[serde(default)]
  pub ss58_format: u16,
  pub token_decimals: u32,
  pub token_symbol: String,
}

pub struct InnerClient {
  rpc: RpcHandler,
  runtime_version: RuntimeVersion,
  genesis_hash: BlockHash,
  metadata: Metadata,
  event_records: TypeRef,
  account_info: TypeRef,
  call_ty: TypeRef,
  cached_blocks: DashMap<BlockHash, Block>,
  cached_events: DashMap<BlockHash, Dynamic>,
}

impl InnerClient {
  pub fn new(rpc: RpcHandler, lookup: &TypeLookup) -> Result<Arc<Self>, Box<EvalAltResult>> {
    let runtime_version = lookup.get_runtime_version();
    let genesis_hash = Self::rpc_get_genesis_hash(&rpc)?;
    let metadata = lookup
      .get_metadata()
      .expect("Failed to load chain metadata");

    let event_records = lookup.resolve("EventRecords");
    let account_info = lookup.resolve("AccountInfo");
    let call_ty = lookup.resolve("Call");
    Ok(Arc::new(Self {
      rpc,
      runtime_version,
      genesis_hash,
      metadata,
      event_records,
      account_info,
      call_ty,
      cached_blocks: DashMap::new(),
      cached_events: DashMap::new(),
    }))
  }

  // Get runtime version from rpc node.
  fn rpc_get_runtime_version(
    rpc: &RpcHandler,
    hash: Option<BlockHash>,
  ) -> Result<RuntimeVersion, Box<EvalAltResult>> {
    let params = match hash {
      Some(hash) => json!([hash]),
      None => Value::Null,
    };
    Ok(
      rpc
        .call_method("state_getRuntimeVersion", params)?
        .ok_or_else(|| format!("Failed to get RuntimeVersion from node."))?,
    )
  }

  // Get block hash from rpc node.
  fn rpc_get_block_hash(
    rpc: &RpcHandler,
    block_number: u64,
  ) -> Result<Option<BlockHash>, Box<EvalAltResult>> {
    Ok(rpc.call_method("chain_getBlockHash", json!([block_number]))?)
  }

  // Get genesis hash from rpc node.
  fn rpc_get_genesis_hash(rpc: &RpcHandler) -> Result<BlockHash, Box<EvalAltResult>> {
    Ok(
      Self::rpc_get_block_hash(rpc, 0)?
        .ok_or_else(|| format!("Failed to get genesis hash from node."))?,
    )
  }

  pub fn get_transaction_version(&self) -> i64 {
    self.runtime_version.transaction_version as i64
  }

  pub fn get_spec_version(&self) -> i64 {
    self.runtime_version.spec_version as i64
  }

  pub fn get_metadata(&self) -> Metadata {
    self.metadata.clone()
  }

  pub fn get_signed_extra(&self) -> AdditionalSigned {
    (
      self.runtime_version.spec_version,
      self.runtime_version.transaction_version,
      self.genesis_hash,
      self.genesis_hash,
      (),
      (),
      (),
    )
  }

  /// Get block hash.
  pub fn get_block_hash(&self, block_number: u64) -> Result<Option<BlockHash>, Box<EvalAltResult>> {
    Self::rpc_get_block_hash(&self.rpc, block_number)
  }

  pub fn get_block_by_number(
    &self,
    block_number: u64,
  ) -> Result<Option<Block>, Box<EvalAltResult>> {
    let hash = self.get_block_hash(block_number)?;
    self.get_block(hash)
  }

  /// Get block RuntimeVersion.
  pub fn get_block_runtime_version(
    &self,
    hash: Option<BlockHash>,
  ) -> Result<RuntimeVersion, Box<EvalAltResult>> {
    Self::rpc_get_runtime_version(&self.rpc, hash)
  }

  pub fn get_block(&self, hash: Option<BlockHash>) -> Result<Option<Block>, Box<EvalAltResult>> {
    // Only check for cached blocks when the hash is provided.
    Ok(if let Some(hash) = hash {
      let block = self.cached_blocks.get(&hash);
      if block.is_some() {
        block.as_deref().cloned()
      } else {
        let block = self.get_signed_block(Some(hash))?.map(|mut signed| {
          signed.block.call_ty = Some(self.call_ty.clone());
          signed.block
        });
        if let Some(block) = &block {
          // Cache new block.
          self.cached_blocks.insert(hash, block.clone());
        }
        block
      }
    } else {
      self.get_signed_block(hash)?.map(|signed| signed.block)
    })
  }

  pub fn get_chain_properties(&self) -> Result<Option<ChainProperties>, Box<EvalAltResult>> {
    self.rpc.call_method("system_properties", json!([]))
  }

  pub fn get_signed_block(
    &self,
    hash: Option<BlockHash>,
  ) -> Result<Option<SignedBlock>, Box<EvalAltResult>> {
    self.rpc.call_method("chain_getBlock", json!([hash]))
  }

  pub fn get_storage_keys_paged(
    &self,
    prefix: &StorageKey,
    count: u32,
    start_key: Option<&StorageKey>,
  ) -> Result<Vec<StorageKey>, Box<EvalAltResult>> {
    self
      .rpc
      .call_method(
        "state_getKeysPaged",
        json!([prefix, count, start_key.unwrap_or(prefix)]),
      )
      .map(|res| res.unwrap_or_default())
  }

  pub fn get_storage_by_key(
    &self,
    key: StorageKey,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    self
      .rpc
      .call_method("state_getStorage", json!([key, at_block]))
  }

  pub fn get_storage_by_keys(
    &self,
    keys: &[StorageKey],
    at_block: Option<BlockHash>,
  ) -> Result<Vec<Option<StorageData>>, Box<EvalAltResult>> {
    let tokens: Vec<RequestToken> = keys
      .into_iter()
      .map(|k| {
        self
          .rpc
          .async_call_method("state_getStorage", json!([k, at_block]))
      })
      .collect::<Result<Vec<_>, Box<EvalAltResult>>>()?;
    self.rpc.get_responses(tokens.as_slice())
  }

  pub fn get_storage_key_at_blocks(
    &self,
    key: StorageKey,
    at_blocks: Vec<BlockHash>,
  ) -> Result<Vec<Option<StorageData>>, Box<EvalAltResult>> {
    let tokens: Vec<RequestToken> = at_blocks
      .into_iter()
      .map(|at_block| {
        self
          .rpc
          .async_call_method("state_getStorage", json!([&key, at_block]))
      })
      .collect::<Result<Vec<_>, Box<EvalAltResult>>>()?;
    self.rpc.get_responses(tokens.as_slice())
  }

  pub fn get_storage_value(
    &self,
    module: &str,
    storage: &str,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    let md = self.metadata.get_storage(module, storage)?;
    let key = md.get_value_key()?;
    self.get_storage_by_key(key, at_block)
  }

  pub fn get_storage_map(
    &self,
    module: &str,
    storage: &str,
    key: Vec<u8>,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    let md = self.metadata.get_storage(module, storage)?;
    let key = md.raw_map_key(key)?;
    self.get_storage_by_key(key, at_block)
  }

  pub fn get_storage_double_map(
    &self,
    module: &str,
    storage: &str,
    key1: Vec<u8>,
    key2: Vec<u8>,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    let md = self.metadata.get_storage(module, storage)?;
    let key = md.raw_double_map_key(key1, key2)?;
    self.get_storage_by_key(key, at_block)
  }

  fn get_block_events(&self, hash: Option<BlockHash>) -> Result<Dynamic, Box<EvalAltResult>> {
    match self.get_storage_value("System", "Events", hash)? {
      Some(value) => Ok(self.event_records.decode(value.0)?),
      None => Ok(Dynamic::UNIT),
    }
  }

  pub fn get_events(&self, hash: Option<BlockHash>) -> Result<Dynamic, Box<EvalAltResult>> {
    if let Some(hash) = hash {
      let events = self.cached_events.get(&hash);
      if let Some(events) = events {
        Ok(events.clone())
      } else {
        let events = self.get_block_events(Some(hash))?;
        // Cache new events.
        self.cached_events.insert(hash, events.clone());
        Ok(events)
      }
    } else {
      self.get_block_events(hash)
    }
  }

  pub fn get_account_info(
    &self,
    account: AccountId,
  ) -> Result<Option<Dynamic>, Box<EvalAltResult>> {
    match self.get_storage_map("System", "Account", account.encode(), None)? {
      Some(value) => {
        // Decode chain's 'AccountInfo' value.
        Ok(Some(self.account_info.decode(value.0)?))
      }
      None => Ok(None),
    }
  }

  pub fn get_nonce(&self, account: AccountId) -> Result<Option<u32>, Box<EvalAltResult>> {
    match self.get_account_info(account)? {
      Some(value) => {
        // Get nonce.
        let account_info: AccountInfo = from_dynamic(&value)?;
        Ok(Some(account_info.nonce))
      }
      None => Ok(None),
    }
  }

  pub fn get_request_block_hash(
    &self,
    token: RequestToken,
  ) -> Result<Option<BlockHash>, Box<EvalAltResult>> {
    let hash = loop {
      let status = self.rpc.get_update(token)?;
      match status {
        Some(TransactionStatus::InBlock(hash))
        | Some(TransactionStatus::Finalized(hash))
        | Some(TransactionStatus::FinalityTimeout(hash)) => {
          break Some(hash);
        }
        Some(TransactionStatus::Future) => {
          log::warn!("Transaction in future (maybe nonce issue)");
        }
        Some(TransactionStatus::Ready) => {
          log::debug!("Transaction ready.");
        }
        Some(TransactionStatus::Broadcast(nodes)) => {
          log::debug!("Transaction broadcast: {:?}", nodes);
        }
        Some(TransactionStatus::Retracted(hash)) => {
          log::error!("Transaction retracted: {:?}", hash);
        }
        Some(TransactionStatus::Usurped(tx_hash)) => {
          log::error!(
            "Transaction was replaced by another in the pool: {:?}",
            tx_hash
          );
          break None;
        }
        Some(TransactionStatus::Dropped) => {
          log::error!("Transaction dropped.");
          break None;
        }
        Some(TransactionStatus::Invalid) => {
          log::error!("Transaction invalid.");
          break None;
        }
        None => {
          break None;
        }
      }
    };
    self.rpc.close_request(token)?;

    Ok(hash)
  }

  pub fn submit(&self, xthex: String) -> Result<(RequestToken, String), Box<EvalAltResult>> {
    let token = self.rpc.subscribe(
      "author_submitAndWatchExtrinsic",
      json!([xthex]),
      "author_unwatchExtrinsic",
    )?;
    Ok((token, xthex))
  }

  pub fn submit_call(
    &self,
    user: &User,
    call: EncodedCall,
  ) -> Result<(RequestToken, String), Box<EvalAltResult>> {
    let extra = Extra::new(Era::Immortal, user.nonce);
    let payload = SignedPayload::new(&call, &extra, self.get_signed_extra());

    let sig = payload.using_encoded(|p| user.pair.sign(p));

    let xt = ExtrinsicV4::signed(user.acc(), sig.into(), extra, call);
    let xthex = xt.to_hex();

    self.submit(xthex)
  }

  pub fn submit_unsigned(
    &self,
    call: EncodedCall,
  ) -> Result<(RequestToken, String), Box<EvalAltResult>> {
    let xthex = ExtrinsicV4::unsigned(call).to_hex();

    self.submit(xthex)
  }
}

#[derive(Clone)]
pub struct Client {
  inner: Arc<InnerClient>,
}

impl Client {
  pub fn connect(rpc: RpcHandler, lookup: &TypeLookup) -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {
      inner: InnerClient::new(rpc, lookup)?,
    })
  }

  pub fn get_transaction_version(&self) -> i64 {
    self.inner.get_transaction_version()
  }

  pub fn get_spec_version(&self) -> i64 {
    self.inner.get_spec_version()
  }

  pub fn get_metadata(&self) -> Metadata {
    self.inner.get_metadata()
  }

  pub fn get_signed_extra(&self) -> AdditionalSigned {
    self.inner.get_signed_extra()
  }

  pub fn get_chain_properties(&self) -> Result<Option<ChainProperties>, Box<EvalAltResult>> {
    self.inner.get_chain_properties()
  }

  pub fn get_block_hash(&self, block_number: u64) -> Result<Option<BlockHash>, Box<EvalAltResult>> {
    self.inner.get_block_hash(block_number)
  }

  pub fn get_block_runtime_version(
    &self,
    hash: Option<BlockHash>,
  ) -> Result<RuntimeVersion, Box<EvalAltResult>> {
    self.inner.get_block_runtime_version(hash)
  }

  pub fn get_block(&self, hash: Option<BlockHash>) -> Result<Option<Block>, Box<EvalAltResult>> {
    self.inner.get_block(hash)
  }

  pub fn get_block_by_number(
    &self,
    block_number: u64,
  ) -> Result<Option<Block>, Box<EvalAltResult>> {
    self.inner.get_block_by_number(block_number)
  }

  pub fn get_block_events(&self, hash: Option<BlockHash>) -> Result<Dynamic, Box<EvalAltResult>> {
    self.inner.get_block_events(hash)
  }

  pub fn get_storage_keys_paged(
    &self,
    prefix: &StorageKey,
    count: u32,
    start_key: Option<&StorageKey>,
  ) -> Result<Vec<StorageKey>, Box<EvalAltResult>> {
    self.inner.get_storage_keys_paged(prefix, count, start_key)
  }

  pub fn get_storage_by_key(
    &self,
    key: StorageKey,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    self.inner.get_storage_by_key(key, at_block)
  }

  pub fn get_storage_by_keys(
    &self,
    keys: &[StorageKey],
    at_block: Option<BlockHash>,
  ) -> Result<Vec<Option<StorageData>>, Box<EvalAltResult>> {
    self.inner.get_storage_by_keys(keys, at_block)
  }

  pub fn get_storage_key_at_blocks(
    &self,
    key: StorageKey,
    at_blocks: Vec<BlockHash>,
  ) -> Result<Vec<Option<StorageData>>, Box<EvalAltResult>> {
    self.inner.get_storage_key_at_blocks(key, at_blocks)
  }

  pub fn get_storage_value(
    &self,
    prefix: &str,
    key_name: &str,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    self.inner.get_storage_value(prefix, key_name, at_block)
  }

  pub fn get_storage_map(
    &self,
    prefix: &str,
    key_name: &str,
    map_key: Vec<u8>,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    self
      .inner
      .get_storage_map(prefix, key_name, map_key, at_block)
  }

  pub fn get_storage_double_map(
    &self,
    prefix: &str,
    storage_name: &str,
    key1: Vec<u8>,
    key2: Vec<u8>,
    at_block: Option<BlockHash>,
  ) -> Result<Option<StorageData>, Box<EvalAltResult>> {
    self
      .inner
      .get_storage_double_map(prefix, storage_name, key1, key2, at_block)
  }

  pub fn get_events(&self, block: Option<BlockHash>) -> Result<Dynamic, Box<EvalAltResult>> {
    self.inner.get_events(block)
  }

  pub fn get_nonce(&self, account: AccountId) -> Result<Option<u32>, Box<EvalAltResult>> {
    self.inner.get_nonce(account)
  }

  pub fn get_request_block_hash(
    &self,
    token: RequestToken,
  ) -> Result<Option<BlockHash>, Box<EvalAltResult>> {
    self.inner.get_request_block_hash(token)
  }

  fn call_results(
    &self,
    res: Result<(RequestToken, String), Box<EvalAltResult>>,
  ) -> Result<ExtrinsicCallResult, Box<EvalAltResult>> {
    let (token, xthex) = res?;
    Ok(ExtrinsicCallResult::new(self, token, xthex))
  }

  pub fn submit(&self, xthex: String) -> Result<ExtrinsicCallResult, Box<EvalAltResult>> {
    self.call_results(self.inner.submit(xthex))
  }

  pub fn submit_call(
    &self,
    user: &User,
    call: EncodedCall,
  ) -> Result<ExtrinsicCallResult, Box<EvalAltResult>> {
    self.call_results(self.inner.submit_call(user, call))
  }

  pub fn submit_unsigned(
    &self,
    call: EncodedCall,
  ) -> Result<ExtrinsicCallResult, Box<EvalAltResult>> {
    self.call_results(self.inner.submit_unsigned(call))
  }

  pub fn inner(&self) -> Arc<InnerClient> {
    self.inner.clone()
  }
}

pub struct InnerCallResult {
  client: Client,
  token: RequestToken,
  hash: Option<BlockHash>,
  xthex: String,
  idx: Option<u32>,
  events: Option<EventRecords>,
}

impl InnerCallResult {
  pub fn new(client: &Client, token: RequestToken, xthex: String) -> Self {
    Self {
      client: client.clone(),
      token,
      hash: None,
      xthex,
      idx: None,
      events: None,
    }
  }

  fn get_block_hash(&mut self) -> Result<(), Box<EvalAltResult>> {
    if self.hash.is_some() {
      return Ok(());
    }

    self.hash = self.client.get_request_block_hash(self.token)?;

    Ok(())
  }

  pub fn is_in_block(&mut self) -> Result<bool, Box<EvalAltResult>> {
    self.get_block_hash()?;
    Ok(self.hash.is_some())
  }

  pub fn block_hash(&mut self) -> Result<String, Box<EvalAltResult>> {
    self.get_block_hash()?;
    Ok(self.hash.unwrap_or_default().to_string())
  }

  fn load_events(&mut self) -> Result<(), Box<EvalAltResult>> {
    if self.events.is_some() {
      return Ok(());
    }
    self.get_block_hash()?;
    let events = match self.hash {
      Some(hash) => {
        // Load block and find the index of our extrinsic.
        let xt_idx = match self.client.get_block(Some(hash))? {
          Some(block) => block.find_extrinsic(&self.xthex),
          None => None,
        };
        self.idx = xt_idx.map(|idx| idx as u32);
        let mut events = EventRecords::from_dynamic(self.client.get_events(Some(hash))?)?;
        if let Some(idx) = self.idx {
          events.filter(Phase::ApplyExtrinsic(idx));
        }
        events
      }
      None => EventRecords::default(),
    };

    self.events = Some(events);
    Ok(())
  }

  pub fn events_filtered(&mut self, prefix: &str) -> Result<Vec<Dynamic>, Box<EvalAltResult>> {
    self.load_events()?;
    match &self.events {
      Some(events) => Ok(events.prefix_filtered(prefix)),
      None => Ok(vec![]),
    }
  }

  pub fn events(&mut self) -> Result<Vec<Dynamic>, Box<EvalAltResult>> {
    self.events_filtered("")
  }

  pub fn result(&mut self) -> Result<Dynamic, Box<EvalAltResult>> {
    // Look for event `System.ExtrinsicSuccess` or `System.ExtrinsicFailed`
    // to get the Extrinsic result.
    let mut events = self.events_filtered("System.Extrinsic")?;
    // Just return the last found event.  Should only be one.
    match events.pop() {
      Some(result) => Ok(result),
      None => Ok(Dynamic::UNIT),
    }
  }

  pub fn is_success(&mut self) -> Result<bool, Box<EvalAltResult>> {
    // Look for event `System.ExtrinsicSuccess`.
    let events = self.events_filtered("System.ExtrinsicSuccess")?;
    Ok(events.len() > 0)
  }

  pub fn block(&mut self) -> Result<Dynamic, Box<EvalAltResult>> {
    self.get_block_hash()?;
    match self.hash {
      Some(hash) => match self.client.get_block(Some(hash))? {
        Some(block) => Ok(Dynamic::from(block)),
        None => Ok(Dynamic::UNIT),
      },
      None => Ok(Dynamic::UNIT),
    }
  }

  pub fn xthex(&self) -> String {
    self.xthex.clone()
  }

  pub fn to_string(&mut self) -> String {
    let _ = self.get_block_hash();
    match &self.hash {
      Some(hash) => {
        format!("InBlock: {:?}", hash)
      }
      None => {
        format!("NoBlock")
      }
    }
  }
}

#[derive(Clone)]
pub struct ExtrinsicCallResult(Arc<RwLock<InnerCallResult>>);

impl ExtrinsicCallResult {
  pub fn new(client: &Client, token: RequestToken, xthex: String) -> Self {
    Self(Arc::new(RwLock::new(InnerCallResult::new(
      client, token, xthex,
    ))))
  }

  pub fn is_in_block(&mut self) -> Result<bool, Box<EvalAltResult>> {
    self.0.write().unwrap().is_in_block()
  }

  pub fn block_hash(&mut self) -> Result<String, Box<EvalAltResult>> {
    self.0.write().unwrap().block_hash()
  }

  pub fn events_filtered(&mut self, prefix: &str) -> Result<Vec<Dynamic>, Box<EvalAltResult>> {
    self.0.write().unwrap().events_filtered(prefix)
  }

  pub fn events(&mut self) -> Result<Vec<Dynamic>, Box<EvalAltResult>> {
    self.0.write().unwrap().events()
  }

  pub fn result(&mut self) -> Result<Dynamic, Box<EvalAltResult>> {
    self.0.write().unwrap().result()
  }

  pub fn is_success(&mut self) -> Result<bool, Box<EvalAltResult>> {
    self.0.write().unwrap().is_success()
  }

  pub fn block(&mut self) -> Result<Dynamic, Box<EvalAltResult>> {
    self.0.write().unwrap().block()
  }

  pub fn xthex(&mut self) -> String {
    self.0.read().unwrap().xthex()
  }

  pub fn to_string(&mut self) -> String {
    self.0.write().unwrap().to_string()
  }
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, rpc, _hash| {
    // Get Chain properties.
    let chain_props: Option<ChainProperties> = rpc.call_method("system_properties", json!([]))?;
    // Set default ss58 format.
    let ss58_format = chain_props
      .as_ref()
      .and_then(|p| Ss58AddressFormat::try_from(p.ss58_format).ok());
    if let Some(ss58_format) = ss58_format {
      set_default_ss58_version(ss58_format);
    }

    // Get the `tokenDecimals` value from the chain properties.
    let token_decimals = chain_props.as_ref().map(|p| p.token_decimals).unwrap_or(0);
    let balance_scale = 10u128.pow(token_decimals);
    log::info!(
      "token_deciamls: {:?}, balance_scale={:?}",
      token_decimals,
      balance_scale
    );
    types.custom_encode("Balance", TypeId::of::<INT>(), move |value, data| {
      let mut val = value.cast::<INT>() as u128;
      val *= balance_scale;
      if data.is_compact() {
        data.encode(Compact::<u128>(val));
      } else {
        data.encode(val);
      }
      Ok(())
    })?;
    types.custom_encode("Balance", TypeId::of::<Decimal>(), move |value, data| {
      let mut dec = value.cast::<Decimal>();
      dec *= Decimal::from(balance_scale);
      let val = dec
        .to_u128()
        .ok_or_else(|| format!("Expected unsigned integer"))?;
      if data.is_compact() {
        data.encode(Compact::<u128>(val));
      } else {
        data.encode(val);
      }
      Ok(())
    })?;
    types.custom_decode("Balance", move |mut input, is_compact| {
      let val = if is_compact {
        Compact::<u128>::decode(&mut input)?.into()
      } else {
        u128::decode(&mut input)?
      };
      log::debug!("Balance = {}", val);
      Ok(match Decimal::from_u128(val) {
        Some(val) => {
          Dynamic::from_decimal(val / Decimal::from(balance_scale))
        }
        None => {
          // TODO: create `Balance` type wrapper.
          Dynamic::from(val)
        }
      })
    })?;
    Ok(())
  });

  Ok(())
}

pub fn init_engine(
  rpc: &RpcHandler,
  engine: &mut Engine,
  lookup: &TypeLookup,
) -> Result<Client, Box<EvalAltResult>> {
  engine
    .register_type_with_name::<Client>("Client")
    .register_result_fn(
      "get_block_hash",
      |client: &mut Client, num: i64| match client.get_block_hash(num as u64)? {
        Some(hash) => Ok(Dynamic::from(hash)),
        None => Ok(Dynamic::UNIT),
      },
    )
    .register_result_fn(
      "get_block",
      |client: &mut Client, hash: Dynamic| match client.get_block(hash_from_dynamic(hash))? {
        Some(block) => Ok(Dynamic::from(block)),
        None => Ok(Dynamic::UNIT),
      },
    )
    .register_result_fn("get_block_events", |client: &mut Client, hash: Dynamic| {
      client.get_block_events(hash_from_dynamic(hash))
    })
    .register_result_fn(
      "get_block_runtime_version",
      |client: &mut Client, hash: Dynamic| {
        to_dynamic(client.get_block_runtime_version(hash_from_dynamic(hash))?)
      },
    )
    .register_result_fn(
      "get_block_by_number",
      |client: &mut Client, num: i64| match client.get_block_by_number(num as u64)? {
        Some(block) => Ok(Dynamic::from(block)),
        None => Ok(Dynamic::UNIT),
      },
    )
    .register_fn("get_transaction_version", |client: &mut Client| {
      client.get_transaction_version()
    })
    .register_fn("get_spec_version", |client: &mut Client| {
      client.get_spec_version()
    })
    .register_result_fn("submit_unsigned", Client::submit_unsigned)
    .register_type_with_name::<RuntimeVersion>("RuntimeVersion")
    .register_get("specName", |v: &mut RuntimeVersion| v.spec_name.to_string())
    .register_get("specVersion", |v: &mut RuntimeVersion| {
      v.spec_version as INT
    })
    .register_get("implName", |v: &mut RuntimeVersion| v.impl_name.to_string())
    .register_get("implVersion", |v: &mut RuntimeVersion| {
      v.impl_version as INT
    })
    .register_get("transactionVersion", |v: &mut RuntimeVersion| {
      v.transaction_version as INT
    })
    .register_type_with_name::<ExtrinsicCallResult>("ExtrinsicCallResult")
    .register_result_fn("events", ExtrinsicCallResult::events_filtered)
    .register_get_result("events", ExtrinsicCallResult::events)
    .register_get_result("block", ExtrinsicCallResult::block)
    .register_get_result("block_hash", ExtrinsicCallResult::block_hash)
    .register_get_result("result", ExtrinsicCallResult::result)
    .register_get_result("is_success", ExtrinsicCallResult::is_success)
    .register_get_result("is_in_block", ExtrinsicCallResult::is_in_block)
    .register_get("xthex", ExtrinsicCallResult::xthex)
    .register_fn("to_string", ExtrinsicCallResult::to_string);

  let client = Client::connect(rpc.clone(), lookup)?;

  Ok(client)
}
