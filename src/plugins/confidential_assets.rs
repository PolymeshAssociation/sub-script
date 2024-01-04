use parity_scale_codec::Encode;
use sp_core::hashing::blake2_256;

use confidential_assets::{
  elgamal::CipherText,
  transaction::ConfidentialTransferProof,
  Balance, ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar,
};
use rand::{rngs::StdRng, SeedableRng};

use dashmap::DashMap;

use std::sync::{Arc, RwLock};
use std::any::TypeId;
use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult, INT};
use rust_decimal::{
  prelude::{FromPrimitive, ToPrimitive},
  Decimal,
};

use crate::users::SharedUser;
use crate::client::Client;
use crate::rpc::RpcHandler;
use crate::types::TypesRegistry;

pub fn to_balance(val: Dynamic) -> Result<Balance, Box<EvalAltResult>> {
  let type_id = val.type_id();
  if type_id == TypeId::of::<Decimal>() {
    let val = val.as_decimal().unwrap();
    Ok(val.to_u64().unwrap_or_default() as Balance)
  } else if type_id == TypeId::of::<INT>() {
    let val = val.as_int().unwrap();
    Ok(val as Balance)
  } else {
    return Err(format!("Can't convert {} to `Balance`", val.type_name()).into());
  }
}

pub fn to_ciphertext(val: Dynamic) -> Result<CipherText, Box<EvalAltResult>> {
  let type_id = val.type_id();
  if type_id == TypeId::of::<Decimal>() {
    let val = val.as_decimal().unwrap();
    Ok(CipherText::value(val.to_u64().unwrap_or_default().into()))
  } else if type_id == TypeId::of::<INT>() {
    let val = val.as_int().unwrap();
    Ok(CipherText::value((val as Balance).into()))
  } else if type_id == TypeId::of::<CipherText>() {
    Ok(val.cast::<CipherText>())
  } else {
    return Err(format!("Can't convert {} to `CipherText`", val.type_name()).into());
  }
}

pub fn to_seed(seed: Dynamic) -> Result<Option<[u8; 32]>, Box<EvalAltResult>> {
  if seed.is::<()>() {
    Ok(None)
  } else {
    let seed_str = seed.into_immutable_string()?;
    Ok(Some(blake2_256(seed_str.as_bytes())))
  }
}

#[derive(Clone)]
pub struct ConfidentialUser {
  pub user: SharedUser,
  name: String,
  keys: ElgamalKeys,
  props: HashMap<String, Dynamic>,
}

impl ConfidentialUser {
  pub fn new(user: SharedUser) -> Self {
    let name = user.name();
    let seed = blake2_256(name.as_bytes());
    let mut rng = StdRng::from_seed(seed);

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    Self {
      user,
      name,
      keys: ElgamalKeys {
        public: elg_secret.get_public_key(),
        secret: elg_secret,
      },
      props: HashMap::new(),
    }
  }

  pub fn decrypt_balance(
    &self,
    encrypted_value: CipherText,
  ) -> Result<Decimal, Box<EvalAltResult>> {
    let value = { self.keys.secret.decrypt(&encrypted_value) };

    let value = Decimal::from_u64(value.map_err(|e| e.to_string())?)
      .ok_or_else(|| format!("Failed to convert balance to `Decimal`"))?;

    Ok(value)
  }

  pub fn decrypt_balance_with_hint(
    &self,
    encrypted_value: CipherText,
    low: Dynamic,
    high: Dynamic,
  ) -> Result<Dynamic, Box<EvalAltResult>> {
    let low = to_balance(low)?;
    let high = to_balance(high)?;
    let balance = self.keys
      .secret
      .decrypt_with_hint(&encrypted_value, low, high)
      .and_then(|v| Decimal::from_u64(v as u64))
      .map(|v| Dynamic::from_decimal(v))
      .unwrap_or_else(|| Dynamic::UNIT);
    Ok(balance)
  }

  pub fn create_sender_proof(
    &self,
    receiver: ElgamalPublicKey,
    auditors: Dynamic,
    amount: Dynamic,
    pending_enc_balance: CipherText,
    pending_balance: Dynamic,
  ) -> Result<ConfidentialTransferProof, Box<EvalAltResult>> {
    let mut rng = rand::thread_rng();

    let pending_balance = to_balance(pending_balance)?;
    let amount = to_balance(amount)?;
    // Sort auditors.
    let mut auditors = auditors.into_typed_array::<ElgamalPublicKey>()?;
    auditors.sort();
    // Sort auditors.
    let auditors = auditors
      .into_iter()
      .collect();
    // Create sender proof.
    let init_tx = ConfidentialTransferProof::new(
      &self.keys,
      &pending_enc_balance,
      pending_balance,
      &receiver,
      &auditors,
      amount,
      &mut rng,
    )
    .map_err(|e| e.to_string())?;

    Ok(init_tx)
  }

  pub fn get_signer(&self) -> SharedUser {
    self.user.clone()
  }

  pub fn get_keys(&self) -> ElgamalKeys {
    self.keys.clone()
  }

  pub fn get_pub_key(&self) -> ElgamalPublicKey {
    self.keys.public.clone()
  }

  pub fn name(&self) -> String {
    self.name.clone()
  }

  pub fn get_prop(&self, name: &str) -> Dynamic {
    self.props.get(name)
      .map(|d| Dynamic::from(d.clone()))
      .unwrap_or_else(|| Dynamic::UNIT)
  }

  pub fn set_prop(&mut self, name: &str, value: Dynamic) {
    self.props.insert(name.to_string(), value);
  }
}

#[derive(Clone)]
pub struct SharedConfidentialUser(Arc<RwLock<ConfidentialUser>>);

impl SharedConfidentialUser {
  pub fn get_signer(&mut self) -> SharedUser {
    self.0.read().unwrap().get_signer()
  }

  pub fn get_keys(&mut self) -> ElgamalKeys {
    self.0.read().unwrap().get_keys()
  }

  pub fn get_pub_key(&mut self) -> ElgamalPublicKey {
    self.0.read().unwrap().get_pub_key()
  }

  pub fn to_string(&mut self) -> String {
    self.0.read().unwrap().name()
  }

  pub fn get_prop(&mut self, name: &str) -> Dynamic {
    self.0.read().unwrap().get_prop(name)
  }

  pub fn set_prop(&mut self, name: &str, value: Dynamic) {
    self.0.write().unwrap().set_prop(name, value)
  }

  pub fn decrypt_balance(
    &mut self,
    encrypted_value: CipherText,
  ) -> Result<Decimal, Box<EvalAltResult>> {
    self.0.read().unwrap().decrypt_balance(encrypted_value)
  }

  pub fn decrypt_balance_with_hint(
    &mut self,
    encrypted_value: CipherText,
    low: Dynamic,
    high: Dynamic,
  ) -> Result<Dynamic, Box<EvalAltResult>> {
    self.0.read().unwrap().decrypt_balance_with_hint(encrypted_value, low, high)
  }

  pub fn create_sender_proof(
    &mut self,
    receiver: ElgamalPublicKey,
    auditors: Dynamic,
    amount: Dynamic,
    pending_enc_balance: CipherText,
    pending_balance: Dynamic,
  ) -> Result<ConfidentialTransferProof, Box<EvalAltResult>> {
    self.0.read().unwrap().create_sender_proof(receiver, auditors, amount, pending_enc_balance, pending_balance)
  }
}

pub struct InnerConfidentialUsers {
  users: DashMap<String, Dynamic>,
}

impl InnerConfidentialUsers {
  pub fn new() -> Self {
    Self {
      users: DashMap::new(),
    }
  }

  pub fn from_user(&self, user: SharedUser) -> Dynamic {
    let name = user.name();
    // Try save user.  If another thread generated the user first, then use that user.
    use dashmap::mapref::entry::Entry;
    match self.users.entry(name) {
      Entry::Occupied(entry) => entry.get().clone(),
      Entry::Vacant(entry) => {
        // Generate new confidential user.
        let user = ConfidentialUser::new(user);
        // Create a shared wrapper for the user.
        let shared = Dynamic::from(SharedConfidentialUser(Arc::new(RwLock::new(user))));
        entry.insert(shared.clone());
        shared
      }
    }
  }
}

#[derive(Clone)]
pub struct ConfidentialUsers(Arc<InnerConfidentialUsers>);

impl ConfidentialUsers {
  pub fn new() -> Self {
    Self(Arc::new(InnerConfidentialUsers::new()))
  }

  pub fn from_user(&mut self, user: SharedUser) -> Dynamic {
    self.0.from_user(user)
  }
}

pub fn hex_to_string<T: Encode>(val: &mut T) -> String {
  let encoded = hex::encode(val.encode());
  format!("0x{encoded}")
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, _rpc, _hash| {
    types.register_scale_type::<ConfidentialTransferProof>("confidential_assets::transaction::ConfidentialTransferProof")?;
    types.register_scale_type::<ElgamalPublicKey>("pallet_confidential_asset::ConfidentialAccount")?;
    types.register_scale_type::<ElgamalPublicKey>("pallet_confidential_asset::AuditorAccount")?;
    types.register_scale_type::<CipherText>("confidential_assets::elgamal::CipherText")?;
    types.register_scale_type::<CipherText>("CipherText")?;

    Ok(())
  });
  Ok(())
}

pub fn init_engine(
  _rpc: &RpcHandler,
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
  _client: &Client,
) -> Result<(), Box<EvalAltResult>> {
  let users = ConfidentialUsers::new();
  globals.insert(
    "ConfidentialUsers".into(),
    Dynamic::from(users.clone()),
  );

  engine
    .register_type_with_name::<SharedConfidentialUser>("ConfidentialUser")
    .register_get("signer", SharedConfidentialUser::get_signer)
    .register_get("keys", SharedConfidentialUser::get_keys)
    .register_get("pub_key", SharedConfidentialUser::get_pub_key)
    .register_fn("to_string", SharedConfidentialUser::to_string)
    .register_result_fn("decrypt_balance", SharedConfidentialUser::decrypt_balance)
    .register_result_fn(
      "decrypt_balance_with_hint",
      SharedConfidentialUser::decrypt_balance_with_hint,
    )
    .register_result_fn(
      "create_sender_proof",
      SharedConfidentialUser::create_sender_proof,
    )
    .register_indexer_get(SharedConfidentialUser::get_prop)
    .register_indexer_set(SharedConfidentialUser::set_prop)
    .register_type_with_name::<ConfidentialUsers>("ConfidentialUsers")
    .register_fn("from_user", ConfidentialUsers::from_user)
    .register_type_with_name::<ElgamalKeys>("ElgamalKeys")
    .register_get("pub_key", |v: &mut ElgamalKeys| v.public)
    .register_type_with_name::<ElgamalPublicKey>("ElgamalPublicKey")
    .register_result_fn(
      "encrypt_amount",
      |k: &mut ElgamalPublicKey, amount: Dynamic| {
        let amount = to_balance(amount)?;
        let mut rng = rand::thread_rng();
        let (_, enc_amount) = k.encrypt_value(amount.into(), &mut rng);
        Ok(enc_amount as CipherText)
      },
    )
    .register_fn("to_string", hex_to_string::<ElgamalPublicKey>)
    .register_type_with_name::<CipherText>("CipherText")
    .register_fn("new_CipherText", || {
      CipherText::default()
    })
    .register_fn("==", |a: &mut CipherText, b: CipherText| {
      *a == b
    })
    .register_fn("!=", |a: &mut CipherText, b: CipherText| {
      *a != b
    })
    .register_result_fn("+", |a: &mut CipherText, b: Dynamic| {
      let b = to_ciphertext(b)?;
      Ok(*a + b)
    })
    .register_result_fn("-", |a: &mut CipherText, b: Dynamic| {
      let b = to_ciphertext(b)?;
      Ok(*a - b)
    })
    .register_fn("to_string", hex_to_string::<CipherText>)
    .register_type_with_name::<ConfidentialTransferProof>("ConfidentialTransferProof")
    .register_get(
      "sender_amount",
      |proof: &mut ConfidentialTransferProof| {
        proof.sender_amount()
      },
    )
    .register_get(
      "receiver_amount",
      |proof: &mut ConfidentialTransferProof| {
        proof.receiver_amount()
      },
    )
    .register_result_fn(
      "receiver_verify",
      |proof: &mut ConfidentialTransferProof, receiver: ElgamalKeys, amount: Dynamic| {
        let amount = to_balance(amount)?;
        proof
          .receiver_verify(receiver, Some(amount))
          .map_err(|e| e.to_string())?;
        Ok(())
      },
    )
    .register_result_fn(
      "mediator_verify",
      |proof: &mut ConfidentialTransferProof, mediator: ElgamalKeys, amount: Dynamic| {
        let amount = to_balance(amount)?;
        let tx_amount = proof
          .auditor_verify(0, &mediator, Some(amount))
          .map_err(|e| e.to_string())?;
        if tx_amount != amount {
          return Err("Transaction amount didn't match expected amount".into());
        }
        Ok(tx_amount)
      },
    )
    .register_fn("to_string", hex_to_string::<ConfidentialTransferProof>);

  Ok(())
}
