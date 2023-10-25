use parity_scale_codec::{Decode, Encode};

use confidential_assets::{
  elgamal::CipherText,
  transaction::{AuditorId, ConfidentialTransferProof},
  Balance, ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use std::any::TypeId;
use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult, INT};
use rust_decimal::{
  prelude::{FromPrimitive, ToPrimitive},
  Decimal,
};

use crate::client::Client;
use crate::rpc::RpcHandler;
use crate::types::TypesRegistry;

pub fn to_balance(val: Dynamic) -> Result<Balance, Box<EvalAltResult>> {
  let type_id = val.type_id();
  if type_id == TypeId::of::<Decimal>() {
    let mut val = val.as_decimal().unwrap();
    val *= Decimal::from(1_000_000u64);
    Ok(val.to_u64().unwrap_or_default() as Balance)
  } else if type_id == TypeId::of::<INT>() {
    let val = val.as_int().unwrap();
    Ok(val as Balance)
  } else {
    return Err(format!("Can't convert {} to `Balance`", val.type_name()).into());
  }
}

pub enum Op {
  Add,
  Subtract,
}

#[derive(Clone)]
pub struct ConfidentialAssetsUtils {
  seed: Option<[u8; 32]>,
}

impl ConfidentialAssetsUtils {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self { seed: None })
  }

  pub fn gen_seed() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
  }

  pub fn create_rng(&mut self) -> StdRng {
    let seed = self.seed();
    StdRng::from_seed(seed)
  }

  pub fn set_seed(&mut self, seed: Option<[u8; 32]>) {
    self.seed = seed;
  }

  pub fn seed(&mut self) -> [u8; 32] {
    self.seed.get_or_insert_with(|| Self::gen_seed()).clone()
  }

  pub fn create_account(&mut self) -> ElgamalKeys {
    let mut rng = self.create_rng();

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    ElgamalKeys {
      public: elg_secret.get_public_key(),
      secret: elg_secret,
    }
  }

  pub fn decrypt_balance(
    &mut self,
    account: ElgamalKeys,
    encrypted_value: CipherText,
  ) -> Result<Decimal, Box<EvalAltResult>> {
    #[cfg(not(all(feature = "discrete_log", feature = "rayon")))]
    let value = { account.secret.decrypt(&encrypted_value) };
    #[cfg(all(not(feature = "discrete_log"), feature = "rayon"))]
    let value = { account.secret.decrypt_parallel(&encrypted_value) };
    #[cfg(feature = "discrete_log")]
    let value = { account.secret.decrypt_discrete_log(&encrypted_value) };

    let mut value = Decimal::from_u64(value.map_err(|e| e.to_string())?)
      .ok_or_else(|| format!("Failed to convert balance to `Decimal`"))?;
    value /= Decimal::from(1_000_000);

    Ok(value)
  }

  pub fn decrypt_balance_with_hint(
    &mut self,
    account: ElgamalKeys,
    encrypted_value: CipherText,
    low: Dynamic,
    high: Dynamic,
  ) -> Result<Dynamic, Box<EvalAltResult>> {
    let low = to_balance(low)?;
    let high = to_balance(high)?;
    let balance = account
      .secret
      .decrypt_with_hint(&encrypted_value, low, high)
      .and_then(|v| Decimal::from_u64(v as u64))
      .map(|v| Dynamic::from_decimal(v / Decimal::from(1_000_000)))
      .unwrap_or_else(|| Dynamic::UNIT);
    Ok(balance)
  }

  pub fn create_sender_proof(
    &mut self,
    sender: ElgamalKeys,
    receiver: ElgamalPublicKey,
    auditors: Dynamic,
    amount: Dynamic,
    pending_enc_balance: CipherText,
    pending_balance: Dynamic,
  ) -> Result<ConfidentialTransferProof, Box<EvalAltResult>> {
    let mut rng = self.create_rng();

    let pending_balance = to_balance(pending_balance)?;
    let amount = to_balance(amount)?;
    // Sort auditors.
    let mut auditors = auditors.into_typed_array::<ElgamalPublicKey>()?;
    auditors.sort();
    // assign AuditorIds to each auditor.
    let auditors = auditors
      .into_iter()
      .enumerate()
      .map(|(idx, key)| (AuditorId(idx as _), key))
      .collect();
    // Create sender proof.
    let init_tx = ConfidentialTransferProof::new(
      &sender,
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

  pub fn add_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Add, first, second)
  }

  pub fn sub_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Subtract, first, second)
  }

  fn add_subtract(&self, op: Op, first: String, second: String) -> String {
    let mut data: &[u8] = &hex::decode(first).unwrap();
    let first = CipherText::decode(&mut data).unwrap();
    let mut data: &[u8] = &hex::decode(second).unwrap();
    let second = CipherText::decode(&mut data).unwrap();

    match op {
      Op::Add => format!("0x{}", hex::encode((first + second).encode())),
      Op::Subtract => format!("0x{}", hex::encode((first - second).encode())),
    }
  }
}

pub fn hex_to_string<T: Encode>(val: &mut T) -> String {
  let encoded = hex::encode(val.encode());
  format!("0x{encoded}")
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, _rpc, _hash| {
    types.vec_encoded::<ConfidentialTransferProof>("pallet_confidential_asset::SenderProof")?;
    // Don't use vec wrapper for `ConfidentialAccount` or `CipherText`.
    types.register_scale_type::<ElgamalPublicKey>("pallet_confidential_asset::ConfidentialAccount")?;
    types.register_scale_type::<ElgamalPublicKey>("pallet_confidential_asset::MediatorAccount")?;
    types.register_scale_type::<CipherText>("pallet_confidential_asset::elgamal::CipherText")?;
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
  let utils = ConfidentialAssetsUtils::new()?;
  globals.insert(
    "ConfidentialAssetsUtils".into(),
    Dynamic::from(utils.clone()),
  );

  engine
    .register_type_with_name::<ConfidentialAssetsUtils>("ConfidentialAssetsUtils")
    .register_fn("create_account", ConfidentialAssetsUtils::create_account)
    .register_result_fn("decrypt_balance", ConfidentialAssetsUtils::decrypt_balance)
    .register_result_fn(
      "decrypt_balance_with_hint",
      ConfidentialAssetsUtils::decrypt_balance_with_hint,
    )
    .register_result_fn(
      "create_sender_proof",
      ConfidentialAssetsUtils::create_sender_proof,
    )
    .register_fn("add_balance", ConfidentialAssetsUtils::add_balance)
    .register_fn("sub_balance", ConfidentialAssetsUtils::sub_balance)
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
    .register_fn("to_string", hex_to_string::<CipherText>)
    .register_type_with_name::<AuditorId>("AuditorId")
    .register_fn("to_string", hex_to_string::<AuditorId>)
    .register_type_with_name::<ConfidentialTransferProof>("ConfidentialTransferProof")
    .register_result_fn(
      "receiver_verify",
      |proof: &mut ConfidentialTransferProof, receiver: ElgamalKeys, amount: Dynamic| {
        let amount = to_balance(amount)?;
        proof
          .receiver_verify(receiver, amount)
          .map_err(|e| e.to_string())?;
        Ok(())
      },
    )
    .register_result_fn(
      "mediator_verify",
      |proof: &mut ConfidentialTransferProof, mediator: ElgamalKeys, amount: Dynamic| {
        let amount = to_balance(amount)?;
        let tx_amount = proof
          .auditor_verify(AuditorId(0), &mediator)
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
