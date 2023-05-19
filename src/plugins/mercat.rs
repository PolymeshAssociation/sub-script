use curve25519_dalek::scalar::Scalar;
use parity_scale_codec::{Decode, Encode};

use log::info;
use mercat::{
  account::AccountCreator,
  asset::AssetIssuer,
  confidential_identity_core::asset_proofs::{Balance, ElgamalSecretKey},
  transaction::{CtxMediator, CtxReceiver, CtxSender},
  Account, AccountCreatorInitializer, AmountSource, AssetTransactionIssuer, EncryptedAmount, EncryptionKeys,
  EncryptionPubKey, FinalizedTransferTx, InitializedAssetTx, InitializedTransferTx,
  JustifiedTransferTx, PubAccount, PubAccountTx, SecAccount, MediatorAccount,
  TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
};
pub use mercat_common::{
  create_rng_from_seed,
  errors::Error, gen_seed, init_print_logger,
  user_public_account_file, update_account_map, user_secret_account_file, OrderedPubAccount,
  OFF_CHAIN_DIR, ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};

use std::any::TypeId;
use std::collections::HashMap;

use rust_decimal::{prelude::{ToPrimitive, FromPrimitive}, Decimal};
use rhai::{Dynamic, Engine, EvalAltResult, INT};

use crate::client::Client;
use crate::rpc::RpcHandler;
use crate::types::{Types, TypesRegistry};

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
pub struct MercatUtils {
  seed: Option<String>,
}

impl MercatUtils {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {
      seed: None,
    })
  }

  pub fn set_seed(&mut self, seed: Option<String>) {
    self.seed = seed;
  }

  pub fn seed(&mut self) -> Option<String> {
    let seed = self.seed.get_or_insert_with(|| gen_seed());
    Some(seed.clone())
  }

  pub fn create_account_tx(
    &mut self,
    account: Account,
  ) -> Result<PubAccountTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_account_tx(account)
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_account_tx(
    &mut self,
    account: Account,
  ) -> Result<PubAccountTx, Error> {
    let seed = self.seed();
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account tx.
    let account_tx = AccountCreator
      .create(&account.secret, &mut rng)
      .map_err(|error| Error::LibraryError { error })?;

    info!(
      "Account Transaction as hex:\n0x{}\n",
      hex::encode(account_tx.encode())
    );

    Ok(account_tx)
  }

  fn mercat_create_keys(
    &mut self,
  ) -> Result<EncryptionKeys, Error> {
    let seed = self.seed();
    let mut rng = create_rng_from_seed(seed)?;

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();
    Ok(EncryptionKeys {
      public: elg_pub,
      secret: elg_secret,
    })
  }

  pub fn create_mediator(
    &mut self,
  ) -> Result<MediatorAccount, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_mediator()
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_mediator(
    &mut self,
  ) -> Result<MediatorAccount, Error> {
    let encryption_key = self.mercat_create_keys()?;

    Ok(MediatorAccount {
      encryption_key,
    })
  }

  pub fn create_secret_account(
    &mut self,
  ) -> Result<Account, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_secret_account()
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_secret_account(
    &mut self,
  ) -> Result<Account, Error> {
    let enc_keys = self.mercat_create_keys()?;

    let account = Account {
      public: PubAccount {
        owner_enc_pub_key: enc_keys.public,
      },
      secret: SecAccount {
        enc_keys,
      },
    };

    Ok(account)
  }

  pub fn decrypt_balance(
    &mut self,
    account: Account,
    encrypted_value: EncryptedAmount,
  ) -> Result<Decimal, Box<EvalAltResult>> {
    #[cfg(not(all(feature = "discrete_log", feature = "rayon")))]
    let value = {
      account.secret.enc_keys.secret.decrypt(&encrypted_value)
    };
    #[cfg(all(not(feature = "discrete_log"), feature = "rayon"))]
    let value = {
      account.secret.enc_keys.secret.decrypt_parallel(&encrypted_value)
    };
    #[cfg(feature = "discrete_log")]
    let value = {
      account.secret.enc_keys.secret.decrypt_discrete_log(&encrypted_value)
    };

    let mut value = Decimal::from_u64(value.map_err(|e| e.to_string())?)
      .ok_or_else(|| format!("Failed to convert balance to `Decimal`"))?;
    value /= Decimal::from(1_000_000);

    Ok(value)
  }

  pub fn decrypt_balance_with_hint(
    &mut self,
    account: Account,
    encrypted_value: EncryptedAmount,
    low: Dynamic,
    high: Dynamic,
  ) -> Result<Dynamic, Box<EvalAltResult>> {
    let low = to_balance(low)?;
    let high = to_balance(high)?;
    let balance = account.secret.enc_keys.secret
      .decrypt_with_hint(&encrypted_value, low, high)
      .and_then(|v| Decimal::from_u64(v as u64))
      .map(|v| Dynamic::from_decimal(v / Decimal::from(1_000_000)))
      .unwrap_or_else(|| Dynamic::UNIT);
    Ok(balance)
  }

  pub fn mint_asset(
    &mut self,
    issuer: Account,
    amount: Dynamic,
  ) -> Result<InitializedAssetTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_mint_asset(
          issuer,
          to_balance(amount)?,
        )
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_mint_asset(
    &mut self,
    issuer: Account,
    amount: Balance,
  ) -> Result<InitializedAssetTx, Error> {
    let seed = self.seed();
    let mut rng = create_rng_from_seed(seed)?;

    let ctx_issuer = AssetIssuer;
    let asset_tx = ctx_issuer
      .initialize_asset_transaction(&issuer, &[], amount, &mut rng)
      .map_err(|error| Error::LibraryError { error })?;
    info!(
      "CLI log: Asset Mint Transaction as hex:\n0x{}\n",
      hex::encode(asset_tx.encode())
    );

    Ok(asset_tx)
  }

  pub fn create_tx(
    &mut self,
    sender: Account,
    receiver: PubAccount,
    mediator: EncryptionPubKey,
    amount: Dynamic,
    pending_enc_balance: EncryptedAmount,
    pending_balance: Dynamic,
  ) -> Result<InitializedTransferTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_tx(
          sender,
          receiver,
          mediator,
          to_balance(amount)?,
          pending_enc_balance,
          to_balance(pending_balance)?,
        )
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_tx(
    &mut self,
    sender_account: Account,
    receiver: PubAccount,
    mediator: EncryptionPubKey,
    amount: Balance,
    pending_enc_balance: EncryptedAmount,
    pending_balance: Balance,
  ) -> Result<InitializedTransferTx, Error> {
    let seed = self.seed();
    let mut rng = create_rng_from_seed(seed)?;

    // Initialize the transaction.
    let ctx_sender = CtxSender {};
    let init_tx = ctx_sender
      .create_transaction(
        &sender_account,
        &pending_enc_balance,
        pending_balance,
        &receiver,
        Some(&mediator),
        &[],
        amount,
        &mut rng,
      )
      .map_err(|error| Error::LibraryError { error })?;

    Ok(init_tx)
  }

  pub fn finalize_tx(
    &mut self,
    receiver: Account,
    amount: Dynamic,
    init_tx: InitializedTransferTx,
  ) -> Result<(), Box<EvalAltResult>> {
    Ok(
      self
        .mercat_finalize_tx(receiver, to_balance(amount)?, init_tx)
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_finalize_tx(
    &mut self,
    receiver_account: Account,
    amount: Balance,
    init_tx: InitializedTransferTx,
  ) -> Result<(), Error> {

    // Finalize the transaction.
    let receiver = CtxReceiver {};
    receiver
      .finalize_transaction(&init_tx, receiver_account, amount)
      .map_err(|error| Error::LibraryError { error })?;

    Ok(())
  }

  pub fn justify_tx(
    &mut self,
    mediator: MediatorAccount,
    sender: PubAccount,
    sender_balance: EncryptedAmount,
    receiver: PubAccount,
    init_tx: InitializedTransferTx,
  ) -> Result<(), Box<EvalAltResult>> {
    Ok(
      self
        .mercat_justify_tx(
          mediator,
          sender,
          sender_balance,
          receiver,
          init_tx,
        )
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_justify_tx(
    &mut self,
    mediator: MediatorAccount,
    sender: PubAccount,
    sender_balance: EncryptedAmount,
    receiver: PubAccount,
    init_tx: InitializedTransferTx,
  ) -> Result<(), Error> {
    let seed = self.seed();
    // Load the transaction, mediator's credentials, and issuer's public account.
    let mut rng = create_rng_from_seed(seed)?;

    // Justification.
    CtxMediator {}
      .justify_transaction(
        &init_tx,
        AmountSource::Encrypted(&mediator.encryption_key),
        &sender,
        &sender_balance,
        &receiver,
        &[],
        &mut rng,
      )
      .map_err(|error| Error::LibraryError { error })?;

    Ok(())
  }

  pub fn add_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Add, first, second)
  }

  pub fn sub_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Subtract, first, second)
  }

  fn add_subtract(&self, op: Op, first: String, second: String) -> String {
    let mut data: &[u8] = &hex::decode(first).unwrap();
    let first = EncryptedAmount::decode(&mut data).unwrap();
    let mut data: &[u8] = &hex::decode(second).unwrap();
    let second = EncryptedAmount::decode(&mut data).unwrap();

    match op {
      Op::Add => format!("0x{}", hex::encode((first + second).encode())),
      Op::Subtract => format!("0x{}", hex::encode((first - second).encode())),
    }
  }
}

pub fn init_vec_encoded<T: Decode + Encode + Clone + Send + Sync + 'static>(name: &str, types: &mut Types) -> Result<(), Box<EvalAltResult>> {
  types.custom_encode(
    name,
    TypeId::of::<T>(),
    move |value, data| {
      let val = value.cast::<T>();
      let encoded = val.encode();
      data.encode(encoded);
      Ok(())
    },
  )?;
  types.custom_decode(
    name,
    |mut input, _is_compact| {
      let encoded = Vec::decode(&mut input)?;
      Ok(Dynamic::from(T::decode(&mut encoded.as_slice())?))
    }
  )?;
  Ok(())
}

pub fn hex_to_string<T: Encode>(val: &mut T) -> String {
  let encoded = hex::encode(val.encode());
  format!("0x{encoded}")
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, _rpc, _hash| {
    init_vec_encoded::<PubAccountTx>("pallet_confidential_asset::MercatPubAccountTx", types)?;
    init_vec_encoded::<EncryptedAmount>("pallet_confidential_asset::MercatEncryptedAmount", types)?;
    init_vec_encoded::<InitializedAssetTx>("pallet_confidential_asset::MercatMintAssetTx", types)?;
    init_vec_encoded::<InitializedTransferTx>("pallet_confidential_asset::SenderProof", types)?;
    // Don't use vec wrapper for `MercatAccount`.
    types.custom_encode(
      "pallet_confidential_asset::MercatAccount",
      TypeId::of::<EncryptionPubKey>(),
      move |value, data| {
        let val = value.cast::<EncryptionPubKey>();
        data.encode(val);
        Ok(())
      },
    )?;
    types.custom_decode(
      "pallet_confidential_asset::MercatAccount",
      |mut input, _is_compact| {
        Ok(Dynamic::from(EncryptionPubKey::decode(&mut input)?))
      }
    )?;

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
  info!("Initialized MERCAT.");
  init_print_logger();

  let utils = MercatUtils::new()?;
  globals.insert("MercatUtils".into(), Dynamic::from(utils.clone()));

  engine
    .register_type_with_name::<MercatUtils>("MercatUtils")
    .register_result_fn("create_mediator", MercatUtils::create_mediator)
    .register_result_fn("create_account_tx", MercatUtils::create_account_tx)
    .register_result_fn("create_secret_account", MercatUtils::create_secret_account)
    .register_result_fn("mint_asset", MercatUtils::mint_asset)
    .register_result_fn("decrypt_balance", MercatUtils::decrypt_balance)
    .register_result_fn("decrypt_balance_with_hint", MercatUtils::decrypt_balance_with_hint)
    .register_result_fn("create_tx", MercatUtils::create_tx)
    .register_result_fn("finalize_tx", MercatUtils::finalize_tx)
    .register_result_fn("justify_tx", MercatUtils::justify_tx)
    .register_fn("add_balance", MercatUtils::add_balance)
    .register_fn("sub_balance", MercatUtils::sub_balance)
    .register_type_with_name::<PubAccountTx>("PubAccountTx")
    .register_get("account", |v: &mut PubAccountTx| v.pub_account.clone())
    .register_fn("to_string", hex_to_string::<PubAccountTx>)
    .register_type_with_name::<Account>("Account")
    .register_type_with_name::<MediatorAccount>("MediatorAccount")
    .register_get("pub_key", |v: &mut MediatorAccount| v.encryption_key.public)
    .register_type_with_name::<PubAccount>("PubAccount")
    .register_get("pub_key", |v: &mut PubAccount| v.owner_enc_pub_key)
    .register_fn("to_string", hex_to_string::<PubAccount>)
    .register_type_with_name::<EncryptedAmount>("EncryptedAmount")
    .register_fn("to_string", hex_to_string::<EncryptedAmount>)
    .register_type_with_name::<EncryptionPubKey>("EncryptionPubKey")
    .register_result_fn("encrypt_amount", |k: &mut EncryptionPubKey, amount: Dynamic| {
      let amount = to_balance(amount)?;
      let mut rng = rand::thread_rng();
      let (_, enc_amount) = k.encrypt_value(amount.into(), &mut rng);
      Ok(enc_amount as EncryptedAmount)
    })
    .register_fn("to_string", hex_to_string::<EncryptionPubKey>)
    .register_type_with_name::<InitializedAssetTx>("InitializedAssetTx")
    .register_fn("to_string", hex_to_string::<InitializedAssetTx>)
    .register_type_with_name::<InitializedTransferTx>("InitializedTransferTx")
    .register_fn("to_string", hex_to_string::<InitializedTransferTx>)
    .register_type_with_name::<FinalizedTransferTx>("FinalizedTransferTx")
    .register_fn("to_string", hex_to_string::<FinalizedTransferTx>)
    .register_type_with_name::<JustifiedTransferTx>("JustifiedTransferTx")
    .register_fn("to_string", hex_to_string::<JustifiedTransferTx>);

  Ok(())
}
