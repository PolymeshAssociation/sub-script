use confidential_identity_core::asset_proofs::{AssetId, CommitmentWitness, ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;
use parity_scale_codec::{Decode, Encode};

use log::info;
use mercat::{
  account::{convert_asset_ids, AccountCreator},
  transaction::{CtxMediator, CtxReceiver, CtxSender},
  Account, AccountCreatorInitializer, EncryptedAmount, EncryptedAssetId, EncryptionKeys,
  EncryptionPubKey, FinalizedTransferTx, InitializedAssetTx, InitializedTransferTx,
  JustifiedTransferTx, MediatorAccount, PubAccount, PubAccountTx, SecAccount,
  TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
};
pub use mercat_common::{
  account_issue::process_issue_asset, create_rng_from_seed, debug_decrypt_base64_account_balance,
  errors::Error, gen_seed, init_print_logger, justify::process_create_mediator, load_object,
  save_object, user_public_account_file, user_secret_account_file, OrderedPubAccount,
  OFF_CHAIN_DIR, ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use rand::{CryptoRng, RngCore};

use std::any::TypeId;
use std::collections::HashMap;
use std::path::PathBuf;

use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString, INT};

use super::polymesh::str_to_ticker;

use crate::client::Client;
use crate::rpc::RpcHandler;
use crate::types::TypesRegistry;

pub const TX_ID: u32 = 1;

pub enum Op {
  Add,
  Subtract,
}

#[derive(Clone)]
pub struct MercatUtils {
  db_dir: PathBuf,
  seed: Option<String>,
}

impl MercatUtils {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {
      db_dir: PathBuf::from("./mercat_db/"),
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

  fn db_dir(&self) -> PathBuf {
    self.db_dir.clone()
  }

  pub fn create_account(
    &mut self,
    user: String,
    ticker: String,
    ticker_names: Dynamic,
  ) -> Result<PubAccountTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_account(user, ticker, ticker_names.into_typed_array()?)
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_account(
    &mut self,
    user: String,
    ticker: String,
    ticker_names: Vec<String>,
  ) -> Result<PubAccountTx, Error> {
    let seed = self.seed();
    let db_dir = self.db_dir();
    let mut rng = create_rng_from_seed(seed)?;

    let valid_asset_ids: Vec<AssetId> = ticker_names
      .into_iter()
      .map(|ticker_name| {
        let mut asset_id = [0u8; 12];
        let decoded = hex::decode(ticker_name).unwrap();
        asset_id[..decoded.len()].copy_from_slice(&decoded);
        Ok(AssetId { id: asset_id })
      })
      .collect::<Result<Vec<AssetId>, Error>>()?;
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    // Create the account.
    let secret_account = Self::create_secret_account(&mut rng, ticker.clone())?;

    let account_tx = AccountCreator
      .create(&secret_account, &valid_asset_ids, &mut rng)
      .map_err(|error| Error::LibraryError { error })?;

    // Save the artifacts to file.
    save_object(
      db_dir.clone(),
      OFF_CHAIN_DIR,
      &user,
      &user_secret_account_file(&ticker),
      &secret_account,
    )?;

    let account_id = account_tx.pub_account.enc_asset_id;

    info!(
      "CLI log: tx-{}:\n\nAccount ID as base64:\n{}\n\nAccount Transaction as base64:\n{}\n",
      TX_ID,
      base64::encode(account_id.encode()),
      base64::encode(account_tx.encode())
    );

    let ordered_account = OrderedPubAccount {
      pub_account: account_tx.pub_account.clone(),
      last_processed_tx_counter: Some(TX_ID),
    };
    save_object(
      db_dir,
      ON_CHAIN_DIR,
      &user,
      &user_public_account_file(&ticker),
      &ordered_account,
    )?;

    Ok(account_tx)
  }

  fn create_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    ticker_id: String,
  ) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
      public: elg_pub,
      secret: elg_secret,
    };

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).unwrap();
    asset_id[..decoded.len()].copy_from_slice(&decoded);

    let asset_id = AssetId { id: asset_id };
    let asset_id_witness = CommitmentWitness::new(asset_id.into(), Scalar::random(rng));

    Ok(SecAccount {
      enc_keys,
      asset_id_witness,
    })
  }

  pub fn create_mediator(&mut self, user: String) -> Result<EncryptionPubKey, Box<EvalAltResult>> {
    Ok(
      process_create_mediator(self.seed().unwrap(), self.db_dir(), user)
        .map_err(|e| e.to_string())?,
    )
  }

  pub fn decrypt_balance(
    &mut self,
    user: String,
    ticker: String,
    encrypted_value: String,
  ) -> Result<i64, Box<EvalAltResult>> {
    Ok(
      debug_decrypt_base64_account_balance(user, encrypted_value, ticker, self.db_dir())
        .map_err(|e| e.to_string())? as i64,
    )
  }

  pub fn mint_asset(
    &mut self,
    issuer: String,
    ticker: String,
    amount: INT,
  ) -> Result<InitializedAssetTx, Box<EvalAltResult>> {
    Ok(
      process_issue_asset(
        self.seed().unwrap(),
        self.db_dir(),
        issuer,
        ticker,
        amount as u32,
        true,
        TX_ID,
        false,
      )
      .map_err(|e| e.to_string())?,
    )
  }

  pub fn create_tx(
    &mut self,
    sender: String,
    receiver: Dynamic,
    mediator: String,
    ticker: String,
    amount: i64,
    pending_balance: String,
  ) -> Result<InitializedTransferTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_create_tx(
          sender,
          receiver.into_typed_array()?,
          mediator,
          ticker,
          amount as u32,
          pending_balance,
        )
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_create_tx(
    &mut self,
    sender: String,
    receiver: Vec<String>,
    mediator: String,
    ticker: String,
    amount: u32,
    pending_balance: String,
  ) -> Result<InitializedTransferTx, Error> {
    let seed = self.seed();
    let db_dir = self.db_dir();
    let mut rng = create_rng_from_seed(seed)?;

    let sender_ordered_pub_account: OrderedPubAccount = load_object(
      db_dir.clone(),
      ON_CHAIN_DIR,
      &sender,
      &user_public_account_file(&ticker),
    )?;
    let sender_account = Account {
      secret: load_object(
        db_dir,
        OFF_CHAIN_DIR,
        &sender,
        &user_secret_account_file(&ticker),
      )?,
      public: sender_ordered_pub_account.pub_account,
    };

    // Calculate the pending
    let mut data: &[u8] = &base64::decode(pending_balance).unwrap();
    let pending_balance = EncryptedAmount::decode(&mut data).unwrap(); // For now the same as initial balance

    let mut data0: &[u8] = &base64::decode(&receiver[0]).unwrap();
    let mut data1: &[u8] = &base64::decode(&receiver[1]).unwrap();
    let receiver_pub_account = PubAccount {
      enc_asset_id: EncryptedAssetId::decode(&mut data0).unwrap(),
      owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    let mut data: &[u8] = &base64::decode(mediator).unwrap();
    let mediator_account = EncryptionPubKey::decode(&mut data).unwrap();

    // Initialize the transaction.
    let ctx_sender = CtxSender {};
    let pending_account = Account {
      secret: sender_account.secret,
      public: PubAccount {
        enc_asset_id: sender_account.public.enc_asset_id,
        owner_enc_pub_key: sender_account.public.owner_enc_pub_key,
      },
    };
    let asset_tx = ctx_sender
      .create_transaction(
        &pending_account,
        &pending_balance,
        &receiver_pub_account,
        &mediator_account,
        &[],
        amount,
        &mut rng,
      )
      .map_err(|error| Error::LibraryError { error })?;

    info!(
      "CLI log: Initialized Transaction as base64:\n{}\n",
      base64::encode(asset_tx.encode())
    );

    Ok(asset_tx)
  }

  pub fn finalize_tx(
    &mut self,
    receiver: String,
    ticker: String,
    amount: i64,
    init_tx: String,
  ) -> Result<FinalizedTransferTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_finalize_tx(receiver, ticker, amount as u32, init_tx)
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_finalize_tx(
    &mut self,
    receiver: String,
    ticker: String,
    amount: u32,
    init_tx: String,
  ) -> Result<FinalizedTransferTx, Error> {
    let seed = self.seed();
    let db_dir = self.db_dir();
    let mut rng = create_rng_from_seed(seed)?;

    let receiver_ordered_pub_account: OrderedPubAccount = load_object(
      db_dir.clone(),
      ON_CHAIN_DIR,
      &receiver,
      &user_public_account_file(&ticker),
    )?;

    let receiver_account = Account {
      secret: load_object(
        db_dir,
        OFF_CHAIN_DIR,
        &receiver,
        &user_secret_account_file(&ticker),
      )?,
      public: receiver_ordered_pub_account.pub_account,
    };

    let mut data: &[u8] = &base64::decode(&init_tx).unwrap();
    let tx = InitializedTransferTx::decode(&mut data).unwrap();

    // Finalize the transaction.
    let receiver = CtxReceiver {};
    let asset_tx = receiver
      .finalize_transaction(tx, receiver_account, amount, &mut rng)
      .map_err(|error| Error::LibraryError { error })?;

    // Save the artifacts to file.
    info!(
      "CLI log: Finalized Transaction as base64:\n{}\n",
      base64::encode(asset_tx.encode())
    );

    Ok(asset_tx)
  }

  pub fn justify_tx(
    &mut self,
    sender: Dynamic,
    sender_balance: String,
    receiver: Dynamic,
    mediator: String,
    ticker: String,
    finalized_tx: String,
  ) -> Result<JustifiedTransferTx, Box<EvalAltResult>> {
    Ok(
      self
        .mercat_justify_tx(
          sender.into_typed_array()?,
          sender_balance,
          receiver.into_typed_array()?,
          mediator,
          ticker,
          finalized_tx,
        )
        .map_err(|e| e.to_string())?,
    )
  }

  fn mercat_justify_tx(
    &mut self,
    sender: Vec<String>,
    sender_balance: String,
    receiver: Vec<String>,
    mediator: String,
    ticker: String,
    finalized_tx: String,
  ) -> Result<JustifiedTransferTx, Error> {
    let seed = self.seed();
    let db_dir = self.db_dir();
    // Load the transaction, mediator's credentials, and issuer's public account.
    let mut rng = create_rng_from_seed(seed)?;

    let mut data: &[u8] = &base64::decode(&finalized_tx).unwrap();
    let asset_tx = FinalizedTransferTx::decode(&mut data).unwrap();

    let mediator_account: MediatorAccount =
      load_object(db_dir, OFF_CHAIN_DIR, &mediator, SECRET_ACCOUNT_FILE)?;

    let mut data0: &[u8] = &base64::decode(&sender[0]).unwrap();
    let mut data1: &[u8] = &base64::decode(&sender[1]).unwrap();
    let sender_pub_account = PubAccount {
      enc_asset_id: EncryptedAssetId::decode(&mut data0).unwrap(),
      owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    let mut data: &[u8] = &base64::decode(&sender_balance).unwrap();
    let sender_balance = EncryptedAmount::decode(&mut data).unwrap();

    let mut data0: &[u8] = &base64::decode(&receiver[0]).unwrap();
    let mut data1: &[u8] = &base64::decode(&receiver[1]).unwrap();
    let receiver_pub_account = PubAccount {
      enc_asset_id: EncryptedAssetId::decode(&mut data0).unwrap(),
      owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    // Justification.

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(&ticker).unwrap();
    asset_id[..decoded.len()].copy_from_slice(&decoded);
    let asset_id = AssetId { id: asset_id };

    let justified_tx = CtxMediator {}
      .justify_transaction(
        asset_tx,
        &mediator_account.encryption_key,
        &sender_pub_account,
        &sender_balance,
        &receiver_pub_account,
        &[],
        asset_id,
        &mut rng,
      )
      .map_err(|error| Error::LibraryError { error })?;

    info!(
      "CLI log: Justified Transaction as base64:\n{}\n",
      base64::encode(justified_tx.encode())
    );

    Ok(justified_tx)
  }

  pub fn add_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Add, first, second)
  }

  pub fn sub_balance(&mut self, first: String, second: String) -> String {
    self.add_subtract(Op::Subtract, first, second)
  }

  fn add_subtract(&self, op: Op, first: String, second: String) -> String {
    let mut data: &[u8] = &base64::decode(first).unwrap();
    let first = EncryptedAmount::decode(&mut data).unwrap();
    let mut data: &[u8] = &base64::decode(second).unwrap();
    let second = EncryptedAmount::decode(&mut data).unwrap();

    match op {
      Op::Add => base64::encode((first + second).encode()),
      Op::Subtract => base64::encode((first - second).encode()),
    }
  }
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, _rpc, _hash| {
    types.custom_encode("AssetId", TypeId::of::<ImmutableString>(), |value, data| {
      let value = value.cast::<ImmutableString>();
      let asset_id = str_to_ticker(value.as_str())?;
      data.encode(&asset_id);
      Ok(())
    })?;

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
    .register_result_fn("create_account", MercatUtils::create_account)
    .register_result_fn("create_mediator", MercatUtils::create_mediator)
    .register_result_fn("mint_asset", MercatUtils::mint_asset)
    .register_result_fn("decrypt_balance", MercatUtils::decrypt_balance)
    .register_result_fn("create_tx", MercatUtils::create_tx)
    .register_result_fn("finalize_tx", MercatUtils::finalize_tx)
    .register_result_fn("justify_tx", MercatUtils::justify_tx)
    .register_fn("add_balance", MercatUtils::add_balance)
    .register_fn("sub_balance", MercatUtils::sub_balance)
    .register_type_with_name::<PubAccountTx>("PubAccountTx")
    .register_get("account", |v: &mut PubAccountTx| v.pub_account.clone())
    .register_get("base64", |v: &mut PubAccountTx| base64::encode(v.encode()))
    .register_fn("to_string", |v: &mut PubAccountTx| format!("{:?}", v))
    .register_type_with_name::<PubAccount>("PubAccount")
    .register_get("account_id", |v: &mut PubAccount| v.enc_asset_id)
    .register_get("pub_key", |v: &mut PubAccount| v.owner_enc_pub_key)
    .register_get("base64", |v: &mut PubAccount| base64::encode(v.encode()))
    .register_fn("to_string", |v: &mut PubAccount| format!("{:?}", v))
    .register_type_with_name::<EncryptedAssetId>("EncryptedAssetId")
    .register_get("base64", |v: &mut EncryptedAssetId| {
      base64::encode(v.encode())
    })
    .register_fn("to_string", |v: &mut EncryptedAssetId| format!("{:?}", v))
    .register_type_with_name::<EncryptedAmount>("EncryptedAmount")
    .register_get("base64", |v: &mut EncryptedAmount| {
      base64::encode(v.encode())
    })
    .register_fn("to_string", |v: &mut EncryptedAmount| format!("{:?}", v))
    .register_type_with_name::<PubAccount>("EncryptionPubKey")
    .register_result_fn("encrypt_amount", |k: &mut EncryptionPubKey, amount: INT| {
      let mut rng = rand::thread_rng();
      let (_, enc_amount) = k.encrypt_value((amount as u32).into(), &mut rng);
      Ok(enc_amount as EncryptedAmount)
    })
    .register_get("base64", |k: &mut EncryptionPubKey| {
      base64::encode(k.encode())
    })
    .register_fn("to_string", |k: &mut EncryptionPubKey| format!("{k:?}"))
    .register_type_with_name::<InitializedAssetTx>("InitializedAssetTx")
    .register_get("base64", |tx: &mut InitializedAssetTx| {
      base64::encode(tx.encode())
    })
    .register_fn("to_string", |tx: &mut InitializedAssetTx| format!("{tx:?}"))
    .register_type_with_name::<InitializedTransferTx>("InitializedTransferTx")
    .register_get("base64", |tx: &mut InitializedTransferTx| {
      base64::encode(tx.encode())
    })
    .register_fn("to_string", |tx: &mut InitializedTransferTx| {
      format!("{tx:?}")
    })
    .register_type_with_name::<FinalizedTransferTx>("FinalizedTransferTx")
    .register_get("base64", |tx: &mut FinalizedTransferTx| {
      base64::encode(tx.encode())
    })
    .register_fn("to_string", |tx: &mut FinalizedTransferTx| {
      format!("{tx:?}")
    })
    .register_type_with_name::<JustifiedTransferTx>("JustifiedTransferTx")
    .register_get("base64", |tx: &mut JustifiedTransferTx| {
      base64::encode(tx.encode())
    })
    .register_fn("to_string", |tx: &mut JustifiedTransferTx| {
      format!("{tx:?}")
    })
    .register_type_with_name::<AssetId>("AssetId")
    .register_fn("to_string", |asset_id: &mut AssetId| {
      let s = String::from_utf8_lossy(asset_id.id.as_slice());
      format!("{s}")
    });

  Ok(())
}
