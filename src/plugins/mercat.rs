use confidential_identity_core::asset_proofs::{AssetId, CommitmentWitness, ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;
use parity_scale_codec::{Decode, Encode};

use log::info;
use mercat::{
  account::{convert_asset_ids, AccountCreator},
  transaction::{CtxMediator, CtxReceiver, CtxSender},
  Account, AccountCreatorInitializer, EncryptedAmount, EncryptedAssetId, EncryptionKeys,
  EncryptionPubKey, FinalizedTransferTx, InitializedTransferTx, MediatorAccount, PubAccount,
  SecAccount, TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
};
pub use mercat_common::{
  account_issue::process_issue_asset, create_rng_from_seed, debug_decrypt_base64_account_balance,
  errors::Error, gen_seed, init_print_logger, justify::process_create_mediator, load_object,
  save_object, user_public_account_file, user_secret_account_file, OrderedPubAccount,
  OFF_CHAIN_DIR, ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use rand::{CryptoRng, RngCore};
use std::path::PathBuf;

pub const TX_ID: u32 = 1;

pub enum Op {
  Add,
  Subtract,
}

pub fn init_mercat() {
  info!("Initialized MERCAT.");
  init_print_logger();
}

/*
fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    match args {
        CLI::CreateUserAccount(cfg) => {
            let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
            process_create_account(
                cfg.seed,
                db_dir,
                cfg.user,
                cfg.ticker,
                cfg.valid_ticker_names,
            )
            .unwrap()
        }
        CLI::CreateMediatorAccount(cfg) => process_create_mediator(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.user,
        )
        .unwrap(),
        CLI::Mint(cfg) => process_issue_asset(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.issuer,
            cfg.account_id_from_ticker,
            cfg.amount,
            true,
            TX_ID,
            false,
        )
        .unwrap(),
        CLI::CreateTransaction(cfg) => process_create_tx(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.mediator,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.pending_balance,
        )
        .unwrap(),
        CLI::FinalizeTransaction(cfg) => process_finalize_tx(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.receiver,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.init_tx,
        )
        .unwrap(),
        CLI::JustifyTransaction(cfg) => justify_asset_transfer_transaction(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.sender_balance,
            cfg.receiver,
            cfg.mediator,
            cfg.ticker,
            cfg.finalized_tx,
        )
        .unwrap(),
        CLI::Decrypt(cfg) => info!(
            "Account balance: {}",
            debug_decrypt_base64_account_balance(
                cfg.user,
                cfg.encrypted_value,
                cfg.ticker,
                cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap()
            )
            .unwrap()
        ),
        CLI::Add(cfg) => info!("Result: {}", add_subtract(Op::Add, cfg.first, cfg.second,)),
        CLI::Subtract(cfg) => info!(
            "Result: {}",
            add_subtract(Op::Subtract, cfg.first, cfg.second,)
        ),
    };
    info!("The program finished successfully.");
}
*/

pub fn process_create_account(
  seed: Option<String>,
  db_dir: PathBuf,
  user: String,
  ticker: String,
  ticker_names: Vec<String>,
) -> Result<(), Error> {
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
  let secret_account = create_secret_account(&mut rng, ticker.clone())?;

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
    pub_account: account_tx.pub_account,
    last_processed_tx_counter: Some(TX_ID),
  };
  save_object(
    db_dir,
    ON_CHAIN_DIR,
    &user,
    &user_public_account_file(&ticker),
    &ordered_account,
  )?;

  Ok(())
}

pub fn create_secret_account<R: RngCore + CryptoRng>(
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

pub fn process_create_tx(
  seed: String,
  db_dir: PathBuf,
  sender: String,
  receiver: Vec<String>,
  mediator: String,
  ticker: String,
  amount: u32,
  pending_balance: String,
) -> Result<(), Error> {
  let mut rng = create_rng_from_seed(Some(seed))?;

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

  Ok(())
}

pub fn process_finalize_tx(
  seed: String,
  db_dir: PathBuf,
  receiver: String,
  ticker: String,
  amount: u32,
  init_tx: String,
) -> Result<(), Error> {
  let mut rng = create_rng_from_seed(Some(seed))?;

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

  Ok(())
}

pub fn justify_asset_transfer_transaction(
  seed: String,
  db_dir: PathBuf,
  sender: Vec<String>,
  sender_balance: String,
  receiver: Vec<String>,
  mediator: String,
  ticker: String,
  finalized_tx: String,
) -> Result<(), Error> {
  // Load the transaction, mediator's credentials, and issuer's public account.
  let mut rng = create_rng_from_seed(Some(seed))?;

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

  Ok(())
}

pub fn add_subtract(op: Op, first: String, second: String) -> String {
  let mut data: &[u8] = &base64::decode(first).unwrap();
  let first = EncryptedAmount::decode(&mut data).unwrap();
  let mut data: &[u8] = &base64::decode(second).unwrap();
  let second = EncryptedAmount::decode(&mut data).unwrap();

  match op {
    Op::Add => base64::encode((first + second).encode()),
    Op::Subtract => base64::encode((first - second).encode()),
  }
}
