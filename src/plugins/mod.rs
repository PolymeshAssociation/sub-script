use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult};

use crate::client::Client;
use crate::rpc::RpcHandler;
use crate::types::TypesRegistry;

#[cfg(feature = "ledger")]
pub mod ledger;

#[cfg(feature = "mercat")]
pub mod mercat;

#[cfg(feature = "confidential_assets")]
pub mod confidential_assets;

#[cfg(feature = "polymesh")]
pub mod polymesh;

#[cfg(feature = "pg")]
pub mod postgres;

#[cfg(feature = "utils")]
pub mod utils;

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  #[cfg(feature = "ledger")]
  ledger::init_types_registry(types_registry)?;

  #[cfg(feature = "polymesh")]
  polymesh::init_types_registry(types_registry)?;

  #[cfg(feature = "mercat")]
  mercat::init_types_registry(types_registry)?;

  #[cfg(feature = "confidential_assets")]
  confidential_assets::init_types_registry(types_registry)?;

  Ok(())
}

pub fn init_engine(
  _rpc: &RpcHandler,
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
  client: &Client,
) -> Result<(), Box<EvalAltResult>> {
  #[cfg(feature = "ledger")]
  ledger::init_engine(engine, globals, client)?;

  #[cfg(feature = "polymesh")]
  polymesh::init_engine(engine, globals, client)?;

  #[cfg(feature = "mercat")]
  mercat::init_engine(_rpc, engine, globals, client)?;

  #[cfg(feature = "confidential_assets")]
  confidential_assets::init_engine(_rpc, engine, globals, client)?;

  #[cfg(feature = "pg")]
  postgres::init_engine(engine, globals)?;

  #[cfg(feature = "utils")]
  utils::init_engine(engine, globals)?;

  Ok(())
}
