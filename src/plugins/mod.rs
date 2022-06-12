use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult};

use crate::client::Client;
use crate::types::TypesRegistry;

pub mod ledger;

#[cfg(feature = "polymesh")]
pub mod polymesh;

#[cfg(feature = "pg")]
pub mod postgres;

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  ledger::init_types_registry(types_registry)?;

  #[cfg(feature = "polymesh")]
  polymesh::init_types_registry(types_registry)?;

  Ok(())
}

pub fn init_engine(
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
  client: &Client,
) -> Result<(), Box<EvalAltResult>> {
  ledger::init_engine(engine, globals, client)?;

  #[cfg(feature = "polymesh")]
  polymesh::init_engine(engine, globals, client)?;

  #[cfg(feature = "pg")]
  postgres::init_engine(engine, globals)?;

  Ok(())
}
