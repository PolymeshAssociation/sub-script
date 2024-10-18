use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use hex::{FromHex, ToHex};

use sp_core::{blake2_128, blake2_256, H256};
use parity_scale_codec::Encode;

use rhai::{Array, Blob, Dynamic, Engine, EvalAltResult, INT};

#[derive(Clone)]
pub struct UtilsPlugin {}

impl UtilsPlugin {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {})
  }

  pub fn babe_secondary_slot_author(&mut self, randomness: Dynamic, slot: INT, authorities_len: INT) -> Result<INT, Box<EvalAltResult>> {
    let rand = if randomness.is::<Array>() {
      randomness.into_typed_array::<INT>()?.into_iter().map(|b| b as u8).collect()
    } else if randomness.is::<Blob>() {
      randomness.cast::<Blob>()
    } else {
      vec![0u8; 32]
    };
    let rand = H256::from_slice(&rand);
    let rand = sp_core::U256::from((rand, slot as u64).using_encoded(blake2_256));

    let authorities_len = sp_core::U256::from(authorities_len);
    let idx = rand % authorities_len;

    Ok(idx.as_u32() as _)
  }

  pub fn write_hex_to_file(&mut self, file: &str, val: &str) -> Result<(), Box<EvalAltResult>> {
    let bytes = Vec::from_hex(&val[2..]).map_err(|e| e.to_string())?;
    let mut f = File::create(file).map_err(|e| e.to_string())?;
    f.write_all(&bytes).map_err(|e| e.to_string())?;

    Ok(())
  }

  pub fn from_hex(&mut self, val: &str) -> Result<Vec<u8>, Box<EvalAltResult>> {
    Ok(Vec::from_hex(&val[2..]).map_err(|e| e.to_string())?)
  }

  pub fn to_hex(&mut self, data: Vec<u8>) -> String {
    data.encode_hex::<String>()
  }

  pub fn blake2_128(&mut self, data: Vec<u8>) -> Dynamic {
    let hash = blake2_128(&data);
    Dynamic::from(hash.to_vec())
  }

  pub fn blake2_256(&mut self, data: Vec<u8>) -> Dynamic {
    let hash = blake2_256(&data);
    Dynamic::from(hash.to_vec())
  }
}

pub fn init_engine(
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
) -> Result<(), Box<EvalAltResult>> {
  engine
    .register_type_with_name::<UtilsPlugin>("UtilsPlugin")
    .register_result_fn("babe_secondary_slot_author", UtilsPlugin::babe_secondary_slot_author)
    .register_result_fn("from_hex", UtilsPlugin::from_hex)
    .register_fn("to_hex", UtilsPlugin::to_hex)
    .register_fn("blake2_128", UtilsPlugin::blake2_128)
    .register_fn("blake2_256", UtilsPlugin::blake2_256)
    .register_result_fn("write_hex_to_file", UtilsPlugin::write_hex_to_file);

  let plugin = UtilsPlugin::new()?;
  globals.insert("Utils".into(), Dynamic::from(plugin.clone()));

  Ok(())
}
