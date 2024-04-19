use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use hex::FromHex;

use sp_core::{blake2_256, H256};
use parity_scale_codec::Encode;

use rand::{Rng, rngs::StdRng, SeedableRng};

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
      return Err(format!("Invalid randomness type.").into());
    };
    let rand = H256::from_slice(&rand);
    let seed = (rand, slot).using_encoded(blake2_256);
    let mut rng = StdRng::from_seed(seed);
    let idx = rng.gen_range(0..authorities_len);
    Ok(idx)
    /*
    let rand = sp_core::U256::from((rand, slot).using_encoded(blake2_256));

    let authorities_len = sp_core::U256::from(authorities_len);
    let idx = rand % authorities_len;

    Ok(idx.as_u32() as _)
    */
  }

  pub fn write_hex_to_file(&mut self, file: &str, val: &str) -> Result<(), Box<EvalAltResult>> {
    let bytes = Vec::from_hex(&val[2..]).map_err(|e| e.to_string())?;
    let mut f = File::create(file).map_err(|e| e.to_string())?;
    f.write_all(&bytes).map_err(|e| e.to_string())?;

    Ok(())
  }
}

pub fn init_engine(
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
) -> Result<(), Box<EvalAltResult>> {
  engine
    .register_type_with_name::<UtilsPlugin>("UtilsPlugin")
    .register_result_fn("babe_secondary_slot_author", UtilsPlugin::babe_secondary_slot_author)
    .register_result_fn("write_hex_to_file", UtilsPlugin::write_hex_to_file);

  let plugin = UtilsPlugin::new()?;
  globals.insert("Utils".into(), Dynamic::from(plugin.clone()));

  Ok(())
}
