use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use hex::FromHex;

use rhai::{Dynamic, Engine, EvalAltResult};

#[derive(Clone)]
pub struct UtilsPlugin {}

impl UtilsPlugin {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {})
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
    .register_result_fn("write_hex_to_file", UtilsPlugin::write_hex_to_file)
    ;

  let plugin = UtilsPlugin::new()?;
  globals.insert("Utils".into(), Dynamic::from(plugin.clone()));

  Ok(())
}
