use std::any::TypeId;
use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString};

use polymesh_primitives::{Claim, IdentityId, Ticker};

use sp_runtime::MultiSignature;

use crate::client::Client;
use crate::types::TypesRegistry;
use crate::users::SharedUser;

pub fn str_to_ticker(val: &str) -> Result<Ticker, Box<EvalAltResult>> {
  let ticker = if val.starts_with("0x") {
    let b = hex::decode(&val.as_bytes()[2..]).map_err(|e| e.to_string())?;
    Ticker::from_slice_truncated(b.as_slice())
  } else if val.len() == 12 {
    Ticker::from_slice_truncated(val.as_bytes())
  } else {
    let mut ticker = [0u8; 12];
    for (idx, b) in val.as_bytes().iter().take(12).enumerate() {
      ticker[idx] = *b;
    }
    Ticker::from_slice_truncated(&ticker[..])
  };
  Ok(ticker)
}

#[derive(Clone)]
pub struct PolymeshUtils {}

impl PolymeshUtils {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {})
  }
}

pub fn init_types_registry(types_registry: &TypesRegistry) -> Result<(), Box<EvalAltResult>> {
  types_registry.add_init(|types, _rpc, _hash| {
    types.custom_encode("Signatory", TypeId::of::<SharedUser>(), |value, data| {
      let user = value.cast::<SharedUser>();
      // Encode variant idx.
      data.encode(1u8); // Signatory::Account
      data.encode(user.public());
      Ok(())
    })?;
    types.register_scale_type::<IdentityId>("IdentityId")?;
    types.register_scale_type::<IdentityId>("polymesh_primitives::identity_id::IdentityId")?;
    types.custom_encode("Ticker", TypeId::of::<ImmutableString>(), |value, data| {
      let value = value.cast::<ImmutableString>();
      let ticker = str_to_ticker(value.as_str())?;
      data.encode(&ticker);
      Ok(())
    })?;
    types.custom_encode(
      "polymesh_primitives::ticker::Ticker",
      TypeId::of::<ImmutableString>(),
      |value, data| {
        let value = value.cast::<ImmutableString>();
        let ticker = str_to_ticker(value.as_str())?;
        data.encode(&ticker);
        Ok(())
      },
    )?;
    types.register_scale_type::<Claim>("Claim")?;

    types.register_scale_type::<MultiSignature>("OffChainSignature")?;
    types.custom_encode("H512", TypeId::of::<MultiSignature>(), |value, data| {
      let sig = value.cast::<MultiSignature>();
      match sig {
        MultiSignature::Ed25519(hash) => data.encode(hash),
        MultiSignature::Sr25519(hash) => data.encode(hash),
        _ => Err(format!("Unsupported Signature -> H512 conversion."))?,
      }
      Ok(())
    })?;

    Ok(())
  });
  Ok(())
}

pub fn init_engine(
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
  _client: &Client,
) -> Result<(), Box<EvalAltResult>> {
  engine
    .register_type_with_name::<PolymeshUtils>("PolymeshUtils")
    .register_type_with_name::<Claim>("Claim")
    .register_type_with_name::<IdentityId>("IdentityId")
    .register_fn("==", |v1: IdentityId, v2: IdentityId| v1 == v2)
    .register_fn("!=", |v1: IdentityId, v2: IdentityId| v1 != v2)
    .register_fn("to_string", |did: &mut IdentityId| format!("{:?}", did))
    .register_type_with_name::<Ticker>("Ticker")
    .register_fn("to_string", |ticker: &mut Ticker| {
      let s = String::from_utf8_lossy(ticker.as_slice());
      format!("{}", s)
    });

  let utils = PolymeshUtils::new()?;
  globals.insert("PolymeshUtils".into(), Dynamic::from(utils.clone()));

  Ok(())
}
