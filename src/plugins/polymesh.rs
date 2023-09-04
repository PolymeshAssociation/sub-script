use std::any::TypeId;
use std::collections::HashMap;

use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString};

use polymesh_primitives::{
  Claim, IdentityId, Ticker,
};
#[cfg(feature = "confidential_identity")]
use polymesh_primitives::{
  investor_zkproof_data::v1, valid_proof_of_investor, CddId, InvestorUid, Scope,
};

use parity_scale_codec::Decode;

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

  #[cfg(feature = "confidential_identity")]
  pub fn did_to_uid(&mut self, did: IdentityId) -> InvestorUid {
    InvestorUid::from(confidential_identity_v1::mocked::make_investor_uid(
      did.as_bytes(),
    ))
  }

  #[cfg(feature = "confidential_identity")]
  pub fn make_cdd_claim(&mut self, did: IdentityId) -> Claim {
    let uid = InvestorUid::from(confidential_identity_v1::mocked::make_investor_uid(
      did.as_bytes(),
    ));
    self.make_cdd_claim_uid(did, uid)
  }

  #[cfg(feature = "confidential_identity")]
  pub fn make_cdd_claim_uid(&mut self, did: IdentityId, uid: InvestorUid) -> Claim {
    let cdd_id = CddId::new_v1(did, uid);
    Claim::CustomerDueDiligence(cdd_id)
  }

  #[cfg(feature = "confidential_identity")]
  pub fn create_investor_uniqueness(
    &mut self,
    did: IdentityId,
    ticker: &str,
    uid: InvestorUid,
  ) -> Result<Vec<Dynamic>, Box<EvalAltResult>> {
    let ticker = str_to_ticker(ticker)?;

    let proof = v1::InvestorZKProofData::new(&did, &uid, &ticker);
    let cdd_id = CddId::new_v1(did, uid);

    let scope_id = v1::InvestorZKProofData::make_scope_id(&ticker.as_slice(), &uid);

    let claim = Claim::InvestorUniqueness(Scope::Ticker(ticker), scope_id, cdd_id);
    Ok(vec![Dynamic::from(claim), Dynamic::from(proof)])
  }

  #[cfg(feature = "confidential_identity")]
  pub fn validate_investor_uniqueness(
    &mut self,
    target: IdentityId,
    claim: Claim,
    proof: v1::InvestorZKProofData,
  ) -> Result<bool, Box<EvalAltResult>> {
    // Decode needed fields and ensures `claim` is `InvestorUniqueness*`.
    let (scope, _scope_id, _cdd_id) = match &claim {
      Claim::InvestorUniqueness(scope, scope_id, cdd_id) => (scope, scope_id.clone(), cdd_id),
      Claim::InvestorUniquenessV2(_cdd_id) => {
        return Err(format!("Unsupported V2 uniqueness claim.").into());
      }
      _ => Err(format!("ClaimVariantNotAllowed"))?,
    };

    // Verify the confidential claim.
    let is_valid = valid_proof_of_investor::v1::evaluate_claim(scope, &claim, &target, &proof);
    Ok(is_valid)
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
    types.custom_encode("IdentityId", TypeId::of::<IdentityId>(), |value, data| {
      data.encode(value.cast::<IdentityId>());
      Ok(())
    })?;
    types.custom_decode("IdentityId", |mut input, _is_compact| {
      Ok(Dynamic::from(IdentityId::decode(&mut input)?))
    })?;
    types.custom_encode(
      "polymesh_primitives::identity_id::IdentityId",
      TypeId::of::<IdentityId>(),
      |value, data| {
        data.encode(value.cast::<IdentityId>());
        Ok(())
      },
    )?;
    types.custom_decode(
      "polymesh_primitives::identity_id::IdentityId",
      |mut input, _is_compact| Ok(Dynamic::from(IdentityId::decode(&mut input)?)),
    )?;
    types.custom_encode("Ticker", TypeId::of::<ImmutableString>(), |value, data| {
      let value = value.cast::<ImmutableString>();
      let ticker = str_to_ticker(value.as_str())?;
      data.encode(&ticker);
      Ok(())
    })?;
    types.custom_encode("polymesh_primitives::ticker::Ticker", TypeId::of::<ImmutableString>(), |value, data| {
      let value = value.cast::<ImmutableString>();
      let ticker = str_to_ticker(value.as_str())?;
      data.encode(&ticker);
      Ok(())
    })?;
    types.custom_encode("Claim", TypeId::of::<Claim>(), |value, data| {
      data.encode(value.cast::<Claim>());
      Ok(())
    })?;
    types.custom_decode("Claim", |mut input, _is_compact| {
      Ok(Dynamic::from(Claim::decode(&mut input)?))
    })?;
    #[cfg(feature = "confidential_identity")]
    types.custom_encode(
      "InvestorZKProofData",
      TypeId::of::<v1::InvestorZKProofData>(),
      |value, data| {
        data.encode(value.cast::<v1::InvestorZKProofData>());
        Ok(())
      },
    )?;
    #[cfg(feature = "confidential_identity")]
    types.custom_decode("InvestorZKProofData", |mut input, _is_compact| {
      Ok(Dynamic::from(v1::InvestorZKProofData::decode(&mut input)?))
    })?;
    types.custom_encode(
      "OffChainSignature",
      TypeId::of::<MultiSignature>(),
      |value, data| {
        data.encode(value.cast::<MultiSignature>());
        Ok(())
      },
    )?;
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

  #[cfg(feature = "confidential_identity")]
  {
    engine
      .register_result_fn(
        "create_investor_uniqueness",
        PolymeshUtils::create_investor_uniqueness,
      )
      .register_result_fn(
        "validate_investor_uniqueness",
        PolymeshUtils::validate_investor_uniqueness,
      )
      .register_fn("did_to_uid", PolymeshUtils::did_to_uid)
      .register_fn("make_cdd_claim", PolymeshUtils::make_cdd_claim)
      .register_fn("make_cdd_claim_uid", PolymeshUtils::make_cdd_claim_uid)
      .register_type_with_name::<v1::InvestorZKProofData>("InvestorZKProofData")
      .register_type_with_name::<InvestorUid>("InvestorUid")
      .register_fn("to_string", |uid: &mut InvestorUid| format!("{:?}", uid));
  }

  let utils = PolymeshUtils::new()?;
  globals.insert("PolymeshUtils".into(), Dynamic::from(utils.clone()));

  Ok(())
}
