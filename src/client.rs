use std::sync::{Arc, RwLock};

use frame_metadata::RuntimeMetadataPrefixed;
use sp_runtime::generic::Era;
use sp_core::sr25519::Pair;

use substrate_api_client::Api;
use substrate_api_client::rpc::XtStatus;
use substrate_api_client::extrinsic::{
  compose_extrinsic_offline,
  xt_primitives::*,
};

use rhai::{Engine, EvalAltResult};

use super::metadata::EncodedCall;

pub struct InnerClient {
  api: Api<Pair>,
}

impl InnerClient {
  pub fn from_api(api: Api<Pair>) -> Arc<RwLock<Self>> {
    Arc::new(RwLock::new(Self { api }))
  }

  pub fn check_url(&self, url: &str) -> bool {
    self.api.url == url
  }

  pub fn url(&self) -> &str {
    &self.api.url
  }

  pub fn print_metadata(&self) {
    self.api.metadata.print_overview();
  }

  pub fn get_metadata(&self) -> Result<RuntimeMetadataPrefixed, Box<EvalAltResult>> {
    Ok(self.api.get_metadata().map_err(|e| e.to_string())?)
  }

  pub fn submit_call(&self, call: EncodedCall) -> Result<String, Box<EvalAltResult>> {
    let xt = if let Some(signer) = &self.api.signer {
      compose_extrinsic_offline(
        signer,
        call.into_call(),
        self.api.get_nonce(),
        Era::Immortal,
        self.api.genesis_hash,
        self.api.genesis_hash,
        self.api.runtime_version.spec_version,
        self.api.runtime_version.transaction_version,
      ).hex_encode()
    } else {
      (UncheckedExtrinsicV4 {
        signature: None,
        function: call.into_call(),
      }).hex_encode()
    };
    let hash = self.api.send_extrinsic(xt, XtStatus::InBlock)
      .map_err(|e| e.to_string())?;

    /*
    if let Some(hash) = hash {
      let events = self.api.get_storage_value("System", "Events", Some(hash))
        .map_err(|e| e.to_string())?;
      eprintln!("events = {:?}", events)
    }
    */

    Ok(hash.map(|hash| format!("{:x}", hash))
      .unwrap_or_default())
  }
}

#[derive(Clone)]
pub struct Client {
  inner: Arc<RwLock<InnerClient>>,
}

impl Client {
  pub fn connect(url: &str) -> Result<Self, Box<EvalAltResult>> {
    let api = Api::new(url.into()).map_err(|e| e.to_string())?;
    Ok(Self { inner: InnerClient::from_api(api) })
  }

  pub fn connect_with_signer(signer: Pair, url: &str) -> Result<Self, Box<EvalAltResult>> {
    let api = Api::new(url.into())
      .and_then(|api| api.set_signer(signer))
      .map_err(|e| e.to_string())?;
    Ok(Self { inner: InnerClient::from_api(api) })
  }

  pub fn check_url(&self, url: &str) -> bool {
    self.inner.read().unwrap().check_url(url)
  }

  pub fn print_metadata(&mut self) {
    self.inner.read().unwrap().print_metadata()
  }

  pub fn get_metadata(&self) -> Result<RuntimeMetadataPrefixed, Box<EvalAltResult>> {
    self.inner.read().unwrap().get_metadata()
  }

  pub fn submit_call(&self, call: EncodedCall) -> Result<String, Box<EvalAltResult>> {
    self.inner.read().unwrap().submit_call(call)
  }

  pub fn inner(&self) -> Arc<RwLock<InnerClient>> {
    self.inner.clone()
  }
}

pub fn init_engine(engine: &mut Engine) {
  engine
    .register_type_with_name::<Client>("Client")
    .register_fn("print_metadata", Client::print_metadata);
}
