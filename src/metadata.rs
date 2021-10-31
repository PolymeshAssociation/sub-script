use std::collections::HashMap;

use frame_metadata::{
  DecodeDifferent, DecodeDifferentArray,
  FunctionArgumentMetadata, FunctionMetadata,
  RuntimeMetadata, RuntimeMetadataPrefixed, META_RESERVED,
};

use rhai::{Dynamic, Engine, EvalAltResult, Scope};

use super::types::{TypeLookup, TypeRef};

fn decode<B: 'static, O: 'static>(
  encoded: &DecodeDifferent<B, O>,
) -> Result<&O, Box<EvalAltResult>> {
  match encoded {
    DecodeDifferent::Decoded(val) => Ok(val),
    _ => Err(format!("Failed to decode value.").into()),
  }
}

#[derive(Clone)]
pub struct Metadata {
  url: String,
  modules: HashMap<String, ModuleMetadata>,
}

impl Metadata {
  pub fn new(url: &str, lookup: &TypeLookup) -> Result<Self, Box<EvalAltResult>> {
    let client = crate::client::Client::connect(url)?;

    // Get runtime metadata.
    let metadata_prefixed = client.get_metadata()?;

    Self::decode(url, metadata_prefixed, lookup)
  }

  pub fn decode(
    url: &str,
    metadata_prefixed: RuntimeMetadataPrefixed,
    lookup: &TypeLookup,
  ) -> Result<Self, Box<EvalAltResult>> {
    if metadata_prefixed.0 != META_RESERVED {
      return Err(format!("Invalid metadata prefix {}", metadata_prefixed.0).into());
    }

    // Get versioned metadata.
    let md = match metadata_prefixed.1 {
      RuntimeMetadata::V12(v12) => v12,
      _ => {
        return Err(format!("Unsupported metadata version").into());
      }
    };

    let mut api_md = Self {
      url: url.into(),
      modules: HashMap::new(),
    };

    // Decode module metadata.
    decode(&md.modules)?
      .iter()
      .try_for_each(|m| -> Result<(), Box<EvalAltResult>> {
        let m = ModuleMetadata::decode(m, lookup)?;
        let name = m.name.clone();
        api_md.modules.insert(name, m);
        Ok(())
      })?;

    Ok(api_md)
  }

  fn modules(&mut self) -> Vec<Dynamic> {
    self.modules.values().cloned().map(Dynamic::from).collect()
  }

  fn indexer_get(&mut self, name: String) -> Result<Dynamic, Box<EvalAltResult>> {
    let m = self
      .modules
      .get(&name)
      .cloned()
      .ok_or_else(|| format!("Module {} not found", name))?;
    Ok(Dynamic::from(m))
  }
}

#[derive(Clone)]
pub struct ModuleMetadata {
  name: String,
  index: u8,
  storage_prefix: String,
  storage: HashMap<String, StorageMetadata>,
  funcs: HashMap<String, FuncMetadata>,
}

impl ModuleMetadata {
  fn decode(md: &frame_metadata::ModuleMetadata, lookup: &TypeLookup) -> Result<Self, Box<EvalAltResult>> {
    let mod_idx = md.index;
    let mod_name = decode(&md.name)?;
    let mut module = Self {
      name: mod_name.clone(),
      index: mod_idx,
      storage_prefix: "".into(),
      storage: HashMap::new(),
      funcs: HashMap::new(),
    };

    // Decode module functions.
    if let Some(calls) = &md.calls {
      decode(calls)?.iter().enumerate().try_for_each(
        |(func_idx, md)| -> Result<(), Box<EvalAltResult>> {
          let func = FuncMetadata::decode(&mod_name, mod_idx, func_idx as u8, md, lookup)?;
          let name = func.name.clone();
          module.funcs.insert(name, func);
          Ok(())
        },
      )?;
    }

    // Decode module storage.
    if let Some(storage) = &md.storage {
      let md = decode(storage)?;
      let mod_prefix = decode(&md.prefix)?;
      decode(&md.entries)?
        .iter()
        .try_for_each(|md| -> Result<(), Box<EvalAltResult>> {
          let storage = StorageMetadata::decode(mod_prefix, md)?;
          let name = storage.name.clone();
          module.storage.insert(name, storage);
          Ok(())
        })?;
      module.storage_prefix = mod_prefix.into();
    }

    Ok(module)
  }

  fn funcs(&mut self) -> Vec<Dynamic> {
    self.funcs.values().cloned().map(Dynamic::from).collect()
  }

  fn to_string(&mut self) -> String {
    format!("ModuleMetadata: {}", self.name)
  }

  fn indexer_get(&mut self, name: String) -> Result<Dynamic, Box<EvalAltResult>> {
    // Look for storage value matching that name.
    if let Some(storage) = self.storage.get(&name) {
      Ok(Dynamic::from(storage.clone()))
    } else {
      // If no matching storage, look for a matching call.
      if let Some(func) = self.funcs.get(&name) {
        Ok(Dynamic::from(func.clone()))
      } else {
        Err(format!("Storage or function {} not found", name).into())
      }
    }
  }
}

#[derive(Clone)]
pub struct StorageMetadata {
  prefix: String,
  name: String,
  docs: Docs,
}

impl StorageMetadata {
  fn decode(prefix: &str, md: &frame_metadata::StorageEntryMetadata) -> Result<Self, Box<EvalAltResult>> {
    let storage = Self {
      prefix: prefix.into(),
      name: decode(&md.name)?.clone(),
      docs: Docs::decode(&md.documentation)?,
    };

    Ok(storage)
  }

  fn title(&mut self) -> String {
    self.docs.title()
  }

  fn docs(&mut self) -> String {
    self.docs.to_string()
  }

  fn to_string(&mut self) -> String {
    format!("StorageMetadata: {}", self.name)
  }
}

#[derive(Clone)]
pub struct FuncMetadata {
  mod_name: String,
  name: String,
  mod_idx: u8,
  func_idx: u8,
  args: Vec<ArgMetadata>,
  docs: Docs,
}

impl FuncMetadata {
  fn decode(
    mod_name: &str,
    mod_idx: u8,
    func_idx: u8,
    md: &FunctionMetadata,
    lookup: &TypeLookup,
  ) -> Result<Self, Box<EvalAltResult>> {
    let mut func = Self {
      mod_name: mod_name.into(),
      name: decode(&md.name)?.clone(),
      mod_idx,
      func_idx,
      args: Vec::new(),
      docs: Docs::decode(&md.documentation)?,
    };

    // Decode function arguments.
    decode(&md.arguments)?
      .iter()
      .try_for_each(|md| -> Result<(), Box<EvalAltResult>> {
        let arg = ArgMetadata::decode(md, lookup)?;
        func.args.push(arg);
        Ok(())
      })?;

    Ok(func)
  }

  fn args(&mut self) -> Dynamic {
    let args: Vec<Dynamic> = self.args.iter().map(|arg| Dynamic::from(arg.clone())).collect();
    Dynamic::from(args)
  }

  fn title(&mut self) -> String {
    self.docs.title()
  }

  fn docs(&mut self) -> String {
    self.docs.to_string()
  }

  fn to_string(&mut self) -> String {
    let args = self
      .args
      .iter_mut()
      .map(|a| a.to_string())
      .collect::<Vec<String>>()
      .join(", ");
    format!("Func: {}.{}({})", self.mod_name, self.name, args)
  }
}

#[derive(Clone)]
pub struct ArgMetadata {
  name: String,
  ty: String,
  ty_meta: TypeRef,
}

impl ArgMetadata {
  fn decode(md: &FunctionArgumentMetadata, lookup: &TypeLookup) -> Result<Self, Box<EvalAltResult>> {
    let ty = decode(&md.ty)?.clone();
    let ty_meta = lookup.parse_type(&ty)?;
    let arg = Self {
      name: decode(&md.name)?.clone(),
      ty: ty.clone(),
      ty_meta,
    };

    Ok(arg)
  }

  fn get_name(&mut self) -> String {
    self.name.clone()
  }

  fn get_type(&mut self) -> String {
    self.ty.clone()
  }

  fn get_meta(&mut self) -> TypeRef {
    self.ty_meta.clone()
  }

  fn to_string(&mut self) -> String {
    format!("{}: {:?}", self.name, self.ty_meta)
  }
}

#[derive(Clone)]
pub struct Docs {
  lines: Vec<String>,
}

impl Docs {
  fn decode(md: &DecodeDifferentArray<&'static str, String>) -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {
      lines: decode(md)?.clone(),
    })
  }

  pub fn title(&mut self) -> String {
    self
      .lines
      .first()
      .map(|s| s.trim().into())
      .unwrap_or_default()
  }

  fn to_string(&mut self) -> String {
    self.lines.join("\n")
  }
}

pub fn init_engine(engine: &mut Engine) {
  engine
    .register_type_with_name::<Metadata>("Metadata")
    .register_get("modules", Metadata::modules)
    .register_indexer_get_result(Metadata::indexer_get)
    .register_type_with_name::<ModuleMetadata>("ModuleMetadata")
    .register_get("funcs", ModuleMetadata::funcs)
    .register_fn("to_string", ModuleMetadata::to_string)
    .register_indexer_get_result(ModuleMetadata::indexer_get)
    .register_type_with_name::<StorageMetadata>("StorageMetadata")
    .register_fn("to_string", StorageMetadata::to_string)
    .register_get("title", StorageMetadata::title)
    .register_get("docs", StorageMetadata::docs)
    .register_type_with_name::<FuncMetadata>("FuncMetadata")
    .register_fn("to_string", FuncMetadata::to_string)
    .register_get("args", FuncMetadata::args)
    .register_get("title", FuncMetadata::title)
    .register_get("docs", FuncMetadata::docs)
    .register_type_with_name::<ArgMetadata>("ArgMetadata")
    .register_fn("to_string", ArgMetadata::to_string)
    .register_fn("name", ArgMetadata::get_name)
    .register_fn("type", ArgMetadata::get_type)
    .register_fn("meta", ArgMetadata::get_meta)
    .register_type_with_name::<Docs>("Docs")
    .register_fn("to_string", Docs::to_string)
    .register_get("title", Docs::title);
}

pub fn init_scope(url: &str, lookup: &TypeLookup, scope: &mut Scope<'_>) -> Result<Metadata, Box<EvalAltResult>> {
  let lookup = Metadata::new(url, lookup)?;
  scope.push_constant("METADATA", lookup.clone());

  Ok(lookup)
}
