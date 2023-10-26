use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryFrom;
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, RwLock};

use parity_scale_codec::{Compact, Encode, Decode, Error as PError, Input};
use serde_json::{json, Map, Value};

#[cfg(feature = "v14")]
use scale_info::{Field, form::PortableForm, PortableRegistry, Type, TypeDef, TypeDefPrimitive};

use rust_decimal::{prelude::ToPrimitive, Decimal};

use rhai::{Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map as RMap};
use smartstring::{LazyCompact, SmartString};

use indexmap::map::IndexMap;

use dashmap::DashMap;

use super::block::{hash_from_dynamic, BlockHash};
use super::engine::EngineOptions;
use super::metadata::EncodedArgs;
use super::metadata::Metadata;
use super::rpc::RpcHandler;
use super::users::SharedUser;
use crate::RuntimeVersion;

#[cfg(feature = "v14")]
pub fn is_type_compact(ty: &Type<PortableForm>) -> bool {
  match ty.type_def() {
    TypeDef::Compact(_) => true,
    _ => false,
  }
}

#[cfg(feature = "v14")]
pub fn get_type_name(ty: &Type<PortableForm>, types: &PortableRegistry, full: bool) -> String {
  let name = match ty.type_def() {
    TypeDef::Sequence(s) => {
      let elm_ty = types
        .resolve(s.type_param().id())
        .expect("Failed to resolve sequence element type");
      format!("Vec<{}>", get_type_name(elm_ty, types, full))
    }
    TypeDef::Array(a) => {
      let elm_ty = types
        .resolve(a.type_param().id())
        .expect("Failed to resolve array element type");
      format!("[{}; {}]", get_type_name(elm_ty, types, full), a.len())
    }
    TypeDef::Tuple(t) => {
      let fields = t
        .fields()
        .iter()
        .map(|f| {
          let f_ty = types
            .resolve(f.id())
            .expect("Failed to resolve tuple element type");
          get_type_name(f_ty, types, full)
        })
        .collect::<Vec<_>>();
      format!("({})", fields.join(","))
    }
    TypeDef::Primitive(p) => {
      use TypeDefPrimitive::*;
      match p {
        Bool => "bool".into(),
        Char => "char".into(),
        Str => "Text".into(),
        U8 => "u8".into(),
        U16 => "u16".into(),
        U32 => "u32".into(),
        U64 => "u64".into(),
        U128 => "u128".into(),
        U256 => "u256".into(),
        I8 => "i8".into(),
        I16 => "i16".into(),
        I32 => "i32".into(),
        I64 => "i64".into(),
        I128 => "i128".into(),
        I256 => "i256".into(),
      }
    }
    TypeDef::Compact(c) => {
      let elm_ty = types
        .resolve(c.type_param().id())
        .expect("Failed to resolve Compact type");
      format!("Compact<{}>", get_type_name(elm_ty, types, full))
    }
    _ => {
      if full {
        format!("{}", ty.path())
      } else {
        ty.path().ident().expect("Missing type name")
      }
    }
  };
  let ty_params = ty.type_params();
  if ty_params.len() > 0 {
    let params = ty_params
      .iter()
      .map(|p| match p.ty() {
        Some(ty) => {
          let p_ty = types
            .resolve(ty.id())
            .expect("Failed to resolve type parameter");
          get_type_name(p_ty, types, full)
        }
        None => p.name().clone(),
      })
      .collect::<Vec<_>>();
    format!("{}<{}>", name, params.join(","))
  } else {
    name
  }
}

#[derive(Clone, Debug, Default)]
pub struct EnumVariant {
  idx: u8,
  name: String,
  type_ref: Option<TypeRef>,
}

#[derive(Clone, Debug, Default)]
pub struct EnumVariants {
  variants: Vec<Option<EnumVariant>>,
  name_map: HashMap<String, u8>,
}

impl EnumVariants {
  pub fn new() -> Self {
    Default::default()
  }

  pub fn insert_at(&mut self, idx: u8, name: &str, type_ref: Option<TypeRef>) {
    let len = idx as usize;
    if let Some(variant) = self.variants.get_mut(len) {
      *variant = Some(EnumVariant {
        idx,
        name: name.into(),
        type_ref,
      });
    } else {
      while len > self.variants.len() {
        self.variants.push(None);
      }
      let insert_idx = self.insert(name, type_ref);
      assert!(insert_idx == idx);
    }
  }

  pub fn insert(&mut self, name: &str, type_ref: Option<TypeRef>) -> u8 {
    let idx = self.variants.len() as u8;
    self.variants.push(Some(EnumVariant {
      idx,
      name: name.into(),
      type_ref,
    }));
    self.name_map.insert(name.into(), idx);
    idx
  }

  pub fn get_by_idx(&self, idx: u8) -> Option<&EnumVariant> {
    self.variants.get(idx as usize).and_then(|v| v.as_ref())
  }

  pub fn get_by_name(&self, name: &str) -> Option<&EnumVariant> {
    self
      .name_map
      .get(name)
      .and_then(|idx| self.get_by_idx(*idx))
  }
}

#[derive(Clone)]
pub struct WrapEncodeFn(
  Arc<dyn Fn(Dynamic, &mut EncodedArgs) -> Result<(), Box<EvalAltResult>> + Send + Sync + 'static>,
);

impl WrapEncodeFn {
  pub fn encode_value(
    &self,
    value: Dynamic,
    data: &mut EncodedArgs,
  ) -> Result<(), Box<EvalAltResult>> {
    self.0(value, data)
  }
}

pub struct BoxedInput<'a>(Box<&'a mut dyn Input>);

impl<'a> BoxedInput<'a> {
  pub fn new(input: &'a mut dyn Input) -> Self {
    let boxed = Box::new(input);
    Self(boxed)
  }
}

impl<'a> Input for BoxedInput<'a> {
  fn remaining_len(&mut self) -> Result<Option<usize>, PError> {
    self.0.remaining_len()
  }

  fn read(&mut self, into: &mut [u8]) -> Result<(), PError> {
    self.0.read(into)
  }
}

#[derive(Clone)]
pub struct WrapDecodeFn(
  Arc<dyn Fn(BoxedInput, bool) -> Result<Dynamic, PError> + Send + Sync + 'static>,
);

impl WrapDecodeFn {
  pub fn decode_value<I: Input>(&self, input: &mut I, is_compact: bool) -> Result<Dynamic, PError> {
    let boxed = BoxedInput::new(input);
    self.0(boxed, is_compact)
  }
}

#[derive(Clone)]
pub struct CustomType {
  encode_map: HashMap<TypeId, WrapEncodeFn>,
  decode: Option<WrapDecodeFn>,
  type_meta: Box<TypeMeta>,
}

impl std::fmt::Debug for CustomType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_fmt(format_args!("CustomType({:?})", self.type_meta))
  }
}

impl CustomType {
  pub fn new(type_meta: TypeMeta) -> Self {
    Self {
      encode_map: Default::default(),
      decode: None,
      type_meta: Box::new(type_meta),
    }
  }

  pub fn is_compact(&self) -> bool {
    self.type_meta.is_compact()
  }

  pub fn is_u8(&self) -> bool {
    self.type_meta.is_u8()
  }

  pub fn custom_encode(&mut self, type_id: TypeId, func: WrapEncodeFn) {
    self.encode_map.insert(type_id, func);
  }

  pub fn custom_decode(&mut self, func: WrapDecodeFn) {
    self.decode = Some(func);
  }

  pub fn encode_value(
    &self,
    value: Dynamic,
    data: &mut EncodedArgs,
  ) -> Result<(), Box<EvalAltResult>> {
    let type_id = value.type_id();
    log::debug!("encode Custom: type_id={:?}", type_id);
    if let Some(func) = self.encode_map.get(&type_id) {
      func.encode_value(value, data)
    } else {
      self.type_meta.encode_value(value, data)
    }
  }

  pub fn decode_value<I: Input>(&self, input: &mut I, is_compact: bool) -> Result<Dynamic, PError> {
    match &self.decode {
      Some(func) => func.decode_value(input, is_compact),
      None => self.type_meta.decode_value(input, is_compact),
    }
  }
}

#[derive(Clone)]
pub struct TypeRef(Arc<RwLock<TypeMeta>>);

impl TypeRef {
  fn to_string(&mut self) -> String {
    format!("TypeRef: {:?}", self.0.read().unwrap())
  }

  pub fn custom_encode(&self, type_id: TypeId, func: WrapEncodeFn) {
    self.0.write().unwrap().custom_encode(type_id, func)
  }

  pub fn custom_decode(&self, func: WrapDecodeFn) {
    self.0.write().unwrap().custom_decode(func)
  }

  pub fn encode_value(
    &self,
    value: Dynamic,
    data: &mut EncodedArgs,
  ) -> Result<(), Box<EvalAltResult>> {
    self.0.read().unwrap().encode_value(value, data)
  }

  pub fn decode_value<I: Input>(&self, input: &mut I, is_compact: bool) -> Result<Dynamic, PError> {
    self.0.read().unwrap().decode_value(input, is_compact)
  }

  pub fn encode_arg(&self, value: Dynamic) -> Result<EncodedArgs, Box<EvalAltResult>> {
    let mut data = EncodedArgs::new();
    self.encode_value(value, &mut data)?;
    Ok(data)
  }

  pub fn encode(&self, value: Dynamic) -> Result<Vec<u8>, Box<EvalAltResult>> {
    let data = self.encode_arg(value)?;
    Ok(data.into_inner())
  }

  pub fn decode(&self, data: Vec<u8>) -> Result<Dynamic, Box<EvalAltResult>> {
    Ok(
      self
        .decode_value(&mut &data[..], false)
        .map_err(|e| e.to_string())?,
    )
  }

  pub fn encode_mut(&mut self, value: Dynamic) -> Result<Vec<u8>, Box<EvalAltResult>> {
    self.encode(value)
  }

  pub fn decode_mut(&mut self, data: Vec<u8>) -> Result<Dynamic, Box<EvalAltResult>> {
    self.decode(data)
  }

  pub fn is_compact(&self) -> bool {
    self.0.read().unwrap().is_compact()
  }

  pub fn is_u8(&self) -> bool {
    self.0.read().unwrap().is_u8()
  }
}

impl From<TypeMeta> for TypeRef {
  fn from(meta: TypeMeta) -> Self {
    TypeRef(Arc::new(RwLock::new(meta.clone())))
  }
}

impl std::fmt::Debug for TypeRef {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    let meta = self.0.read().unwrap();
    meta.fmt(f)
  }
}

#[derive(Clone)]
pub enum TypeMeta {
  /// Zero-sized `()`
  Unit,
  /// (width, signed)
  Integer(u8, bool),
  Bool,
  Option(TypeRef),
  Box(TypeRef),
  /// Special case for `Option<bool>`
  OptionBool,
  /// (ok, err)
  Result(TypeRef, TypeRef),
  Vector(TypeRef),

  BTreeSet(TypeRef),
  BTreeMap(TypeRef, TypeRef),

  /// Fixed length.
  Slice(usize, TypeRef),
  String,

  Tuple(Vec<TypeRef>),
  Struct(IndexMap<String, TypeRef>),
  Enum(EnumVariants),

  Compact(TypeRef),
  NewType(String, TypeRef),

  Unresolved(String),

  CustomType(CustomType),
}

impl std::fmt::Debug for TypeMeta {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    match self {
      Self::Unit => f.write_fmt(format_args!("Unit")),
      Self::Integer(size, compact) => f.write_fmt(format_args!("Integer({size}, {compact})")),
      Self::Bool => f.write_fmt(format_args!("Bool")),
      Self::Option(_) => f.write_fmt(format_args!("Option")),
      Self::Box(_) => f.write_fmt(format_args!("Box")),
      Self::OptionBool => f.write_fmt(format_args!("OptionBool")),
      Self::Result(_, _) => f.write_fmt(format_args!("Result")),
      Self::Vector(_) => f.write_fmt(format_args!("Vector")),

      Self::BTreeSet(_) => f.write_fmt(format_args!("BTreeSet")),
      Self::BTreeMap(_, _) => f.write_fmt(format_args!("BTreeMap")),

      Self::Slice(len, _) => f.write_fmt(format_args!("Slice({len})")),
      Self::String => f.write_fmt(format_args!("String")),

      Self::Tuple(_) => f.write_fmt(format_args!("Tuple")),
      Self::Struct(_) => f.write_fmt(format_args!("Struct")),
      Self::Enum(_) => f.write_fmt(format_args!("Enum")),

      Self::Compact(_) => f.write_fmt(format_args!("Compact")),
      Self::NewType(name, _) => f.write_fmt(format_args!("NewType({name})")),

      Self::Unresolved(name) => f.write_fmt(format_args!("Unresolved({name})")),

      Self::CustomType(_) => f.write_fmt(format_args!("CustomType")),
    }
  }
}

impl Default for TypeMeta {
  fn default() -> Self {
    Self::Unit
  }
}

impl TypeMeta {
  fn to_string(&mut self) -> String {
    format!("TypeMeta: {:?}", self)
  }

  pub fn is_compact(&self) -> bool {
    match self {
      Self::Option(ty) => ty.is_compact(),
      Self::Box(ty) => ty.is_compact(),
      Self::Compact(_) => true,
      Self::NewType(_, ty) => ty.is_compact(),
      Self::CustomType(ty) => ty.is_compact(),
      _ => false
    }
  }

  pub fn is_u8(&self) -> bool {
    match self {
      Self::Integer(1, _) => true,
      Self::Box(ty) => ty.is_u8(),
      Self::NewType(_, ty) => ty.is_u8(),
      Self::CustomType(ty) => ty.is_u8(),
      _ => false,
    }
  }

  fn make_custom_type(&mut self) {
    match self {
      TypeMeta::CustomType(_) => {
        // already wrapped.
        return;
      }
      _ => (),
    }
    let meta = self.clone();
    *self = TypeMeta::CustomType(CustomType::new(meta));
  }

  pub fn custom_encode(&mut self, type_id: TypeId, func: WrapEncodeFn) {
    self.make_custom_type();
    match self {
      TypeMeta::CustomType(custom) => {
        custom.custom_encode(type_id, func);
      }
      _ => unreachable!(),
    }
  }

  pub fn custom_decode(&mut self, func: WrapDecodeFn) {
    self.make_custom_type();
    match self {
      TypeMeta::CustomType(custom) => {
        custom.custom_decode(func);
      }
      _ => unreachable!(),
    }
  }

  pub fn encode_value(
    &self,
    value: Dynamic,
    data: &mut EncodedArgs,
  ) -> Result<(), Box<EvalAltResult>> {
    log::debug!("encode TypeMeta: {:?}", self);
    match self {
      TypeMeta::Unit => (),
      TypeMeta::Integer(len, signed) => {
        if let Some(num) = value.as_int().ok() {
          match (len, signed) {
            (_, false) if data.is_compact() => data.encode(Compact::<u128>(num as u128)),
            (1, true) => data.encode(num as i8),
            (1, false) => data.encode(num as u8),
            (2, true) => data.encode(num as i16),
            (2, false) => data.encode(num as u16),
            (4, true) => data.encode(num as i32),
            (4, false) => data.encode(num as u32),
            (8, true) => data.encode(num as i64),
            (8, false) => data.encode(num as u64),
            (16, true) => data.encode(num as i128),
            (16, false) => data.encode(num as u128),
            _ => Err(format!("Unsupported integer type: {:?}", self))?,
          }
        } else if let Some(dec) = value.as_decimal().ok() {
          match (len, signed) {
            (_, false) if data.is_compact() => {
              let num = dec
                .to_u128()
                .ok_or_else(|| format!("Expected unsigned integer"))?;
              data.encode(Compact::<u128>(num))
            }
            (1, true) => data.encode(
              dec
                .to_i8()
                .ok_or_else(|| format!("Integer too large for `i8`"))?,
            ),
            (1, false) => data.encode(
              dec
                .to_u8()
                .ok_or_else(|| format!("Integer too large for `u8` or negative."))?,
            ),
            (2, true) => data.encode(
              dec
                .to_i16()
                .ok_or_else(|| format!("Integer too large for `i16`"))?,
            ),
            (2, false) => data.encode(
              dec
                .to_u16()
                .ok_or_else(|| format!("Integer too large for `u16` or negative."))?,
            ),
            (4, true) => data.encode(
              dec
                .to_i32()
                .ok_or_else(|| format!("Integer too large for `i32`"))?,
            ),
            (4, false) => data.encode(
              dec
                .to_u32()
                .ok_or_else(|| format!("Integer too large for `u32` or negative."))?,
            ),
            (8, true) => data.encode(
              dec
                .to_i64()
                .ok_or_else(|| format!("Integer too large for `i64`"))?,
            ),
            (8, false) => data.encode(
              dec
                .to_u64()
                .ok_or_else(|| format!("Integer too large for `u64` or negative."))?,
            ),
            (16, signed) => {
              if *signed {
                data.encode(
                  dec
                    .to_i128()
                    .ok_or_else(|| format!("Integer too large for `u128`."))?,
                )
              } else {
                data.encode(
                  dec
                    .to_u128()
                    .ok_or_else(|| format!("Expected a non-negative integer/decimal."))?,
                )
              }
            }
            _ => Err(format!("Unsupported integer type: {:?}", self))?,
          }
        } else {
          Err(format!(
            "Expected an integer or decimal value, got {:?}",
            value
          ))?;
        }
      }
      TypeMeta::Bool => data.encode(value.as_bool()?),
      TypeMeta::Option(type_ref) => {
        if value.is::<()>() {
          // None
          data.encode(0u8);
        } else {
          // Some
          data.encode(1u8);
          type_ref.encode_value(value, data)?
        }
      }
      TypeMeta::OptionBool => data.encode(value.as_bool().ok()),
      TypeMeta::Vector(type_ref) => {
        if value.is::<Array>() {
          let values = value.cast::<Array>();
          // Encode vector length.
          data.encode(Compact::<u64>(values.len() as u64));
          for value in values.into_iter() {
            type_ref.encode_value(value, data)?
          }
        } else if value.is::<Blob>() {
          let bytes = value.into_blob()?;
          data.encode(bytes);
        } else if value.is::<ImmutableString>() {
          let s = value.into_immutable_string()?;
          // Maybe Hex-encoded string.
          if s.starts_with("0x") {
            data.encode(hex::decode(&s.as_bytes()[2..]).map_err(|e| e.to_string())?);
          } else {
            data.encode(s.as_bytes());
          }
        } else {
          Err(format!("Expected a vector, got {:?}", value.type_id()))?;
        }
      }
      TypeMeta::BTreeSet(type_ref) => {
        if value.is::<Array>() {
          let values = value.cast::<Array>();
          // Build BTreeSet from values.
          let mut set = BTreeSet::new();
          for value in values.into_iter() {
            set.insert(type_ref.encode_arg(value)?);
          }
          data.encode(set);
        } else {
          Err(format!("Expected an array, got {:?}", value.type_id()))?;
        }
      }
      TypeMeta::BTreeMap(key_ty, value_ty) => {
        if value.is::<Array>() {
          let values = value.cast::<Array>();
          // Build BTreeMap from values.
          let mut map = BTreeMap::new();
          for value in values.into_iter() {
            if value.is::<Array>() {
              let mut pair = value.cast::<Array>();
              let len = pair.len();
              let value = pair.pop();
              let key = pair.pop();
              match (key, value, len) {
                (Some(key), Some(value), 2) => {
                  let key = key_ty.encode_arg(key)?;
                  let value = value_ty.encode_arg(value)?;
                  map.insert(key, value);
                }
                (_, _, len) => {
                  Err(format!("Expected array of length 2, got length {:?}", len))?;
                }
              }
            } else {
              Err(format!(
                "Expected array of 2 values, got {:?}",
                value.type_id()
              ))?;
            }
          }
          data.encode(map);
        } else {
          Err(format!(
            "Expected an array of (key, value) pairs, got {:?}",
            value.type_id()
          ))?;
        }
      }
      TypeMeta::Slice(len, type_ref) => {
        if value.is::<Array>() {
          let values = value.cast::<Array>();
          if values.len() != *len {
            Err(format!(
              "Wrong slice length: Expected {} got {}",
              len,
              values.len()
            ))?;
          }
          for value in values.into_iter() {
            type_ref.encode_value(value, data)?
          }
          return Ok(());
        } else if type_ref.is_u8() {
          let type_id = value.type_id();
          // Handle fixed-length byte arrays: [u8; len]
          if type_id == TypeId::of::<SharedUser>() && *len == 32 {
            let user = value.cast::<SharedUser>();
            data.encode(user.public());
            return Ok(());
          } else if type_id == TypeId::of::<ImmutableString>() {
            let s = value.into_immutable_string()?;
            if s.len() <= *len {
              let fill = *len - s.len();
              // Write string as bytes.
              data.write(s.as_bytes());
              if fill > 0 {
                // and Null-fill.
                data.write(&vec![0; fill]);
              }
            } else if s.len() >= (*len * 2) {
              // Maybe Hex-encoded string.
              let bytes = if s.starts_with("0x") {
                hex::decode(&s.as_bytes()[2..]).map_err(|e| e.to_string())?
              } else {
                hex::decode(s.as_bytes()).map_err(|e| e.to_string())?
              };
              data.write(&bytes[..]);
            } else {
              // Failed to convert string to fixed-length byte array.
              return Err(format!(
                "Unhandled slice type: {:?}, from string='{}'",
                self, s
              ))?;
            }
            return Ok(());
          }
        }
        // Unhandled slice type.
        return Err(format!(
          "Unhandled slice type: {:?}, value={:?}",
          self, value
        ))?;
      }
      TypeMeta::String => {
        if value.is::<Vec<u8>>() {
          let d = value.cast::<Vec<u8>>();
          data.encode(d.as_slice());
        } else {
          let s = value.into_immutable_string()?;
          data.encode(s.as_str());
        }
      }

      TypeMeta::Tuple(types) => {
        if value.is::<Array>() {
          let values = value.cast::<Array>();
          if values.len() != types.len() {
            Err(format!(
              "Wrong Tuple length: Expected {} got {}",
              types.len(),
              values.len()
            ))?;
          }
          for (type_ref, value) in types.iter().zip(values.into_iter()) {
            type_ref.encode_value(value, data)?
          }
        } else {
          Err(format!("Expected a Tuple, got {:?}", value.type_id()))?;
        }
      }
      TypeMeta::Struct(fields) => {
        if value.is::<RMap>() {
          let map = value.cast::<RMap>();
          for (name, type_ref) in fields {
            let name: SmartString<LazyCompact> = name.into();
            if let Some(value) = map.get(&name) {
              type_ref.encode_value(value.clone(), data)?;
            } else {
              Err(format!("Missing field `{}` in Struct", name))?;
            }
          }
        } else {
          Err(format!("Expected a Struct, got {:?}", value.type_id()))?;
        }
      }
      TypeMeta::Enum(variants) => {
        if value.is::<RMap>() {
          let map = value.cast::<RMap>();
          let mut encoded = false;
          for (name, value) in map.into_iter() {
            if let Some(variant) = variants.get_by_name(name.as_str()) {
              if encoded {
                // Only allow encoding one Enum variant.
                Err(format!("Can't encode multiple Enum variants."))?;
              }
              encoded = true;
              // Encode enum variant idx.
              data.encode(variant.idx);
              if let Some(type_ref) = &variant.type_ref {
                type_ref.encode_value(value, data)?;
              }
            } else {
              Err(format!("Unknown Enum variant: {}.", name))?;
            }
          }
          // At least one Enum variant must be encoded.
          if !encoded {
            Err(format!("Enum is empty, must provide at least one variant."))?;
          }
        } else {
          Err(format!("Expected a Enum, got {:?}", value.type_id()))?;
        }
      }

      TypeMeta::Compact(type_ref) => {
        let old = data.is_compact();
        data.set_compact(true);
        let res = type_ref.encode_value(value, data);
        data.set_compact(old);
        res?
      }
      TypeMeta::Box(type_ref) | TypeMeta::NewType(_, type_ref) => {
        type_ref.encode_value(value, data)?
      }

      TypeMeta::CustomType(custom) => custom.encode_value(value, data)?,
      TypeMeta::Unresolved(type_def) => Err(format!("Unresolved type: {}", type_def))?,
      _ => Err(format!("Unhandled type: {:?}", self))?,
    }
    Ok(())
  }

  pub fn decode_value<I: Input>(&self, input: &mut I, is_compact: bool) -> Result<Dynamic, PError> {
    let val = match self {
      TypeMeta::Unit => Dynamic::UNIT,
      TypeMeta::Integer(len, signed) => match (len, signed) {
        (_, false) if is_compact => {
          let val = Compact::<u128>::decode(input)?.0;
          match i64::try_from(val) {
            Ok(val) => Dynamic::from_int(val),
            Err(_) => {
              let dec = Decimal::from(val);
              Dynamic::from_decimal(dec)
            }
          }
        }
        (1, true) => Dynamic::from_int(i8::decode(input)? as i64),
        (1, false) => Dynamic::from_int(u8::decode(input)? as i64),
        (2, true) => Dynamic::from_int(i16::decode(input)? as i64),
        (2, false) => Dynamic::from_int(u16::decode(input)? as i64),
        (4, true) => Dynamic::from_int(i32::decode(input)? as i64),
        (4, false) => Dynamic::from_int(u32::decode(input)? as i64),
        (8, true) => Dynamic::from_int(i64::decode(input)?),
        (8, false) => {
          let val = u64::decode(input)?;
          match i64::try_from(val) {
            Ok(val) => Dynamic::from_int(val),
            Err(_) => {
              let dec = Decimal::from(val);
              Dynamic::from_decimal(dec)
            }
          }
        }
        (16, true) => {
          let val = i128::decode(input)?;
          let dec = Decimal::from(val);
          Dynamic::from_decimal(dec)
        }
        (16, false) => {
          let val = u128::decode(input)?;
          let dec = Decimal::from(val);
          Dynamic::from_decimal(dec)
        }
        _ => Err("Unsupported integer type")?,
      },
      TypeMeta::Bool => {
        let val = input.read_byte()?;
        Dynamic::from_bool(val == 1)
      }
      TypeMeta::Option(type_ref) => {
        let val = input.read_byte()?;
        if val == 1 {
          type_ref.decode_value(input, false)?
        } else {
          Dynamic::UNIT
        }
      }
      TypeMeta::OptionBool => {
        let val = input.read_byte()?;
        if val == 1 {
          Dynamic::from_bool(true)
        } else if val == 2 {
          Dynamic::from_bool(false)
        } else {
          Dynamic::UNIT
        }
      }
      TypeMeta::Result(ok_ref, err_ref) => {
        let val = input.read_byte()?;
        let mut map = RMap::new();
        if val == 0 {
          map.insert("Ok".into(), ok_ref.decode_value(input, false)?);
        } else {
          map.insert("Err".into(), err_ref.decode_value(input, false)?);
        }
        Dynamic::from(map)
      }
      TypeMeta::Vector(type_ref) => {
        let len = Compact::<u64>::decode(input)?.0;
        let mut vec = Vec::new();
        for _ in 0..len {
          vec.push(type_ref.decode_value(input, false)?);
        }
        Dynamic::from_array(vec)
      }
      TypeMeta::BTreeSet(type_ref) => {
        let len = Compact::<u64>::decode(input)?.0;
        let mut vec = Vec::new();
        for _ in 0..len {
          vec.push(type_ref.decode_value(input, false)?);
        }
        Dynamic::from_array(vec)
      }
      TypeMeta::BTreeMap(key_ty, value_ty) => {
        let len = Compact::<u64>::decode(input)?.0;
        let mut vec = Vec::new();
        for _ in 0..len {
          let key = key_ty.decode_value(input, false)?;
          let value = value_ty.decode_value(input, false)?;
          vec.push(Dynamic::from_array(vec![key, value]));
        }
        Dynamic::from_array(vec)
      }
      TypeMeta::Slice(len, type_ref) => {
        let mut vec = Vec::with_capacity(*len as usize);
        for _ in 0..*len {
          vec.push(type_ref.decode_value(input, false)?);
        }
        Dynamic::from(vec)
      }
      TypeMeta::String => {
        let val = String::decode(input)?;
        Dynamic::from(val)
      }

      TypeMeta::Tuple(types) => {
        let mut vec = Vec::with_capacity(types.len());
        for type_ref in types {
          vec.push(type_ref.decode_value(input, false)?);
        }
        Dynamic::from(vec)
      }
      TypeMeta::Struct(fields) => {
        let mut map = RMap::new();
        for (name, type_ref) in fields {
          log::debug!("decode Struct field: {}({:?})", name, type_ref);
          let value = type_ref.decode_value(input, false)?;
          log::trace!("  -- field: {:?}", value);
          map.insert(name.into(), value);
        }
        Dynamic::from(map)
      }
      TypeMeta::Enum(variants) => {
        let val = input.read_byte()?;
        match variants.get_by_idx(val) {
          Some(variant) => {
            let name = &variant.name;
            log::debug!("decode Enum variant: {}", name);
            let mut map = RMap::new();
            if let Some(type_ref) = &variant.type_ref {
              let value = type_ref.decode_value(input, false)?;
              log::trace!("  -- variant: {:?}", value);
              map.insert(name.into(), value);
            } else {
              map.insert(name.into(), Dynamic::UNIT);
            }
            Dynamic::from(map)
          }
          None if val == 0 => Dynamic::UNIT,
          None => {
            log::debug!(
              "invalid variant: {}, remaining: {:?}, variants={:?}",
              val,
              input.remaining_len()?,
              variants
            );
            Err("Error decoding Enum, invalid variant.")?
          }
        }
      }

      TypeMeta::Compact(type_ref) => {
        type_ref.decode_value(input, true)?
      }
      TypeMeta::Box(type_ref) | TypeMeta::NewType(_, type_ref) => {
        type_ref.decode_value(input, is_compact)?
      }

      TypeMeta::CustomType(custom) => custom.decode_value(input, is_compact)?,
      TypeMeta::Unresolved(type_def) => {
        log::error!("Unresolved type: {}", type_def);
        Err("Unresolved type")?
      }
    };
    Ok(val)
  }
}

#[derive(Clone)]
pub struct Types {
  types: IndexMap<String, TypeRef>,
  runtime_version: RuntimeVersion,
  metadata: Option<Metadata>,
  short_names: HashMap<String, String>,
}

impl Types {
  pub fn new(runtime_version: RuntimeVersion) -> Self {
    let mut types = Self {
      types: IndexMap::new(),
      runtime_version,
      metadata: None,
      short_names: HashMap::new(),
    };
    // Primitive types.
    types.insert_meta("u8", TypeMeta::Integer(1, false));
    types.insert_meta("u16", TypeMeta::Integer(2, false));
    types.insert_meta("u32", TypeMeta::Integer(4, false));
    types.insert_meta("u64", TypeMeta::Integer(8, false));
    types.insert_meta("u128", TypeMeta::Integer(16, false));
    types.insert_meta("u256", TypeMeta::Integer(32, false));
    types.insert_meta("i8", TypeMeta::Integer(1, true));
    types.insert_meta("i16", TypeMeta::Integer(2, true));
    types.insert_meta("i32", TypeMeta::Integer(4, true));
    types.insert_meta("i64", TypeMeta::Integer(8, true));
    types.insert_meta("i128", TypeMeta::Integer(16, true));
    types.insert_meta("i256", TypeMeta::Integer(32, true));
    types.insert_meta("bool", TypeMeta::Bool);
    types.insert_meta("Text", TypeMeta::String);
    types.insert_meta("Option<bool>", TypeMeta::OptionBool);

    types
  }

  pub fn get_runtime_version(&self) -> RuntimeVersion {
    self.runtime_version.clone()
  }

  pub fn set_metadata(&mut self, metadata: Metadata) {
    self.metadata = Some(metadata);
  }

  pub fn get_metadata(&self) -> Option<Metadata> {
    self.metadata.as_ref().cloned()
  }

  pub fn load_schema(&mut self, filename: &str) -> Result<(), Box<EvalAltResult>> {
    log::info!("load_schema: {}", filename);
    let file = File::open(filename).map_err(|e| e.to_string())?;

    let schema: serde_json::Value =
      serde_json::from_reader(BufReader::new(file)).map_err(|e| e.to_string())?;

    let schema = schema
      .as_object()
      .expect("Invalid schema, expected object.");

    let types = match schema.get("types") {
      Some(val) => val.as_object().unwrap_or(schema),
      _ => schema,
    };
    self.parse_schema_types(types)?;

    Ok(())
  }

  fn parse_schema_types(&mut self, types: &Map<String, Value>) -> Result<(), Box<EvalAltResult>> {
    for (name, val) in types.iter() {
      match val {
        Value::String(val) => {
          self.parse_named_type(name, val)?;
        }
        Value::Object(map) => {
          if let Some(variants) = map.get("_enum") {
            self.parse_enum(name, variants)?;
          } else {
            self.parse_struct(name, map)?;
          }
        }
        _ => {
          eprintln!("UNHANDLED JSON VALUE: {} => {:?}", name, val);
        }
      }
    }
    Ok(())
  }

  fn parse_enum(&mut self, name: &str, variants: &Value) -> Result<(), Box<EvalAltResult>> {
    match variants {
      Value::Array(arr) => {
        let variants = arr
          .iter()
          .try_fold(EnumVariants::new(), |mut variants, val| {
            match val.as_str() {
              Some(name) => {
                variants.insert(name, None);
                Ok(variants)
              }
              None => Err(format!(
                "Expected json string for enum {}: got {:?}",
                name, val
              )),
            }
          })?;
        self.insert_meta(name, TypeMeta::Enum(variants));
      }
      Value::Object(obj) => {
        let variants = obj.iter().try_fold(
          EnumVariants::new(),
          |mut variants, (var_name, val)| -> Result<_, Box<EvalAltResult>> {
            match val.as_str() {
              Some("") => {
                variants.insert(var_name, None);
                Ok(variants)
              }
              Some(var_def) => {
                let type_meta = self.parse_type(var_def)?;
                variants.insert(var_name, Some(type_meta));
                Ok(variants)
              }
              None => Err(format!("Expected json string for enum {}: got {:?}", name, val).into()),
            }
          },
        )?;
        self.insert_meta(name, TypeMeta::Enum(variants));
      }
      _ => {
        return Err(format!("Invalid json for `_enum`: {:?}", variants).into());
      }
    }
    Ok(())
  }

  fn parse_struct(
    &mut self,
    name: &str,
    def: &Map<String, Value>,
  ) -> Result<(), Box<EvalAltResult>> {
    let fields = def.iter().try_fold(
      IndexMap::new(),
      |mut map, (field_name, val)| -> Result<_, Box<EvalAltResult>> {
        match val.as_str() {
          Some(field_def) => {
            let type_meta = self.parse_type(field_def)?;
            map.insert(field_name.to_string(), type_meta);
            Ok(map)
          }
          None => Err(
            format!(
              "Expected json string for struct {} field {}: got {:?}",
              name, field_name, val
            )
            .into(),
          ),
        }
      },
    )?;
    self.insert_meta(name, TypeMeta::Struct(fields));
    Ok(())
  }

  pub fn parse_named_type(&mut self, name: &str, def: &str) -> Result<TypeRef, Box<EvalAltResult>> {
    let type_ref = self.parse_type(def)?;

    Ok(self.insert_meta(name, TypeMeta::NewType(name.into(), type_ref)))
  }

  pub fn parse_type(&mut self, name: &str) -> Result<TypeRef, Box<EvalAltResult>> {
    let name = name
      .trim()
      .replace("\r", "")
      .replace("\n", "")
      .replace("T::", "");
    // Try to resolve the type.
    let type_ref = self.resolve(&name);
    let mut type_meta = type_ref.0.write().unwrap();

    // Check if type is unresolved.
    match &*type_meta {
      TypeMeta::Unresolved(def) => {
        // Try parsing it.
        let new_meta = self.parse(def)?;
        *type_meta = new_meta;
      }
      _ => (),
    }
    Ok(type_ref.clone())
  }

  fn parse(&mut self, def: &str) -> Result<TypeMeta, Box<EvalAltResult>> {
    match def.chars().last() {
      Some('>') => {
        // Handle: Vec<T>, Option<T>, Compact<T>
        let (wrap, ty) = def
          .strip_suffix('>')
          .and_then(|s| s.split_once('<'))
          .map(|(wrap, ty)| (wrap.trim(), ty.trim()))
          .ok_or_else(|| format!("Failed to parse Vec/Option/Compact: {}", def))?;
        match wrap {
          "Vec" => {
            let wrap_ref = self.parse_type(ty)?;
            Ok(TypeMeta::Vector(wrap_ref))
          }
          "Option" => {
            let wrap_ref = self.parse_type(ty)?;
            Ok(TypeMeta::Option(wrap_ref))
          }
          "Compact" => {
            let wrap_ref = self.parse_type(ty)?;
            Ok(TypeMeta::Compact(wrap_ref))
          }
          "Box" => {
            let wrap_ref = self.parse_type(ty)?;
            Ok(TypeMeta::Box(wrap_ref))
          }
          "Result" => {
            let (ok_ref, err_ref) = match ty.split_once(',') {
              Some((ok_ty, err_ty)) => {
                let ok_ref = self.parse_type(ok_ty)?;
                let err_ref = self.parse_type(err_ty)?;
                (ok_ref, err_ref)
              }
              None => {
                let ok_ref = self.parse_type(ty)?;
                let err_ref = self.parse_type("Error")?;
                (ok_ref, err_ref)
              }
            };
            Ok(TypeMeta::Result(ok_ref, err_ref))
          }
          "PhantomData" | "sp_std::marker::PhantomData" => Ok(TypeMeta::Unit),
          generic => {
            // Some generic type.
            if self.types.contains_key(generic) {
              Ok(TypeMeta::NewType(generic.into(), self.resolve(generic)))
            } else {
              Ok(TypeMeta::Unresolved(def.into()))
            }
          }
        }
      }
      Some(')') => {
        let mut broken_type = None;
        let defs = def
          .trim_matches(|c| c == '(' || c == ')')
          .split_terminator(',')
          .filter_map(|s| {
            let s = match broken_type.take() {
              Some(s1) => format!("{}, {}", s1, s),
              None => s.to_string(),
            }
            .trim()
            .to_string();
            // Check for broken type.
            let left = s.chars().filter(|c| *c == '<').count();
            let right = s.chars().filter(|c| *c == '>').count();
            if left != right {
              broken_type = Some(s);
              return None;
            }
            if s != "" {
              Some(s)
            } else {
              None
            }
          })
          .try_fold(
            Vec::new(),
            |mut vec, val| -> Result<_, Box<EvalAltResult>> {
              let type_ref = self.parse_type(&val)?;
              vec.push(type_ref);
              Ok(vec)
            },
          )?;
        // Handle tuples.
        Ok(TypeMeta::Tuple(defs))
      }
      Some(']') => {
        let (slice_ty, slice_len) = def
          .trim_matches(|c| c == '[' || c == ']')
          .split_once(';')
          .and_then(|(ty, len)| {
            // parse slice length.
            len.trim().parse::<usize>().ok().map(|l| (ty.trim(), l))
          })
          .ok_or_else(|| format!("Failed to parse slice: {}", def))?;
        // Handle slices.
        let slice_ref = self.parse_type(slice_ty)?;
        Ok(TypeMeta::Slice(slice_len, slice_ref))
      }
      _ => Ok(TypeMeta::Unresolved(def.into())),
    }
  }

  pub fn resolve(&mut self, name: &str) -> TypeRef {
    let name = match self.short_names.get(name) {
      Some(full_name) => full_name,
      None => name,
    };
    let entry = self.types.entry(name.into());
    let type_ref = entry.or_insert_with(|| TypeRef::from(TypeMeta::Unresolved(name.into())));
    type_ref.clone()
  }

  pub fn insert_meta(&mut self, name: &str, type_def: TypeMeta) -> TypeRef {
    self.insert(name, TypeRef::from(type_def))
  }

  pub fn insert(&mut self, name: &str, type_ref: TypeRef) -> TypeRef {
    use indexmap::map::Entry;
    let entry = self.types.entry(name.into());
    match entry {
      Entry::Occupied(entry) => {
        let old_ref = entry.get();
        log::trace!("types.insert: resolve old type[{}]: {:?}", name, type_ref);
        let mut old_meta = old_ref.0.write().unwrap();
        // Already exists.  Check that it is a `TypeMeta::Unresolved`.
        match &*old_meta {
          TypeMeta::Unresolved(_) => (),
          _ => {
            log::warn!("REDEFINE TYPE: {}", name);
          }
        }
        *old_meta = TypeMeta::NewType(name.into(), type_ref.clone());
        old_ref.clone()
      }
      Entry::Vacant(entry) => {
        log::trace!("types.insert: new type[{}]: {:?}", name, type_ref);
        entry.insert(type_ref.clone());
        type_ref
      }
    }
  }

  #[cfg(feature = "v14")]
  fn v14_resolve_field(
    &mut self,
    field: &Field<PortableForm>,
    id_to_ref: &HashMap<u32, TypeRef>,
  ) -> Result<TypeRef, Box<EvalAltResult>> {
    let mut field_ty = id_to_ref
      .get(&field.ty().id())
      .cloned()
      .ok_or_else(|| format!("Failed to resolve field type."))?;
    // Check for `Balance` fields.
    if let Some(type_name) = field.type_name() {
      let name = match (type_name.as_str(), field_ty.is_compact()) {
        ("Balance", false) => Some("Balance"),
        ("Balance", true) => Some("Compact<Balance>"),
        ("Option<Balance>", false) => Some("Option<Balance>"),
        ("Option<Balance>", true) => Some("Option<Compact<Balance>>"),
        _ => None,
      };
      if let Some(name) = name {
        field_ty = self.parse_type(name)?;
      }
    }
    Ok(field_ty)
  }

  #[cfg(feature = "v14")]
  fn import_v14_type(
    &mut self,
    id: u32,
    ty: &Type<PortableForm>,
    id_to_ref: &HashMap<u32, TypeRef>,
  ) -> Result<(), Box<EvalAltResult>> {
    let type_ref = id_to_ref.get(&id).unwrap();
    log::debug!("import_v14_type: {}", ty.path());
    let type_meta = match ty.type_def() {
      TypeDef::Composite(_) if ty.path().segments() == &["BTreeSet"] => {
        let ty_param = &ty.type_params()[0];
        let elm_ty = id_to_ref
          .get(&ty_param.ty().expect("TypeParameter id").id())
          .cloned()
          .expect("Failed to resolve BTreeSet type_param");
        TypeMeta::BTreeSet(elm_ty)
      }
      TypeDef::Composite(_) if ty.path().segments() == &["BTreeMap"] => {
        let ty_param = &ty.type_params()[0];
        let key_ty = id_to_ref
          .get(&ty_param.ty().expect("TypeParameter id").id())
          .cloned()
          .expect("Failed to resolve BTreeMap key type_param");
        let ty_param = &ty.type_params()[1];
        let elm_ty = id_to_ref
          .get(&ty_param.ty().expect("TypeParameter id").id())
          .cloned()
          .expect("Failed to resolve BTreeMap value type_param");
        TypeMeta::BTreeMap(key_ty, elm_ty)
      }
      TypeDef::Composite(s) if s.fields().len() == 1 && s.fields()[0].name().is_none() => {
        // Special handling of tuples.
        log::debug!("import_v14_type: Tuple: variants={:#?}", s.fields());
        let ty_param = &s.fields()[0];
        let elm_ty = self.v14_resolve_field(ty_param, id_to_ref)
          .expect("Failed to resolve Tuple field");
        TypeMeta::NewType(ty.path().ident().unwrap_or_else(|| "unamed".into()), elm_ty)
      }
      TypeDef::Composite(s) => {
        let mut fields = IndexMap::new();
        log::debug!(
          "import_v14_type: Struct({}): fields={:#?}",
          ty.path(),
          s.fields()
        );
        let name_prefix = ty.path().ident();
        for (idx, f) in s.fields().into_iter().enumerate() {
          let name = f.name().cloned().unwrap_or_else(|| match &name_prefix {
            Some(prefix) => format!("{prefix}_{idx}"),
            None => format!("unamed_{idx}"),
          });
          let field_ty = self.v14_resolve_field(f, id_to_ref)
            .expect("Failed to resolve Composite field type");
          fields.insert(name.to_string(), field_ty);
        }
        TypeMeta::Struct(fields)
      }
      TypeDef::Variant(v) if v.variants().len() == 2 && ty.path().segments() == &["Option"] => {
        log::debug!("import_v14_type: Option: variants={:#?}", v.variants());
        // Special handling for `Option` types.
        let ty_param = &v.variants()[1].fields()[0];
        let elm_ty = self.v14_resolve_field(ty_param, id_to_ref)
          .expect("Failed to resolve Option type");
        TypeMeta::Option(elm_ty)
      }
      TypeDef::Variant(v) => {
        let mut variants = EnumVariants::new();
        log::debug!(
          "import_v14_type: Enum({}): variants={:#?}",
          ty.path(),
          v.variants()
        );
        for var in v.variants() {
          let mut fields = IndexMap::new();
          let mut is_struct_variant = true;
          for (idx, f) in var.fields().into_iter().enumerate() {
            let name = f.name().cloned().unwrap_or_else(|| {
              // Has unnamed field, use Tuple variant.
              is_struct_variant = false;
              format!("unamed_{idx}")
            });
            let field_ty = self.v14_resolve_field(f, id_to_ref)
              .expect("Failed to resolve Enum variant field type");
            fields.insert(name.to_string(), field_ty);
          }
          if fields.len() == 0 {
            variants.insert_at(var.index(), var.name(), None);
          } else if is_struct_variant {
            variants.insert_at(
              var.index(),
              var.name(),
              Some(TypeMeta::Struct(fields).into()),
            );
          } else if fields.len() == 1 {
            variants.insert_at(
              var.index(),
              var.name(),
              fields.first().map(|(_, ty)| ty.clone()),
            );
          } else {
            variants.insert_at(
              var.index(),
              var.name(),
              Some(TypeMeta::Tuple(fields.values().cloned().collect()).into()),
            );
          }
        }
        TypeMeta::Enum(variants)
      }
      TypeDef::Sequence(s) => {
        let elm_ty = id_to_ref
          .get(&s.type_param().id())
          .cloned()
          .expect("Failed to resolve Sequence element type");
        TypeMeta::Vector(elm_ty)
      }
      TypeDef::Array(a) => {
        let elm_ty = id_to_ref
          .get(&a.type_param().id())
          .cloned()
          .expect("Failed to resolve Array element type");
        TypeMeta::Slice(a.len() as usize, elm_ty)
      }
      TypeDef::Tuple(t) => {
        let defs = t
          .fields()
          .into_iter()
          .map(|ty| id_to_ref.get(&ty.id()).cloned())
          .collect::<Option<Vec<_>>>()
          .expect("Failed to resolve Tuple field type");
        TypeMeta::Tuple(defs)
      }
      TypeDef::Primitive(p) => {
        use TypeDefPrimitive::*;
        match p {
          Bool => TypeMeta::Bool,
          Char => TypeMeta::Integer(1, false),
          Str => TypeMeta::String,
          U8 => TypeMeta::Integer(1, false),
          U16 => TypeMeta::Integer(2, false),
          U32 => TypeMeta::Integer(4, false),
          U64 => TypeMeta::Integer(8, false),
          U128 => TypeMeta::Integer(16, false),
          U256 => TypeMeta::Integer(32, false),
          I8 => TypeMeta::Integer(1, true),
          I16 => TypeMeta::Integer(2, true),
          I32 => TypeMeta::Integer(4, true),
          I64 => TypeMeta::Integer(8, true),
          I128 => TypeMeta::Integer(16, true),
          I256 => TypeMeta::Integer(32, true),
        }
      }
      TypeDef::Compact(c) => {
        let elm_ty = id_to_ref
          .get(&c.type_param().id())
          .cloned()
          .expect("Failed to resolve Compact type");
        TypeMeta::Compact(elm_ty)
      }
      _ => {
        todo!("Handle TypeDef");
      }
    };
    // Resolve type.
    let mut old_meta = type_ref.0.write().unwrap();
    *old_meta = type_meta;
    Ok(())
  }

  #[cfg(feature = "v14")]
  pub fn import_v14_types(&mut self, types: &PortableRegistry) -> Result<(), Box<EvalAltResult>> {
    let mut id_to_ref = HashMap::new();
    for ty in types.types() {
      let name = get_type_name(ty.ty(), types, true);
      let short_name = get_type_name(ty.ty(), types, false);
      log::debug!(
        "import_v14_type: {:?} => {} ({})",
        ty.id(),
        name,
        short_name
      );
      let type_ref = self.resolve(&name);

      // Try mapping short name to full name.
      if !self.short_names.contains_key(&short_name) {
        self.short_names.insert(short_name, name.clone());
      }
      // Try mapping type ident to full name.
      if let Some(ident) = ty.ty().path().ident() {
        if !self.short_names.contains_key(&ident) {
          self.short_names.insert(ident, name.clone());
        }
      }
      id_to_ref.insert(ty.id(), type_ref);
    }

    for ty in types.types() {
      self.import_v14_type(ty.id(), ty.ty(), &id_to_ref)?;
    }
    Ok(())
  }

  /// Dump types.
  pub fn dump_types(&self) {
    for (idx, (key, type_ref)) in self.types.iter().enumerate() {
      eprintln!("Type[{}]: {} => {:#?}", idx, key, type_ref);
    }
  }

  /// Dump unresolved types.
  pub fn dump_unresolved(&self) {
    for (key, type_ref) in self.types.iter() {
      let meta = type_ref.0.read().unwrap();
      match &*meta {
        TypeMeta::Unresolved(def) => {
          eprintln!("--------- Unresolved: {} => {}", key, def);
        }
        _ => (),
      }
    }
  }

  pub fn custom_encode<F>(
    &mut self,
    name: &str,
    type_id: TypeId,
    func: F,
  ) -> Result<(), Box<EvalAltResult>>
  where
    F: 'static + Send + Sync + Fn(Dynamic, &mut EncodedArgs) -> Result<(), Box<EvalAltResult>>,
  {
    let func = WrapEncodeFn(Arc::new(func));
    let type_ref = self.parse_type(name)?;
    log::trace!("custom_encode: {type_ref:?}");
    type_ref.custom_encode(type_id, func);
    Ok(())
  }

  pub fn custom_decode<F>(&mut self, name: &str, func: F) -> Result<(), Box<EvalAltResult>>
  where
    F: 'static + Send + Sync + Fn(BoxedInput, bool) -> Result<Dynamic, PError>,
  {
    let func = WrapDecodeFn(Arc::new(func));
    let type_ref = self.parse_type(name)?;
    type_ref.custom_decode(func);
    Ok(())
  }

  pub fn register_scale_type<T>(&mut self, name: &str) -> Result<(), Box<EvalAltResult>>
  where
    T: 'static + Encode + Decode + Clone + Send + Sync
  {
    self.custom_encode(name, TypeId::of::<T>(), |value, data| {
      data.encode(value.cast::<T>());
      Ok(())
    })?;
    self.custom_decode(name, |mut input, _is_compact| {
      Ok(Dynamic::from(T::decode(&mut input)?))
    })?;
    Ok(())
  }

  pub fn vec_encoded<T>(&mut self, name: &str) -> Result<(), Box<EvalAltResult>>
  where
    T: 'static + Encode + Decode + Clone + Send + Sync
  {
    self.custom_encode(name, TypeId::of::<T>(), move |value, data| {
      let val = value.cast::<T>();
      let encoded = val.encode();
      data.encode(encoded);
      Ok(())
    })?;
    self.custom_decode(name, |mut input, _is_compact| {
      let encoded = Vec::decode(&mut input)?;
      Ok(Dynamic::from(T::decode(&mut encoded.as_slice())?))
    })?;
    Ok(())
  }
}

#[derive(Clone)]
pub struct TypeLookup {
  types: Arc<RwLock<Types>>,
}

impl TypeLookup {
  pub fn from_types(types: Types) -> Self {
    Self {
      types: Arc::new(RwLock::new(types)),
    }
  }

  pub fn get_runtime_version(&self) -> RuntimeVersion {
    self.types.read().unwrap().get_runtime_version()
  }

  pub fn get_metadata(&self) -> Option<Metadata> {
    self.types.read().unwrap().get_metadata()
  }

  pub fn parse_named_type(&self, name: &str, def: &str) -> Result<TypeRef, Box<EvalAltResult>> {
    let mut t = self.types.write().unwrap();
    t.parse_named_type(name, def)
  }

  pub fn parse_type(&self, def: &str) -> Result<TypeRef, Box<EvalAltResult>> {
    let mut t = self.types.write().unwrap();
    t.parse_type(def)
  }

  pub fn resolve(&self, name: &str) -> TypeRef {
    let mut t = self.types.write().unwrap();
    t.resolve(name)
  }

  pub fn insert_meta(&self, name: &str, type_meta: TypeMeta) -> TypeRef {
    let mut t = self.types.write().unwrap();
    t.insert_meta(name, type_meta)
  }

  pub fn insert(&self, name: &str, type_def: TypeRef) -> TypeRef {
    let mut t = self.types.write().unwrap();
    t.insert(name, type_def)
  }

  #[cfg(feature = "v14")]
  pub fn import_v14_types(&self, types: &PortableRegistry) -> Result<(), Box<EvalAltResult>> {
    let mut t = self.types.write().unwrap();
    t.import_v14_types(types)
  }

  pub fn dump_types(&mut self) {
    self.types.read().unwrap().dump_types();
  }

  pub fn dump_unresolved(&mut self) {
    self.types.read().unwrap().dump_unresolved();
  }

  pub fn custom_encode<F>(
    &self,
    name: &str,
    type_id: TypeId,
    func: F,
  ) -> Result<(), Box<EvalAltResult>>
  where
    F: 'static + Send + Sync + Fn(Dynamic, &mut EncodedArgs) -> Result<(), Box<EvalAltResult>>,
  {
    let mut t = self.types.write().unwrap();
    t.custom_encode(name, type_id, func)
  }

  pub fn custom_decode<F>(&self, name: &str, func: F) -> Result<(), Box<EvalAltResult>>
  where
    F: 'static + Send + Sync + Fn(BoxedInput, bool) -> Result<Dynamic, PError>,
  {
    let mut t = self.types.write().unwrap();
    t.custom_decode(name, func)
  }
}

pub struct InitRegistryFn(
  Box<
    dyn Fn(&mut Types, &RpcHandler, Option<BlockHash>) -> Result<(), Box<EvalAltResult>>
      + Send
      + Sync
      + 'static,
  >,
);

impl InitRegistryFn {
  pub fn init_types(
    &self,
    types: &mut Types,
    rpc: &RpcHandler,
    hash: Option<BlockHash>,
  ) -> Result<(), Box<EvalAltResult>> {
    self.0(types, rpc, hash)
  }
}

#[derive(Debug, Eq, PartialEq, Hash)]
struct SpecVersionKey(String, u32);

impl From<&RuntimeVersion> for SpecVersionKey {
  fn from(version: &RuntimeVersion) -> Self {
    Self(version.spec_name.to_string(), version.spec_version)
  }
}

pub struct InnerTypesRegistry {
  block_types: DashMap<Option<SpecVersionKey>, TypeLookup>,
  initializers: Vec<InitRegistryFn>,
  substrate_types: String,
  custom_types: String,
}

impl InnerTypesRegistry {
  pub fn new(substrate_types: String, custom_types: String) -> Self {
    Self {
      block_types: DashMap::new(),
      initializers: Vec::new(),
      substrate_types,
      custom_types,
    }
  }

  // Get runtime version from rpc node.
  fn rpc_get_runtime_version(
    rpc: &RpcHandler,
    hash: Option<BlockHash>,
  ) -> Result<RuntimeVersion, Box<EvalAltResult>> {
    let params = match hash {
      Some(hash) => json!([hash]),
      None => Value::Null,
    };
    Ok(
      rpc
        .call_method("state_getRuntimeVersion", params)?
        .ok_or_else(|| format!("Failed to get RuntimeVersion from node."))?,
    )
  }

  fn build_types(
    &self,
    rpc: &RpcHandler,
    version: Option<RuntimeVersion>,
    hash: Option<BlockHash>,
  ) -> Result<TypeLookup, Box<EvalAltResult>> {
    let runtime_version = match version {
      Some(version) => version,
      None => Self::rpc_get_runtime_version(&rpc, hash)?,
    };
    // build schema path.
    let spec_name = runtime_version.spec_name.to_string();
    let spec_version = runtime_version.spec_version;
    let name = if let Some((spec_name, _chain_type)) = spec_name.split_once("_") {
      spec_name
    } else {
      &spec_name
    };
    let schema_prefix = format!("./schemas/{}", name);
    log::debug!("schema_prefix = {}", schema_prefix);

    let mut types = Types::new(runtime_version);
    // Load standard substrate types.
    if types
      .load_schema(&format!("{}/init_{}.json", schema_prefix, spec_version))
      .is_err()
    {
      types.load_schema(&self.substrate_types)?;
    }
    // Load custom chain types.
    if types
      .load_schema(&format!("{}/{}.json", schema_prefix, spec_version))
      .is_err()
    {
      types.load_schema(&self.custom_types)?;
    }

    for init in &self.initializers {
      init.init_types(&mut types, rpc, hash)?;
    }
    let lookup = TypeLookup::from_types(types);
    Ok(lookup)
  }

  pub fn get_block_types(
    &self,
    rpc: &RpcHandler,
    version: Option<RuntimeVersion>,
    hash: Option<BlockHash>,
  ) -> Result<TypeLookup, Box<EvalAltResult>> {
    let version = match (version, hash) {
      (Some(version), _) => Some(version),
      (None, hash) => Some(Self::rpc_get_runtime_version(&rpc, hash)?),
    };
    let spec_key: Option<SpecVersionKey> = version.as_ref().map(|v| v.into());
    use dashmap::mapref::entry::Entry;
    Ok(match self.block_types.entry(spec_key) {
      Entry::Occupied(entry) => entry.get().clone(),
      Entry::Vacant(entry) => {
        log::info!(
          "Spec version not found: load schema/metadata.  RuntimeVersion={:?}",
          version
        );
        // Need to build/initialize new Types.
        let lookup = self.build_types(rpc, version, hash)?;
        entry.insert(lookup.clone());
        lookup
      }
    })
  }

  pub fn add_init(&mut self, func: InitRegistryFn) {
    self.initializers.push(func);
  }
}

#[derive(Clone)]
pub struct TypesRegistry(Arc<RwLock<InnerTypesRegistry>>);

impl TypesRegistry {
  pub fn new(substrate_types: String, custom_types: String) -> Self {
    Self(Arc::new(RwLock::new(InnerTypesRegistry::new(
      substrate_types,
      custom_types,
    ))))
  }

  pub fn get_block_types(
    &self,
    rpc: &RpcHandler,
    version: Option<RuntimeVersion>,
    hash: Option<BlockHash>,
  ) -> Result<TypeLookup, Box<EvalAltResult>> {
    self.0.write().unwrap().get_block_types(rpc, version, hash)
  }

  pub fn add_init<F>(&self, func: F)
  where
    F: 'static
      + Send
      + Sync
      + Fn(&mut Types, &RpcHandler, Option<BlockHash>) -> Result<(), Box<EvalAltResult>>,
  {
    self
      .0
      .write()
      .unwrap()
      .add_init(InitRegistryFn(Box::new(func)))
  }
}

pub fn init_engine(
  engine: &mut Engine,
  opts: &EngineOptions,
) -> Result<TypesRegistry, Box<EvalAltResult>> {
  engine
    .register_type_with_name::<TypesRegistry>("TypesRegistry")
    .register_result_fn(
      "get_block_types",
      |registry: &mut TypesRegistry, rpc: RpcHandler, version: Dynamic, hash: Dynamic| {
        let version = version.try_cast::<RuntimeVersion>();
        registry.get_block_types(&rpc, version, hash_from_dynamic(hash))
      },
    )
    .register_type_with_name::<TypeLookup>("TypeLookup")
    .register_get("metadata", |lookup: &mut TypeLookup| {
      lookup
        .get_metadata()
        .map(Dynamic::from)
        .unwrap_or(Dynamic::UNIT)
    })
    .register_fn("dump_types", TypeLookup::dump_types)
    .register_fn("dump_unresolved", TypeLookup::dump_unresolved)
    .register_result_fn(
      "parse_named_type",
      |lookup: &mut TypeLookup, name: &str, def: &str| lookup.parse_named_type(name, def),
    )
    .register_result_fn("parse_type", |lookup: &mut TypeLookup, def: &str| {
      lookup.parse_type(def)
    })
    .register_fn("resolve", |lookup: &mut TypeLookup, name: &str| {
      lookup.resolve(name)
    })
    .register_type_with_name::<Types>("Types")
    .register_type_with_name::<TypeMeta>("TypeMeta")
    .register_fn("to_string", TypeMeta::to_string)
    .register_type_with_name::<TypeRef>("TypeRef")
    .register_fn("to_string", TypeRef::to_string)
    .register_result_fn("encode", TypeRef::encode_mut)
    .register_result_fn("decode", TypeRef::decode_mut);

  let types_registry = TypesRegistry::new(opts.substrate_types.clone(), opts.custom_types.clone());

  Ok(types_registry)
}
