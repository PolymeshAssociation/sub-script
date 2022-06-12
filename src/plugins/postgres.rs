use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rhai::{Dynamic, INT, Engine, EvalAltResult};

use postgres::{Client, Statement, NoTls};
use postgres::types::{accepts, to_sql_checked, ToSql, IsNull, Type};

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct DynamicToSql(pub Dynamic);

impl DynamicToSql {
  fn borrow_to_sql(&self) -> &(dyn ToSql + Sync) {
    &*self
  }
}

impl ToSql for DynamicToSql {
  fn to_sql(&self, ty: &Type, out: &mut bytes::BytesMut) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
    if self.0.is::<()>() {
      Ok(IsNull::Yes)
    } else {
      match *ty {
        Type::BOOL => {
          if let Some(b) = self.0.as_bool().ok() {
            b.to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to an BOOL: {:?}", self.0))?;
          }
        }
        Type::CHAR => {
          if let Some(num) = self.0.as_int().ok() {
            (num as i8).to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to an CHAR(i8): {:?}", self.0))?;
          }
        }
        Type::INT2 => {
          if let Some(num) = self.0.as_int().ok() {
            (num as i16).to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to an INT2(i16): {:?}", self.0))?;
          }
        }
        Type::INT4 => {
          if let Some(num) = self.0.as_int().ok() {
            (num as i32).to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to an INT4(i32): {:?}", self.0))?;
          }
        }
        Type::INT8 => {
          if let Some(num) = self.0.as_int().ok() {
            num.to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to an INT8(i64): {:?}", self.0))?;
          }
        }
        Type::VARCHAR | Type::TEXT => {
          if let Some(s) = self.0.clone().into_immutable_string().ok() {
            s.as_str().to_sql(ty, out)?;
          } else {
            Err(format!("Can't convert value to a string: {:?}", self.0))?;
          }
        }
        Type::JSON | Type::JSONB => {
          let val: Value = rhai::serde::from_dynamic(&self.0)?;
          val.to_sql(ty, out)?;
        }
        _ => {
          Err(format!("Unsupported Dynamic -> ToSql type={:?}, value={:?}", ty, self.0))?;
        }
      }
      Ok(IsNull::No)
    }
  }

  accepts!(BOOL, CHAR, INT2, INT4, INT8, VARCHAR, TEXT, JSON, JSONB);

  to_sql_checked!();
}

fn into_err(err: postgres::Error) -> Box<EvalAltResult> {
  err.to_string().into()
}

#[derive(Clone)]
pub struct PgClient(Arc<Mutex<Client>>);

impl PgClient {
  pub fn connect(params: &str) -> Result<Self, Box<EvalAltResult>> {
    let client = Client::connect(params, NoTls).map_err(into_err)?;
    Ok(Self(Arc::new(Mutex::new(client))))
  }

  pub fn prepare(&mut self, query: &str) -> Result<Statement, Box<EvalAltResult>> {
    let stmt = self.0.lock().unwrap().prepare(query).map_err(into_err)?;
    Ok(stmt)
  }

  pub fn execute(&mut self, stmt: Statement, params: Vec<Dynamic>) -> Result<INT, Box<EvalAltResult>> {
    let d_params: Vec<DynamicToSql> = params.into_iter().map(|d| DynamicToSql(d)).collect();
    let s_params: Vec<&(dyn ToSql + Sync)> = d_params.iter().map(|d| d.borrow_to_sql()).collect();
    let res = self.0.lock().unwrap().execute(&stmt, s_params.as_slice()).map_err(into_err)?;
    Ok(res as INT)
  }
}

#[derive(Clone)]
pub struct PostgresPlugin {}

impl PostgresPlugin {
  pub fn new() -> Result<Self, Box<EvalAltResult>> {
    Ok(Self {})
  }

  pub fn connect(&mut self, params: &str) -> Result<Dynamic, Box<EvalAltResult>> {
    let client = PgClient::connect(params)?;

    Ok(Dynamic::from(client))
  }
}

pub fn init_engine(
  engine: &mut Engine,
  globals: &mut HashMap<String, Dynamic>,
) -> Result<(), Box<EvalAltResult>> {
  engine
    .register_type_with_name::<PostgresPlugin>("PostgresPlugin")
    .register_result_fn("connect", PostgresPlugin::connect)
    .register_type_with_name::<PgClient>("PgClient")
    .register_result_fn("prepare", PgClient::prepare)
    .register_result_fn("execute", PgClient::execute)
    .register_type_with_name::<Statement>("PgStatement")
    ;

  let plugin = PostgresPlugin::new()?;
  globals.insert("Postgres".into(), Dynamic::from(plugin.clone()));

  Ok(())
}
