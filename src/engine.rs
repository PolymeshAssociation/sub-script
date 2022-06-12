use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use std::thread::{spawn, JoinHandle};
use std::sync::mpsc;

use std::path::PathBuf;
use std::{fs::File, io::Read};

pub use rhai::{Dynamic, Engine, EvalAltResult, ParseError, Position, Scope, AST, INT};

#[cfg(not(feature = "no_optimize"))]
use rhai::OptimizationLevel;

use crate::{block, client, metadata, plugins, rpc, storage, types, users};

#[derive(Debug, Clone)]
pub struct EngineOptions {
  pub url: String,
  pub substrate_types: String,
  pub custom_types: String,
  pub args: Vec<String>,
}

pub fn read_script(script: &PathBuf) -> Result<(String, String), Box<EvalAltResult>> {
  let mut contents = String::new();

  let filename = match script.as_path().canonicalize() {
    Err(err) => Err(format!("Error script file path: {:?}\n{}", script, err))?,
    Ok(f) => match f.strip_prefix(std::env::current_dir().unwrap().canonicalize().unwrap()) {
      Ok(f) => f.into(),
      _ => f,
    },
  };

  let mut f = match File::open(&filename) {
    Err(err) => Err(format!(
      "Error reading script file: {}\n{}",
      filename.to_string_lossy(),
      err
    ))?,
    Ok(f) => f,
  };

  if let Err(err) = f.read_to_string(&mut contents) {
    Err(format!(
      "Error reading script file: {}\n{}",
      filename.to_string_lossy(),
      err
    ))?;
  }

  let contents = if contents.starts_with("#!") {
    // Skip shebang
    &contents[contents.find('\n').unwrap_or(0)..]
  } else {
    &contents[..]
  };
  let filename = filename.to_string_lossy();

  Ok((contents.to_string(), filename.to_string()))
}

pub fn eprint_script_error(path: &PathBuf, err: EvalAltResult) {
  let (contents, filename) = match read_script(path) {
    Ok(v) => v,
    Err(err) => {
      eprintln!("{:?}", err);
      return;
    }
  };

  eprintln!("{:=<1$}", "", filename.len());
  eprintln!("{}", filename);
  eprintln!("{:=<1$}", "", filename.len());
  eprintln!("");

  eprint_error(&contents, err);
}

pub fn eprint_error(input: &str, mut err: EvalAltResult) {
  fn eprint_line(lines: &[&str], pos: Position, err_msg: &str) {
    let line = pos.line().unwrap();
    let line_no = format!("{}: ", line);

    if line < lines.len() {
      eprintln!("{}{}", line_no, lines[line - 1]);
    }
    eprintln!(
      "{:>1$} {2}",
      "^",
      line_no.len() + pos.position().unwrap(),
      err_msg
    );
    eprintln!("");
  }

  let lines: Vec<_> = input.split('\n').collect();

  // Print error
  let pos = err.take_position();

  if pos.is_none() {
    // No position
    eprintln!("{}", err);
  } else {
    // Specific position
    eprint_line(&lines, pos, &err.to_string())
  }
}

type Sender = mpsc::Sender<Dynamic>;
type SyncSender = mpsc::SyncSender<Dynamic>;
type Receiver = mpsc::Receiver<Dynamic>;

#[derive(Clone)]
pub struct TaskSender(Arc<Mutex<Option<Sender>>>);

impl TaskSender {
  fn new(sender: Sender) -> Dynamic {
    Dynamic::from(Self(Arc::new(Mutex::new(Some(sender)))))
  }

  pub fn send(&mut self, val: Dynamic) -> Result<(), Box<EvalAltResult>> {
    let sender = self.0.lock().unwrap();
    if let Some(sender) = &*sender {
      Ok(sender.send(val).map_err(|e| e.to_string())?)
    } else {
      Err(format!("Sender was closed"))?
    }
  }

  pub fn close(&mut self) {
    self.0.lock().unwrap().take();
  }
}

#[derive(Clone)]
pub struct TaskSyncSender(Arc<Mutex<Option<SyncSender>>>);

impl TaskSyncSender {
  fn new(sender: SyncSender) -> Dynamic {
    Dynamic::from(Self(Arc::new(Mutex::new(Some(sender)))))
  }

  pub fn send(&mut self, val: Dynamic) -> Result<(), Box<EvalAltResult>> {
    let sender = self.0.lock().unwrap();
    if let Some(sender) = &*sender {
      Ok(sender.send(val).map_err(|e| e.to_string())?)
    } else {
      Err(format!("Sender was closed"))?
    }
  }

  pub fn close(&mut self) {
    self.0.lock().unwrap().take();
  }
}

#[derive(Clone)]
pub struct TaskReceiver(Arc<Mutex<Option<Receiver>>>);

impl TaskReceiver {
  fn new(receiver: Receiver) -> Dynamic {
    Dynamic::from(Self(Arc::new(Mutex::new(Some(receiver)))))
  }

  pub fn recv(&mut self) -> Dynamic {
    let receiver = self.0.lock().unwrap();
    if let Some(receiver) = &*receiver {
      receiver.recv().unwrap_or(Dynamic::UNIT)
    } else {
      Dynamic::UNIT
    }
  }

  pub fn close(&mut self) {
    self.0.lock().unwrap().take();
  }
}

#[derive(Clone)]
pub struct TaskHandle(Arc<RwLock<Option<JoinHandle<Result<Dynamic, Box<EvalAltResult>>>>>>);

impl TaskHandle {
  fn new(handle: JoinHandle<Result<Dynamic, Box<EvalAltResult>>>) -> Self {
    Self(Arc::new(RwLock::new(Some(handle))))
  }

  pub fn join(&mut self) -> Result<Dynamic, Box<EvalAltResult>> {
    match self.0.write().unwrap().take() {
      Some(handle) => handle
        .join()
        .map_err(|err| format!("Failed to join thread: {:?}", err))?,
      _ => Err(format!("Already joined task"))?,
    }
  }
}

#[derive(Clone)]
pub struct SharedEngine(Arc<RwLock<Engine>>);

impl SharedEngine {
  fn new(engine: Engine) -> Self {
    Self(Arc::new(RwLock::new(engine)))
  }

  pub fn compile(&self, script: &str) -> Result<AST, Box<EvalAltResult>> {
    Ok(self.0.read().unwrap().compile(script)?)
  }

  pub fn compile_file(&self, path: PathBuf) -> Result<AST, Box<EvalAltResult>> {
    let (contents, filename) = read_script(&path)?;
    let mut ast = self.0.read().unwrap().compile(contents)?;
    ast.set_source(filename);
    Ok(ast)
  }

  pub fn run_ast_with_scope(&self, scope: &mut Scope, ast: &AST) -> Result<(), Box<EvalAltResult>> {
    self.0.read().unwrap().run_ast_with_scope(scope, ast)
  }

  pub fn eval_ast_with_scope(
    &self,
    scope: &mut Scope,
    ast: &AST,
  ) -> Result<Dynamic, Box<EvalAltResult>> {
    self.0.read().unwrap().eval_ast_with_scope(scope, ast)
  }

  pub fn run_file_with_scope(
    &self,
    scope: &mut Scope,
    path: PathBuf,
  ) -> Result<(), Box<EvalAltResult>> {
    let ast = self.compile_file(path)?;
    self.0.read().unwrap().run_ast_with_scope(scope, &ast)
  }

  pub fn spawn_task(&mut self, script: &str) -> Result<TaskHandle, Box<EvalAltResult>> {
    let ast = self.compile(script)?;
    self.spawn_task_ast_args(ast, Dynamic::UNIT)
  }

  pub fn spawn_task_args(
    &mut self,
    script: &str,
    args: Dynamic,
  ) -> Result<TaskHandle, Box<EvalAltResult>> {
    let ast = self.compile(script)?;
    self.spawn_task_ast_args(ast, args)
  }

  pub fn spawn_file_task(&mut self, file: &str) -> Result<TaskHandle, Box<EvalAltResult>> {
    let ast = self.compile_file(file.into())?;
    self.spawn_task_ast_args(ast, Dynamic::UNIT)
  }

  pub fn spawn_file_task_args(
    &mut self,
    file: &str,
    args: Dynamic,
  ) -> Result<TaskHandle, Box<EvalAltResult>> {
    let ast = self.compile_file(file.into())?;
    self.spawn_task_ast_args(ast, args)
  }

  fn spawn_task_ast_args(
    &mut self,
    ast: AST,
    args: Dynamic,
  ) -> Result<TaskHandle, Box<EvalAltResult>> {
    let engine = self.clone();
    let handle = spawn(move || {
      let mut scope = engine.new_scope(args);
      engine.eval_ast_with_scope(&mut scope, &ast)
    });
    Ok(TaskHandle::new(handle))
  }

  fn new_scope(&self, args: Dynamic) -> Scope {
    let mut scope = Scope::new();
    scope.push("ARG", args);
    scope.push("ENGINE", self.clone());
    scope
  }

  pub fn args_to_scope(&self, args: &[String]) -> Scope {
    // Convert script arguments.
    let args = args
      .into_iter()
      .cloned()
      .map(|arg| Dynamic::from(arg))
      .collect::<Vec<Dynamic>>();

    self.new_scope(args.into())
  }
}

pub fn init_engine(opts: &EngineOptions) -> Result<SharedEngine, Box<EvalAltResult>> {
  let mut engine = Engine::new();
  let mut globals = HashMap::new();

  #[cfg(not(feature = "no_optimize"))]
  engine.set_optimization_level(OptimizationLevel::Full);
  engine.set_max_expr_depths(64, 64);

  // Initialize types, client, users, metadata and plugins.
  let rpc_manager = rpc::init_engine(&mut engine)?;
  let rpc = rpc_manager.get_client(&opts.url)?;

  let types_registry = types::init_engine(&mut engine, &opts)?;
  client::init_types_registry(&types_registry)?;
  metadata::init_types_registry(&types_registry)?;
  plugins::init_types_registry(&types_registry)?;

  // Get metadata/types for current block.
  let lookup = types_registry.get_block_types(&rpc, None, None)?;

  let client = client::init_engine(&rpc, &mut engine, &lookup)?;
  block::init_engine(&mut engine)?;
  let users = users::init_engine(&mut engine, &client);
  let metadata = metadata::init_engine(&mut engine, &mut globals, &client)?;
  let storage = storage::init_engine(&mut engine, &client, &metadata);
  plugins::init_engine(&mut engine, &mut globals, &client)?;

  // Setup globals for easy access.
  globals.insert("CLIENT".into(), Dynamic::from(client));
  globals.insert("RPC_MANAGER".into(), Dynamic::from(rpc_manager));
  globals.insert("RPC".into(), Dynamic::from(rpc));
  globals.insert("Types".into(), Dynamic::from(lookup));
  globals.insert("TypesRegistry".into(), Dynamic::from(types_registry));
  globals.insert("STORAGE".into(), Dynamic::from(storage));
  globals.insert("USER".into(), Dynamic::from(users));

  // For easier access to globals.
  engine.on_var(move |name, _, _| {
    let val = globals.get(name).cloned();
    Ok(val)
  });

  engine
    .register_type_with_name::<SharedEngine>("Engine")
    .register_result_fn("spawn_task", SharedEngine::spawn_task)
    .register_result_fn("spawn_task_args", SharedEngine::spawn_task_args)
    .register_result_fn("spawn_file_task", SharedEngine::spawn_file_task)
    .register_result_fn("spawn_file_task_args", SharedEngine::spawn_file_task_args)
    .register_type_with_name::<TaskHandle>("TaskHandle")
    .register_result_fn("join", TaskHandle::join)
    .register_fn("new_channel", || {
      let (sender, receiver) = mpsc::channel();
      vec![TaskSender::new(sender), TaskReceiver::new(receiver)]
    })
    .register_fn("new_sync_channel", |bound: INT| {
      let (sender, receiver) = mpsc::sync_channel(bound as usize);
      vec![TaskSyncSender::new(sender), TaskReceiver::new(receiver)]
    })
    .register_type_with_name::<TaskSender>("TaskSender")
    .register_result_fn("send", TaskSender::send)
    .register_fn("close", TaskSender::close)
    .register_type_with_name::<TaskSyncSender>("TaskSyncSender")
    .register_result_fn("send", TaskSyncSender::send)
    .register_fn("close", TaskSyncSender::close)
    .register_type_with_name::<TaskReceiver>("TaskReceiver")
    .register_fn("recv", TaskReceiver::recv)
    .register_fn("close", TaskReceiver::close)
    ;

  Ok(SharedEngine::new(engine))
}
