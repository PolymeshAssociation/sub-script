
// Get arguments.
let start_block = ARG.shift();
if start_block == () {
	print("Need start block number");
	return;
}
start_block = parse_int(start_block);
// Number of blocks to scan.
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
// Batch size.
let batch_size = ARG.shift();
batch_size = if batch_size == () { 10 } else { parse_int(batch_size) };

let end_block = start_block + count;

const DB = Postgres.connect("host=comp002 port=5433 user=postgres password=postgres");

fn build_upsert(db, schema, table, columns, on_conflict, has_created_at, has_updated_at) {
	let NL = "\n";
	let col_names = "";
	let values = "";
	let updates = "";
	for (col, idx) in columns {
		let val = `$${idx + 1}`;
		let name = col;
		if type_of(col) == "array" {
			name = col[0];
			col[1].replace("$$", val);
			val = col[1];
		}
		let update = `  "${name}" = EXCLUDED."${name}"`;
		if idx == 0 {
			col_names += `"${name}"`;
			values += val;
			updates += update;
		} else {
			col_names += `, "${name}"`;
			values += `, ${val}`;
			updates += `,${NL}${update}`;
		}
		// insert a newline every 5 columns.
		if idx % 5 == 4 {
			col_names += NL;
			values += NL;
		}
	}
	if has_created_at {
		col_names += `, "created_at"`;
		values += `, current_timestamp`;
	}
	if has_updated_at {
		col_names += `, "updated_at"`;
		values += `, current_timestamp`;
		updates += `,${NL}  "updated_at" = EXCLUDED."updated_at"`;
	}
	let sql = `
INSERT INTO "${schema}"."${table}"(${NL}${col_names}${NL}) VALUES(
  ${values}
)  ON CONFLICT (${on_conflict})
   DO UPDATE SET${NL}${updates}`;
	//print(`sql: ${sql}`);
	return db.prepare(sql);
}

const STMT_BLOCK = build_upsert(DB, "sub_script", "blocks", [
	"id", "block_id", "parent_id", "hash", "parent_hash", "state_root", "extrinsics_root",
  "count_extrinsics", "count_extrinsics_unsigned", "count_extrinsics_signed", "count_extrinsics_error", "count_extrinsics_success",
  "count_events", "spec_version_id", ["datetime", "to_timestamp($$::INT8 / 1000)" ]
], `"id"`, true, true);

const STMT_EXTRINSIC = build_upsert(DB, "sub_script", "extrinsics", [
	"id", "block_id", "extrinsic_idx", "extrinsic_length",
	"signed", "signedby_address", "address",
	"module_id", "call_id", ["params_txt", "$$::JSONB"], "success", "nonce",
	"extrinsic_hash", "spec_version_id",
], `"id"`, true, true);

const STMT_EVENT = build_upsert(DB, "sub_script", "events", [
	"id", "block_id", "event_idx", "extrinsic_idx", "spec_version_id",
	"module_id", "event_id", ["attributes_txt", "$$::JSONB"],
	["event_arg_0", "$$::JSONB"],
	["event_arg_1", "$$::JSONB"],
	["event_arg_2", "$$::JSONB"],
	["event_arg_3", "$$::JSONB"],
	"claim_type", "claim_scope", "claim_issuer", "claim_expiry",
	"corporate_action_ticker", "fundraiser_offering_asset", "transfer_to",
], `"id"`, true, true);

fn import_block(metadata, hash, spec_version, block, events) {
	let block_id = block.block_number;
	let parent_id = block_id - 1;
	let block_ts = 0;
	let parent_hash = block.parent.to_debug();
	let state_root = block.state_root.to_debug();
	let extrinsics_root = block.extrinsics_root.to_debug();

	//print(`block = ${block}`);
	//print(`events = ${events}`);
	//print(`parent_hash = ${parent_hash}`);

	// Decode block extrinsics.
	let extrinsics = block.extrinsics;
  let count_extrinsics = extrinsics.len();

	// Track extrinsic success/failed status.
	let extrinsic_result = [];
	extrinsic_result.pad(count_extrinsics, 0);

	// Process events.
	let count_events = events.len();
	let count_extrinsics_error = 0;
	let count_extrinsics_success = 0;
	let extrinsic_events = [];
	for (event, event_idx) in events {
		//print(`events[${event_idx}] = ${event}`);

		// Get the extrinsic index.
		let extrinsic_idx = 0;
		if event.phase != () {
			extrinsic_idx = event.phase.ApplyExtrinsic;
		}
		//print(`extrinsic_idx = ${extrinsic_idx}`);

		// Get event module_id and event_id.
		let attributes = [];
		let module_id = "";
		let event_id = "";
		if event.event != () {
			for mod_name in event.event.keys() {
				module_id = mod_name;
				let mod = event.event[mod_name];
				for event_name in mod.keys() {
					event_id = event_name;
					attributes = mod[event_name];
				}
			}
		}
		// Check for extrinsic success/failed.
		let success = ();
		if module_id == "System" {
			if event_id == "ExtrinsicSuccess" {
				success = 1;
				count_extrinsics_success += 1;
			}
			if event_id == "ExtrinsicFailed" {
				success = 0;
				count_extrinsics_error += 1;
			}
		}
		if extrinsic_idx != () {
			extrinsic_result[extrinsic_idx] = success;
		}
		if attributes == () {
			attributes = [];
		}

		// Process event args.
		let a_len = attributes.len();
		let args_0 = if a_len >= 1 { attributes[0] } else { () };
		let args_1 = if a_len >= 2 { attributes[1] } else { () };
		let args_2 = if a_len >= 3 { attributes[2] } else { () };
		let args_3 = if a_len >= 4 { attributes[3] } else { () };
		let claim_type = ();
		let claim_scope = ();
		let claim_issuer = ();
		let claim_expiry = ();
		let corporate_action_ticker = ();
		let fundraiser_offering_asset = ();
		let transfer_to = ();

		let row = [
			`${block_id}/${event_idx}`, block_id, event_idx, extrinsic_idx,
			spec_version, module_id.to_lower(), event_id, attributes,
			args_0, args_1, args_2, args_3,
			claim_type, claim_scope, claim_issuer, claim_expiry,
			corporate_action_ticker, fundraiser_offering_asset, transfer_to,
		];
		// Insert event into DB.
		let res = global::DB.execute(global::STMT_EVENT, row);
		if res != 1 {
			print(`Extrinsic import failed: res = ${res}`);
		}
	}

	// Process extrinsics.
	let count_extrinsics_unsigned = 0;
	let count_extrinsics_signed = 0;
	for (extrinsic, idx) in extrinsics {
		//print(`extrinsics[${idx}] = ${extrinsic}`);
		let success = extrinsic_result[idx];

		// Count signed/unsigned
		let signed = if extrinsic.is_signed {
			count_extrinsics_signed += 1;
			1
		} else {
			count_extrinsics_unsigned += 1;
			0
		};

		// Get module/call id and parameters.
		let decoded = extrinsic.decoded_call;
		let params = ();
		let module_id = "";
		let call_id = "";
		for mod_name in decoded.keys() {
			module_id = mod_name;
			let mod = decoded[module_id];
			for func_name in mod.keys() {
				call_id = func_name;
				params = mod[func_name];
			}
		}
		if params == () {
			params = [];
		}

		// Get block timestamp.
		if module_id == "Timestamp" && call_id == "set" {
			block_ts = params[0];
		}

		// TODO: Fix parameters
		//params = [];
		for (p, idx) in params {
			params[idx] = p.to_string();
		}

		let row = [
			`${block_id}/${idx}`, block_id, idx, extrinsic.len, signed, signed, extrinsic.signed_by,
			module_id.to_lower(), call_id.to_lower(), params, success,
			extrinsic.nonce, extrinsic.hash,
			spec_version
		];
		//print(`insert extrinsic: ${row}`);
		// Insert extrinsic into DB.
		let res = global::DB.execute(global::STMT_EXTRINSIC, row);
		if res != 1 {
			print(`Extrinsic import failed: res = ${res}`);
		}
	}

	if count_extrinsics != 1 || count_events != 1 {
		print(`${block.block_number}: ${hash}: spec: ${spec_version}: extrinsics = ${count_extrinsics}, events = ${count_events}`);
	}

	// Insert block into DB.
	let res = global::DB.execute(global::STMT_BLOCK, [
		`${block_id}`, block_id, parent_id, hash, parent_hash, state_root, extrinsics_root,
		count_extrinsics, count_extrinsics_unsigned, count_extrinsics_signed, count_extrinsics_error, count_extrinsics_success,
		count_events, spec_version, block_ts,
	]);
	if res != 1 {
		print(`Block import failed: res = ${res}`);
	}
}

fn build_metadata_lookup(metadata) {
	let modules = #{};
	for mod in metadata.modules {
		let name = mod.name;
		let functions = #{};
		for func in mod.funcs {
			functions[func.name] = func;
		}
		let events = #{};
		for event in mod.events {
			events[event.name] = event;
		}
		modules[mod.name] = #{
			functions: functions,
			events: events,
		};
	}
	return modules;
}

fn get_block_hashes(block_number, end_block, batch_size) {
	let blocks = [];
	// Async request block hashes.
	while block_number <= end_block && blocks.len() <= batch_size {
		let hash = RPC.async_method("chain_getBlockHash",[block_number]);
		blocks += #{
			number: block_number,
			hash: hash,
		};
		block_number += 1;
	}
	// wait for block hashes.
	for (block, idx) in blocks {
		let hash = RPC.get_response(block.hash);
		block.hash = hash;
		// Request RuntimeVersion, Block, and events.
		block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
		block.block = RPC.async_method("chain_getBlock",[hash]);
		block.events = RPC.async_method("state_getStorage",["0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7", hash]);
		blocks[idx] = block;
	}
	return blocks;
}

let chain_current_block = CLIENT.get_block(());
if end_block > chain_current_block.block_number {
	end_block = chain_current_block.block_number;
}

let last_rt = ();
let last_types = Types;
let last_metadata = build_metadata_lookup(Types.metadata);
let cur_spec = 0;

let block_number = start_block;
let counter = 0;

// Pre-fetch a batch of blocks.
let next_blocks = get_block_hashes(block_number, end_block, batch_size);

while block_number <= end_block {
	let blocks = next_blocks;
	block_number += blocks.len();
	if block_number <= end_block {
		// Pre-fetch next batch.
		next_blocks = get_block_hashes(block_number, end_block, batch_size);
	}
	for block in blocks {
		let hash = block.hash;
		// Load the block's RuntimeVersion.
		let rt = RPC.get_response_as_runtime_version(block.rt);

		if last_rt == () || cur_spec != rt.specVersion {
			last_rt = rt;
			last_types = TypesRegistry.get_block_types(RPC, rt, hash);
			last_metadata = build_metadata_lookup(last_types.metadata);
			//print(`metadata = ${last_metadata}`);
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
		}
		let events = RPC.get_response_as_block_events(last_types, block.events);
		let block = RPC.get_response_as_block(last_types, block.block);

		import_block(last_metadata, hash, cur_spec, block, events);

		counter += 1;
		if counter > 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}
}
print(`end = ${block_number}`);
