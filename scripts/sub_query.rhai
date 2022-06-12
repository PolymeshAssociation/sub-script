
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

let channel = new_channel();
let sender = channel[0];
let db_task = ENGINE.spawn_file_task_args("./scripts/sub_query_db_task.rhai", [channel[1]]);

fn process_block(metadata, hash, spec_version, block, events) {
	let block_id = block.block_number;
	let parent_id = block_id - 1;
	let block_ts = 0;
	let parent_hash = block.parent.to_debug();
	let state_root = block.state_root.to_debug();
	let extrinsics_root = block.extrinsics_root.to_debug();

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
	let processed_events = [];
	for (event, event_idx) in events {
		let row = #{
			id: `${block_id}/${event_idx}`,
			block_id: block_id,
			event_idx: event_idx,
			spec_version_id: spec_version,
		};
		//print(`events[${event_idx}] = ${event}`);

		// Get the extrinsic index.
		let extrinsic_idx = 0;
		if event.phase != () {
			extrinsic_idx = event.phase.ApplyExtrinsic;
		}
		row.extrinsic_idx = extrinsic_idx;
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
		row.module_id = module_id;
		row.event_id = event_id;
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
		row.attributes_txt = attributes;

		// Process event args.
		let a_len = attributes.len();
		row.event_arg_0 = if a_len >= 1 { attributes[0] } else { () };
		row.event_arg_1 = if a_len >= 2 { attributes[1] } else { () };
		row.event_arg_2 = if a_len >= 3 { attributes[2] } else { () };
		row.event_arg_3 = if a_len >= 4 { attributes[3] } else { () };

		processed_events += row;
	}

	// Process extrinsics.
	let count_extrinsics_unsigned = 0;
	let count_extrinsics_signed = 0;
	let processed_extrinsics = [];
	for (extrinsic, idx) in extrinsics {
		//print(`extrinsics[${idx}] = ${extrinsic}`);
		let row = #{
			id: `${block_id}/${idx}`,
			block_id: block_id,
			extrinsic_idx: idx,
			extrinsic_length: extrinsic.len,
			spec_version_id: spec_version,
			success: extrinsic_result[idx],
			nonce: extrinsic.nonce,
			extrinsic_hash: extrinsic.hash,
		};

		// Count signed/unsigned
		let signed = if extrinsic.is_signed {
			count_extrinsics_signed += 1;
			row.address = extrinsic.signed_by;
			1
		} else {
			count_extrinsics_unsigned += 1;
			0
		};
		row.signed = signed;
		row.signedby_address = signed;

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
		row.module_id = module_id.to_lower();
		row.call_id = call_id.to_lower();

		// Get block timestamp.
		if module_id == "Timestamp" && call_id == "set" {
			block_ts = params[0];
		}

		// TODO: Fix parameters
		//params = [];
		for (p, idx) in params {
			params[idx] = p.to_string();
		}
		row.params_txt = params;

		processed_extrinsics += row;
	}

	if count_extrinsics != 1 || count_events != 1 {
		print(`${block.block_number}: ${hash}: spec: ${spec_version}: extrinsics = ${count_extrinsics}, events = ${count_events}`);
	}

	let block_row = #{
		id: `${block_id}`,
		block_id: block_id,
		parent_id: parent_id,
		hash: hash,
		parent_hash: parent_hash,
		state_root: state_root,
		extrinsics_root: extrinsics_root,
		count_extrinsics: count_extrinsics,
		count_extrinsics_unsigned: count_extrinsics_unsigned,
		count_extrinsics_signed: count_extrinsics_signed,
		count_extrinsics_error: count_extrinsics_error,
		count_extrinsics_success: count_extrinsics_success,
		count_events: count_events,
		spec_version_id: spec_version,
		datetime: block_ts,
	};

	return #{
		block: block_row,
		processed_extrinsics: processed_extrinsics,
		processed_events: processed_events,
	};
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

		let batch = process_block(last_metadata, hash, cur_spec, block, events);

		// Send batch to DB Task.
		sender.send(batch);

		counter += 1;
		if counter >= 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}
}

// Signal the DB Task to finish.
sender.close();
print("Wait for DB Task to finish.");
db_task.join();

print(`end = ${block_number}`);
