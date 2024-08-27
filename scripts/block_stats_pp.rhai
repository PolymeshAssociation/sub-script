
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
		// Request RuntimeVersion, Block.
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
let cur_spec = 0;

let block_number = start_block;
let counter = 0;

let max_block_weight = 2700.0 * 1_000_000_000.0;

// Pre-fetch a batch of blocks.
let next_blocks = get_block_hashes(block_number, end_block, batch_size);

let total_extrinsics = 0;
let total_success = 0;
let total_error = 0;
let total_non_confidential = 0;
let total_non_confidential_moves = 0;
let total_confidential = 0;
let total_confidential_moves = 0;
let total_fees = 0;
let non_empty_blocks = 0;
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
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
		}
		let events = RPC.get_response_as_block_events(last_types, block.events);
		let block = RPC.get_response_as_block(last_types, block.block);

		let e_count = 0;
		if events != () {
			e_count = events.len();
		} else {
			print(`${block.block_number}: missing events, or failed to decode.`);
			events = [];
		}

		let block_weight = 0;
		let count_extrinsics = 0;
		let count_extrinsics_error = 0;
		let count_extrinsics_success = 0;
		let count_non_confidential = 0;
		let count_confidential = 0;
		let count_events = #{};
		let block_fees = 0;
		for (event, event_idx) in events {
			// Get the extrinsic index.
			let extrinsic_idx = 0;
			if event.phase != () {
				extrinsic_idx = event.phase.ApplyExtrinsic;
			}
			// Skip the `Timestamp` call.
			if extrinsic_idx == 0 {
				continue;
			}
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
			if attributes == () {
				attributes = [];
			}
			//print(`${block.block_number}: mod=${module_id}, event=${event_id}`);
			// Check for extrinsic success/failed.
			let success = ();
			let info = ();
			if module_id == "System" {
				if event_id == "ExtrinsicSuccess" {
					success = 1;
					count_extrinsics += 1;
					count_extrinsics_success += 1;
					total_extrinsics += 1;
					total_success += 1;
					info = attributes[0];
				}
				if event_id == "ExtrinsicFailed" {
					success = 0;
					count_extrinsics += 1;
					count_extrinsics_error += 1;
					total_extrinsics += 1;
					total_error += 1;
					print(`${block.block_number}: idx=${extrinsic_idx}, event=${event_id}, attr=${attributes}`);
				}
				//print(` -- mod=${module_id}, event=${event_id}, attr=${attributes}`);
			}
			// Transaction fees
			if module_id == "TransactionPayment" {
			  if event_id == "TransactionFeePaid" {
					let fee = attributes[1];
					block_fees += fee;
					total_fees += fee;
				}
			}
			let count_this_event = false;
			if module_id == "Settlement" {
			  if event_id == "InstructionExecuted" {
					count_non_confidential += 1;
					total_non_confidential += 1;
				}
				count_this_event = true;
			}
			if module_id == "ConfidentialAsset" {
				if event_id == "TransactionExecuted" {
					count_confidential += 1;
					total_confidential += 1;
				}
				if event_id == "FundsMoved" {
					count_confidential += 1;
					total_confidential_moves += 1;
				}
				count_this_event = true;
			}
			if module_id == "Portfolio" {
				if event_id == "FundsMovedBetweenPortfolios" {
					count_non_confidential += 1;
					total_non_confidential_moves += 1;
				}
				count_this_event = true;
			}
			if count_this_event {
				let count = count_events[event_id];
				if count == () {
					count = 0;
				}
				count_events[event_id] = count + 1;
			}
			let weight = ();
			if info != () {
				weight = info.weight;
			}
			if weight != () {
				block_weight += weight.ref_time;
			}
		}
		let block_percent = (block_weight / max_block_weight * 100).to_string();
		block_percent.truncate(4);
		block_weight /= 1000000000;
		if count_extrinsics > 0 {
			print(`${block.block_number}: % filled=${block_percent}, extrinsics=${count_extrinsics} success=${count_extrinsics_success}, failed=${count_extrinsics_error}, fees=${block_fees}`);
		}
		// Empty blocks only have one `Timestamp` call.
		if count_extrinsics > 0 {
			print(`  -- ${block.block_number}: ${count_events}`);
			non_empty_blocks += 1;
		}
		counter += 1;
		if counter > 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}
}
//print(`end = ${block_number}`);
let elapsed = (non_empty_blocks * 6.0);
print(`Non-empty blocks: ${non_empty_blocks} (elapsed time ${elapsed} seconds)`);
print(`total extrinsics: ${total_extrinsics}`);
print(`total extrinsic success: ${total_success}`);
print(`total extrinsic failed: ${total_error}`);
print(`fees: total=${total_fees}`);
if total_non_confidential > 0 {
	let ps = (total_non_confidential / elapsed).to_string();
	ps.truncate(5);
	print(`total Non-confidential settlements: ${total_non_confidential}`);
	print(`Non-confidential settlements per second: ${ps}`);
	print(`fees / settlements: ${total_fees / total_non_confidential}`);
}
if total_non_confidential_moves > 0 {
	let ps = (total_non_confidential_moves / elapsed).to_string();
	ps.truncate(5);
	print(`total Non-confidential asset moves: ${total_non_confidential_moves}`);
	print(`Non-Confidential asset moves per second: ${ps}`);
}
if total_confidential > 0 {
	let ps = (total_confidential / elapsed).to_string();
	ps.truncate(5);
	print(`total confidential settlements: ${total_confidential}`);
	print(`Confidential settlements per second: ${ps}`);
}
if total_confidential_moves > 0 {
	let ps = (total_confidential_moves / elapsed).to_string();
	ps.truncate(5);
	print(`total confidential asset moves: ${total_confidential_moves}`);
	print(`Confidential asset moves per second: ${ps}`);
}
let tps = (total_extrinsics / elapsed).to_string();
tps.truncate(5);
print(`TPS: ${tps}`);

