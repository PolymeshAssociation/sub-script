
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
// Skip blocks for fast scan.
let skip_size = ARG.shift();
skip_size = if skip_size == () { 1 } else { parse_int(skip_size) };

let end_block = start_block + count;

fn get_block_hashes(block_number, end_block, batch_size, skip_size) {
	let blocks = [];
	// Async request block hashes.
	while block_number <= end_block && blocks.len() <= batch_size {
		let hash = RPC.async_method("chain_getBlockHash",[block_number]);
		blocks += #{
			number: block_number,
			hash: hash,
		};
		block_number += skip_size;
	}
	// wait for block hashes.
	for (block, idx) in blocks {
		let hash = RPC.get_response(block.hash);
		block.hash = hash;
		// Requests.
		block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
		block.epoch_index = RPC.async_method("state_getStorage", ["0x1cb6f36e027abb2091cfb5110ab5087f38316cbf8fa0da822a20ac1c55bf1be3", hash]);
		block.session_index = RPC.async_method("state_getStorage", ["0xcec5070d609dd3497f72bde07fc96ba072763800a36a99fdfc7c10f6415f6ee6", hash]);
		blocks[idx] = block;
	}
	return blocks;
}

let chain_current_block = CLIENT.get_block(());
if end_block > chain_current_block.block_number {
	end_block = chain_current_block.block_number;
}

let last_rt = ();
let last_epoch_index = ();
let last_session_index = ();
let last_types = Types;
let last_epoch_index_ty = Types.resolve("u64");
let last_session_index_ty = Types.resolve("u32");
let last_info = ();
let last_rand = ();
let cur_spec = 0;

let block_number = start_block;
let counter = 0;

// Pre-fetch a batch of blocks.
let next_blocks = get_block_hashes(block_number, end_block, batch_size, skip_size);

while block_number <= end_block {
	let blocks = next_blocks;
	block_number += blocks.len() * skip_size;
	if block_number <= end_block {
		// Pre-fetch next batch.
		next_blocks = get_block_hashes(block_number, end_block, batch_size, skip_size);
	}
	for block_reqs in blocks {
		let hash = block_reqs.hash;
		let block_number = block_reqs.number;
		// Load the block's RuntimeVersion.
		let rt = RPC.get_response_as_runtime_version(block_reqs.rt);

		if last_rt == () || cur_spec != rt.specVersion {
			last_rt = rt;
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
			last_types = TypesRegistry.get_block_types(RPC, rt, hash);
		}
		// Get Babe.epochIndex and Session.currentIndex.
		let epoch_index = RPC.get_response(block_reqs.epoch_index);
		if epoch_index != () {
			epoch_index = last_epoch_index_ty.decode(Utils.from_hex(epoch_index));
		}
		let session_index = RPC.get_response(block_reqs.session_index);
		if session_index != () {
			session_index = last_session_index_ty.decode(Utils.from_hex(session_index));
		}
		let updated_index = false;

		if last_epoch_index != epoch_index {
			//print(`number = ${block_number}: epoch_index=${epoch_index}`);
			updated_index = true;
		}
		last_epoch_index = epoch_index;
		if last_session_index != session_index {
			//print(`number = ${block_number}: session_index=${session_index}`);
			updated_index = true;
		}
		last_session_index = session_index;
		if updated_index && epoch_index != session_index {
			print(`number = ${block_number}: OUT_OF_SYNC: epoch_index=${epoch_index}, session_index=${session_index}`);
		}
		//print(`number = ${block.number}: slot = ${babe.slot}`);
		counter += skip_size;
		if counter >= 1000 {
			counter = 0;
		}
			print(`${block_number}: epoch_index=${epoch_index}, session_index=${session_index}`);
	}
}
