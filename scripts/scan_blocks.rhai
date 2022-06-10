
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
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
		}
		let events = RPC.get_response_as_block_events(last_types, block.events);
		let block = RPC.get_response_as_block(last_types, block.block);

		let e_count = 0;
		if events != () {
			e_count = events.len();
		}

		// Get decoded transactions from block.
		let calls = block.extrinsics;
		let c_count = calls.len();
		if c_count != 1 || e_count != 1 {
			print(`${block.block_number}: ${hash}: spec: ${cur_spec}: calls = ${c_count}, events = ${e_count}`);
		} else {
			counter += 1;
			if counter > 1000 {
				counter = 0;
				print(`number = ${block.block_number}`);
			}
		}
	}
}
print(`end = ${block_number}`);
