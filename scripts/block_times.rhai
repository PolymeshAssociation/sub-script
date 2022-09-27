
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

let last_ts = ();
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
		let block = RPC.get_response_as_block(last_types, block.block);

		// Get decoded transactions from block.
		let calls = block.extrinsics;
		let c_count = calls.len;
		for xt in block.extrinsics {
			let dec = xt.decoded_call;
			if dec.Timestamp == () {
				continue;
			}
			let args = dec.Timestamp.set;
			if type_of(args) != "array" {
				continue;
			}
			let ts = args[0];
			if last_ts != () {
				let diff_ts = (ts - last_ts) / 1000.0;
				if diff_ts > 6.01 || c_count > 2 {
					print(`${block.block_number}: ts=${ts}, diff=${diff_ts}, calls=${c_count}`);
				}
			}
			last_ts = ts;
		}
		counter += 1;
		if counter > 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}
}
print(`end = ${block_number}`);
