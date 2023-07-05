
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

fn download_runtime(rt, hash) {
	let filename = `./runtimes/${rt.specName}/${rt.specVersion}.wasm`;
	let runtime = RPC.call_method("state_getStorage",["0x3a636f6465", hash]);
	print(`-- write runtime: ${filename}`);
	Utils.write_hex_to_file(filename, runtime);
}

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
		// Request RuntimeVersion, Block, and events.
		block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
		blocks[idx] = block;
	}
	return blocks;
}

let chain_current_block = CLIENT.get_block(());
if end_block > chain_current_block.block_number {
	end_block = chain_current_block.block_number;
}

let last_rt = ();
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
	for block in blocks {
		let hash = block.hash;
		// Load the block's RuntimeVersion.
		let rt = RPC.get_response_as_runtime_version(block.rt);

		if last_rt == () || cur_spec != rt.specVersion {
			last_rt = rt;
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
			download_runtime(rt, hash);
		}
		counter += skip_size;
		if counter >= 100000 {
			counter = 0;
			print(`number = ${block.number}`);
		}
	}
}
print(`end block = ${block_number}`);
