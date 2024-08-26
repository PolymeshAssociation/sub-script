
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
		//block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
		//block.block = RPC.async_method("chain_getBlock",[hash]);
		//block.events = RPC.async_method("state_getStorage",["0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7", hash]);
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

while block_number <= end_block {
	block_number += 1;
	let hash = CLIENT.get_block_hash(block_number);
	print(`${block_number}: ${hash}`);
}
print(`end = ${block_number}`);
