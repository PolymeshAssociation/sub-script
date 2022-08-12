
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

fn merge_metadata(modules, metadata) {
	for mod in metadata.modules {
		let mod_name = mod.name;
		let pallet = modules[mod_name];
		if pallet == () {
			pallet = #{
			  functions: #{},
			  events: #{},
			};
		}
		let functions = pallet.functions;
		for func in mod.funcs {
			functions[func.name] = func.name;
		}
		let events = pallet.events;
		for event in mod.events {
			events[event.name] = event.name;
		}
		pallet.functions = functions;
		pallet.events = events;
		modules[mod_name] = pallet;
	}
	return modules;
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
let last_types = Types;
let modules = merge_metadata(#{}, Types.metadata);
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
			last_types = TypesRegistry.get_block_types(RPC, rt, hash);
			modules = merge_metadata(modules, last_types.metadata);
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
		}
		counter += skip_size;
		if counter >= 100000 {
			counter = 0;
			print(`number = ${block.number}`);
		}
	}
}
print(`end block = ${block_number}`);

// Dump functions.
print(`------------ Functions`);
for mod_name in modules.keys() {
	let pallet = modules[mod_name];
	let name = mod_name.to_lower();
	print(`  ## ${name} ##`);
	let names = [];
	for name in pallet.functions.keys() {
		names += name;
	}
	names.sort();
	for name in names {
		print(`  ${name}`);
	}
	print(``);
}
print(`------------ Events`);
for mod_name in modules.keys() {
	let pallet = modules[mod_name];
	let name = mod_name.to_lower();
	print(`  ## ${name} ##`);
	let names = [];
	for name in pallet.events.keys() {
		names += name;
	}
	names.sort();
	for name in names {
		print(`  ${name}`);
	}
	print(``);
}
