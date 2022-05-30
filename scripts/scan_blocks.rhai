
// Get arguments.
let start_block = ARG.shift();
if start_block == () {
	print("Need start block number");
	return;
}
start_block = parse_int(start_block);
// Number of blocks to search.
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
// What to search for.
let filter = ARG.shift();
filter = if filter == () { "98002408011220a01a227d0b9f75830" } else { filter };

let end_block = start_block + count;

let chain_current_block = CLIENT.get_block(());
if end_block > chain_current_block.block_number {
	end_block = chain_current_block.block_number;
}

let last_rt = ();
let cur_spec = 0;

let block_number = start_block;
let counter = 0;
while block_number <= end_block {
	let block = CLIENT.get_block_by_number(block_number);
	let hash = CLIENT.get_block_hash(block_number);

	let rt = CLIENT.get_block_runtime_version(hash);
	if last_rt == () || cur_spec != rt.specVersion {
		last_rt = rt;
		cur_spec = rt.specVersion;
		print(`================= New spec version: ${cur_spec}`);
	}

	let events = CLIENT.get_block_events(hash);
	let e_count = 0;
	if events != () {
		e_count = events.len();
	}

	// Get decoded transactions from block.
	let calls = block.extrinsics;
	let c_count = calls.len();
	if c_count > 1 || e_count > 1 {
		print(`${block.block_number}: ${hash}: spec: ${cur_spec}: calls = ${calls.len()}, events = ${events.len()}`);
	} else {
		counter += 1;
		if counter > 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}

	block_number += 1;
}
