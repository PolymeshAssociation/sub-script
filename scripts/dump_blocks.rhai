//let call_ty = Types.resolve("Call");
//print(`call = ${call_ty}`);

// Only dump ImOnline.Heartbeat calls.
//let filter = "041700";
//let filter = "04";
let filter = "";

// Get arguments.
let block_number = ARG.shift();
while block_number != () {
	let hash = CLIENT.get_block_hash(parse_int(block_number));
	let block = CLIENT.get_block(hash);
	print(`block = ${block}`);

	let events = CLIENT.get_block_events(hash);
	let e_count = 0;
	if events != () {
		e_count = events.len();
	}

	// Get hex encoded extrinsics from block.
	let calls = block.extrinsics_filtered(filter);
	print(`${block.block_number}: calls = ${calls}, events: ${e_count}`);

	for event in events {
		print(`  -- event: ${event}`);
	}

	block_number = ARG.shift();
}
