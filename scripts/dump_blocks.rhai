//let call_ty = Types.resolve("Call");
//print(`call = ${call_ty}`);

// Only dump ImOnline.Heartbeat calls.
//let filter = "041700";
//let filter = "04";
let filter = "";

fn get_block(block_number) {
	// Async request block hashes.
	let hash = RPC.call_method("chain_getBlockHash",[block_number]);
	// Request RuntimeVersion, Block, and events.
	let rt = RPC.async_method("state_getRuntimeVersion",[hash]);
	let block = RPC.async_method("chain_getBlock",[hash]);
	let events = RPC.async_method("state_getStorage",["0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7", hash]);

	let rt = RPC.get_response_as_runtime_version(rt);

	return #{
		hash: hash,
		rt: rt,
		block: block,
		events: events,
	};
}

// Get arguments.
let block_number = ARG.shift();
while block_number != () {
	let block = get_block(parse_int(block_number));
	let hash = block.hash;
	let rt = block.rt;

	// Get the types for decoding this block.
	let last_types = TypesRegistry.get_block_types(RPC, rt, hash);

	let events = RPC.get_response_as_block_events(last_types, block.events);
	let block = RPC.get_response_as_block(last_types, block.block);

	print(`block = ${block}`);

	let e_count = 0;
	if events != () {
		e_count = events.len();
	}

	// Get hex encoded extrinsics from block.
	let calls = block.extrinsics_filtered(filter);
	print(`${block.block_number}: calls = ${calls}, events: ${e_count}`);

	for tx in calls {
		print(`  -- call: ${tx.hex}`);
	}
	for event in events {
		print(`  -- event: ${event}`);
	}

	block_number = ARG.shift();
}
