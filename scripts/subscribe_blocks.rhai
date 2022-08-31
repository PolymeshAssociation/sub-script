
fn get_block(block_number) {
	let hash = RPC.call_method("chain_getBlockHash",[block_number]);
	let block = #{
		number: block_number,
		hash: hash,
	};
	// Request RuntimeVersion, Block, and events.
	block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
	block.block = RPC.async_method("chain_getBlock",[hash]);
	block.events = RPC.async_method("state_getStorage",["0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7", hash]);
	return block;
}

let last_rt = ();
let last_types = Types;
let cur_spec = 0;

let counter = 0;

let sub = RPC.subscribe("chain_subscribeNewHeads",[], "chain_unsubscribeNewHeads");
loop {
	// Wait for new block.
	let header = RPC.get_update_as_header(sub);

	let block = get_block(header.block_number);
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
	print(`${block.block_number}: ${hash}: spec: ${cur_spec}: calls = ${c_count}, events = ${e_count}`);
	if c_count != 1 || e_count != 1 {
		print(`- calls:`);
		for xt in block.extrinsics {
			print(`  -- ${xt.decoded_call}`);
		}
		print(`events = ${events}`);
	} else {
		counter += 1;
		if counter > 1000 {
			counter = 0;
			print(`number = ${block.block_number}`);
		}
	}
}
