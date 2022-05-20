// Only dump ImOnline.Heartbeat calls.
let filter = "041700";

// Get arguments.
let block_number = ARG.shift();
while block_number != () {
	let block = CLIENT.get_block_by_number(parse_int(block_number));

	// Get hex encoded extrinsics from block.
	let calls = block.extrinsics_filtered(filter);
	for xt in calls {
		if xt.ImOnline != () {
			let heartbeat = xt.ImOnline.heartbeat[0];
			let network = heartbeat.network_state;
			print(`block ${block.block_number}:  heartbeat: peer_id: ${network.peer_id}, addresses: ${network.external_addresses}, authority: ${heartbeat.authority_index}, session: ${heartbeat.session_index}`);
			/*
			for addr in network.external_addresses {
				print(`    address: ${addr}`);
			}
			print(`    authority: ${heartbeat.authority_index}`);
			print(`    session: ${heartbeat.session_index}`);
			*/
		}
	}

	block_number = ARG.shift();
}
