let client = RPC;
print(`client = ${client}`);

let sub = client.subscribe("chain_subscribeNewHeads",[], "chain_unsubscribeNewHeads");
print(`sub = ${sub}`);

loop {
	let update = client.get_update_as_header(sub);
	print(`${update}`);
}
