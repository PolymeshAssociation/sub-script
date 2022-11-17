import "scripts/mod/polymesh" as p;

// Get arguments.
let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}
let hash = ARG.shift();
if hash == () {
	print("Need block hash");
	return;
}

let rt = RPC.get_response_as_runtime_version(RPC.async_method("state_getRuntimeVersion", [hash]));
let types = TypesRegistry.get_block_types(RPC, rt, hash);
let metadata = types.metadata;
let block_storage = new_storage(CLIENT, metadata);

let managers = block_storage.map_at_block("Statistics", "ActiveTransferManagers", ticker, hash);
print(`managers = ${managers}`);

let count = block_storage.map_at_block("Statistics", "InvestorCountPerAsset", ticker, hash);
print(`count = ${count}`);
