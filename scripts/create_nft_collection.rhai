print("Create NFT collection");

let alice = USER.Alice;

let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}

let res = alice.submit(Utility.batch_atomic([
	Asset.create_asset("Nft SZN 2024", ticker, false, #{ NonFungible: #{ Derivative: () } }, [], ()),
	Asset.register_asset_metadata_local_type(ticker, "Variant", #{url: (), description: "Variant of NFT Image (1-50)", type_def: "Number - not SCALE encoded"}),
	Asset.register_asset_metadata_local_type(ticker, "Rarity", #{url: (), description: "Rarity of NFT image (Rare, Uncommon, Common)", type_def: "Text - not SCALE encoded"}),
	Asset.register_asset_metadata_local_type(ticker, "Bonus", #{url: (), description: "Single letter from POLYMESH", type_def: "Text - not SCALE encoded"}),
	Asset.register_asset_metadata_local_type(ticker, "Description", #{url: (), description: "Description of the NFT collection", type_def: "Text - not SCALE encoded"}),
	Nft.create_nft_collection(ticker, (), [
		#{ Global: 4 }, // imageURI
		#{ Local: 1 }, // Variant
		#{ Local: 2 }, // Rarity
		#{ Local: 3 }, // Bonus
	]),
]));

// Display all events for the batch.
for event in res.events {
	print(`EventName: ${event.name}`);
	print(`  Args: ${event.args}`);
}
