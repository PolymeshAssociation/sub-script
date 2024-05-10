import "scripts/mod/polymesh" as p;

print("Create NFT collection");

let alice = USER.Alice;

let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}
let image_base = "ipfs://QmfUARYf1VrRYPGEmxaKpdJBEyzkDn2nmk7PAX73TENpCo/";

let letters = ["P", "O", "L", "Y", "M", "E", "S", "H"];
let rarities = ["Rare", "Uncommon", "Common"];
let max_bonus = letters.len() - 1;
let max_rarity = rarities.len() - 1;
let max_variant = 50;

let mints = [];

let last_bonus = max_bonus;
let last_rarity = max_rarity;
let last_variant = max_variant;

for idx in range(0, 30000) {
	last_variant += 1;
	if last_variant > max_variant {
		last_variant = 0;
	}
	last_bonus += 1;
	if last_bonus > max_bonus {
		last_bonus = 0;
	}
	last_rarity += 1;
	if last_rarity > max_rarity {
		last_rarity = 0;
	}
	let variant = last_variant;
	let rarity = rarities[last_rarity];
	let bonus = letters[last_bonus];
	mints += Nft.issue_nft(ticker, [
		#{ key: #{ Global: 4 }, value: `${image_base}/${variant}.png` },
		#{ key: #{ Local: 1 }, value: `${variant}` },
		#{ key: #{ Local: 2 }, value: `${rarity}` },
		#{ key: #{ Local: 3 }, value: `${bonus}` },
	], #{ Default: () });
}

print("Submit NFT mints in batches.");
let results = p::execute_batch_all(alice, mints, 200);
print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
