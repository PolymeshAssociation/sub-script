import "scripts/mod/polymesh" as p;

print("Create NFT collection");

let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}
let nft_per_did = ARG.shift();
nft_per_did = if nft_per_did == () { 10 } else { parse_int(nft_per_did) };

let user = ARG.shift();
if user == () {
	user = USER.Alice;
} else {
	try {
		user = USER.new_user_from_secret(user)
	} catch {
		user = USER[user]
	}
}
print(`Issuer signer ${user}`);
let issuer_did = p::get_did(user);

let colleciton_id = STORAGE.map("Nft", "CollectionTicker", ticker);
let nft_count = STORAGE.map("Nft", "NextNFTId", colleciton_id);
print(`NFT Collection: ticker=${ticker}, id=${colleciton_id}, count=${nft_count}`);
let investor_count = nft_count / nft_per_did;

print(`Create ${investor_count} investors.`);
let investors = p::create_keys_batch(`${ticker}_Investor`, 0, investor_count);
let dids = p::get_dids(investors);

print("Affirm settlements to receive airdropped NFTs");
let results = [];
let counts = #{
	sender_asset_count: #{
		fungible: 0,
		non_fungible: 10,
		off_chain: 0,
	},
	receiver_asset_count: #{
		fungible: 0,
		non_fungible: 10,
		off_chain: 0,
	},
	offchain_count: 0,
};
for investor in investors {
	let did = p::get_did(investor);
	let portfolio = #{
		did: did,
		kind: #{ Default: () },
	};
	let paged = STORAGE.double_paged("Settlement", "UserAffirmations", portfolio);
	do {
		let records = paged.next_key_values();
		if records == () {
			break;
		}
		for rec in records {
			let settlement_id = rec.key;
			let status = rec.value;
			if "Pending" in status {
				//print(`Affirm Settlement: ${settlement_id}, status=${status}`);
				results.push(investor.submit(Settlement.affirm_instruction_with_count(settlement_id, [portfolio], counts)));
			}
		}
	} while paged.has_more;
}

print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
