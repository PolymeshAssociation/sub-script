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
let investors = p::create_users_batch(`${ticker}_Investor`, 0, investor_count, 100000.0);
let dids = p::get_dids(investors);

let venue_id = p::get_or_create_venue(user, #{ Other: () });
let sender = #{ did: issuer_did, kind: #{ Default: () }};
let s_type = #{ SettleOnAffirmation: () };

print("Create settlement to airdrop the NFTs");
let last_nft_id = 1;
let results = [];
for did in dids {
	let receiver = #{ did: did, kind: #{ Default: () }};
	let ids = [];
	for idx in range(0, nft_per_did) {
		ids.push(last_nft_id);
		last_nft_id += 1;
	}
	let legs = [#{
		NonFungible: #{
			sender: sender,
			receiver: receiver,
			nfts: #{
				ticker: ticker,
				ids: ids,
			}
		}
	}];
	results.push(user.submit(Settlement.add_and_affirm_instruction(venue_id, s_type, (), (), legs, [sender], ())));
}

print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
