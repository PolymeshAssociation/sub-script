import "scripts/mod/polymesh" as p;

print("Redeem NFT Collection");

let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}

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
let issuer_did = p::get_did(user);
print(`Issuer signer ${user}, did: ${issuer_did}`);

let colleciton_id = STORAGE.map("Nft", "CollectionTicker", ticker);
let nft_count = STORAGE.map("Nft", "NextNFTId", colleciton_id);
let burn_count = nft_count;
print(`NFT Count ${nft_count}, burn: ${burn_count}`);

let portfolio = #{ Default: () };
//let portfolio = #{ User: 1 };

print("Redeem NFTs");
let burns = [];
let results = [];
let others = 0;
let paged = STORAGE.double_paged("Nft", "NFTOwner", ticker);
do {
	let records = paged.next_key_values();
	if records == () {
		break;
	}
	for rec in records {
		let nft_id = rec.key;
		let portfolio = rec.value;
		if portfolio.did == issuer_did {
			burn_count -= 1;
			if burn_count <= 0 {
				break;
			}
			burns.push(Nft.redeem_nft(ticker, nft_id, portfolio.kind));
			//results.push(user.submit(Nft.redeem_nft(ticker, nft_id, portfolio.kind)));
		} else {
			//print(`We don't own NFT: ${nft_id}, port.did: ${portfolio.did}`);
			others += 1;
		}
	}
} while paged.has_more && burn_count > 0;
let count = burns.len();
print(`Number of burns: ${count}`);
print(`NFTs owned by others: ${others}`);
//let results = p::execute_force_batch(user, burns, 40);
print("Wait for batches to be included in a block.");
p::wait_for_finalized(results);
print("Finished");
