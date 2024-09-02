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
print(`Issuer signer ${user}`);
let issuer_did = p::get_did(user);
let sudo_user = p::get_sudo_user();

let colleciton_id = STORAGE.map("Nft", "CollectionTicker", ticker);
let nft_count = STORAGE.map("Nft", "NextNFTId", colleciton_id);

let portfolio = #{ Default: () };
let weight = #{
	ref_time: 900_000_000,
	proof_size: 0,
};
let as_user = #{
	system: #{
		Signed: user,
	},
};

print("Redeem NFTs");
let burns = [];
for idx in range(0, nft_count) {
	let redeem = Nft.redeem_nft(ticker, idx, portfolio);
	burns.push(Sudo.sudo_unchecked_weight(Utility.dispatch_as(as_user, redeem), weight));
}
let results = p::execute_force_batch(sudo_user, burns, 100);
print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
