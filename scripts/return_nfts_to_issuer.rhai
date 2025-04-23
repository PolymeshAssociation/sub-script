import "scripts/mod/polymesh" as p;

print("Return and Redeem NFTs");

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

// Convert ticker to 12 byte array.
let raw_ticker = blob(12);
raw_ticker.write_ascii(0..12, ticker);
raw_ticker=raw_ticker.to_array();

let venue_id = p::get_or_create_venue(user, #{ Other: () });
let receiver = #{ did: issuer_did, kind: #{ Default: () }};
let s_type = #{ SettleOnAffirmation: () };

print("Create settlement to return NFTs");
let results = [];
for investor in investors {
	let did = p::get_did(investor);
	let portfolio = #{
		did: did,
		kind: #{ Default: () },
	};
	let ids = [];
	let paged = STORAGE.double_paged("Portfolio", "PortfolioNFT", portfolio);
	do {
		let records = paged.next_key_values();
		if records == () {
			break;
		}
		for rec in records {
			let nft = rec.key;
			let nft_ticker = nft[0];
			let nft_id = nft[1];
			if nft_ticker == raw_ticker {
				//print(`Investor NFT: id=${nft_id}`);
				ids.push(nft_id);
			}
		}
	} while paged.has_more;
	if ids.len() == 0 {
		continue;
	}
	let legs = [#{
		NonFungible: #{
			sender: portfolio,
			receiver: receiver,
			nfts: #{
				ticker: ticker,
				ids: ids,
			}
		}
	}];
	results.push(user.submit(Settlement.add_and_affirm_instruction(venue_id, s_type, (), (), legs, [receiver], ())));
}
print(`Pending create settlements: ${results.len()}`);

print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
