import "scripts/mod/polymesh" as p;

print("Create NFT collection");

let ticker = ARG.shift();
if ticker == () {
	print("Need ticker");
	return;
}
let user = ARG.shift();
if user == () {
	user = USER.Alice;
} else {
	user = USER.new_user_from_secret(user)
}
let did = p::get_did(user);
print(`Signer ${user}, did:${did}`);

let src = #{
	did: did,
	kind: #{ Default: () },
};
let dest = #{
	did: did,
	kind: #{ User: 1 },
};

print("Submit NFT moves in batches.");
let results = [];
let ids = [];
for idx in range(1, 100) {
	ids.push(idx);
	if ids.len() > 100 {
		results += user.submit(Portfolio.move_portfolio_funds(src, dest, [
			#{
				description: #{
					NonFungible: #{
						ticker: ticker,
						ids: ids,
					}
				},
				memo: (),
			}
		]));
		ids = [];
	}
}

print("Wait for batches to be included in a block.");
p::wait_for_in_block(results);
print("Finished");
