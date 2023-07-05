import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}

let cdd_user = p::get_cdd_provider();
let results = [];

print(`Create main user.`);
let main_user = USER[`Main_${prefix}`];
p::mock_user(main_user, 1.0);
let main_did = p::get_did(main_user);
let main_uid = PolymeshUtils.did_to_uid(main_did);

print(`Create some investors (all with the same uid).`);
let investors = p::create_keys_batch_with_balance(`Investor_${prefix}`, 0, 10, 1000000.0);
for investor in investors {
	results += cdd_user.submit(Identity.cdd_register_did(investor, []));
}
p::wait_for_in_block(results);
results = [];

let portfolios = [];
let dids = p::get_dids(investors);
for did in dids {
	portfolios.push(#{ did: did, kind: #{ Default: () } });
}

print(`Give all investors CDD claims with the same uid`);
for (investor, idx) in investors {
	let did = dids[idx];
	let cdd = PolymeshUtils.make_cdd_claim_uid(did, main_uid);
	results += cdd_user.submit(Identity.add_claim(did, cdd, ()));
}
p::wait_for_in_block(results);
results = [];

print("Create assets with Investor Uniqueness.");
let supply = 10000.0;
let res = p::create_asset_batch(prefix, 0, 10, supply * (investors.len() + 10), false);
let issuers = res[0];
let tickers = res[1];

// Test Investor Uniqueness claims.
print("Add investor Uniqueness claims");

for issuer in issuers {
	for ticker in tickers {
		results += p::add_investor_uniqueness_claim(issuer, ticker, ());
	}
}
for investor in investors {
	for ticker in tickers {
		results += p::add_investor_uniqueness_claim(investor, ticker, main_uid);
	}
}
p::wait_for_in_block(results);
results = [];

print(`Give the investors some assets`);
for (ticker, idx) in tickers {
	let issuer = issuers[idx];
	p::asset_fund_users(ticker, issuer, investors, supply);
}
