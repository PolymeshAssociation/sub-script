import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}

let portfolios = [];
let results = [];

print(`Get batch 1 investors.`);
let investors = p::create_keys_batch(`Investor_${prefix}`, 0, 10);

print(`Create batch 2 investors (all with different uid).`);
let investors2 = p::create_users_batch(`Investor2_${prefix}`, 0, 10, 1000000.0);
investors += investors2;

// Get investor dids and portfolios.
let dids = p::get_dids(investors);
for did in dids {
	portfolios.push(#{ did: did, kind: #{ Default: () } });
}

print("Get assets and mint more tokens.");
let supply = 10000.0;
let res = p::create_asset_batch(prefix, 0, 10, supply * (investors.len() + 10), false);
let issuers = res[0];
let tickers = res[1];

// Test Investor Uniqueness claims.
print("Add investor Uniqueness claims for batch 2 investors");

for investor in investors2 {
	for ticker in tickers {
		results += p::add_investor_uniqueness_claim(investor, ticker, ());
	}
}
p::wait_for_in_block(results);
results = [];

print(`Give all the investors some more assets`);
for (ticker, idx) in tickers {
	let issuer = issuers[idx];
	p::asset_fund_users(ticker, issuer, investors, supply);
}

