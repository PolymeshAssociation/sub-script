import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let portfolio_count = count;

let threads = ARG.shift();
threads = if threads == () { 4 } else { parse_int(threads) };

// Make sure there are at least 2 users per thread.
if (count / threads) <= 1 {
	portfolio_count = threads * 2;
	count = portfolio_count;
}

let asset_count = threads;

let supply = 100000.0;
let total_supply = supply * (portfolio_count * 20);

let asset_prefix = `${prefix}A`;
let asset_tickers = p::gen_names(asset_prefix, 0, asset_count);
let asset_issuers = p::tickers_to_issuers(asset_tickers);

print("Create assets.");
let res = p::create_asset_batch(asset_prefix, 0, asset_count, total_supply);

print("Finished");
