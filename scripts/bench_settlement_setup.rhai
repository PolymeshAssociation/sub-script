import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let investor_count = count;

let threads = if count > 30 { 30 } else { 1 };

// Make sure there are at least 2 users per thread.
if (count / threads) <= 1 {
	investor_count = threads * 2;
	count = investor_count;
}

let per_thread = 2;
let asset_count = per_thread * threads;
let coin_count = per_thread * threads;
let exchange_count = per_thread * threads;

print(`Create investors.`);
let investors = p::create_users_batch(`${prefix}_Investor`, 0, investor_count, 100000.0);

let supply = 100000.0;
let total_supply = supply * (investor_count * 20);

let asset_prefix = `${prefix}A`;
let asset_tickers = p::gen_names(asset_prefix, 0, asset_count);
let asset_issuers = p::tickers_to_issuers(asset_tickers);
let coin_prefix = `${prefix}C`;
let coin_tickers = p::gen_names(coin_prefix, 0, coin_count);
let coin_issuers = p::tickers_to_issuers(coin_tickers);
let exchange_names = p::gen_names(`${prefix}_Exchange`, 0, exchange_count);

print("Create assets.");
let res = p::create_asset_batch(asset_prefix, 0, asset_count, total_supply);

print("Create coins.");
let res = p::create_coin_batch(coin_prefix, 0, coin_count, total_supply);

print(`Create exchange users.`);
let users = p::create_users(exchange_names, 1000000.0);

print("Finished");
