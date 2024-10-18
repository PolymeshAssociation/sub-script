import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };

print(`Create some investors.`);
let investors = p::create_users_batch(`${prefix}Investor`, 0, count, 1000.0);

let coin_prefix = `${prefix}COIN`;
let coin_balance = 100000000.0;
let asset_prefix = `${prefix}ASSET`;
let asset_balance = 1000.0;

let coin_supply = 10000.0 + (coin_balance * (investors.len() + 1));
let res = p::create_coin_batch(coin_prefix, 0, 1, coin_supply);
let coin_issuer = res[0][0];
let coin = res[1][0];

let asset_supply = 10000.0 + (asset_balance * investors.len());
let res = p::create_asset_batch(asset_prefix, 0, 1, asset_supply);
let asset_issuer = res[0][0];
let asset = res[1][0];

print(`Give the investors ${asset_balance} x ${asset}`);
p::asset_fund_users(asset, asset_issuer, investors, asset_balance);

print(`Give the investors and Asset issuers: ${coin_balance} x ${coin}`);
investors += asset_issuer;
p::asset_fund_users(coin, coin_issuer, investors, coin_balance);

