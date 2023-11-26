import "./scripts/mod/polymesh" as p;
import "./scripts/mod/confidential_assets" as ca;

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

// Per-thread counts.
let per_thread = 2;
let asset_count = per_thread * threads;
let coin_count = per_thread * threads;

let polyx = 100000.0;
print(`Create confidential investors.`);
let investors = ca::create_users_batch(`${prefix}_Investor`, 0, investor_count, polyx);
ca::create_venues(investors);

let supply = 100;
let total_supply = supply * (investor_count + 20);

print("Create confidential assets.");
let assets = ca::create_asset_batch(`${prefix}A`, 0, asset_count, total_supply, polyx);

print("Create confidential coins.");
let coins = ca::create_coin_batch(`${prefix}C`, 0, coin_count, total_supply, polyx);

print("Finished");
