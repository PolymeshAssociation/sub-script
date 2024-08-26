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
let portfolio_count = count;

let threads = ARG.shift();
threads = if threads == () { 4 } else { parse_int(threads) };

// Make sure there are at least 2 users per thread.
if (count / threads) <= 1 {
	portfolio_count = threads * 2;
	count = portfolio_count;
}

let polyx = 1000000.0;
// Per-thread counts.
let asset_count = threads;

let supply = 100;
let total_supply = supply * (portfolio_count + 20);
print("Create confidential assets.");
let assets = ca::create_asset_batch(`${prefix}A`, 0, asset_count, total_supply, polyx);

print("Finished");
