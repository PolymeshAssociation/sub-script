import "./scripts/mod/polymesh" as p;
import "./scripts/mod/confidential_assets" as ca;

print("Confidential Assets benchmark with threads");
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
let investors = ca::create_users_batch(`${prefix}_Investor`, 0, investor_count, polyx, false);

let supply = 100;
let total_supply = supply * (investor_count + 20);

print("Create confidential assets.");
let assets = ca::create_asset_batch(`${prefix}A`, 0, asset_count, total_supply, polyx, false);

print("Create confidential coins.");
let coins = ca::create_coin_batch(`${prefix}C`, 0, coin_count, total_supply, polyx, false);

count /= threads;
asset_count /= threads;
coin_count /= threads;
print(`${threads} threads, (users: ${count}, assets: ${asset_count}, coins: ${coin_count}) per thread.`);

if threads > 1 {
	RPC_MANAGER.set_min_connections(40);
}

let task_code = `
	import "./scripts/mod/polymesh" as p;
	import "./scripts/mod/confidential_assets" as ca;

	let thread_idx = ARG.shift();
	let investors = ARG.shift();
	let assets = ARG.shift();
	let coins = ARG.shift();
	let auditors = ARG.shift();

	let all_results = [];

	let supply = ${supply};

	let settlements = [];

	print("Give the investors some assets.");
	for (asset, idx) in assets {
		let issuer = asset.issuer;
		settlements += ca::setup_asset_fund_users(asset, issuer, investors, supply);
	}

	print("Give the investors some coins.");
	for (coin, idx) in coins {
		let issuer = coin.issuer;
		settlements += ca::setup_asset_fund_users(coin, issuer, investors, supply);
	}

	print("Affirm all settlements.");
	let results = ca::affirm_settlements(settlements);
	p::wait_for_in_block(results);
	all_results += results;

	print("Execute all settlements.");
	let results = ca::execute_settlements(settlements);

	p::wait_for_in_block(results);
	all_results += results;

	print("Apply incoming balances.");
	let results = ca::apply_incoming_settlements(settlements);

	p::wait_for_in_block(results);
	all_results += results;

	let success = 0;
	let failed = 0;
	let blocks = [];
	for res in all_results {
		if res.is_in_block {
			success += 1;
			blocks += res.block_hash;
		} else {
			failed += 1;
		}
	}

	[success, failed, blocks]
`;

let tasks = [];

let auditors = assets.asset_auditors;
auditors += coins.asset_auditors;
assets = assets.assets;
coins = coins.assets;
for thread_idx in range(0, threads) {
  let investor_offset = (thread_idx * count);
  let asset_offset = (thread_idx * asset_count);
  let coin_offset = (thread_idx * coin_count);
	let investors = investors.extract(investor_offset, count);
	let assets = assets.extract(asset_offset, asset_count);
	let coins = coins.extract(coin_offset, coin_count);
	//print(` -- thread[${thread_idx}]: users: ${investors.len()}, assets: ${assets.len()}, coins: ${coins.len()}`);
	tasks += ENGINE.spawn_task_args(task_code, [thread_idx, investors, assets, coins, auditors]);
}

print("wait for tasks to finish.");
let success = 0;
let failed = 0;
let blocks = #{};
for task in tasks {
	let res = task.join();
	success += res[0];
	failed += res[1];
	for block in res[2] {
		let counter = blocks[block];
		if counter == () {
			counter = 0;
		}
		counter += 1;
		blocks[block] = counter;
	}
}
print(`results: success = ${success}, failed = ${failed}`);
print(`blocks: ${blocks}`);
print("finished all tasks.");
