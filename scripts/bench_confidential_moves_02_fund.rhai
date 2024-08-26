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
let assets = ca::create_asset_batch(`${prefix}A`, 0, asset_count, total_supply, polyx, false);

count /= threads;
asset_count /= threads;
print(`${threads} threads, (users: ${count}, assets: ${asset_count}) per thread.`);

if threads > 1 {
	RPC_MANAGER.set_min_connections(40);
}

let task_code = `
	import "./scripts/mod/polymesh" as p;
	import "./scripts/mod/confidential_assets" as ca;

	let thread_idx = ARG.shift();
	let portfolio_count = ARG.shift();
	let asset = ARG.shift();
	let auditors = ARG.shift();

	let all_results = [];

	let supply = ${supply};

	let results = [];

	let issuer = asset.issuer;

	print("Generate new portfolio accounts.");
	let portfolios = [];
	for idx in range(1, portfolio_count+1) {
		portfolios.push(issuer.sub_account(idx));
	}

	print("Give the portfolios some assets.");
	let results = ca::asset_fund_accounts(asset, issuer, portfolios, supply);
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

let portfolio_count = (portfolio_count / threads);
let auditors = assets.asset_auditors;
assets = assets.assets;
for thread_idx in range(0, threads) {
  let asset_offset = (thread_idx * asset_count);
	let asset = assets[thread_idx];
	//print(` -- thread[${thread_idx}]: assets: ${assets.len()}`);
	tasks += ENGINE.spawn_task_args(task_code, [thread_idx, portfolio_count, asset, auditors]);
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
