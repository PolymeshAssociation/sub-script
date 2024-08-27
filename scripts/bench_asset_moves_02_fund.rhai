import "./scripts/mod/polymesh" as p;

print("Asset portfolio moves benchmark with threads");

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
let assets = p::create_asset_batch(asset_prefix, 0, asset_count, total_supply);
let issuers = assets[0];
let tickers = assets[1];

count /= threads;
asset_count /= threads;
print(`${threads} threads, (users: ${count}, assets: ${asset_count}) per thread.`);

if threads > 1 {
	RPC_MANAGER.set_min_connections(40);
}

let task_code = `
	import "./scripts/mod/polymesh" as p;

	let thread_idx = ARG.shift();
	let portfolio_count = ARG.shift();
	let issuer = ARG.shift();
	let asset = ARG.shift();

	let all_results = [];

	let supply = ${supply};

	print("Gen new portfolios.");
	let names = p::gen_names("Port", 0, portfolio_count);
	let portfolios = p::get_or_create_portfolios(issuer, names);

	print("Give the portfolios some assets.");
	let from = p::get_user_portfolio(issuer, "Default");
	let funds = [
		#{
			description: #{
				Fungible: #{
					ticker: asset,
					amount: 1.0,
				}
			},
			memo: (),
		}
	];
	let results = p::asset_fund_portfolios(issuer, from, portfolios, funds);
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

portfolio_count /= threads;
for thread_idx in range(0, threads) {
	let issuer = issuers[thread_idx];
	let asset = tickers[thread_idx];
	tasks += ENGINE.spawn_task_args(task_code, [thread_idx, portfolio_count, issuer, asset]);
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
