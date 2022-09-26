import "./scripts/mod/polymesh" as p;

print("Settlement benchmark with threads");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let investor_count = count;

let threads = if count > 10 { 10 } else { 1 };

// Per-thread counts.
let per_thread = 2;
let asset_count = per_thread;
let coin_count = per_thread;
let exchange_count = per_thread;

count /= threads;
print(`${threads} threads, (users: ${count}, assets: ${asset_count}, coins: ${coin_count}, exchanges: ${exchange_count}) per thread.`);

let task_code = `
	import "./scripts/mod/polymesh" as p;

	let thread_idx = ARG.shift();
	let investor_prefix = "${prefix}_Investor";
	let investor_offset = (thread_idx * ${count});
	let investor_count = ${count} + investor_offset;

	let asset_prefix = "${prefix}A";
	let asset_offset = (thread_idx * ${asset_count});
	let asset_count = ${asset_count} + asset_offset;
	let asset_tickers = p::gen_names(asset_prefix, asset_offset, asset_count);
	let asset_issuers = p::tickers_to_issuers(asset_tickers);

	let coin_prefix = "${prefix}C";
	let coin_offset = (thread_idx * ${coin_count});
	let coin_count = ${coin_count} + coin_offset;
	let coin_tickers = p::gen_names(coin_prefix, coin_offset, coin_count);
	let coin_issuers = p::tickers_to_issuers(coin_tickers);

	let exchange_prefix = "${prefix}_Exchange";
	let exchange_offset = (thread_idx * ${exchange_count});
	let exchange_count = ${exchange_count} + exchange_offset;

	let all_results = [];

	let supply = 100000.0;
	let total_supply = supply * (investor_count * 20);

	print("Gen investors.");
	let investors = p::create_keys_batch(investor_prefix, investor_offset, investor_count);
	let portfolios = [];
	let dids = p::get_dids(investors);
	for did in dids {
		portfolios.push(#{ did: did, kind: #{ Default: () } });
	}

	print("Gen asset users.");
	let asset_issuers = p::create_keys(asset_issuers, ());
	let assets = asset_tickers;

	print("Gen coin users.");
	let coin_issuers = p::create_keys(coin_issuers, ());
	let coins = coin_tickers;

	print("Gen exchange users.");
	let exchanges = p::create_keys_batch(exchange_prefix, exchange_offset, exchange_count);
	let exchange = exchanges[0];

	let settlements = [];

	print("Give the investors some assets.");
	for (asset, idx) in assets {
		let issuer = asset_issuers[idx];
		settlements += p::setup_asset_fund_users(asset, issuer, investors, supply);
	}

	print("Give the investors some coins.");
	for (coin, idx) in coins {
		let issuer = coin_issuers[idx];
		settlements += p::setup_asset_fund_users(coin, issuer, investors, supply);
	}

	print("Affirm all settlements.");
	let results = p::affirm_settlements(settlements);

	// Pre-create venue.
	results += p::create_venue(exchange, #{ Other: () });

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

for thread_idx in range(0, threads) {
	tasks += ENGINE.spawn_task_args(task_code, [thread_idx]);
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
