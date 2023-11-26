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

let threads = if count > 30 { 30 } else { 1 };

// Make sure there are at least 2 users per thread.
if (count / threads) <= 1 {
	investor_count = threads * 2;
	count = investor_count;
}

// Per-thread counts.
let per_thread = 2;
let asset_count = per_thread;
let coin_count = per_thread;
let exchange_count = per_thread;

count /= threads;
print(`${threads} threads, (users: ${count}, assets: ${asset_count}, coins: ${coin_count}, exchanges: ${exchange_count}) per thread.`);

if threads > 1 {
	RPC_MANAGER.set_min_connections(40);
}

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

	let coin_prefix = "${prefix}C";
	let coin_offset = (thread_idx * ${coin_count});
	let coin_count = ${coin_count} + coin_offset;
	let coin_tickers = p::gen_names(coin_prefix, coin_offset, coin_count);

	let exchange_prefix = "${prefix}_Exchange";
	let exchange_offset = (thread_idx * ${exchange_count});
	let exchange_count = ${exchange_count} + exchange_offset;

	let all_results = [];

	print("Gen account keys.");
	let investor_keys = p::create_keys_batch(investor_prefix, investor_offset, investor_count);
	let exchanges = p::create_keys_batch(exchange_prefix, exchange_offset, exchange_count);
	let exchange = exchanges[0];

	let investors = [];
	let dids = p::get_dids(investor_keys);
	for (key, idx) in investor_keys {
		let did = dids[idx];
		investors.push(#{
			user: key,
			portfolio: #{ did: did, kind: #{ Default: () } },
		});
	}

	// Create venue.
	print("Setup exchange venue.");
	let venue_id = p::get_or_create_venue(exchange, #{ Other: () });

	// Create settlements.
	let settlements = [];
	for (buyer, idx) in investors {
		let sell_idx = idx + 1;
		if sell_idx >= investors.len() {
			sell_idx = 0;
		}
		let seller = investors[sell_idx];

		for asset in asset_tickers {
			//for coin in coin_tickers {
			//	settlements += p::create_buy_settlement(exchange, venue_id, buyer, seller, asset, coin, 1.0, 1.0);
			//}
			settlements += p::create_settlement(exchange, venue_id, [
				#{ sender: 0, receiver: 1, ticker: asset, amount: 1 },
			], [buyer, seller]);
		}
	}
	let orders = settlements.len();

	// Affirm settlements.
	let results = p::affirm_settlements(settlements);
	p::wait_for_in_block(results);
	all_results += results;

	// Execute settlements.
	let results = p::execute_settlements(settlements);
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

	[success, failed, blocks, orders]
`;

let tasks = [];

for thread_idx in range(0, threads) {
	tasks += ENGINE.spawn_task_args(task_code, [thread_idx]);
}

print("wait for tasks to finish.");
let success = 0;
let failed = 0;
let blocks = #{};
let orders = 0;
for task in tasks {
	let res = task.join();
	success += res[0];
	failed += res[1];
	orders += res[3];
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
print(`orders: ${orders}`);
print("finished all tasks.");
