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

	let orders = 0;
	let previous_tx = [];
	for asset in assets {
		// Create settlements.
		let settlements = [];
		//for coin in coins {
		for (buyer, idx) in investors {
			if previous_tx.len() > idx {
				let prev_tx = previous_tx[idx];
				if !prev_tx.wait_finalized {
					print("Investors previous tx didn't finalize");
				}
			}
			let sell_idx = idx + 1;
			if sell_idx >= investors.len() {
				sell_idx = 0;
			}
			let seller = investors[sell_idx];
			//	settlements += ca::create_buy_settlement(seller, buyer, seller, asset, coin, 1, 1);
			settlements += ca::create_settlement(seller, [
				#{ sender: 0, receiver: 1, asset: asset, amount: 1 },
			], [seller, buyer]);
		}
		//}
		orders += settlements.len();

		// Process settlements.
		let res = ca::run_settlements(settlements);
		previous_tx = res.exe_results;
		all_results += res.all_results;
	}

	let success = 0;
	let failed = 0;
	let blocks = [];
	for res in all_results {
		if res.is_success {
			success += 1;
			blocks += res.block_hash;
		} else {
			failed += 1;
		}
	}

	[success, failed, blocks, orders]
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
