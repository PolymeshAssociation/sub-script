import "mod/polymesh" as p;

print("Use threads to transfer ERC20 Tokens.");

// Get arguments.
let contract = ARG.shift();
if contract == () {
	print("Need contract address");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let threads = ARG.shift();
threads = if threads == () { 1 } else { parse_int(threads) };

let users = p::create_users_batch("THREAD", 0, threads, 100000.0);

let contract = #{
	Id: contract,
};

let task_code = `
	let count = ARG.shift();
	let contract = ARG.shift();
	let user = ARG.shift();
	let batch_size = 10;

	import "./scripts/mod/polymesh" as p;

	let flip = Contracts.Call(contract, 0, 6946816000, (), "0x633aa551");

	/*
	let calls = [];
	for idx in range(0, batch_size) {
		calls += flip;
	}
	*/
	
	print("Submit transfers.");
	let results = [];
	for idx in range(0, count) {
		//results += user.submit(Utility.batch_optimistic(calls));
		results += user.submit(flip);
	}
	print("Wait for transfers.");
	p::wait_for_in_block(results);

	let success = 0;
	let failed = 0;
	let blocks = [];
	for res in results {
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

print("Spawn threads.");
for idx in range(0, threads) {
	let user = users[idx];
	tasks += ENGINE.spawn_task_args(task_code, [count, contract, user]);
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
