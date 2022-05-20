print("Use threads to transfer POLYX from a lot of users.");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };

let task_code = `
	let offset = ARG.shift();
	let prefix = "${prefix}";
	let count = ${count} + offset;

	import "./scripts/mod/polymesh" as p;

	let alice = USER.Alice;
	let users = p::create_keys_batch(prefix, offset, count);

	print("Submit transfers.");
	let results = [];
	for user in users {
		results += user.submit(Balances.transfer(alice, 1.0));
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

for offset in range(0, 10) {
	tasks += ENGINE.spawn_task_args(task_code, [offset * count]);
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
