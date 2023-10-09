import "./scripts/mod/polymesh" as p;

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

let token = #{
	Id: contract,
};
//let token_owner = USER.Alice;
let token_owner = USER.Test123;
let dst = USER.Bob;
let balance = 0.000001;

const erc20_transfer_params = Types.parse_type("([u8; 4], AccountId, Balance)");
fn erc20_transfer(token, dst, balance) {
	let data = global::erc20_transfer_params.encode(["0x84a15da1", dst.acc, balance]);
	return Contracts.Call(token, 0, 6947000000, (), data);
}

let task_code = `
	let count = ARG.shift();
	let token = ARG.shift();
	let user = ARG.shift();
	let dst = ARG.shift();

	import "./scripts/mod/polymesh" as p;

	const erc20_transfer_params = Types.parse_type("([u8; 4], AccountId, Balance)");
	fn erc20_transfer(token, dst, balance) {
		let data = global::erc20_transfer_params.encode(["0x84a15da1", dst.acc, balance]);
		return Contracts.Call(token, 0, 6947000000, (), data);
	}

	let transfer = erc20_transfer(token, dst, 0.000001);
	
	print("Submit transfers.");
	let results = [];
	for idx in range(0, count) {
		results += user.submit(transfer);
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

let results = [];
let user_balance = (count + 1) * balance;
for idx in range(0, threads) {
	let user = users[idx];
	results += token_owner.submit(erc20_transfer(token, user, user_balance));
}
print("Wait for initial ERC20 transfer.");
p::wait_for_in_block(results);

print("Spawn threads.");
for idx in range(0, threads) {
	let user = users[idx];
	tasks += ENGINE.spawn_task_args(task_code, [count, token, user, dst]);
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
