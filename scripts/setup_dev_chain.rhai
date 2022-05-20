print(`Main`);

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need prefix");
	return;
}

let tasks = [];

tasks += ENGINE.spawn_file_task_args("./scripts/create_users_with_secondary_keys.rhai", [prefix, "100", "4"]);
tasks += ENGINE.spawn_file_task_args("./scripts/create_asset_with_compliance.rhai", [`${prefix}_CM`, "100", "1000000"]);
tasks += ENGINE.spawn_file_task_args("./scripts/create_asset_with_transfer_managers.rhai", [`${prefix}_TM`, "100", "1000000"]);

print("wait for tasks to finish.");
for task in tasks {
	let res = task.join();
	print(`joined.  res = ${res}`);
}
print("finished all tasks.");
