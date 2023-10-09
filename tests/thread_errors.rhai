print("Test Rhai errors in threads.");

let task_code = `
	print("Thread: trigger Rhai error.");
  counter += 1;
	print("Thread: Finished, no error.");
`;

let task = ENGINE.spawn_task_args(task_code, []);

print("wait for task to finish.");
task.join();
print("finished");
