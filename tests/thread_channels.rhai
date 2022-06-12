print("Test channels to send value to threads.");

let task_code = `
	let chan = ARG.shift();

	loop {
		let val = chan.recv();
		if val == () {
			break;
		}
		print("Thread received value: " + val.to_string());
	}
	print("Thread: channel closed.");
`;

let channel = new_channel();
let send = channel[0];
let recv = channel[1];
let task = ENGINE.spawn_task_args(task_code, [recv]);

print("Send values to thread.");

for idx in range(0, 10) {
	send.send(idx);
}
print("Closing channel");
send.close();

print("wait for task to finish.");
task.join();
print("finished");
