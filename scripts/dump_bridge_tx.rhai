let did = ARG.shift();

let paged = STORAGE.double_paged("Bridge", "BridgeTxDetails", ());
paged.set_page_count(100);

let total_tx = 0;
do {
	let key_values = paged.next_key_values();
	if key_values == () {
		break;
	}
	for pair in key_values {
		let target = pair.key[0];
		let nonce = pair.key[1];
		let tx = pair.value;
		total_tx += 1;
		print(`${nonce}, account = ${target}: amount = ${tx.amount}, execution_block = ${tx.execution_block}, status = ${tx.status}`);
		/*
		if tx.status.contains("Timelocked") {
			print(`nonce = ${nonce}, account = ${target}: amount = ${tx.amount}, execution_block = ${tx.execution_block}, status = ${tx.status}`);
		}
		*/
	}
} while paged.has_more;

print(`total_tx = ${total_tx}`);
