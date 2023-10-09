import "./scripts/mod/polymesh" as p;

print("Get number of secondary keys for an identity.");

// Get arguments.
let key = ARG.shift();
if key == () {
	print("Need primary key");
	return;
}

fn get_key_balance(key) {
	let info = STORAGE.map("System", "Account", key);
	if info == () {
		return 0;
	} else {
		return info.data.free;
	}
}
let did = STORAGE.map("Identity", "KeyToIdentityIds", key);
print(`did = ${did}`);

let records = STORAGE.map("Identity", "DidRecords", did);
let primary = records.primary_key;
let balance = get_key_balance(primary);
print(`primary_key = ${primary}`);
print(`primary_key.balance = ${balance}`);

let keys = records.secondary_keys;
print(`count secondary_keys = ${keys.len()}`);
let total_balance = balance;
for key in keys {
	let acc = key.signer.Account;
	let bal = get_key_balance(acc);
	print(`secondary_key = ${acc}`);
	print(`secondary_key.balance = ${bal}`);
	total_balance += bal;
}
print(`total balance = ${total_balance}`);
