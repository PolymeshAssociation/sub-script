import "scripts/mod/polymesh" as p;

print("Create nominators");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };

let balance = ARG.shift();
balance = if balance == () { 100000.0 } else { parse_decimal(balance) };

let bond = ARG.shift();
bond = if bond == () { 1000.0 } else { parse_decimal(bond) };
if bond > balance {
	bond = balance - 10.0;
}
bond *= 1_000_000;

let offset = ARG.shift();
offset = if offset == () { 0 } else { parse_int(offset) };
count += offset;

print("Onboard users for the nominators.");
let users = p::create_users_batch(prefix, offset, count, balance);

let validators = STORAGE.value("Session", "Validators");
let targets = [];
for validator in validators {
	targets.push(#{
		Id: validator,
	});
}
const MAX_NOMINATIONS = 16;

print("For each nominator: bond and nominate all active validators.");
let results = [];
let last_idx = 0;
for (user, idx) in users {
	let nominatations = targets;
	if targets.len() > MAX_NOMINATIONS {
		nominatations = [];
		while nominatations.len() < MAX_NOMINATIONS {
			let idx = last_idx;
			last_idx += 1;
			if last_idx >= targets.len() {
				last_idx = 0;
			}
			nominatations.push(targets[idx]);
		}
	}
	// "randomize" the bond amount.
	let bond = bond + (idx * 1_234_567);
	let res = user.submit(Utility.batch_all([
		Staking.bond(user, bond, #{ Staked: () }),
		Staking.nominate(nominatations),
	]));
	results += res;
}
p::wait_for_finalized(results);

