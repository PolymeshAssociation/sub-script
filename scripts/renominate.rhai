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

let offset = ARG.shift();
offset = if offset == () { 0 } else { parse_int(offset) };
count += offset;

print("Onboard users for the nominators.");
let users = p::create_keys_batch(prefix, offset, count);

let validators = STORAGE.value("Session", "Validators");
let targets = [];
for validator in validators {
	targets.push(#{
		Id: validator,
	});
}
const MAX_NOMINATIONS = 10;

print(`For each nominator: re-nominate {MAX_NOMINATIONS} validators.`);
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
	results += user.submit(Staking.nominate(nominatations));
}
p::wait_for_finalized(results);

