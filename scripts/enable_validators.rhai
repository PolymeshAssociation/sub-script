import "scripts/mod/polymesh" as p;

print("Create users");

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

print("For each validator: enable validation.");
let results = [];
for (user, idx) in users {
	results += user.submit(Staking.validate(#{ commission: 100_000_000, blocked: false}));
}
p::wait_for_finalized(results);

