import "scripts/mod/polymesh" as p;

print("Create users");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let keys = [
];
loop {
	let hex = ARG.shift();
	if hex == () {
		break;
	}
	if !hex.starts_with("0x") {
		print(`Invalid session key: ${hex}`);
		return;
	}
	keys.push(hex);
}

let session_keys = [];
for hex in keys {
	let off = 2;
	let grandpa = hex.sub_string(off..off+64);
	off += 64;
	let babe = hex.sub_string(off..off+64);
	off += 64;
	let im_online = hex.sub_string(off..off+64);
	off += 64;
	let authority_discovery = hex.sub_string(off..off+64);
	let key = #{
		grandpa: `0x${grandpa}`,
		babe: `0x${babe}`,
		im_online: `0x${im_online}`,
		authority_discovery: `0x${authority_discovery}`,
	};
	session_keys.push(key);
}
let count = session_keys.len();
let balance = 30_000_000.0;
let bond = 1_000_000_000_000;
let offset = 0;

print("Onboard users for the validators.");
let users = p::create_users_batch(prefix, offset, count, balance);
let dids = p::get_dids(users);

let sudo = p::get_sudo_user();
let calls = [];

for did in dids {
	calls.push(Sudo.sudo(Staking.add_permissioned_validator(did, 10)));
}

print("Permission the validators.");
let results = [];
results += sudo.submit(Utility.batch_all(calls));
p::wait_for_finalized(results);

print("For each validator: bond, set keys and validate.");
let results = [];
for (user, idx) in users {
	let key = session_keys[idx];
	let res = user.submit(Utility.batch_all([
		Staking.bond(user, bond, #{ Staked: () }),
		Session.set_keys(key, []),
		Staking.validate(#{ commission: 100_000_000, blocked: false}),
	]));
	results += res;
}
p::wait_for_finalized(results);

