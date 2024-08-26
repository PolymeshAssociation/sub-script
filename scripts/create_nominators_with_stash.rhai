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
let controllers = p::create_keys_batch(`${prefix}_controller`, offset, count);

// Join controllers to primary key.
let target_auth_ty = Types.resolve("TargetIdAuthorization");
let perms = #{
	asset: #{ Whole: () },
	extrinsic: #{ Whole: () },
	portfolio: #{ Whole: () },
};
let add_sks = [];
for (primary, idx) in users {
	let did = p::get_did(primary);
	let controller = controllers[idx];
	let nonce = STORAGE.map("Identity", "OffChainAuthorizationNonce", did);
	if nonce == () {
		nonce = 0;
	}

	let now = STORAGE.value("Timestamp", "Now");
	let expires_at = now + 100000000;
	let target_auth = #{
		target_id: did,
		nonce: nonce,
		expires_at: expires_at,
	};
	let encoded_auth = target_auth_ty.encode(target_auth);

	let sk_with_auth = [];
	let sig = controller.sign(encoded_auth);
	sk_with_auth += #{
		secondary_key: #{
			key: controller,
			permissions: perms,
		},
		auth_signature: sig,
	};
	add_sks += primary.submit(Utility.batch_all([
		Identity.add_secondary_keys_with_authorization(sk_with_auth, expires_at),
		Balances.transfer(controller, 1000.0),
	]));
}
print("Wait for 'identity.add_secondary_keys_with_authorization' calls.");
p::wait_for_in_block(add_sks);

print("For each nominator setup the stash & controller");
let results = [];
for (stash, idx) in users {
	let controller = controllers[idx];
	results += stash.submit(Staking.bond(controller, bond, #{ Staked: () }));
}
p::wait_for_finalized(results);

let validators = STORAGE.value("Session", "Validators");
let targets = [];
for validator in validators {
	targets.push(#{
		Id: validator,
	});
}

print("For each nominator: use the controller and nominate all active validators.");
let results = [];
for (controller, idx) in controllers {
	results += controller.submit(Staking.nominate(targets));
}
p::wait_for_finalized(results);

