import "./scripts/mod/polymesh" as p;

print("Create users");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let pk_count = ARG.shift();
pk_count = if pk_count == () { 10 } else { parse_int(pk_count) };
let sk_count = ARG.shift();
sk_count = if sk_count == () { 2 } else { parse_int(sk_count) };

let balance = 10000;

print("Create primary keys:");
let primary_keys = p::create_users_batch(prefix, 0, pk_count, balance);

let keys = p::create_keys_batch_with_balance(`${prefix}_SK_`, 0, pk_count * sk_count, balance);

let auths = [];
let auth_data = #{
	JoinIdentity: #{
		asset: #{ Whole: () },
		extrinsic: #{ Whole: () },
		portfolio: #{ Whole: () },
	}
};

for (primary, idx) in primary_keys {
	for idx in range(0, sk_count) {
		let key = keys.pop();
		// Add JoinIdentity authorization for `key` to join `primary`.
		let res = primary.submit(Identity.add_authorization(#{
			Account: key
		}, auth_data, ()));
		auths.push([key, res]);
	}
}

let joins = [];
for (auth, idx) in auths {
	let key = auth[0];
	let res = auth[1];
	let events = res.events("Identity.AuthorizationAdded");
	
	// Get auth_id from events and accept the authorization.
	for event in events {
		let auth_id = event.args[3];
		joins += key.submit(Identity.join_identity_as_key(auth_id));
	}
}
p::wait_for_in_block(joins);

