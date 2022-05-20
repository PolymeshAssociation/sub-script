import "mod/polymesh" as p;

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

let target_auth_ty = Types.resolve("TargetIdAuthorization");

let perms = #{
	asset: #{ Whole: () },
	extrinsic: #{ Whole: () },
	portfolio: #{ Whole: () },
};

let add_sks = [];
for (primary, idx) in primary_keys {
	let target_id = p::get_did(primary);
	let nonce = STORAGE.map("Identity", "OffChainAuthorizationNonce", target_id);
	if nonce == () {
		nonce = 0;
	}

	let now = STORAGE.value("Timestamp", "Now");
	let expires_at = now + 100000000;
	let target_auth = #{
		target_id: target_id,
		nonce: nonce,
		expires_at: expires_at,
	};
	let encoded_auth = target_auth_ty.encode(target_auth);

	let keys = p::create_keys_batch(`${prefix}_${idx}_SK_`, 0, sk_count);
	let sk_with_auth = [];
	for key in keys {
		let sig = key.sign(encoded_auth);
		sk_with_auth += #{
			secondary_key: #{
				signer: key,
				permissions: perms,
			},
			auth_signature: sig,
		};
	}
	add_sks += primary.submit(Identity.add_secondary_keys_with_authorization(sk_with_auth, expires_at));
}

print("Wait for 'identity.add_secondary_keys_with_authorization' calls.");
p::wait_for_in_block(add_sks);
