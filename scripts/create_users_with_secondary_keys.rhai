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

let asset_count = ARG.shift();
asset_count = if asset_count == () { 0 } else { parse_int(asset_count) };
let portfolio_count = ARG.shift();
portfolio_count = if portfolio_count == () { 0 } else { parse_int(portfolio_count) };
let pallet_count = ARG.shift();
pallet_count = if pallet_count == () { 0 } else { parse_int(pallet_count) };
let extrinsic_count = ARG.shift();
extrinsic_count = if extrinsic_count == () { 0 } else { parse_int(extrinsic_count) };

let balance = 10000;

print("Create primary keys:");
let primary_keys = p::create_users_batch(prefix, 0, pk_count, balance);

let target_auth_ty = Types.resolve("TargetIdAuthorization");

let perms = #{
	asset: #{ Whole: () },
	extrinsic: #{ Whole: () },
	portfolio: #{ Whole: () },
};

if asset_count > 0 {
	let assets = p::gen_names("TICKER", 0, asset_count);
	perms.asset = #{ These: assets };
}
if portfolio_count > 0 {
	let portfolios = [];
	for idx in range(0, portfolio_count) {
		portfolios += #{
			did: "0x0100000000000000000000000000000000000000000000000000000000000000",
			kind: #{ User: idx },
		};
	}
	perms.portfolio = #{ These: portfolios };
}
if pallet_count > 0 {
	let pallets = [];
	let extrinsics = p::gen_names("Func", 0, extrinsic_count);
	let dispatchable_names = #{ Whole: () };
	if extrinsic_count > 0 {
		dispatchable_names = #{
			These: extrinsics,
		};
	}
	let names = p::gen_names("Pallet", 0, pallet_count);
	for name in names {
		pallets += #{
			pallet_name: name,
			dispatchable_names: dispatchable_names,
		};
	}
	perms.extrinsic = #{ These: pallets };
}

let add_sks = [];
for (primary, idx) in primary_keys {
	print(`primary: ${primary.acc}`);
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
				key: key,
				permissions: perms,
			},
			auth_signature: sig,
		};
	}
	add_sks += primary.submit(Identity.add_secondary_keys_with_authorization(sk_with_auth, expires_at));
}

print("Wait for 'identity.add_secondary_keys_with_authorization' calls.");
p::wait_for_in_block(add_sks);
