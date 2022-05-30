import "mod/polymesh" as p;

print("Create assets.");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}
if CLIENT.get_transaction_version() < 3 {
	print("New Transfer compliance rules not supported on this chain.");
	return;
}

let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let supply = ARG.shift();
supply = if supply == () { 10.0 } else { parse_decimal(supply) };
let offset = ARG.shift();
offset = if offset == () { 0 } else { parse_int(offset) };
count += offset;

let res = p::create_asset_batch(prefix, offset, count, supply, true);
let issuers = res[0];
let tickers = res[1];

let tms = [
	#{ CountTransferManager: 1000 },
	#{ PercentageTransferManager: 400000 },
	#{ CountTransferManager: 1001 },
];
let results = [];
for (ticker, idx) in tickers {
	let issuer = issuers[idx];
	let issuer_did = p::get_did(issuer);
	let claim_issuer = [#{ Accredited: () }, issuer_did];
	let stat_types = [
		// Count investors.
		#{ op: #{ Count: () }, claim_issuer: () },
		// Count Accredited investors.
		#{ op: #{ Count: () }, claim_issuer: claim_issuer },
		// Track % ownership.
		#{ op: #{ Balance: () }, claim_issuer: () },
		// Track % ownership of Accredited investors.
		#{ op: #{ Balance: () }, claim_issuer: claim_issuer },
	];
	// Set active stats.
	results += issuer.submit(Statistics.set_active_asset_stats(#{ Ticker: ticker }, stat_types));
	// Transfer conditions.
	let transfer_conditions = [
		#{ MaxInvestorCount: 1000 },
		#{ MaxInvestorOwnership: 400000 },
		//#{ ClaimCount: [#{ Accredited: true }, issuer_did, 0, #{ Some: 1000 } ] },
		#{ ClaimOwnership: [#{ Accredited: true }, issuer_did, 0, 400000] },
	];
	results += issuer.submit(Statistics.set_asset_transfer_compliance(#{ Ticker: ticker }, transfer_conditions));
	// Add exempt entities.
	results += issuer.submit(Statistics.set_entities_exempt(true, #{
    asset: #{ Ticker: ticker },
		op: #{ Count: () },
		claim_type: #{ Accredited: () },
	}, [issuer_did]));
}
p::wait_for_in_block(results);

