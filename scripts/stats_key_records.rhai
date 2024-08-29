let total_dids = 0;
let total_keys = 0;
let total_ms_keys = 0;
let total_primary_keys = 0;
let total_secondary_keys = 0;
let max_keys = 0;
let max_assets = 0;
let max_pallets = 0;
let max_funcs = 0;
let max_portfolios = 0;
let max_name = 0;

let paged = STORAGE.map_paged("Identity", "DidRecords");
paged.set_page_count(500);

do {
	let records = paged.next_keys();
	for rec in records {
		total_dids += 1;
	}
} while paged.has_more;

let paged = STORAGE.map_paged("Identity", "KeyRecords");
paged.set_page_count(500);

fn perm_len(perm) {
	let len = 0;
	for val in perm.values() {
		if val != () {
			len = val.len();
		}
	}
	return len;
}

do {
	let records = paged.next();
	for rec in records {
		let did = ();
		let perms = ();
		if rec != () {
			if rec.PrimaryKey != () {
				total_primary_keys += 1;
				did = rec.PrimaryKey;
			}
			if rec.SecondaryKey != () {
				total_secondary_keys += 1;
				did = rec.SecondaryKey[0];
				perms = rec.SecondaryKey[1];
			}
			if rec.MultiSigSignerKey != () {
				total_ms_keys += 1;
			}
		}
		total_keys += 1;
		if did == () {
			// Multisig signer.
			continue;
		}
		if perms == () {
			continue;
		}
		let assets_len = perm_len(perms.asset);
		if assets_len > max_assets {
			max_assets = assets_len;
		}
		let portfolios_len = perm_len(perms.portfolio);
		if portfolios_len > max_portfolios {
			max_portfolios = portfolios_len;
		}
		let pallets_len = 0;
		for pallets in perms.extrinsic.values() {
			if pallets != () {
				let pallet_len = pallets.len();
				if pallet_len > max_pallets {
					max_pallets = pallet_len;
				}
				for pallet in pallets {
					let name_len = pallet.pallet_name.len();
					if name_len > max_name {
						max_name = name_len;
					}
					for funcs in pallet.dispatchable_names.values() {
						if funcs != () {
							let func_len = funcs.len();
							if func_len > max_funcs {
								max_funcs = func_len;
							}
							for func in funcs {
								let name_len = func.len();
								if name_len > max_name {
									max_name = name_len;
								}
							}
						}
					}
				}
			}
		}
	}
} while paged.has_more;

print(`total_dids = ${total_dids}`);
print(`total_keys = ${total_keys}`);
print(`total_primary_keys = ${total_primary_keys}`);
print(`total_secondary_keys = ${total_secondary_keys}`);
print(`total_ms_signer_keys = ${total_ms_keys}`);
print(`max_assets = ${max_assets}`);
print(`max_pallets = ${max_pallets}`);
print(`max_funcs = ${max_funcs}`);
print(`max_portfolios = ${max_portfolios}`);
