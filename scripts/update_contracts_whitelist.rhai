// Build pallet & extrinsic lookup tables.
let metadata = METADATA;
let modules = #{};
let extrinsic_lookup = #{};

for mod in metadata.modules {
	let extrinsics = #{};

	for func in mod.funcs {
		let name = func.name;
		let idx = func.index;
		let extrinsic = #{
			module_name: mod.name,
			module_idx: mod.index,
			name: name,
			idx: idx,
		};
		extrinsics[name] = extrinsic;
		extrinsics[`${idx}`] = extrinsic;
		extrinsic_lookup[`${mod.index},${idx}`] = extrinsic;
		extrinsic_lookup[`${mod.name}.${name}`] = extrinsic;
	}

	let mod = #{
		name: mod.name,
		idx: mod.index,
		extrinsics: extrinsics,
	};
	modules[mod.name] = mod;
	modules[`${mod.index}`] = mod;
}

// Use Alice for sudo.
let alice = USER.Alice;

let whitelist = [
	"Asset.accept_asset_ownership_transfer",
	"Asset.accept_ticker_transfer",
	"Asset.create_asset",
	"Asset.issue",
	"Asset.redeem",
	"Asset.redeem_from_portfolio",
	"Asset.register_custom_asset_type",
	"Asset.register_ticker",
	"ComplianceManager.pause_asset_compliance",
	"CapitalDistribution.claim",
	"CorporateAction.initiate_corporate_action_and_distribute",
	"PolymeshContracts.instantiate_with_hash_perms",
	"Portfolio.accept_portfolio_custody",
	"Portfolio.create_portfolio",
	"Portfolio.create_custody_portfolio",
	"Portfolio.move_portfolio_funds",
	"Portfolio.quit_portfolio_custody",
	"Settlement.add_and_affirm_instruction",
	"Settlement.create_venue",
	"Settlement.execute_manual_instruction",
	"System.remark",
	"System.remark_with_event",
	"Utility.batch",
	"Utility.batch_optimistic",
];

let updates = [];
for name in whitelist {
	let extrinsic = extrinsic_lookup[name];
	if extrinsic == () {
		print(`Not found: ${name}`);
	} else {
		updates.push([#{
			"ExtrinsicId_0": extrinsic.module_idx,
			"ExtrinsicId_1": extrinsic.idx,
		}, true]);
	}
}

let res = alice.submit(Sudo.sudo(PolymeshContracts.update_call_runtime_whitelist(updates)));
print(`res = ${res}`);
