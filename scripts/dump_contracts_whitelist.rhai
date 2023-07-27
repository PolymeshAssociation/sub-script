
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
	}

	let mod = #{
		name: mod.name,
		idx: mod.index,
		extrinsics: extrinsics,
	};
	modules[mod.name] = mod;
	modules[`${mod.index}`] = mod;
}

let paged = STORAGE.map_paged("PolymeshContracts", "CallRuntimeWhitelist");
paged.set_page_count(100);

let whitelist = [];
do {
	let pairs = paged.next_key_values();
	for pair in pairs {
		let key = pair.key;
		let allowed = pair.value;
		let mod_id = key.ExtrinsicId_0;
		let ext_id = key.ExtrinsicId_1;
		let extrinsic = extrinsic_lookup[`${mod_id},${ext_id}`];
		if extrinsic == () {
			let mod = modules[`${mod_id}`];
			print(`Unknown extrinsic = ${key}, module = ${mod}`);
		} else {
			let name = `${extrinsic.module_name}.${extrinsic.name}`;
			whitelist += name;
			//print(`${name} = ${allowed}`);
		}
	}
} while paged.has_more;

whitelist.sort();
print(`let whitelist = ${whitelist};`);
