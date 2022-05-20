// simple test.

// Limits
let limit_len = 28;
let limit_func_name_len = 50;

let max_pallets = METADATA.modules.len();
let max_funcs = 0;
let max_mod_name_len = 0;
let max_func_name_len = 0;
let min_mod_name_len = 1000;
let min_func_name_len = 1000;
let max_per_pallet_len = 0;
let total_len = 0;
let count_names = 0;
for mod in METADATA.modules {
	let name = mod.name;
	print(`------------- Pallet: ${name}`);
	total_len += name.len();
	count_names += 1;
	if name.len() > limit_len {
		print(`Pallet name over limit: ${name}`);
	}
	if name.len() > max_mod_name_len {
		max_mod_name_len = name.len();
		//print(`Larger pallet name: ${name}`);
	}
	if name.len() < min_mod_name_len {
		min_mod_name_len = name.len();
		//print(`Small pallet name: ${name}`);
	}
	let funcs = mod.funcs;
	let func_count = funcs.len();
	if func_count > limit_len {
		print(`Pallet func count over limit: ${name}`);
	}
	if func_count > max_funcs {
		max_funcs = func_count;
		//print(`Larger func count: ${func_count}`);
	}
	let pallet_total_len = 0;
	for func in funcs {
		let name = func.name;
		total_len += name.len();
		count_names += 1;
		pallet_total_len += name.len();
		if name.len() > limit_func_name_len {
			print(`Func name over limit: ${name}`);
		}
		if name.len() > max_func_name_len {
			max_func_name_len = name.len();
			//print(`Larger func name: ${name}`);
		}
		if name.len() < min_func_name_len {
			min_func_name_len = name.len();
			//print(`Small func name: ${name}`);
		}
	}
	print(` -- pallet_len = ${pallet_total_len}`);
	if pallet_total_len > max_per_pallet_len {
		max_per_pallet_len = pallet_total_len;
	}
}
print(`pallets = ${max_pallets}`);
print(`max_funcs = ${max_funcs}`);
print(`max_mod_name_len = ${max_mod_name_len}`);
print(`max_func_name_len = ${max_func_name_len}`);
print(`min_mod_name_len = ${min_mod_name_len}`);
print(`min_func_name_len = ${min_func_name_len}`);
print(`max_per_pallet_len = ${max_per_pallet_len}`);
print(`total_names_len = ${total_len}`);
let avg_name_len = total_len / count_names;
print(`avg_name_len = ${avg_name_len}`);
