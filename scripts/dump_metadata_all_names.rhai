// Dump node metadata.

let block_hash = ARG.shift();
let rt = CLIENT.get_block_runtime_version(block_hash);
print(`runtime version: ${rt}`);
let last_types = TypesRegistry.get_block_types(RPC, rt, block_hash);
//let metadata = METADATA;
let metadata = last_types.metadata;
let modules = metadata.modules;
modules.sort(|m1, m2| {
	return m1.index - m2.index;
});
for mod in modules {
	let mod_name = mod.name;
	let idx = mod.index;
	//print(`-- Pallet: ${idx} -> ${mod_name}`);
	print(`"Pallet","${idx}","${mod_name}"`);
	let funcs = mod.funcs;
	funcs.sort(|f1, f2| {
		return f1.index - f2.index;
	});
	for func in funcs {
		let name = func.name;
		let idx = func.index;
	  print(`"Function","${mod_name}","${idx}","${name}"`);
		//print(`  Func: ${idx} -> ${name}`);
	}
	let events = mod.events;
	events.sort(|f1, f2| {
		return f1.index - f2.index;
	});
	for event in events {
		let name = event.name;
		let idx = event.index;
	  print(`"Event","${mod_name}","${idx}","${name}"`);
		//print(`  Event: ${idx} -> ${name}`);
	}
	let errors = mod.errors;
	errors.sort(|f1, f2| {
		return f1.index - f2.index;
	});
	for error in errors {
		let name = error.name;
		let idx = error.index;
	  print(`"Error","${mod_name}","${idx}","${name}"`);
		//print(`  Error: ${idx} -> ${name}`);
	}
}
