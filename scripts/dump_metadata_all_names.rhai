// Dump node metadata.

let modules = METADATA.modules;
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
}
