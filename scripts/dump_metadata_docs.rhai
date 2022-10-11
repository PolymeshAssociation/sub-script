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
		let docs = func.title;
	  print(`"Function","${mod_name}","${idx}","${name}", "${docs}"`);
		//print(`  Func: ${idx} -> ${name}`);
	}
	let events = mod.events;
	events.sort(|f1, f2| {
		return f1.index - f2.index;
	});
	for event in events {
		let name = event.name;
		let idx = event.index;
		let docs = event.title;
	  print(`"Event","${mod_name}","${idx}","${name}", "${docs}"`);
		//print(`  Event: ${idx} -> ${name}`);
	}
	let errors = mod.errors;
	errors.sort(|f1, f2| {
		return f1.index - f2.index;
	});
	for error in errors {
		let name = error.name;
		let idx = error.index;
		let docs = error.title;
	  print(`"Error","${mod_name}","${idx}","${name}", "${docs}"`);
		//print(`  Error: ${idx} -> ${name}`);
	}
}
