//let paged = STORAGE.map_paged("Identity", "DidRecords");
let paged = STORAGE.map_paged("Portfolio", "NextPortfolioNumber");
paged.set_page_count(500);

let total_duplicates = 0;
do {
	let key_values = paged.next_key_values();
	if key_values == () {
		break;
	}
	for pair in key_values {
		let did = pair.key;
		let max_number = pair.value;
		let names = #{};
		let has_duplicates = false;
		// Check portfolio names for this identity.
		for id in range(1,max_number) {
      let name = STORAGE.double_map("Portfolio", "Portfolios", did, id);
			if name == () {
				continue;
			}
			let count = names[name];
			if count == () {
				count = 0;
			}
			count += 1;
			names[name] = count;
			if count > 1 {
				has_duplicates = true;
				if count == 2 {
				  total_duplicates += 1;
				}
			}
		}
		if has_duplicates {
		  print(`did = ${did} has duplicate portfolio names`);
			for name in names.keys() {
				let count = names[name];
			  print(` -- found duplicate: name=${name}, count=${count}`);
			}
		}
	}
} while paged.has_more;
