
// Get arguments.
let start_block = ARG.shift();
if start_block == () {
	print("Need start block number");
	return;
}
start_block = parse_int(start_block);
// Number of blocks to scan.
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
// Batch size.
let batch_size = ARG.shift();
batch_size = if batch_size == () { 10 } else { parse_int(batch_size) };
// Skip blocks for fast scan.
let skip_size = ARG.shift();
skip_size = if skip_size == () { 1 } else { parse_int(skip_size) };

let end_block = start_block + count;

fn dump_babe_digest(digests) {
	for digest in digests {
		if digest.len() == 3 {
			if digest[0] == "PreRuntime" && digest[1] == "BABE" {
				let data = digest[2];
				let variant = data.shift();
				let authority_index = data.parse_le_int(0, 4);
				let slot0 = data.parse_le_int(4, 8);
				let slot1 = data.parse_le_int(8, 12);
				// Little-endian
				let slot = slot1 << 32 + slot0;
				if variant == 1 {
					return #{
						is_primary: true,
						has_vrf: true,
						slot: slot,
						authority_index: authority_index,
					};
				} else if variant == 2 {
					return #{
						is_primary: false,
						has_vrf: false,
						slot: slot,
						authority_index: authority_index,
					};
				} else if variant == 3 {
					return #{
						is_primary: false,
						has_vrf: true,
						slot: slot,
						authority_index: authority_index,
					};
				} else {
				}
			}
		}
	}
	return ();
}

fn dump_babe_info(metadata, block, parent) {
	let mt_STORAGE = new_storage(CLIENT, metadata);
	let authorities = mt_STORAGE.value_at_block("Babe", "Authorities", parent);
	let authorities_len = authorities.len();
	//print(`authorities len = ${authorities_len}`);
	let rand = mt_STORAGE.value_at_block("Babe", "Randomness", parent);
	let slot = mt_STORAGE.value_at_block("Babe", "CurrentSlot", block);
	let author = Utils.babe_secondary_slot_author(rand, slot, authorities_len);
	//print(`author = ${author}`);
	return #{
		//rand: rand,
		slot: slot,
		author: author,
		authorities_len: authorities_len,
	};
}

fn get_block_hashes(block_number, end_block, batch_size, skip_size) {
	let blocks = [];
	// Async request block hashes.
	while block_number <= end_block && blocks.len() <= batch_size {
		let hash = RPC.async_method("chain_getBlockHash",[block_number]);
		blocks += #{
			number: block_number,
			hash: hash,
		};
		block_number += skip_size;
	}
	// wait for block hashes.
	for (block, idx) in blocks {
		let hash = RPC.get_response(block.hash);
		block.hash = hash;
		// Request RuntimeVersion, Block, and events.
		block.rt = RPC.async_method("state_getRuntimeVersion",[hash]);
		block.block = RPC.async_method("chain_getBlock",[hash]);
		blocks[idx] = block;
	}
	return blocks;
}

let chain_current_block = CLIENT.get_block(());
if end_block > chain_current_block.block_number {
	end_block = chain_current_block.block_number;
}

let last_rt = ();
let last_types = Types;
let cur_spec = 0;
let last_rand = ();
let authors = [];
let secondary = [];
let secondary2 = [];
let primary = [];
let total = 0;
let pri_total = 0;
let sec_total = 0;

let block_number = start_block;
let counter = 0;

// Pre-fetch a batch of blocks.
let next_blocks = get_block_hashes(block_number, end_block, batch_size, skip_size);

while block_number <= end_block {
	let blocks = next_blocks;
	block_number += blocks.len() * skip_size;
	if block_number <= end_block {
		// Pre-fetch next batch.
		next_blocks = get_block_hashes(block_number, end_block, batch_size, skip_size);
	}
	for block in blocks {
		let hash = block.hash;
		// Load the block's RuntimeVersion.
		let rt = RPC.get_response_as_runtime_version(block.rt);

		if last_rt == () || cur_spec != rt.specVersion {
			last_rt = rt;
			cur_spec = rt.specVersion;
			print(`================= New spec version: ${cur_spec}`);
			last_types = TypesRegistry.get_block_types(RPC, rt, hash);
		}
		let block = RPC.get_response_as_block(last_types, block.block);
		let parent = block.parent;
		let digest = block.digest;
		let babe_digest = dump_babe_digest(digest);
		total += 1;
		//*
		let idx = babe_digest.authority_index;
		if babe_digest.is_primary {
			while idx >= primary.len() {
				primary.push(0);
			}
			primary[idx] += 1;
			pri_total += 1;
		} else {
			while idx >= secondary.len() {
				secondary.push(0);
			}
			secondary[idx] += 1;
			sec_total += 1;
			let babe = dump_babe_info(last_types.metadata, hash, parent);
			if last_rand != babe.rand {
				print(`number = ${block_number}: babe.rand changed = ${babe.rand}`);
				last_rand = babe.rand;
			}
			//print(`babe: digest = ${babe_digest}, info = ${babe}`);
			let idx2 = babe.author;
			while idx2 >= secondary2.len() {
				secondary2.push(0);
			}
			secondary2[idx2] += 1;
		}
		while idx >= authors.len() {
			authors.push(0);
		}
		authors[idx] += 1;
		// */
		//print(`number = ${block.number}: slot = ${babe.slot}`);
		counter += skip_size;
		if counter >= 1000 {
			counter = 0;
			print(`number = ${block_number}`);
			print(`pri authors = ${primary}`);
			print(`sec authors = ${secondary}`);
		}
	}
}
let auth_len = secondary.len();
print(`end block = ${block_number}`);
print(`pri authors = ${primary}`);
print(`pri total=${pri_total}, avg=${pri_total / auth_len}`);
print(`sec authors = ${secondary}`);
print(`sec total=${sec_total}, avg=${sec_total / auth_len}`);
print(`sec2 authors = ${secondary2}`);
print(`authors = ${authors}`);
print(`total=${total}, avg=${total / auth_len}`);

authors.sort();
print(`sorted authors = ${authors}`);
let highest = authors.pop();
print(`highest=${highest}`);

secondary2.sort();
print(`sorted secondary2 = ${secondary2}`);
let highest = secondary2.pop();
print(`highest=${highest}`);

