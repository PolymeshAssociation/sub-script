let total_nft_count = 0;
let max_nft_count = 0;

let paged = STORAGE.double_paged("Nft", "NumberOfNFTs", ());
paged.set_page_count(500);

do {
	let records = paged.next_key_values();
	if records == () {
		break;
	}
	for rec in records {
		let ticker = rec.key[0];
		let did = rec.key[1];
		let nft_count = rec.value;
		total_nft_count += nft_count;
		if nft_count > max_nft_count {
			max_nft_count = nft_count;
		}
		//print(`number of NFTs: ${ticker},${did} => ${nft_count}`);
	}
} while paged.has_more;

print(`total_nft_count = ${total_nft_count}`);
print(`max_nft_count = ${max_nft_count}`);
