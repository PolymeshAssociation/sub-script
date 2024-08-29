let total_dids = 0;
let total_portfolios = 0;
let total_non_empty_portfolios = 0;
let total_asset_count = 0;
let total_nft_count = 0;
let max_portfolios = 0;
let max_asset_count = 0;
let max_nft_count = 0;

/*
let paged = STORAGE.map_paged("Identity", "DidRecords");
paged.set_page_count(500);

do {
	let records = paged.next_keys();
	if records == () {
		break;
	}
	for rec in records {
		let did = rec;
		total_dids += 1;
		let count = STORAGE.map("Portfolio", "NextPortfolioNumber", did);
		if count == () {
			count = 1;
		}
		if count > max_portfolios {
			max_portfolios = count;
		}
		total_portfolios += count;
		//print(`did=${did}: next port. number = ${count}`);
	}
} while paged.has_more;

// Get Fungible asset counts.
let paged = STORAGE.map_paged("Portfolio", "PortfolioAssetCount");
paged.set_page_count(500);
do {
	let records = paged.next_key_values();
	if records == () {
		break;
	}
	for rec in records {
		let portfolio = rec.key;
		let asset_count = rec.value;
		total_non_empty_portfolios += 1;
		total_asset_count += asset_count;
		if asset_count > max_asset_count {
			max_asset_count = asset_count;
		}
		//print(`${portfolio}, assets: ${asset_count}`);
	}
} while paged.has_more;
*/

// Count NFTs in the portfolio.
let nft_paged = STORAGE.double_paged("Portfolio", "PortfolioNFT", ());
let nft_portfolios = #{};
nft_paged.set_page_count(1000);
do {
	let records = nft_paged.next_key_values();
	if records == () {
		break;
	}
	for rec in records {
		let portfolio = rec.key[0];
		let did = portfolio.did;
		let kind = portfolio.kind.User;
		let nft = rec.key[1];
		let has = rec.value;
		let port_key = `${did}-${kind}`;
		let nft_count = nft_portfolios[port_key];
		if nft_count == () {
			nft_count = 0;
		}
		nft_count += 1;
		nft_portfolios[port_key] = nft_count;
		total_nft_count += 1;
		if nft_count > max_nft_count {
			max_nft_count = nft_count;
		}
		//print(`port: ${port_key}, nft=${nft}, has=${has}`);
	}
} while nft_paged.has_more;

print(`total_dids = ${total_dids}`);
print(`total_portfolios = ${total_portfolios}`);
print(`total_non_empty_portfolios = ${total_non_empty_portfolios}`);
print(`total_asset_count = ${total_asset_count}`);
print(`total_nft_count = ${total_nft_count}`);
print(`max_portfolios = ${max_portfolios}`);
print(`max_asset_count = ${max_asset_count}`);
print(`max_nft_count = ${max_nft_count}`);
