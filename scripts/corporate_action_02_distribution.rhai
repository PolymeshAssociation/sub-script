import "./scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need user prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };

print(`Create some investors.`);
let investors = p::create_keys_batch(`${prefix}Investor`, 0, count);
let investor_dids = p::get_dids(investors);

let coin_prefix = `${prefix}COIN`;
let coin_balance = 100000000.0;
let coin_supply = 10000.0 + (coin_balance * (investors.len() + 1));
let coin_tickers = p::gen_names(coin_prefix, 0, 1);
let coin_issuers = p::tickers_to_issuers(coin_tickers);
let coin_issuers = p::create_keys(coin_issuers, ());
let coin_issuer = coin_issuers[0];
let coin = coin_tickers[0];

let asset_prefix = `${prefix}ASSET`;
let asset_balance = 1000.0;
let asset_supply = 10000.0 + (asset_balance * investors.len());
let asset_tickers = p::gen_names(asset_prefix, 0, 1);
let asset_issuers = p::tickers_to_issuers(asset_tickers);
let asset_issuers = p::create_keys(asset_issuers, ());

let per_share = coin_balance / asset_supply / 10.0;
let total_amount = per_share * asset_supply;

print(`Create Capital Distribution`);
let results = [];

let now = STORAGE.value("Timestamp", "Now");
let payment_at = now + (4 * 6 * 1000) - 1; // about 4 blocks in the future.
let ca_ids = [];
for (issuer, idx) in asset_issuers {
	let ticker = asset_tickers[idx];
	let ca_id = STORAGE.map("CorporateAction", "CAIdSequence", ticker);
	if ca_id == () {
		ca_id = 0;
	}
	ca_ids += #{ ticker: ticker, local_id: ca_id };
	results += issuer.submit(Utility.force_batch([
    Checkpoint.create_checkpoint(ticker),
    CorporateAction.initiate_corporate_action_and_distribute(
      #{
        ticker: ticker,
        kind: #{ PredictableBenefit: () },
        decl_date: 0,
        record_date: #{ Existing: 1 },
        details: "Capital Distribution",
        targets: (), // Exclude none.
        default_withholding_tax: (), // default Tax.
        withholding_tax: (),
      },
      (), // Default portfolio of the asset issuer.
      coin,
      per_share,
      total_amount,
      payment_at, // payment at
      (),
    ),
  ]));
}
print(`Wait for Capital Distributions to be created`);
p::wait_for_in_block(results);

print(`Wait for payment_at time.`);
let now = STORAGE.value("Timestamp", "Now");
let last_now = ();
while now <= payment_at {
	if last_now != now {
		let diff = (payment_at - now) / 1000.0;
		last_now = now;
		print(`waiting: now=${now / 1000.0}, payment_at=${payment_at / 1000.0}, diff=${diff} seconds`);
	}
	sleep(6);
	now = STORAGE.value("Timestamp", "Now");
}

let results = [];
for ca_id in ca_ids {
	for investor in investors {
		results += investor.submit(CapitalDistribution.claim(ca_id));
	}
}

print(`Wait for investors to claim distributions.`);
p::wait_for_in_block(results);
