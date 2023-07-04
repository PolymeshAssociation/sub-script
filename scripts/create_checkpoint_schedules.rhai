import "scripts/mod/polymesh" as p;

print("Create assets.");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let supply = ARG.shift();
supply = if supply == () { 10.0 } else { parse_decimal(supply) };
let offset = ARG.shift();
offset = if offset == () { 0 } else { parse_int(offset) };
count += offset;

let res = p::create_asset_batch(prefix, offset, count, supply);
let issuers = res[0];
let tickers = res[1];

let now = STORAGE.value("Timestamp", "Now");
let start = now + 1_000_000_000;

let schedules = 52;
let spec = #{
	start: start,
	period: #{
		unit: #{ Year: () },
		amount: 1,
	},
	remaining: 0,
};

let results = [];
for (ticker, idx) in tickers {
	let issuer = issuers[idx];
	let calls = [];
	for x in range(0, schedules) {
		calls += Checkpoint.create_schedule(ticker, spec);
	}
	results += issuer.submit(Utility.batch_optimistic(calls));
}
p::wait_for_in_block(results);

