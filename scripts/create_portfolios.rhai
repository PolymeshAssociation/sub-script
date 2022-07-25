import "./scripts/mod/polymesh" as p;

print("Create portfolios.");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need portfolio name prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let offset = ARG.shift();
offset = if offset == () { 0 } else { parse_int(offset) };
count += offset;

// Portfolio owner.
let user = USER[`Portfolio_${prefix}`];
p::mock_user(user, 100000.0);

let names = p::gen_names(prefix, offset, count);

let batch_calls = [];
let results = [];
for (name, idx) in names {
	batch_calls += Portfolio.create_portfolio(name);
	if batch_calls.len() > 200 {
	  results += user.submit(Utility.batch(batch_calls));
		batch_calls = [];
	}
}
if batch_calls.len() > 0 {
  results += user.submit(Utility.batch(batch_calls));
}
// Wait for all results.
print("CreatePortfolios: Wait for batch results");
p::wait_for_in_block(results);
