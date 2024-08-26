import "scripts/mod/polymesh" as p;

print("Create nominators");

// Get arguments.
let era = ARG.shift();
if era == () {
	print("Need era number");
	return;
}
era = parse_int(era);
let count = ARG.shift();
count = if count == () { 1 } else { parse_int(count) };
let era_end = era + count;
print(`Run payouts for eras: ${era} - ${era_end}`);

let validators = STORAGE.value("Session", "Validators");

print(`For each validator payout the era rewards`);
let results = [];
let last_idx = 0;
let user = USER.Alice;
while era < era_end {
	print(` Run payouts for era: ${era}`);
	for validator in validators {
		results += user.submit(Staking.payout_stakers(validator, era));
	}
	p::wait_for_in_block(results);
	era += 1;
}

