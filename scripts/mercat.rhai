print("Test MERCAT");

import "scripts/mod/polymesh" as p;

let results = [];

fn setup_user(name, polyx, ticker) {
	let user = #{ name: name, ticker: ticker };
	user.acc = USER[name];

	// Make sure the test users have identities and POLYX.
	p::mock_user(user.acc, polyx);

	user.did = p::get_did(user.acc);
	print(`${user.name} did = ${user.did}`);

	user;
}

fn create_mercat_account(user, tickers) {
	let mercat = #{};
	mercat.acc_tx = MercatUtils.create_account(user.name, user.ticker, tickers);
	mercat.acc = mercat.acc_tx.account;
	mercat.id = mercat.acc.account_id;
	mercat.pub_key = mercat.acc.pub_key;
	print(`${user.name} account = ${mercat.id.base64}`);
	print(`${user.name} pub_key = ${mercat.pub_key.base64}`);
	//print(`${user.name} tx = ${mercat.acc_tx.base64}`);

	user.portfolio = #{ did: user.did, kind: #{ Default: () } };
	user.mercat = mercat;
	user;
}

fn create_mercat_mediator(user) {
	let mediator = #{};
	mediator.acc = MercatUtils.create_mediator(user.name);
	print(`${user.name} mediator = ${mediator.acc.base64}`);

	user.portfolio = #{ did: user.did, kind: #{ Default: () } };
	user.mediator = mediator;
	user;
}

fn get_mercat_balance(user) {
	// Get user's token balance from the chain.
	let enc_balance_base64 = STORAGE.double_map(
	  "ConfidentialAsset", "MercatAccountBalance",
		user.did, user.mercat.id.base64,
	);
	let balance = MercatUtils.decrypt_balance(user.name, user.ticker, enc_balance_base64);
	print(`${user.name}'s balance = ${balance}`);
	return #{
		balance: balance,
		base64: enc_balance_base64,
	};
}

// Test users.
let issuer = setup_user("issuer", 100000.0, "31");
let investor = setup_user("investor", 100000.0, "31");
let mediator = setup_user("mediator", 100000.0, "31");

//
// Create ConfidentialAssets.
//

results += issuer.acc.submit(ConfidentialAsset.create_confidential_asset(
	`Token 1`, "0x31", true, #{ EquityCommon: () }, [], ()
));
results += issuer.acc.submit(ConfidentialAsset.create_confidential_asset(
	`Token 2`, "0x32", true, #{ EquityCommon: () }, [], ()
));

//
// Setup MERCAT accounts
//

issuer = create_mercat_account(issuer, ["31", "32"]);
results += issuer.acc.submit(ConfidentialAsset.validate_mercat_account(issuer.mercat.acc_tx.base64));

investor = create_mercat_account(investor, ["31", "32"]);
results += investor.acc.submit(ConfidentialAsset.validate_mercat_account(investor.mercat.acc_tx.base64));

//
// Setup Mediator
//

mediator = create_mercat_mediator(mediator);
results += mediator.acc.submit(ConfidentialAsset.add_mediator_mercat_account(mediator.mediator.acc.base64));

let issuer_balance = 1000;
let mint_tx = MercatUtils.mint_asset("issuer", "31", issuer_balance);
//print(`mint_tx = ${mint_tx.base64}`);
results += issuer.acc.submit(ConfidentialAsset.mint_confidential_asset(
	"0x31",
	issuer_balance / 1000000.0, // sub-script will scale `Balance` types (i.e. add 6 decimal places).
	mint_tx.base64,
));

//
// Setup venue and settlement instruction.
//
let venue_id = p::get_or_create_venue(mediator.acc, #{ Other: () });

// Wait for previous transactions.
p::wait_for_in_block(results);

fn run_mercat_settlement(venue_id, issuer, investor, mediator, amount) {
	let res = mediator.acc.submit(Settlement.add_instruction(
		venue_id, #{ SettleOnAffirmation: () }, (), (),
		[#{
			from: issuer.portfolio,
			to: investor.portfolio,
			kind: #{
				Confidential: #{
					mediator: mediator.portfolio,
					from_account_id: issuer.mercat.id.base64,
					to_account_id: investor.mercat.id.base64,
				}
			}
		}]
	));
	let instruction_id = ();
	print("get instruction_id from events.");
	for event in res.events("Settlement.InstructionCreated") {
		instruction_id = event.args[2];
	}
	print(`instruction_id = ${instruction_id}`);

	let results = [];

	// Get Issuer's balance from the chain.
	let issuer_balance = get_mercat_balance(issuer);
	get_mercat_balance(investor);

	let init_tx = MercatUtils.create_tx(
			issuer.name,
			[investor.mercat.id.base64, investor.mercat.pub_key.base64],
			mediator.mediator.acc.base64,
			issuer.ticker, amount,
			issuer_balance.base64
		);
	//print(`init_tx = ${init_tx.base64}`);
	print("Issuer affirms with init_tx");
	results += issuer.acc.submit(Settlement.affirm_confidential_instruction(
		instruction_id,
	  #{ InitializedTransfer: init_tx.base64 },
		[
			issuer.portfolio
		],
		1
	));

	let finalize_tx = MercatUtils.finalize_tx(investor.name, investor.ticker, amount, init_tx.base64);
	//print(`finalize_tx = ${finalize_tx.base64}`);
	print("Ferdie affirms with finalize_tx");
	results += investor.acc.submit(Settlement.affirm_confidential_instruction(
		instruction_id,
	  #{ FinalizedTransfer: finalize_tx.base64 },
		[
			investor.portfolio
		],
		1
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions before sending justify_tx.");
	p::wait_for_in_block(results);
	results = [];

	let justify_tx = MercatUtils.justify_tx(
			[issuer.mercat.id.base64, issuer.mercat.pub_key.base64],
			issuer_balance.base64,
			[investor.mercat.id.base64, investor.mercat.pub_key.base64],
			mediator.name,
			mediator.ticker,
			finalize_tx.base64);
	//print(`justify_tx = ${justify_tx.base64}`);
	print("Mediator affirms with justify_tx");
	results += mediator.acc.submit(Settlement.affirm_confidential_instruction(
		instruction_id,
	  #{ JustifiedTransfer: justify_tx.base64 },
		[
			mediator.portfolio
		],
		1
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions");
	p::wait_for_in_block(results);
}

run_mercat_settlement(venue_id, issuer, investor, mediator, 100);
// Wait for settlement to execute.
p::wait_blocks(1);

run_mercat_settlement(venue_id, issuer, investor, mediator, 150);
// Wait for settlement to execute.
p::wait_blocks(1);

run_mercat_settlement(venue_id, issuer, investor, mediator, 350);
// Wait for settlement to execute.
p::wait_blocks(1);

// Get Issuer's balance from the chain.
let issuer_balance = get_mercat_balance(issuer);
get_mercat_balance(investor);
