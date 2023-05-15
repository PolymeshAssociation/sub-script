print("Test MERCAT");

import "scripts/mod/polymesh" as p;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}

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

fn create_mercat_account() {
	let mercat = #{ balance: 0.0 };
	mercat.sec = MercatUtils.create_secret_account();
	mercat.acc_tx = MercatUtils.create_account_tx(mercat.sec);
	mercat.acc = mercat.acc_tx.account;
	mercat.pub_key = mercat.acc.pub_key;
	print(`${this.name} pub_key = ${mercat.pub_key}`);
	//print(`${this.name} tx = ${mercat.acc_tx}`);

	this.mercat = mercat;
}

fn create_mercat_mediator() {
	let mediator = #{};
	mediator.sec = MercatUtils.create_mediator();
	mediator.acc = mediator.sec.pub_key;
	print(`${this.name} mediator = ${mediator.acc}`);

	this.mediator = mediator;
}

fn get_mercat_balance() {
	// Get user's token balance from the chain.
	let enc_balance = STORAGE.double_map(
	  "ConfidentialAsset", "MercatAccountBalance",
		this.mercat.pub_key, this.ticker,
	);
	// Try decrypt with hint
	let hint = this.mercat.balance;
	let balance = MercatUtils.decrypt_balance_with_hint(this.mercat.sec, enc_balance, hint, hint);
	if balance == () {
		balance = MercatUtils.decrypt_balance(this.mercat.sec, enc_balance);
	}
	print(`${this.name}'s balance = ${balance}`);
	return #{
		balance: balance,
		enc: enc_balance,
	};
}

fn update_mercat_balance(amount) {
	this.mercat.balance += amount;
}

fn tx_mint_asset(ticker, amount) {
	let mint_tx = MercatUtils.mint_asset(this.mercat.sec, amount);
	this.update_mercat_balance(amount);
	//print(`mint_tx = ${mint_tx}`);
	return this.acc.submit(ConfidentialAsset.mint_confidential_asset(
		ticker,
		amount,
		mint_tx,
	));
}

// Test users.
let ticker = `${prefix}T`;
let issuer = setup_user(`${prefix}_issuer`, 100000.0, ticker);
let investor = setup_user(`${prefix}_investor`, 100000.0, ticker);
let mediator = setup_user(`${prefix}_mediator`, 100000.0, ticker);

//
// Create ConfidentialAssets.
//

results += issuer.acc.submit(ConfidentialAsset.create_confidential_asset(
	`Token 1`, ticker, #{ EquityCommon: () }
));

//
// Setup MERCAT accounts
//

issuer.create_mercat_account();
results += issuer.acc.submit(ConfidentialAsset.validate_mercat_account(ticker, issuer.mercat.acc_tx));

investor.create_mercat_account();
results += investor.acc.submit(ConfidentialAsset.validate_mercat_account(ticker, investor.mercat.acc_tx));

//
// Setup Mediator
//

mediator.create_mercat_mediator();
results += mediator.acc.submit(ConfidentialAsset.add_mediator_mercat_account(mediator.mediator.acc));

let mint_amount = 10_000_000.0;
results += issuer.tx_mint_asset(ticker, mint_amount);

//
// Setup venue and settlement transaction.
//
//let venue_id = p::get_or_create_venue(mediator.acc, #{ Other: () });
let venue_id = 0;

// Wait for previous transactions.
p::wait_for_in_block(results);

fn run_mercat_settlement(venue_id, issuer, investor, mediator, ticker, amount) {
	let res = mediator.acc.submit(ConfidentialAsset.add_transaction(
		venue_id,
		[#{
			ticker: ticker,
			sender: issuer.mercat.pub_key,
			receiver: investor.mercat.pub_key,
			mediator: mediator.did,
		}]
	));
	let transaction_id = ();
	print("get transaction_id from events.");
	for event in res.events("ConfidentialAsset.TransactionCreated") {
		transaction_id = event.args[2];
	}
	print(`transaction_id = ${transaction_id}`);

	let results = [];

	// Get Issuer's balance from the chain.
	let issuer_balance = issuer.get_mercat_balance();
	investor.get_mercat_balance();

	let init_tx = MercatUtils.create_tx(
			issuer.mercat.sec,
			investor.mercat.acc,
			mediator.mediator.acc,
			amount,
			issuer_balance.enc,
			issuer_balance.balance,
		);
	//print(`init_tx = ${init_tx}`);
	print("Issuer affirms with init_tx");
	results += issuer.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, parity: #{ SenderProof: init_tx }}
	));
	issuer.update_mercat_balance(-amount);

	let finalize_tx = MercatUtils.finalize_tx(investor.mercat.sec, amount, init_tx);
	//print(`finalize_tx = ${finalize_tx}`);
	print("Ferdie affirms with finalize_tx");
	results += investor.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, parity: #{ ReceiverAffirm: () }}
	));

	let justify_tx = MercatUtils.justify_tx(
			mediator.mediator.sec,
			issuer.mercat.acc,
			issuer_balance.enc,
			investor.mercat.acc,
			init_tx);
	//print(`justify_tx = ${justify_tx}`);
	print("Mediator affirms with justify_tx");
	results += mediator.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, parity: #{ MediatorAffirm: () }}
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions before sending justify_tx.");
	p::wait_for_in_block(results);
	results = [];

	print("Mediator executes the transaction");
	results += mediator.acc.submit(ConfidentialAsset.execute_transaction(
		transaction_id, 1
	));
	investor.update_mercat_balance(amount);

	// Wait for pending tx and show any errors.
	print("Wait for all transactions");
	p::wait_for_in_block(results);
}

run_mercat_settlement(venue_id, issuer, investor, mediator, ticker, 10_000.01);

run_mercat_settlement(venue_id, issuer, investor, mediator, ticker, 15_000.015);

run_mercat_settlement(venue_id, issuer, investor, mediator, ticker, 35_000.035);

// Get Issuer's balance from the chain.
issuer.get_mercat_balance();
investor.get_mercat_balance();
