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
	let balance = MercatUtils.decrypt_balance_with_hint(this.mercat.sec, enc_balance, hint - 1.0, hint + 1.0);
	if balance == () {
		print(`--------------- Slow decrypt: ${this.name}, hint was: ${hint}`);
		balance = MercatUtils.decrypt_balance(this.mercat.sec, enc_balance);
	}
	print(`${this.name}'s balance = ${balance}`);
	return #{
		balance: balance,
		enc: enc_balance,
	};
}

fn update_mercat_balance(amount) {
	print(`Update balance: ${this.name}, balance=${this.mercat.balance}, amount=${amount}`);
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

fn create_venue() {
	// Get next venue id.
	let venue_id = STORAGE.value("ConfidentialAsset", "VenueCounter");
	// Create venue.
	let res = this.acc.submit(ConfidentialAsset.create_venue());
	if !res.is_success {
		print(`call failed: ${res.result()}`);
	}
	return venue_id;
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

let mint_amount = 9_000_000.0;
results += issuer.tx_mint_asset(ticker, mint_amount);

//
// Transaction state management.
//

fn create_tx_state(issuer, investor, mediator, ticker) {
	// Setup venue.
	let venue_id = mediator.create_venue();
	// Asset issuer allow venue.
	let res = issuer.acc.submit(ConfidentialAsset.allow_venues(ticker, [venue_id]));
	if !res.is_in_block {
		print(`Failed to allow venue: ${res}`);
	}
	return #{
		venue_id: venue_id,
		issuer: issuer,
		investor: investor,
		mediator: mediator,
		ticker: ticker,
	};
}

fn transfer_tokens(amount) {
	let res = this.mediator.acc.submit(ConfidentialAsset.add_transaction(
		this.venue_id,
		[#{
			ticker: this.ticker,
			sender: this.issuer.mercat.pub_key,
			receiver: this.investor.mercat.pub_key,
			mediator: this.mediator.did,
		}],
		"01234567890123456789012345678901"
	));
	let transaction_id = ();
	print("get transaction_id from events.");
	for event in res.events("ConfidentialAsset.TransactionCreated") {
		transaction_id = event.args[2];
	}
	print(`transaction_id = ${transaction_id}`);
	if transaction_id == () {
		print(`Failed to create transaction: ${res}`);
	}

	let results = [];

	// Get Issuer's balance from the chain.
	let issuer_balance = this.issuer.get_mercat_balance();
	this.investor.get_mercat_balance();

	let init_tx = MercatUtils.create_tx(
			this.issuer.mercat.sec,
			this.investor.mercat.acc,
			this.mediator.mediator.acc,
			amount,
			issuer_balance.enc,
			issuer_balance.balance,
		);
	//print(`init_tx = ${init_tx}`);
	print("Issuer affirms with init_tx");
	results += this.issuer.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Sender: init_tx }}
	));
	this.issuer.update_mercat_balance(-amount);

	let finalize_tx = MercatUtils.finalize_tx(this.investor.mercat.sec, amount, init_tx);
	//print(`finalize_tx = ${finalize_tx}`);
	print("Investor affirms with finalize_tx");
	results += this.investor.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Receiver: () }}
	));

	let justify_tx = MercatUtils.justify_tx(
			this.mediator.mediator.sec,
			this.issuer.mercat.acc,
			issuer_balance.enc,
			this.investor.mercat.acc,
			init_tx);
	//print(`justify_tx = ${justify_tx}`);
	print("Mediator affirms with justify_tx");
	results += this.mediator.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Mediator: () }}
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions before sending justify_tx.");
	p::wait_for_in_block(results);
	results = [];

	print("Mediator executes the transaction");
	results += this.mediator.acc.submit(ConfidentialAsset.execute_transaction(
		transaction_id, 1
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions");
	p::wait_for_in_block(results);

	// Apply the investor's incoming balance to their main balance.
	let res = this.investor.acc.submit(ConfidentialAsset.apply_incoming_balance(
		this.investor.mercat.pub_key,
		this.ticker,
	));
	this.investor.update_mercat_balance(amount);
	return res;
}

let tx = create_tx_state(issuer, investor, mediator, ticker);
tx.transfer_tokens(10_000.01);

tx.transfer_tokens(15_000.015);

let res = tx.transfer_tokens(35_000.035);

// Wait for last `apply_incoming_balance` tx.
let in_block = res.is_in_block;

// Get Issuer's balance from the chain.
tx.issuer.get_mercat_balance();
tx.investor.get_mercat_balance();
