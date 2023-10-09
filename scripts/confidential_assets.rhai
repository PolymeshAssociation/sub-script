print("Test Confidential Assets");

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

fn create_confidential_account() {
	let confidential = #{ balance: 0.0 };
	confidential.sec = ConfidentialAssetsUtils.create_account();
	confidential.pub_key = confidential.sec.pub_key;
	print(`${this.name} pub_key = ${confidential.pub_key}`);

	this.confidential = confidential;
}

fn create_confidential_mediator() {
	let mediator = #{};
	mediator.sec = ConfidentialAssetsUtils.create_account();
	mediator.pub_key = mediator.sec.pub_key;
	print(`${this.name} mediator = ${mediator.pub_key}`);

	this.mediator = mediator;
}

fn get_confidential_balance() {
	// Get user's token balance from the chain.
	let enc_balance = STORAGE.double_map(
	  "ConfidentialAsset", "AccountBalance",
		this.confidential.pub_key, this.ticker,
	);
	// Try decrypt with hint
	let hint = this.confidential.balance;
	let balance = ConfidentialAssetsUtils.decrypt_balance_with_hint(this.confidential.sec, enc_balance, hint - 1.0, hint + 1.0);
	if balance == () {
		print(`--------------- Slow decrypt: ${this.name}, hint was: ${hint}`);
		balance = ConfidentialAssetsUtils.decrypt_balance(this.confidential.sec, enc_balance);
	}
	print(`${this.name}'s balance = ${balance}`);
	return #{
		balance: balance,
		enc: enc_balance,
	};
}

fn update_confidential_balance(amount) {
	print(`Update balance: ${this.name}, balance=${this.confidential.balance}, amount=${amount}`);
	this.confidential.balance += amount;
}

fn tx_mint_asset(ticker, amount) {
	this.update_confidential_balance(amount);
	return this.acc.submit(ConfidentialAsset.mint_confidential_asset(
		ticker,
		amount,
		this.confidential.pub_key,
	));
}

fn create_venue() {
	// Get next venue id.
	let venue_id = STORAGE.value("ConfidentialAsset", "VenueCounter");
	// Create venue.
	let res = this.acc.submit(ConfidentialAsset.create_venue());
	if !res.is_success {
		print(`call failed: ${res}`);
	}
	return venue_id;
}

// Test users.
let ticker = `${prefix}T`;
let issuer = setup_user(`${prefix}_issuer`, 100000.0, ticker);
let investor = setup_user(`${prefix}_investor`, 100000.0, ticker);
let mediator = setup_user(`${prefix}_mediator`, 100000.0, ticker);

//
// Setup Mediator
//

mediator.create_confidential_mediator();
results += mediator.acc.submit(ConfidentialAsset.add_mediator_account(mediator.mediator.pub_key));

//
// Create ConfidentialAssets.
//

results += issuer.acc.submit(ConfidentialAsset.create_confidential_asset(
	`Token 1`, ticker, #{ EquityCommon: () },
	#{ auditors: [
			[mediator.mediator.pub_key, #{ Mediator: () }],
		 ]
	},
));

//
// Setup confidential accounts
//

issuer.create_confidential_account();
results += issuer.acc.submit(ConfidentialAsset.create_account(ticker, issuer.confidential.pub_key));

investor.create_confidential_account();
results += investor.acc.submit(ConfidentialAsset.create_account(ticker, investor.confidential.pub_key));

let mint_amount = 9_000_000.0;
results += issuer.tx_mint_asset(ticker, mint_amount);

//
// Transaction state management.
//

fn create_tx_state(issuer, investor, mediator, ticker) {
	// Setup venue.
	let venue_id = mediator.create_venue();
	print(`Created venue: ${venue_id}`);
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
			sender: this.issuer.confidential.pub_key,
			receiver: this.investor.confidential.pub_key,
			auditors: #{
				auditors: [
					[this.mediator.mediator.pub_key, #{ Mediator: () }],
				]
			},
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
	let issuer_balance = this.issuer.get_confidential_balance();
	this.investor.get_confidential_balance();

	let init_tx = ConfidentialAssetsUtils.create_sender_proof(
			this.issuer.confidential.sec,
			this.investor.confidential.pub_key,
			[this.mediator.mediator.pub_key],
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
	this.issuer.update_confidential_balance(-amount);

	init_tx.receiver_verify(this.investor.confidential.sec, amount);
	print("Investor affirms.");
	results += this.investor.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Receiver: () }}
	));

	init_tx.mediator_verify(this.mediator.mediator.sec, amount);
	print("Mediator affirms.");
	results += this.mediator.acc.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Mediator: this.mediator.mediator.pub_key }}
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions before executing.");
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
		this.investor.confidential.pub_key,
		this.ticker,
	));
	this.investor.update_confidential_balance(amount);
	return res;
}

let tx = create_tx_state(issuer, investor, mediator, ticker);
tx.transfer_tokens(10_000.01);

tx.transfer_tokens(15_000.015);

let res = tx.transfer_tokens(35_000.035);

// Wait for last `apply_incoming_balance` tx.
let in_block = res.is_in_block;

// Get Issuer's balance from the chain.
tx.issuer.get_confidential_balance();
tx.investor.get_confidential_balance();
