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
	let user = ConfidentialUsers.from_user(USER[name]);
	user.ticker = ticker;

	// Make sure the test users have identities and POLYX.
	p::mock_user(user.signer, polyx);

	user.did = p::get_did(user.signer);
	print(`${user} did = ${user.did}`);

	user;
}

// Get user's token balance from the chain.
fn get_enc_balance() {
	return STORAGE.double_map(
	  "ConfidentialAsset", "AccountBalance",
		this.pub_key, this.ticker,
	);
}

fn get_confidential_balance() {
	let enc_balance = this.get_enc_balance();
	// Try decrypt with hint
	let hint = this.balance;
	let balance = ();
	if hint != () {
		balance = this.decrypt_balance_with_hint(enc_balance, hint - 1.0, hint + 1.0);
	}
	if balance == () {
		print(`--------------- Slow decrypt: ${this}, hint was: ${hint}`);
		balance = this.decrypt_balance(enc_balance);
	}
	print(`${this}'s balance = ${balance}`);
	this.balance = balance;
	return #{
		balance: balance,
		enc: enc_balance,
	};
}

fn update_confidential_balance(amount) {
	let asset = this.get_confidential_balance();
	print(`Update balance: ${this}, balance=${asset.balance}, amount=${amount}`);
	asset.balance += amount;
	this.balance = asset.balance;
	return asset;
}

fn tx_mint_asset(ticker, amount) {
	this.update_confidential_balance(amount);
	return this.signer.submit(ConfidentialAsset.mint_confidential_asset(
		ticker,
		amount,
		this.pub_key,
	));
}

fn create_venue() {
	// Get next venue id.
	let venue_id = STORAGE.value("ConfidentialAsset", "VenueCounter");
	// Create venue.
	let res = this.signer.submit(ConfidentialAsset.create_venue());
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

results += mediator.signer.submit(ConfidentialAsset.add_mediator_account(mediator.pub_key));

//
// Create ConfidentialAssets.
//

results += issuer.signer.submit(ConfidentialAsset.create_confidential_asset(
	`Token 1`, ticker, #{ EquityCommon: () },
	#{ auditors: [
			[mediator.pub_key, #{ Mediator: () }],
		 ]
	},
));

//
// Setup confidential accounts
//

results += issuer.signer.submit(ConfidentialAsset.create_account(ticker, issuer.pub_key));

results += investor.signer.submit(ConfidentialAsset.create_account(ticker, investor.pub_key));

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
	let res = issuer.signer.submit(ConfidentialAsset.allow_venues(ticker, [venue_id]));
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
	let res = this.mediator.signer.submit(ConfidentialAsset.add_transaction(
		this.venue_id,
		[#{
			ticker: this.ticker,
			sender: this.issuer.pub_key,
			receiver: this.investor.pub_key,
			auditors: #{
				auditors: [
					[this.mediator.pub_key, #{ Mediator: () }],
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

	let init_tx = this.issuer.create_sender_proof(
			this.investor.pub_key,
			[this.mediator.pub_key],
			amount,
			issuer_balance.enc,
			issuer_balance.balance,
		);
	//print(`init_tx = ${init_tx}`);
	print("Issuer affirms with init_tx");
	results += this.issuer.signer.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Sender: init_tx }}
	));
	this.issuer.update_confidential_balance(-amount);

	init_tx.receiver_verify(this.investor.keys, amount);
	print("Investor affirms.");
	results += this.investor.signer.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Receiver: () }}
	));

	init_tx.mediator_verify(this.mediator.keys, amount);
	print("Mediator affirms.");
	results += this.mediator.signer.submit(ConfidentialAsset.affirm_transaction(
		transaction_id,
		#{ leg_id: 0, party: #{ Mediator: this.mediator.pub_key }}
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions before executing.");
	p::wait_for_in_block(results);
	results = [];

	print("Mediator executes the transaction");
	results += this.mediator.signer.submit(ConfidentialAsset.execute_transaction(
		transaction_id, 1
	));

	// Wait for pending tx and show any errors.
	print("Wait for all transactions");
	p::wait_for_in_block(results);

	// Apply the investor's incoming balance to their main balance.
	let res = this.investor.signer.submit(ConfidentialAsset.apply_incoming_balance(
		this.investor.pub_key,
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
