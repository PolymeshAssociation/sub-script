import "polymesh" as p;

fn cut_head(size) {
	let len = this.len();
	if len < size {
		size = len;
	}
	let head = this.extract(0, size);
	this.chop(len - size);
	return head;
}

// Create a batch of Confidential Asset users.
fn create_users_batch(prefix, offset, count, balance) {
	return create_users_batch(prefix, offset, count, balance, true);
}

// Create a batch of Confidential Asset users.
fn create_users_batch(prefix, offset, count, balance, gen_dids) {
	print(`CreateConfidentialUsers: prefix='${prefix}', range=(${offset}..${count}), balance=${balance}`);
	let names = p::gen_names(prefix, offset, count);
	return create_users(names, balance, gen_dids);
}

// Create Confidential Asset users.
fn create_users(names, balance) {
	return create_users(names, balance, true);
}

// Create Confidential Asset users.
fn create_users(names, balance, gen_dids) {
	let users = p::create_users(names, balance, gen_dids);
	for (user, idx) in users {
		let user = ConfidentialUsers.from_user(user);
		user.balances = #{};
		users[idx] = user;
	}
	return users;
}

// Create Confidential Asset user.
fn create_user(name, balance) {
	return create_user(name, balance, true);
}

// Create Confidential Asset user.
fn create_user(name, balance, gen_dids) {
	let users = create_users([name], balance, gen_dids);
	return users[0];
}

fn tickers_to(prefix, tickers) {
	let ticker_to = |ticker| `${prefix}_${ticker}`;
	return tickers.map(ticker_to);
}

fn tickers_to_issuers(tickers) {
	return tickers_to("Confidential_Issuer", tickers);
}

fn tickers_to_mediators(tickers) {
	return tickers_to("Confidential_Mediator", tickers);
}

// Create a batch of confidential assets, issuers and mediators.
fn create_asset_batch(prefix, offset, count, supply, polyx) {
	return create_asset_batch(prefix, offset, count, supply, polyx, true);
}

// Create a batch of confidential assets, issuers and mediators.
fn create_asset_batch(prefix, offset, count, supply, polyx, init_assets) {
	print(`Create Confidential Assets: prefix='${prefix}', range=(${offset}..${count}), supply=${supply}`);
	let tickers = p::gen_names(prefix, offset, count);
	return create_assets(tickers, #{ EquityCommon: () }, supply, polyx, true, init_assets);
}

// Create a batch of confidential stable coin, issuers and mediators.
fn create_coin_batch(prefix, offset, count, supply, polyx) {
	return create_coin_batch(prefix, offset, count, supply, polyx, true);
}

// Create a batch of confidential stable coin, issuers and mediators.
fn create_coin_batch(prefix, offset, count, supply, polyx, init_assets) {
	print(`Create Confidential Stable Coins: prefix='${prefix}', range=(${offset}..${count}), supply=${supply}`);
	let tickers = p::gen_names(prefix, offset, count);
	return create_assets(tickers, #{ StableCoin: () }, supply, polyx, false, init_assets);
}

// Create a confidential asset, issuer and mediator.
fn create_asset(ticker, supply) {
	let assets = create_assets([ticker], #{ EquityCommon: () }, supply, 100000.0, true, true);
	return assets.assets[0];
}

// Create confidential assets, issuers and mediators.
fn create_assets(tickers, asset_type, supply, polyx, require_mediator) {
	return create_assets(tickers, asset_type, supply, polyx, require_mediator, true);
}

// Create confidential assets, issuers and mediators.
fn create_assets(tickers, asset_type, supply, polyx, require_mediator, init_assets) {
	let names = [];
	names += tickers_to_issuers(tickers);
	names += tickers_to_mediators(tickers);
	let issuers = create_users(names, polyx);
	let mediators = issuers.split(tickers.len());

	let results = [];

	if init_assets {
		// Init mediators.
		results += mediators.init_mediators();
	}

	// Create a venue for each mediator.
	mediators.init_venues_full(false);
	// Create a venue for each issuer.
	issuers.init_venues_full(false);

	let assets = [];
	let asset_auditors = #{};
	// Create assets.
	for (ticker, idx) in tickers {
		let issuer = issuers[idx];
		let mediator = mediators[idx];
		let pub_key = issuer.pub_key;

		let role = #{ Auditor: () };
		let auditor_pub_key = mediator.pub_key;
		if require_mediator {
			role = #{ Mediator: () };
		} else {
			mediator = ();
		}
		let auditors = #{
			auditors: [
				[auditor_pub_key, role],
			]
		};
		asset_auditors[ticker] = auditors;

		if init_assets {
			issuer.add_confidential_balance(ticker, supply);
			results += issuer.signer.submit(Utility.force_batch([
				ConfidentialAsset.create_confidential_asset(`token ${ticker}`, ticker, asset_type, auditors),
				ConfidentialAsset.create_account(ticker, pub_key),
				ConfidentialAsset.mint_confidential_asset(
					ticker,
					supply,
					pub_key,
				),
			]));
		} else {
			// Init local copy of encrypted balance.
			issuer.get_confidential_balance(ticker);
		}
		assets.push(#{
			ticker: ticker,
			issuer: issuer,
			mediator: mediator,
			auditors: auditors,
		});
	}
	// Wait for all results.
	if init_assets {
		print("CreateConfidentialAssets: Wait for batch results");
		p::wait_for_in_block(results);
	}

	return #{
		assets: assets,
		asset_auditors: asset_auditors,
	};
}

fn auditors_keys() {
	let keys = [];
	for auditor in this.auditors.auditors {
		keys += auditor[0];
	}
	return keys;
}

fn init_mediators() {
	let results = [];
	for user in this {
		results += user.signer.submit(ConfidentialAsset.add_mediator_account(user.pub_key));
	}
	return results;
}

fn init_mediator() {
	return this.signer.submit(ConfidentialAsset.add_mediator_account(this.pub_key));
}

fn init_accounts(users, ticker) {
	let results = [];
	for (user, idx) in users {
		let enc_balance = user.get_enc_balance(ticker);
		if enc_balance == () {
			user.update_confidential_balance(ticker, 0.0);
			results += user.signer.submit(ConfidentialAsset.create_account(ticker, user.pub_key));
		}
	}
	return results;
}

fn init_account(ticker) {
	let enc_balance = this.get_enc_balance(ticker);
	if enc_balance == () {
		this.update_confidential_balance(ticker, 0.0);
		return this.signer.submit(ConfidentialAsset.create_account(ticker, this.pub_key));
	}
}

fn init_account(user, ticker) {
	return user.init_account(ticker);
}

// Get user's token balance from the chain.
fn get_enc_balance(ticker) {
	return STORAGE.double_map(
	  "ConfidentialAsset", "AccountBalance",
		this.pub_key, ticker,
	);
}

fn get_confidential_balance(ticker) {
	let asset = this.balances[ticker];
	if asset == () {
		asset = #{};
	}
	if asset.enc == () {
		// Get user's token balance from the chain.
		asset.enc = this.get_enc_balance(ticker);
		if asset.enc == () {
			asset.enc = new_CipherText();
			asset.balance = 0.0;
		}
	}
	asset.balance = this.decrypt_balance(asset.enc);
	//print(`${this}'s balance = ${asset.balance}`);
	this.balances[ticker] = asset;
	return asset;
}

fn get_confidential_balance(user, ticker) {
	return user.get_confidential_balance(ticker);
}

fn add_confidential_balance(ticker, amount) {
	return this.update_confidential_balance(ticker, amount, "add");
}

fn sub_confidential_balance(ticker, amount) {
	return this.update_confidential_balance(ticker, amount, "sub");
}

fn update_confidential_balance(ticker, amount) {
	return this.update_confidential_balance(ticker, amount, "add");
}

fn update_confidential_balance(ticker, amount, action) {
	let asset = this.get_confidential_balance(ticker);
	//print(`Update balance: ${this}, balance=${asset.balance}, amount=${amount}, action=${action}`);
	switch action {
		"add" => {
			asset.enc += amount;
		},
		"sub" => {
			asset.enc -= amount;
		},
	}
	asset.balance = this.decrypt_balance(asset.enc);
	this.balances[ticker] = asset;
	return asset;
}

fn get_venues() {
	let did = p::get_did(this.signer);
	let paged = STORAGE.double_paged("ConfidentialAsset", "IdentityVenues", did);
	paged.set_page_count(500);
	let venues = [];
	do {
		let keys = paged.next_keys();
		if keys == () {
			break;
		}
		for key in keys {
			venues += key;
		}
	} while paged.has_more;
	return venues;
}

fn get_or_create_venue() {
	let venues = this.get_venues();
	if venues.len() > 0 {
		this.venue_id = venues[0];
	} else {
		let res = this.signer.submit(ConfidentialAsset.create_venue());
		let venue_id = ();
		for event in res.events("ConfidentialAsset.VenueCreated") {
			venue_id = event.args[1];
		}
		if venue_id == () {
			print(`Failed to create venue: ${res}`);
		}
		this.venue_id = venue_id;
	}
	return this.venue_id;
}

fn init_venues() {
	return this.init_venues_full(true);
}

fn init_venues_full(wait_for_ids) {
	let pending = [];
	for user in this {
		let venues = user.get_venues();
		if venues.len() > 0 {
			user.venue_id = venues[0];
		} else {
			let res = user.signer.submit(ConfidentialAsset.create_venue());
			pending += #{
				user: user,
				res: res,
			};
		}
	}
	if wait_for_ids {
		return this.init_venues_process(pending);
	}
	return pending;
}

fn init_venues_process(pending) {
	for result in pending {
		let venue_id = ();
		for event in result.res.events("ConfidentialAsset.VenueCreated") {
			venue_id = event.args[1];
		}
		if venue_id == () {
			print(`Failed to create venue: ${res}`);
		}
		result.user.venue_id = venue_id;
	}
	return pending;
}

fn create_venues(users) {
	return users.init_venues_full(false);
}

fn tx_mint_asset(ticker, amount) {
	this.add_confidential_balance(ticker, amount);
	return this.signer.submit(ConfidentialAsset.mint_confidential_asset(
		ticker,
		amount,
		this.pub_key,
	));
}

fn create_settlement(exchange, orders, sides) {
	// Get or create venue.
	let venue_id = exchange.get_or_create_venue();
	// Create settlements.
	let legs = [];
	let leg_details = [];

	for order in orders {
		let asset = order.asset;
		let sender = sides[order.sender];
		let receiver = sides[order.receiver];
		legs.push(#{
			ticker: asset.ticker,
			sender: sender.pub_key,
			receiver: receiver.pub_key,
			auditors: asset.auditors,
		});
		leg_details.push(#{
			asset: asset,
			sender: sender,
			receiver: receiver,
			amount: order.amount,
		});
	}
	let res = exchange.signer.submit(ConfidentialAsset.add_transaction(venue_id, legs, ()));
	return #{
		res: res,
		leg_count: legs.len(),
		venue_user: exchange,
		leg_details: leg_details,
	};
}

fn create_buy_settlement(exchange, buyer, seller, asset, coin, asset_amount, coin_amount) {
	return create_settlement(exchange, [
		#{ sender: 0, receiver: 1, asset: asset, amount: asset_amount },
		#{ sender: 1, receiver: 0, asset: coin, amount: coin_amount },
	], [buyer, seller]);
}

const MAX_CONFIDENTIAL_LEGS = 10;

fn setup_exchanges(assets, exchanges) {
	let results = [];

	// Get all exchange venues.
	let exchange_venues = [];
	for exchange in exchanges {
		exchange_venues += exchange.get_or_create_venue();
	}

	// Allow the exchange venues for each asset. 
	for (asset, idx) in assets {
		let issuer = asset.issuer;
		let mediator = asset.mediator;
		let ticker = asset.ticker;

		let venues = [
			issuer.venue_id,
		];
		if mediator != () {
			venues += mediator.venue_id;
		}
		venues += exchange_venues;

		results += issuer.signer.submit(ConfidentialAsset.allow_venues(ticker, venues));
	}
	return results;
}

fn setup_asset_fund_users(asset, from, users, amount) {
	let exchange = asset.issuer;

	// Initialize the users confidential accounts.
	init_accounts(users, asset.ticker);

	// Create settlements.
	let settlements = [];
	while users.len() > 0 {
		let sides = [from];
		let receivers = users.cut_head(global::MAX_CONFIDENTIAL_LEGS);
		sides += receivers;
		let orders = [];
		for idx in 1..=receivers.len() {
			orders += #{
				sender: 0, receiver: idx, asset: asset, amount: amount,
			};
		}

		settlements += create_settlement(exchange, orders, sides);
	}
	//print(`  setup_asset_fund_users: users=${users.len()}, settlements=${settlements.len()}`);

	return settlements;
}

fn asset_fund_users(asset, from, users, amount) {
	let all_results = [];
	let settlements = setup_asset_fund_users(asset, from, users, amount);

	let results = affirm_settlements(settlements);
	wait_for_in_block(results);
	all_results += results;

	let results = execute_settlements(settlements);
	wait_for_in_block(results);
	all_results += results;

	let results = apply_incoming_settlements(settlements);
	all_results += results;
	return all_results;
}

fn get_settlement_id() {
	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.transaction_id;
	if transaction_id != () {
		return transaction_id;
	}
	for event in this.res.events("ConfidentialAsset.TransactionCreated") {
		transaction_id = event.args[2];
	}
	if transaction_id == () {
		let reason = this.res.result;
		print(`Failed to create confidential transaction: ${reason}`);
	}
	this.transaction_id = transaction_id;
	return transaction_id;
}

fn affirm_settlement() {
	let results = [];

	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.get_settlement_id();
	if transaction_id == () {
		return [];
	}

	// Affirm the settlement with all parties.
	for (leg, leg_id) in this.leg_details {
		let asset = leg.asset;
		let sender = leg.sender;
		let receiver = leg.receiver;
		let auditors = asset.auditors_keys();
		let amount = leg.amount;
		// Get Sender's balance from the chain.
		let sender_balance = sender.get_confidential_balance(asset.ticker);

		// Sender affirms.
		let sender_proof = sender.create_sender_proof(
				receiver.pub_key,
				auditors,
				amount,
				sender_balance.enc,
				sender_balance.balance,
			);
		//print(`sender_proof = ${sender_proof}`);
		sender.sub_confidential_balance(asset.ticker, sender_proof.sender_amount);
		//print("Sender affirms with sender_proof");
		results += sender.signer.submit(ConfidentialAsset.affirm_transaction(
			transaction_id,
			#{ leg_id: leg_id, party: #{ Sender: sender_proof }}
		));

		// Receiver affirms.
		results += receiver.signer.submit(ConfidentialAsset.affirm_transaction(
			transaction_id,
			#{ leg_id: leg_id, party: #{ Receiver: () }}
		));

		// Mediator affirms.
		let mediator = leg.asset.mediator;
		if mediator != () {
			results += mediator.signer.submit(ConfidentialAsset.affirm_transaction(
				transaction_id,
				#{ leg_id: leg_id, party: #{ Mediator: mediator.pub_key }}
			));
		}
	}
	return results;
}

fn affirm_settlements(settlements) {
	let results = [];
	for settlement in settlements {
		results += settlement.affirm_settlement();
	}
	return results;
}

fn execute_settlement() {
	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.get_settlement_id();
	if transaction_id == () {
		return [];
	}

	// Execute the settlement.
	return this.venue_user.signer.submit(
		ConfidentialAsset.execute_transaction(transaction_id, this.leg_count)
	);
}

fn execute_settlements(settlements) {
	let results = [];
	for settlement in settlements {
		results += settlement.execute_settlement();
	}
	return results;
}

fn apply_incoming_settlement() {
	let results = [];

	// Apply incoming balance to all receiver's accounts.
	for leg in this.leg_details {
		let ticker = leg.asset.ticker;
		let receiver = leg.receiver;

		// Receiver apply incoming balance.
		results += receiver.signer.submit(
			ConfidentialAsset.apply_incoming_balance(receiver.pub_key, ticker)
		);
	}
	return results;
}

fn apply_incoming_settlements(settlements) {
	let results = [];
	for settlement in settlements {
		results += settlement.apply_incoming_settlement();
	}
	return results;
}
