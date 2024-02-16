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

fn bytes_to_hex(bytes) {
	return "0x" + bytes.reduce(|hex, b| {
		let b = b.to_hex();
		if b.len() == 1 {
			b = "0" + b;
		}
		hex + b
	});
}

fn get_all_assets_details() {
	let details = #{};
	let paged = STORAGE.map_paged("ConfidentialAsset", "Details");
	paged.set_page_count(100);
	do {
		let key_values = paged.next_key_values();
		if key_values == () {
			break;
		}
		for pair in key_values {
			let asset_id = bytes_to_hex(pair.key);
			details[asset_id] = pair.value;
		}
	} while paged.has_more;
	return details;
}

fn build_ticker_to_asset_id_map() {
	let tickers = #{};
	let paged = STORAGE.map_paged("ConfidentialAsset", "Details");
	paged.set_page_count(100);
	do {
		let key_values = paged.next_key_values();
		if key_values == () {
			break;
		}
		for pair in key_values {
			let asset_id = bytes_to_hex(pair.key);
			let details = pair.value;
			let ticker = details.data;
			if ticker.len() > 0 {
				let ticker = bytes_to_hex(ticker);
				//print(`${ticker} = ${asset_id}`);
				tickers[ticker] = asset_id;
			}
		}
	} while paged.has_more;
	print(`Build ticker to assetId map: length=${tickers.len()}`);
	return tickers;
}
const ASSET_MAP = build_ticker_to_asset_id_map();

fn get_asset_id(ticker) {
	let hex = bytes_to_hex(ticker.to_blob().to_array());
	return global::ASSET_MAP[hex];
}

fn tickers_to_asset_ids(tickers) {
	let lookup = global::ASSET_MAP;
	let ids = [];
	for ticker in tickers {
		let hex = bytes_to_hex(ticker.to_blob().to_array());
		ids += lookup[hex];
	}
	return ids;
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

		let mediators = [];
		let auditor_pub_key = mediator.pub_key;
		if require_mediator {
			let did = p::get_did(mediator.signer);
			mediators.push(did);
		} else {
			mediator = ();
		}
		let auditors = #{
			auditors: [auditor_pub_key],
			mediators: mediators,
		};

		let asset_id = ();
		if init_assets {
			let create_res = issuer.signer.submit(Utility.force_batch([
				ConfidentialAsset.create_asset(ticker, auditors),
				ConfidentialAsset.create_account(pub_key),
			]));
			// Wait for asset to be created.
			if !create_res.is_success {
				print(`Failed to create asset[${ticker}]: ${create_res.result()}`);
			}
			for event in create_res.events("ConfidentialAsset.AssetCreated") {
				asset_id = bytes_to_hex(event.args[1]);
			}
			//print(` --- mint[${ticker}]: amount=${supply}`);
			issuer.add_confidential_balance(asset_id, supply);
			results += issuer.signer.submit(ConfidentialAsset.mint(
				asset_id,
				supply / 1000000.0,
				pub_key,
			));
		} else {
			asset_id = get_asset_id(ticker);
			// Init local copy of encrypted balance.
			issuer.get_confidential_balance(asset_id);
		}
		asset_auditors[asset_id] = auditors;
		assets.push(#{
			asset_id: asset_id,
			ticker: ticker,
			issuer: issuer,
			mediator: mediator,
			auditors: auditors,
		});
	}
	// Wait for all results.
	if init_assets {
		print("CreateConfidentialAssets: Wait for batch results");
		p::wait_for_finalized(results);
	}

	return #{
		assets: assets,
		asset_auditors: asset_auditors,
	};
}

fn auditors_keys() {
	let keys = [];
	for auditor in this.auditors.auditors {
		keys += auditor;
	}
	return keys;
}

fn init_accounts(users) {
	let results = [];
	for (user, idx) in users {
		let did = user.get_account_did();
		if did == () {
			results += user.signer.submit(ConfidentialAsset.create_account(user.pub_key));
		}
	}
	return results;
}

fn init_account() {
	let did = this.get_account_did();
	if did == () {
		return this.signer.submit(ConfidentialAsset.create_account(this.pub_key));
	}
}

fn init_account(user) {
	return user.init_account();
}

// Get user's incoming balance from the chain.
fn get_enc_incoming_balance(asset_id) {
	return STORAGE.double_map(
	  "ConfidentialAsset", "IncomingBalance",
		this.pub_key, asset_id,
	);
}

// Get user's token balance from the chain.
fn get_enc_balance(asset_id) {
	return STORAGE.double_map(
	  "ConfidentialAsset", "AccountBalance",
		this.pub_key, asset_id,
	);
}

// Get the confidential account's identity.
fn get_account_did() {
	return STORAGE.map(
	  "ConfidentialAsset", "AccountDid",
		this.pub_key,
	);
}

fn get_confidential_balance(asset_id) {
	let asset = this.balances[asset_id];
	if asset == () {
		asset = #{};
	}
	// Get user's token balance from the chain.
	if asset.enc == () {
		let enc = this.get_enc_balance(asset_id);
		if enc == () {
			asset.enc = new_CipherText();
			asset.balance = 0.0;
		} else {
			asset.enc = enc;
			asset.balance = this.decrypt_balance(enc);
		}
	}
	//print(`${this}'s balance = ${asset.balance}`);
	this.balances[asset_id] = asset;
	return asset;
}

fn get_confidential_balance(user, asset_id) {
	return user.get_confidential_balance(asset_id);
}

fn add_confidential_balance(asset_id, amount) {
	return this.update_confidential_balance(asset_id, amount, "add");
}

fn sub_confidential_balance(asset_id, amount) {
	return this.update_confidential_balance(asset_id, amount, "sub");
}

fn update_confidential_balance(asset_id, amount) {
	return this.update_confidential_balance(asset_id, amount, "add");
}

fn update_confidential_balance(asset_id, amount, action) {
	let asset = this.get_confidential_balance(asset_id);
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
	//print(`${this}'s balance updated = ${asset.balance}`);
	this.balances[asset_id] = asset;
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
	for (user, idx) in this {
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
		this[idx] = user;
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

fn tx_mint_asset(asset_id, amount) {
	this.add_confidential_balance(asset_id, amount);
	return this.signer.submit(ConfidentialAsset.mint(
		asset_id,
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
			assets: [asset.asset_id],
			sender: sender.pub_key,
			receiver: receiver.pub_key,
			auditors: [],
			mediators: [],
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
		prev_tx: res,
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
		let asset_id = asset.asset_id;

		let venues = [
			issuer.venue_id,
		];
		if mediator != () {
			venues += mediator.venue_id;
		}
		venues += exchange_venues;

		results += issuer.signer.submit(ConfidentialAsset.allow_venues(asset_id, venues));
	}
	return results;
}

fn setup_asset_fund_users(asset, from, users, amount) {
	let exchange = asset.issuer;

	// Initialize the users confidential accounts.
	let results = init_accounts(users);
	//p::wait_for_finalized(results);
	p::wait_for_in_block(results);

	// Create settlements.
	let settlements = [];
	while users.len() > 0 {
		let sides = [from];
		let receivers = users.cut_head(global::MAX_CONFIDENTIAL_LEGS);
		sides += receivers;
		let orders = [];
		for receiver in receivers {
			let receiver_balance = receiver.get_confidential_balance(asset.asset_id);
			// Only fund the receiver if their current balance is less then the amount.
			if receiver_balance.balance < amount {
				let idx = sides.len();
				sides += receiver;
				orders += #{
					sender: 0, receiver: idx, asset: asset, amount: amount,
				};
			}
		}

		if orders.len() > 0 {
			settlements += create_settlement(exchange, orders, sides);
		}
	}
	//print(`  setup_asset_fund_users: users=${users.len()}, settlements=${settlements.len()}`);

	return settlements;
}

fn asset_fund_users(asset, from, users, amount) {
	let all_results = [];
	let settlements = setup_asset_fund_users(asset, from, users, amount);

	let results = affirm_settlements(settlements);
	p::wait_for_finalized(results);
	all_results += results;

	let results = execute_settlements(settlements);
	p::wait_for_finalized(results);
	all_results += results;

	let results = apply_incoming_settlements(settlements);
	all_results += results;
	return all_results;
}

fn get_settlement_id() {
	return this.get_settlement_id(true);
}

fn get_settlement_id(wait) {
	let prev_tx = this.prev_tx;
	// Wait finalization of prev_tx to finalize.
	if wait {
		if !prev_tx.wait_finalized {
			print(`Failed to finalize previous settlement transaction: ${prev_tx.result}`);
		}
	}

	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.transaction_id;
	if transaction_id != () {
		return transaction_id;
	}
	for event in prev_tx.events("ConfidentialAsset.TransactionCreated") {
		transaction_id = event.args[2];
	}
	if transaction_id == () {
		let reason = prev_tx.result;
		print(`Failed to create confidential transaction: ${reason}`);
	}
	this.transaction_id = transaction_id;
	return transaction_id;
}

fn sender_affirm_settlement() {
	let results = [];

	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.get_settlement_id();
	if transaction_id == () {
		return [];
	}

	// Sender affirms the settlement.
	for (leg, leg_id) in this.leg_details {
		let asset = leg.asset;
		let sender = leg.sender;
		let receiver = leg.receiver;
		let auditors = asset.auditors_keys();
		let amount = leg.amount;
		// Get Sender's balance from the chain.
		let sender_balance = sender.get_confidential_balance(asset.asset_id);
		//print(`sender_proof: amount=${amount}, sender_balance=${sender_balance.balance}`);

		// Sender affirms.
		let sender_proof = sender.create_sender_proof(
				receiver.pub_key,
				auditors,
				amount,
				sender_balance.enc,
				sender_balance.balance,
			);
		//print(`sender_proof = ${sender_proof}`);
		sender.sub_confidential_balance(asset.asset_id, sender_proof.sender_amount);
		//print("Sender affirms with sender_proof");
		results += sender.signer.submit(ConfidentialAsset.affirm_transactions([#{
			id: transaction_id,
			leg: #{ leg_id: leg_id, party: #{
					Sender: #{
						proofs: [[asset.asset_id, sender_proof]],
					}
				}
			}
		}]));
	}
	if results.len() > 0 {
		this.prev_tx = results[0];
	}
	return results;
}

fn sender_affirm_settlements(settlements) {
	return settlements.sender_affirm_settlements();
}

fn sender_affirm_settlements() {
	let results = [];
	for (settlement, idx) in this {
		results += settlement.sender_affirm_settlement();
		this[idx] = settlement;
	}
	return results;
}

fn receiver_affirm_settlements(settlements) {
	return settlements.receiver_affirm_settlements();
}

fn receiver_affirm_settlement() {
	let results = [];

	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.get_settlement_id();
	if transaction_id == () {
		return [];
	}

	// Affirm the settlement with all parties.
	for (leg, leg_id) in this.leg_details {
		// Receiver affirms.
		results += leg.receiver.signer.submit(ConfidentialAsset.affirm_transactions([#{
			id: transaction_id,
			leg: #{ leg_id: leg_id, party: #{ Receiver: () }}
		}]));
	}
	if results.len() > 0 {
		this.prev_tx = results[0];
	}
	return results;
}

fn mediator_affirm_settlements(settlements) {
	return settlements.mediator_affirm_settlements();
}

fn receiver_affirm_settlements() {
	let results = [];
	for (settlement, idx) in this {
		results += settlement.receiver_affirm_settlement();
		this[idx] = settlement;
	}
	return results;
}

fn mediator_affirm_settlement() {
	let results = [];

	// Wait for settlement to be created and get the transaction_id.
	let transaction_id = this.get_settlement_id();
	if transaction_id == () {
		return [];
	}

	// Affirm the settlement with all parties.
	for (leg, leg_id) in this.leg_details {
		// Mediator affirms.
		let mediator = leg.asset.mediator;
		if mediator != () {
			results += mediator.signer.submit(ConfidentialAsset.affirm_transactions([#{
				id: transaction_id,
				leg: #{ leg_id: leg_id, party: #{ Mediator: () }},
			}]));
		}
	}
	if results.len() > 0 {
		this.prev_tx = results[0];
	}
	return results;
}

fn mediator_affirm_settlements() {
	let results = [];
	for (settlement, idx) in this {
		results += settlement.mediator_affirm_settlement();
		this[idx] = settlement;
	}
	return results;
}

fn affirm_settlements(settlements) {
	return settlements.affirm_settlements();
}

fn affirm_settlements() {
	let results = [];
	print("senders affirm");
	for (settlement, idx) in this {
		results += settlement.sender_affirm_settlement();
		this[idx] = settlement;
	}
	print("receivers affirm");
	for (settlement, idx) in this {
		results += settlement.receiver_affirm_settlement();
		this[idx] = settlement;
	}
	print("mediators affirm");
	for (settlement, idx) in this {
		results += settlement.mediator_affirm_settlement();
		this[idx] = settlement;
	}
	return results;
}

fn run_settlements(settlements) {
	return settlements.run_settlements();
}

fn run_settlements() {
	let all_results = [];
	print("senders affirm");
	for (settlement, idx) in this {
		all_results += settlement.sender_affirm_settlement();
		this[idx] = settlement;
	}
	print("receivers affirm");
	for (settlement, idx) in this {
		all_results += settlement.receiver_affirm_settlement();
		this[idx] = settlement;
	}
	print("mediators affirm");
	for (settlement, idx) in this {
		all_results += settlement.mediator_affirm_settlement();
		this[idx] = settlement;
	}
	print("venues execute settlement");
	let exe_results = [];
	for (settlement, idx) in this {
		exe_results += settlement.execute_settlement();
		this[idx] = settlement;
	}
	all_results += exe_results;
	return #{
		all_results: all_results,
		exe_results: exe_results,
	};
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
	return settlements.execute_settlements();
}

fn execute_settlements() {
	let results = [];
	for (settlement, idx) in this {
		results += settlement.execute_settlement();
		this[idx] = settlement;
	}
	return results;
}

fn apply_incoming_settlement() {
	let results = [];

	// Apply incoming balance to all receiver's accounts.
	for leg in this.leg_details {
		let asset_id = leg.asset.asset_id;
		let receiver = leg.receiver;

		// Receiver apply incoming balance.
		let incoming = receiver.get_enc_incoming_balance(asset_id);
		if incoming != () {
			receiver.add_confidential_balance(asset_id, incoming);
			results += receiver.signer.submit(
				ConfidentialAsset.apply_incoming_balance(receiver.pub_key, asset_id)
			);
		}
	}
	return results;
}

fn apply_incoming_settlements(settlements) {
	return settlements.apply_incoming_settlements();
}

fn apply_incoming_settlements() {
	let results = [];
	for (settlement, idx) in this {
		results += settlement.apply_incoming_settlement();
		this[idx] = settlement;
	}
	return results;
}
