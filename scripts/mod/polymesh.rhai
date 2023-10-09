
const MAX_LEGS = 10;

// Wait for all call results and print errors.
fn wait_for_results(results) {
	for res in results {
		if !res.is_success {
			print(`call failed: ${res.result()}`);
		}
	}
}

// Wait for all calls to be included in a block.
// This doesn't check if the call was successful.
fn wait_for_in_block(results) {
	for res in results {
		if !res.is_in_block {
			print(`call failed: Invalid or dropped`);
		}
	}
}

// get multiple user's account ids.
fn get_accounts(users) {
	return users.map(|u| u.acc);
}

// get current block number
fn get_block_number() {
	return STORAGE.value("System", "Number");
}

// Rhai[1.6.x]: sleep is broken.
fn my_sleep(sec) {
	sleep(sec);
}

// Wait X blocks.
fn wait_blocks(n) {
	let end_block = get_block_number() + n;
	do {
		my_sleep(1);
	} while get_block_number() < end_block;
}

// get user's account info.
fn get_account_info(user) {
	return STORAGE.map("System", "Account", user.acc);
}

// get multiple user's account infos.
fn mult_get_account_info(users) {
	let accounts = get_accounts(users);
	return STORAGE.map_keys("System", "Account", accounts);
}

// get user's balance
fn get_balance(user) {
	let info = get_account_info(user);
	if info == () {
		return 0;
	} else {
		return info.data.free;
	}
}

// get multiple user's balance
fn get_balances(users) {
	let infos = mult_get_account_info(users);
	return infos.map(|info| {
		if info == () {
			return 0;
		} else {
			return info.data.free;
		}
	});
}

const TX_VERSION = CLIENT.get_transaction_version();
const SPEC_VERSION = CLIENT.get_spec_version();

fn key_records_did(rec) {
	if rec == () {
		return ();
	}
	let p_key = rec.PrimaryKey;
	if p_key != () {
		return p_key;
	}
	let s_key = rec.SecondaryKey;
	if s_key != () {
		return s_key[0];
	}
	return ();
}

// get user's identity id.
fn get_did(user) {
	if global::TX_VERSION < 3 {
		return STORAGE.map("Identity", "KeyToIdentityIds", user.acc);
	} else {
		let rec = STORAGE.map("Identity", "KeyRecords", user.acc);
		return key_records_did(rec);
	}
}

// get multiple user's identity id.
fn get_dids(users) {
	let accounts = get_accounts(users);
	if global::TX_VERSION < 3 {
		return STORAGE.map_keys("Identity", "KeyToIdentityIds", accounts);
	} else {
		return STORAGE.map_keys("Identity", "KeyRecords", accounts)
			.map(|rec| key_records_did(rec));
	}
}

fn dev_users() {
	return [
		USER.Alice,
		USER["Alice//stash"],
		USER.Bob,
		USER.Charlie,
		USER.Dave,
		USER.Eve,
		USER.Testnet_CDD,
	];
}

fn get_sudo_user() {
	// Generate common dev users.  This is for the `USER.find_by_account` below.
	dev_users();

	let key = STORAGE.value("Sudo", "Key");
	let sudo = USER.find_by_account(key);
	return sudo;
}

const SUDO_USER = get_sudo_user();

fn get_cdd_provider() {
	// Build list of keys to search for a CDD provider.
	let keys = [];
	if global::SUDO_USER != () {
		keys += global::SUDO_USER;
	}
	keys += dev_users();

	// CddServiceProviders.
	let provider_dids = STORAGE.value("CddServiceProviders", "ActiveMembers");
	let provider = ();

	let dids = get_dids(keys);
	for (did, idx) in dids {
		if did in provider_dids {
			provider = keys[idx];
			break;
		}
	}

	return provider;
}

const CDD_PROVIDER = get_cdd_provider();

// Mock CDD for user and make sure they have POLYX.
fn mock_user(user, balance) {
	let calls = [];
	let did = get_did(user);
	if did == () {
		if global::SPEC_VERSION < 3000 {
			calls += Identity.mock_cdd_register_did(user);
		} else {
			calls += TestUtils.mock_cdd_register_did(user);
		}
	}
	calls += Sudo.sudo(Balances.set_balance(user, balance, 0));
	let res = global::CDD_PROVIDER.submit(Utility.batch_optimistic(calls));
	return res.is_in_block;
}

// Generate list of names from parameters.
fn gen_names(prefix, offset, count) {
	let names = [];
	for idx in range(offset, count) {
		names += `${prefix}${idx}`;
	}

	return names;
}

// Create a batch of keys.
fn create_keys_batch(prefix, offset, count) {
	return create_keys_batch_with_balance(prefix, offset, count, ());
}

// Create a batch of keys with balance.
fn create_keys_batch_with_balance(prefix, offset, count, balance) {
	print(`CreateKeys: prefix='${prefix}', range=(${offset}..${count}), balance=${balance}`);
	let names = gen_names(prefix, offset, count);
	return create_keys(names, balance);
}

// Create keys.
fn create_keys(names, balance) {
	// Generate keys.
	let keys = [];
	for name in names {
		let key = USER[name];
		keys += key;
	}
	// sudo user.
	let sudo_user = global::SUDO_USER;
	if balance != () && sudo_user != () {
		// Query balances.
		let cur_bals = get_balances(keys);

		print("CreateKeys: Batch 'set_balance' calls");
		let results = [];
		let calls = [];
		for (key, idx) in keys {
			let cur_bal = cur_bals[idx];
			if cur_bal < balance {
				calls += Sudo.sudo(Balances.set_balance(key, balance, 0));
			}
			if calls.len() > 200 {
				results += sudo_user.submit(Utility.batch_optimistic(calls));
				calls = [];
			}
		}

		// Final batch if there are still calls to make.
		if calls.len() > 0 {
			results += sudo_user.submit(Utility.batch_optimistic(calls));
		}
		print("CreateKeys: Wait for batch 'set_balance' results");
		wait_for_in_block(results);
	}
	return keys;
}

// Create a batch of users.
fn create_users_batch(prefix, offset, count, balance) {
	print(`CreateUsers: prefix='${prefix}', range=(${offset}..${count}), balance=${balance}`);
	let names = gen_names(prefix, offset, count);
	return create_users(names, balance);
}

// Create users.
fn create_users(names, balance) {
	let users = [];
	// cdd/sudo user.
	let cdd_user = global::SUDO_USER;
	let has_sudo = true;
	if cdd_user == () {
		has_sudo = false;
		cdd_user = global::CDD_PROVIDER;
	}

	// Generate users.
	for name in names {
		let user = USER[name];
		users += user;
	}

	// Query dids and balances.
	let dids = get_dids(users);
	let cur_bals = get_balances(users);

	let results = [];
	let calls = [];
	for (user, idx) in users {
		let did = dids[idx];
		let cur_bal = cur_bals[idx];
		if did == () {
			if global::SPEC_VERSION < 3000 {
				calls += Identity.mock_cdd_register_did(user);
			} else {
				calls += TestUtils.mock_cdd_register_did(user);
			}
		}
		//print(`user: ${user}, cur: ${cur_bal}, bal: ${balance}`);
		if has_sudo && cur_bal < (balance - 100.0) {
			calls += Sudo.sudo(Balances.set_balance(user, balance, 0));
		}
		if calls.len() > 200 {
			results += cdd_user.submit(Utility.batch_optimistic(calls));
			calls = [];
		}
	}

	// Final batch if there are still calls to make.
	if calls.len() > 0 {
		results += cdd_user.submit(Utility.batch_optimistic(calls));
	}
	print("CreateUsers: Wait for batch results");
	wait_for_in_block(results);
	return users;
}

// Create a batch of assets and issuers.
fn create_asset_batch(prefix, offset, count, supply) {
	print(`Create Assets: prefix='${prefix}', range=(${offset}..${count}), supply=${supply}`);
	let tickers = gen_names(prefix, offset, count);
	return create_assets(tickers, #{ EquityCommon: () }, supply);
}

// Create a batch of IU assets and issuers.
fn create_asset_batch_iu(prefix, offset, count, supply) {
	print(`Create IU Assets: prefix='${prefix}', range=(${offset}..${count}), supply=${supply}`);
	let tickers = gen_names(prefix, offset, count);
	return create_assets_full(tickers, #{ EquityCommon: () }, supply, false);
}

// Create a batch of stablecoins and issuers.
fn create_coin_batch(prefix, offset, count, supply) {
	print(`Create Stablecoins: prefix='${prefix}', range=(${offset}..${count}), supply=${supply}`);
	let tickers = gen_names(prefix, offset, count);
	return create_assets(tickers, #{ StableCoin: () }, supply);
}

fn tickers_to_issuers(tickers) {
	let ticker_to_issuer = |ticker| `Issuer_${ticker}`;
	return tickers.map(ticker_to_issuer);
}

fn call_asset_create_asset(name, ticker, divisible, asset_type, idents, funding, disable_iu) {
	if global::SPEC_VERSION < 5003000 {
		return Asset.create_asset(name, ticker, divisible, asset_type, idents, funding, disable_iu);
	} else if global::SPEC_VERSION < 6000000 {
		return Asset.create_asset(name, ticker, divisible, asset_type, idents, funding, true);
	} else {
		return Asset.create_asset(name, ticker, divisible, asset_type, idents, funding);
	}
}

fn call_asset_issue(ticker, supply, portfolio_kind) {
	if global::SPEC_VERSION < 6000000 {
		return Asset.issue(ticker, supply);
	} else {
		return Asset.issue(ticker, supply, portfolio_kind);
	}
}

// Create assets.
fn create_assets(tickers, asset_type, supply) {
	return create_assets_full(tickers, asset_type, supply, true);
}

// Create assets.
fn create_assets_full(tickers, asset_type, supply, disable_iu) {
	let issuers = create_users(tickers_to_issuers(tickers), 100000000.0);

	let stat_types = [
		#{ op: #{ Count: () }, claim_issuer: () },
	];
	let results = [];
	for (ticker, idx) in tickers {
		let issuer = issuers[idx];

		results += issuer.submit(Utility.batch_optimistic([
			call_asset_create_asset(`token ${ticker}`, ticker, true, asset_type, [], (), disable_iu),
			Statistics.set_active_asset_stats(#{ Ticker: ticker }, stat_types),
			call_asset_issue(ticker, supply, #{ Default: () }),
			Settlement.create_venue("", [], #{ Other: () }),
			ComplianceManager.pause_asset_compliance(ticker),
		]));
	}
	// Wait for all results.
	print("CreateAssets: Wait for batch results");
	wait_for_in_block(results);
	
	return [issuers, tickers];
}

// Prepare `Utiltity.relay_tx` call.
fn get_relay_tx_nonce(user) {
	let nonce = STORAGE.map("Utility", "Nonces", user.acc);
	if nonce == () {
		nonce = 0;
	}
	return nonce;
}

// Prepare `Utiltity.relay_tx` call.
fn make_relay_tx(user, c) {
	return make_relay_tx_with_nonce(user, -1, c, 0);
}

fn make_relay_tx_with_offset(user, c, offset) {
	return make_relay_tx_with_nonce(user, -1, c, offset);
}

fn make_relay_tx_with_nonce(user, nonce, c, offset) {
	let acc = user.acc;
	if nonce < 0 {
		if offset == () {
			offset = 0;
		}
		nonce = get_relay_tx_nonce(user) + offset;
	}
	let unique_call = #{
		nonce: nonce,
		"call": c,
	};
	let ty = Types.resolve("UniqueCall");
	let data = ty.encode(unique_call);
	let sig = user.sign(data);
	return Utility.relay_tx(acc, sig, unique_call);
}

fn validate_investor_uniqueness_claim(target, claim, proof) {
	let ty_did = Types.resolve("IdentityId");
	let target = ty_did.decode(ty_did.encode(target));
	print(`target = ${target}`);
	let ty_claim = Types.resolve("Claim");
	let claim = ty_claim.decode(ty_claim.encode(claim));
	print(`claim = ${claim}`);
	let ty_proof = Types.resolve("InvestorZKProofData");
	let proof = ty_proof.decode(ty_proof.encode(proof));
	print(`proof = ${proof}`);

	let is_valid = PolymeshUtils.validate_investor_uniqueness(target, claim, proof);
	print(`is_valid = ${is_valid}`);

	return is_valid;
}

fn add_investor_uniqueness_claim(user, ticker, uid) {
	if global::SPEC_VERSION >= 6000000 {
		// Not supported in v6.0.
		return [];
	}
	let did = get_did(user);
	if uid == () {
		uid = PolymeshUtils.did_to_uid(did);
	}
	// Create investor uniqueness claim & proof.
	let claim = PolymeshUtils.create_investor_uniqueness(did, ticker, uid);
	//print(`claim = ${claim}`);
	
	// Add Investor Uniqueness claim.
	return user.submit(Identity.add_investor_uniqueness_claim(did, claim[0], claim[1], ()));
}

// get a list of the user's venues.
fn get_user_venues(user) {
	let did = get_did(user);
	if global::SPEC_VERSION < 6000000 {
		return STORAGE.map("Settlement", "UserVenues", did);
	}
	let paged = STORAGE.double_paged("Settlement", "UserVenues", did);
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

// Get Venue signers.
fn get_venue_signers(venue_id) {
	let paged = STORAGE.double_paged("Settlement", "VenueSigners", venue_id);
	paged.set_page_count(500);
	let signers = [];
	do {
		let keys = paged.next_keys();
		if keys == () {
			break;
		}
		for key in keys {
			signers += key;
		}
	} while paged.has_more;
	return signers;
}

// Get signer's receipts used.
fn get_signer_receipts_used(user) {
	let paged = STORAGE.double_paged("Settlement", "ReceiptsUsed", user);
	paged.set_page_count(500);
	let receipts_used = [];
	do {
		let keys = paged.next_keys();
		if keys == () {
			break;
		}
		for key in keys {
			receipts_used += key;
		}
	} while paged.has_more;
	return receipts_used;
}

// Get signer's next receipt uid.
fn get_signers_next_receipt_uid(user) {
	let receipts = get_signer_receipts_used(user);
	let uid_max = 0;
	for uid in receipts {
		if uid > uid_max {
			uid_max = uid;
		}
	}
	return uid_max + 1;
}

fn create_venue(user, venue_type) {
	// Create venue.
	return user.submit(Settlement.create_venue("", [], venue_type));
}

fn get_or_create_venue(user, venue_type) {
	// Get or create venue.
	let venues = get_user_venues(user);
	let venue_id = ();
	if venues != () && venues.len() > 0 {
		venue_id = venues[0];
	} else {
		let res = create_venue(user, venue_type);
		for event in res.events("Settlement.VenueCreated") {
			venue_id = event.args[1];
		}
	}
	return venue_id;
}

fn fungible_leg(sender, receiver, ticker, amount) {
	if global::SPEC_VERSION < 6000000 {
		return #{
			from: sender,
			to: receiver,
			asset: ticker,
			amount: amount,
		};
	} else {
		return #{
			Fungible: #{
				sender: sender,
				receiver: receiver,
				ticker: ticker,
				amount: amount,
			}
		};
	}
}

fn call_settlement_add_and_affirm(venue_id, s_type, legs, portfolios, memo) {
	if global::SPEC_VERSION < 6000000 {
		return Settlement.add_and_affirm_instruction(venue_id, s_type, (), (), legs, portfolios);
	} else {
		return Settlement.add_and_affirm_instruction(venue_id, s_type, (), (), legs, portfolios, memo);
	}
}

fn call_settlement_add(venue_id, s_type, legs, portfolios, memo) {
	if global::SPEC_VERSION < 6000000 {
		return Settlement.add_instruction(venue_id, s_type, (), (), legs);
	} else {
		return Settlement.add_instruction(venue_id, s_type, (), (), legs, memo);
	}
}

fn setup_asset_fund_users(ticker, from, users, amount) {
	// Get or create venue.
	let venue_id = get_or_create_venue(from, #{ Other: () });

	let s_type = #{ SettleOnAffirmation: () };
	let is_manual = false;
	if global::SPEC_VERSION >= 5002000 {
		s_type = #{ SettleManual: 0 };
		is_manual = true;
	}
	// Create settlements.
	let settlements = [];
	let from_did = get_did(from);
	let from_portfolio = #{ did: from_did, kind: #{ Default: () } };
	let sides = [];

	let legs = [];
	for user in users {
		let did = get_did(user);
		let portfolio = #{ did: did, kind: #{ Default: () } };
		legs.push(fungible_leg(from_portfolio, portfolio, ticker, amount));
		sides.push(#{ user: user, portfolio: portfolio });

		if legs.len() == global::MAX_LEGS {
			let res = from.submit(call_settlement_add_and_affirm(venue_id, s_type, legs, [from_portfolio], ()));
			settlements.push(#{
				res: res,
				leg_count: legs.len(),
				venue_user: from,
				sides: sides,
				is_manual: is_manual,
			});
			sides = [];
			legs = [];
		}
	}
	if legs.len() > 0 {
		let res = from.submit(call_settlement_add_and_affirm(venue_id, s_type, legs, [from_portfolio], ()));
		settlements.push(#{
			res: res,
			leg_count: legs.len(),
			venue_user: from,
			sides: sides,
			is_manual: is_manual,
		});
	}

	return settlements;
}

fn asset_fund_users(ticker, from, users, amount) {
	let settlements = setup_asset_fund_users(ticker, from, users, amount);
	let results = affirm_settlements(settlements);
	wait_for_in_block(results);
	results += execute_settlements(settlements);
	return results;
}

fn create_settlement(exchange, venue_id, orders, sides) {
	let s_type = #{ SettleOnAffirmation: () };
	let is_manual = false;
	if global::SPEC_VERSION >= 5002000 {
		s_type = #{ SettleManual: 0 };
		is_manual = true;
	}
	// Create settlements.
	let legs = [];
	for order in orders {
		let sender = sides[order.sender];
		let receiver = sides[order.receiver];
		legs.push(fungible_leg(sender.portfolio, receiver.portfolio, order.ticker, order.amount));
	}
	let res = exchange.submit(call_settlement_add(venue_id, s_type, legs, ()));
	return #{
		res: res,
		leg_count: legs.len(),
		sides: sides,
		venue_user: exchange,
		is_manual: is_manual,
	};
}

fn create_buy_settlement(exchange, venue_id, buyer, seller, asset, coin, asset_amount, coin_amount) {
	return create_settlement(exchange, venue_id, [
		#{ sender: 0, receiver: 1, ticker: asset, amount: asset_amount },
		#{ sender: 1, receiver: 0, ticker: coin, amount: coin_amount },
	], [buyer, seller]);
}

fn get_settlement_id(settlement) {
	// Wait for settlement to be created and get the instruction_id.
	let instruction_id = ();
	for event in settlement.res.events("Settlement.InstructionCreated") {
		instruction_id = event.args[2];
	}
	if instruction_id == () {
		let reason = settlement.res.result;
		print(`Failed to create instruction: ${settlement}`);
		for (side, idx) in settlement.sides {
			print(`  - side[${idx}] = ${side.portfolio.did}`);
		}
	}
	return instruction_id;
}

fn affirm_settlement(settlement) {
	let results = [];

	// Wait for settlement to be created and get the instruction_id.
	let instruction_id = get_settlement_id(settlement);
	if instruction_id == () {
		return [];
	}

	// Each side affirms the settlement.
	let leg_count = settlement.leg_count;
	for side in settlement.sides {
		if global::SPEC_VERSION < 6000000 {
			results += side.user.submit(Settlement.affirm_instruction(instruction_id, [side.portfolio], leg_count));
		} else {
			results += side.user.submit(Settlement.affirm_instruction(instruction_id, [side.portfolio]));
		}
	}
	return results;
}

fn affirm_settlements(settlements) {
	let results = [];
	for settlement in settlements {
		results += affirm_settlement(settlement);
	}
	return results;
}

fn execute_settlement(settlement) {
	// Wait for settlement to be created and get the instruction_id.
	let instruction_id = get_settlement_id(settlement);
	if instruction_id == () {
		return [];
	}

	if global::SPEC_VERSION < 5002000 {
		// manual execution not supported.
		return [];
	}
	// Each side affirms the settlement.
	if global::SPEC_VERSION < 6000000 {
		return settlement.venue_user.submit(
			Settlement.execute_manual_instruction(instruction_id, settlement.leg_count, ())
		);
	} else {
		return settlement.venue_user.submit(
			Settlement.execute_manual_instruction(instruction_id, (), settlement.leg_count, 0, 0, ())
		);
	}
}

fn execute_settlements(settlements) {
	let results = [];
	for settlement in settlements {
		if settlement.is_manual {
			results += execute_settlement(settlement);
		}
	}
	return results;
}

fn sign_orderbook_order(user, order) {
	// Encode and sign order.
	let order_ty = Types.resolve("Order<AccountId>");
	let encoded_order = order_ty.encode(order);
	let sig = user.sign(encoded_order);

	return #{
		signature: sig,
		order: order,
	};
}
