print("Test Confidential Assets");

import "scripts/mod/polymesh" as p;
import "./scripts/mod/confidential_assets" as ca;

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}

let results = [];

fn setup_user(name, polyx, asset_id) {
	let user = ca::create_user(name, polyx);
	user.asset_id = asset_id;
	return user;
}

fn get_confidential_balance() {
	let asset = ca::get_confidential_balance(this, this.asset_id);
	print(`${this}'s balance = ${asset.balance}`);
	return asset;
}

// Test Asset with issuer and mediator.
let ticker = `${prefix}T`;
let total_supply = 1_000.0;
let asset = ca::create_asset(ticker, total_supply);
let asset_id = asset.asset_id;
let issuer = asset.issuer;
issuer.asset_id = asset_id;
let mediator = asset.mediator;

// Test investor.
let investor = setup_user(`${prefix}_investor`, 100000.0, asset_id);

//
// Setup confidential accounts
//

results += ca::init_account(investor);

//
// Transaction state management.
//

fn create_tx_state(asset, investor) {
	return #{
		asset: asset,
		investor: investor,
		issuer: asset.issuer,
		mediator: asset.mediator,
	};
}

fn transfer_tokens(amount) {
	let settlement = ca::create_settlement(this.mediator, [
		#{ sender: 0, receiver: 1, asset: this.asset, amount: amount },
	], [this.issuer, this.investor]);
	let settlements = [settlement];

	let results = ca::affirm_settlements(settlements);
	// Wait for pending tx and show any errors.
	print("Wait for all affirmations before executing.");
	p::wait_for_in_block(results);

	let results = ca::execute_settlements(settlements);
	// Wait for pending tx and show any errors.
	print("Wait for execution");
	p::wait_for_in_block(results);

	let results = ca::apply_incoming_settlements(settlements);
	print("Wait for apply incoming");
	p::wait_for_in_block(results);

	this.issuer.get_confidential_balance();
	this.investor.get_confidential_balance();
}

let tx = create_tx_state(asset, investor);
tx.transfer_tokens(100.01);

tx.transfer_tokens(150.015);

tx.transfer_tokens(350.035);

print("Finished");
