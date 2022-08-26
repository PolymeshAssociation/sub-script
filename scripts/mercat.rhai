import "scripts/mod/polymesh" as p;

print("Test MERCAT");

let results = [];

// Test users.
let alice = USER.Alice;
let bob = USER.Bob;
let charlie = USER.Charlie;

// Make sure Bob and Charlie have identities and POLYX.
p::mock_user(bob, 100000000.0);
p::mock_user(charlie, 100000000.0);

// Get DIDs of users.
let alice_did = p::get_did(alice);
let bob_did = p::get_did(bob);
let charlie_did = p::get_did(charlie);
print(`alice did = ${alice_did}`);
print(`bob did = ${bob_did}`);
print(`charlie did = ${charlie_did}`);

//
// Create ConfidentialAssets.
//

results += alice.submit(ConfidentialAsset.create_confidential_asset(
	`Token 1`, "0x31", true, #{ EquityCommon: () }, [], ()
));
results += alice.submit(ConfidentialAsset.create_confidential_asset(
	`Token 2`, "0x32", true, #{ EquityCommon: () }, [], ()
));

//
// Setup MERCAT accounts
//

let alice_acc_tx = MercatUtils.create_account("alice", "31", ["31", "32"]);
let alice_acc = alice_acc_tx.account;
let alice_id = alice_acc.account_id;
let alice_pub_key = alice_acc.pub_key;
let alice_portfolio = #{ did: alice_did, kind: #{ Default: () } };
print(`alice account = ${alice_id.base64}`);
print(`alice pub_key = ${alice_pub_key.base64}`);
//print(`alice tx = ${alice_acc_tx.base64}`);
results += alice.submit(ConfidentialAsset.validate_mercat_account(alice_acc_tx.base64));

let bob_acc_tx = MercatUtils.create_account("bob", "31", ["31", "32"]);
let bob_acc = bob_acc_tx.account;
let bob_id = bob_acc.account_id;
let bob_pub_key = bob_acc.pub_key;
let bob_portfolio = #{ did: bob_did, kind: #{ Default: () } };
print(`bob account = ${bob_id.base64}`);
print(`bob pub_key = ${bob_pub_key.base64}`);
//print(`bob tx = ${bob_acc_tx.base64}`);
results += bob.submit(ConfidentialAsset.validate_mercat_account(bob_acc_tx.base64));

//
// Setup Mediator
//

let charlie_portfolio = #{ did: charlie_did, kind: #{ Default: () } };
let mediator = MercatUtils.create_mediator("charlie");
print(`charlie mediator = ${mediator.base64}`);
results += charlie.submit(ConfidentialAsset.add_mediator_mercat_account(mediator.base64));

let alice_balance = 1000;
let mint_tx = MercatUtils.mint_asset("alice", "31", alice_balance);
//print(`mint_tx = ${mint_tx.base64}`);
results += alice.submit(ConfidentialAsset.mint_confidential_asset(
	"0x31",
	alice_balance / 1000000.0, // sub-script will scale `Balance` types (i.e. add 6 decimal places).
	mint_tx.base64,
));

//
// Setup venue and settlement instruction.
//
let venue_id = p::get_or_create_venue(charlie, #{ Other: () });

let res = charlie.submit(Settlement.add_instruction(
	venue_id, #{ SettleOnAffirmation: () }, (), (),
	[#{
		from: alice_portfolio,
		to: bob_portfolio,
		kind: #{
			Confidential: #{
				mediator: charlie_portfolio,
				from_account_id: alice_id.base64,
				to_account_id: bob_id.base64,
			}
		}
	}]
));
let instruction_id = ();
print("get instruction_id from events.");
for event in res.events("Settlement.InstructionCreated") {
	instruction_id = event.args[2];
	print(`Event: instruction_id = ${instruction_id}`);
}
print(`instruction_id = ${instruction_id}`);

// Wait for previous transactions.
p::wait_for_in_block(results);
results = [];

// Get Alice's balance from the chain.
let alice_enc_balance_base64 = STORAGE.double_map(
  "ConfidentialAsset", "MercatAccountBalance",
	alice_did, alice_id.base64,
);

let init_tx = MercatUtils.create_tx(
		"alice",
		[bob_id.base64, bob_pub_key.base64],
		mediator.base64,
		"31", 100,
		alice_enc_balance_base64
	);
//print(`init_tx = ${init_tx.base64}`);
print("Alice affirms with init_tx");
results += alice.submit(Settlement.affirm_confidential_instruction(
	instruction_id,
  #{ InitializedTransfer: init_tx.base64 },
	[
		alice_portfolio
	],
	1
));

let finalize_tx = MercatUtils.finalize_tx("bob", "31", 100, init_tx.base64);
//print(`finalize_tx = ${finalize_tx.base64}`);
print("Bob affirms with finalize_tx");
results += bob.submit(Settlement.affirm_confidential_instruction(
	instruction_id,
  #{ FinalizedTransfer: finalize_tx.base64 },
	[
		bob_portfolio
	],
	1
));

// Wait for pending tx and show any errors.
print("Wait for all transactions before sending justify_tx.");
p::wait_for_in_block(results);
results = [];

let justify_tx = MercatUtils.justify_tx(
		[alice_id.base64, alice_pub_key.base64],
		alice_enc_balance_base64,
		[bob_id.base64, bob_pub_key.base64],
		"charlie",
		"31",
		finalize_tx.base64);
//print(`justify_tx = ${justify_tx.base64}`);
print("Charlie affirms with justify_tx");
results += charlie.submit(Settlement.affirm_confidential_instruction(
	instruction_id,
  #{ JustifiedTransfer: justify_tx.base64 },
	[
		charlie_portfolio
	],
	1
));

// Wait for pending tx and show any errors.
print("Wait for all transactions");
p::wait_for_in_block(results);
