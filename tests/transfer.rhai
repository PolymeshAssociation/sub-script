// Try batching mock cdd registrations.

print("Batching: Mock CDD");

// Use Alice for mocking cdd.
let alice = USER.Alice;

// Test user
let user = USER.Bob;//Test123;

//alice.submit(TestUtils.mock_cdd_register_did(user));

let tx = Balances.transfer(user, 5.0);
print(`tx = ${tx}`);
let res = alice.submit(tx);
print(`call result = ${res}`);
print(`events = ${res.events}`);
