// Test POLYX transfer.

// Use Alice for mocking cdd.
let alice = USER.Alice;

// Test user
let user = USER.Test123;

let res = alice.submit(Balances.transfer(user, 5.0));
print(`call result = ${res}`);
print(`events = ${res.events}`);
