print("Test simple transaction with Ledger app");

let user = USER.Test123;

// Polymesh ledger app
//let app = LedgerApps.get_app("Polymesh: tcp:127.0.0.1:9999");
let app = LedgerApps.get_app("Polymesh: HID");
print(`ledger app: ${app}`);

let enc = ComplianceManager.add_compliance_requirement(
	"TICKER-12345",
	[#{
		condition_type: #{
			IsIdentity: #{ ExternalAgent: () },
		},
		issuers: [],
	}],
	[]
);
print(`encoded call = ${enc}`);
let res = app.submit(enc);
print(`call result = ${res}`);
//print(`events = ${res.events}`);
