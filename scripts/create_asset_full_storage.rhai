import "./scripts/mod/polymesh" as p;

print("Create assets.");

// Get arguments.
let prefix = ARG.shift();
if prefix == () {
	print("Need ticker prefix");
	return;
}
let count = ARG.shift();
count = if count == () { 10 } else { parse_int(count) };
let supply = 100000000000.0;

let sudo = p::get_sudo_user();

let res = p::create_coin_batch(`${prefix}C`, 0, 1, supply);
let coin_issuer = res[0][0];
let coin_ticker = res[1][0];

let res = p::create_asset_batch(prefix, 0, count, 10.0);
let issuers = res[0];
let tickers = res[1];

let docs = [
  #{
    name: "Test doc",
    uri: "http://example.com/",
    content_hash: #{ None: () },
    doc_type: "Test type",
    filing_date: 42,
  },
];

let results = [];
for (ticker, idx) in tickers {
	let issuer = issuers[idx];
  let did = p::get_did(issuer);
  let portfolio = p::get_or_create_portfolio(issuer, "Test");
  let port_num = portfolio.kind.User;
  let venue_id = p::get_or_create_venue(issuer, #{ Sto: () });
	results += issuer.submit(Utility.force_batch([
    Asset.unfreeze(ticker),
    ComplianceManager.add_default_trusted_claim_issuer(ticker, #{ issuer: did, trusted_for: #{ Any: () }}),
    Asset.add_documents(docs, ticker),
	  Asset.add_mandatory_mediators(ticker, [did]),
	  Asset.pre_approve_ticker(ticker),
    Asset.register_custom_asset_type(`${ticker} Type`),
    Asset.update_asset_type(ticker, #{ Custom: 1 }),
	  Asset.register_asset_metadata_local_type(ticker, "LocalMD", #{
      url: "http://example.com",
      description: "test",
      type_def: "",
    }),
    Asset.set_asset_metadata(ticker, #{ Local: 1 }, "Value", #{
      expire: (),
      lock_status: #{ Locked: () },
    }),
    Asset.set_asset_metadata(ticker, #{ Global: 1 }, "Value", #{
      expire: (),
      lock_status: #{ Locked: () },
    }),
    Asset.update_identifiers(ticker, [
      #{ CUSIP: "023135106" },
    ]),
    ExternalAgents.create_group(ticker, #{
      These: [],
    }),
    Checkpoint.create_checkpoint(ticker),
    Checkpoint.create_schedule(ticker, #{
      pending: [2729176522000],
    }),
    Asset.set_funding_round(ticker, "Funding name"),
    Asset.issue(ticker, supply, portfolio.kind),
    CorporateAction.set_default_targets(ticker, #{
      identities: [did],
      treatment: #{ Exclude: () },
    }),
    CorporateAction.set_default_withholding_tax(ticker, 420000.0),
    CorporateAction.set_did_withholding_tax(ticker, did, 430000.0),
    CorporateAction.initiate_corporate_action(
      ticker,
      #{ PredictableBenefit: () },
      0,
      #{ Existing: 1 },
      "Details",
      #{
        identities: [did],
        treatment: #{ Exclude: () },
      },
      200000.0, // default Tax.
      [ // tax per did.
        [did, 120000.0],
      ],
    ),
    CorporateAction.link_ca_doc(#{ ticker: ticker, local_id: 0 }, [0]),
    CorporateAction.initiate_corporate_action_and_distribute(
      #{
        ticker: ticker,
        kind: #{ PredictableBenefit: () },
        decl_date: 0,
        record_date: #{ Existing: 1 },
        details: "Details",
        targets: #{
          identities: [did],
          treatment: #{ Exclude: () },
        },
        default_withholding_tax: 100000.0, // default Tax.
        withholding_tax: [ // tax per did.
          [did, 120000.0],
        ],
      },
      port_num,
      ticker,
      1,
      100,
      2829176522000, // payment at
      (),
    ),
    Settlement.allow_venues(ticker, [venue_id]),
    Settlement.set_venue_filtering(ticker, true),
    Sto.create_fundraiser(
      portfolio, ticker,
      portfolio, coin_ticker,
      [
        #{ total: 100.0, price: 1 },
      ],
      venue_id,
      (), (),
      1,
      "Fundraising",
    ),
    Asset.freeze(ticker),
  ]));
	results += sudo.submit(Sudo.sudo(Asset.exempt_ticker_affirmation(ticker)));
}

p::wait_for_in_block(results);

