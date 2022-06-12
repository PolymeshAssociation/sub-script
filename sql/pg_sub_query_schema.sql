-- DROP SCHEMA public;

--CREATE SCHEMA public AUTHORIZATION postgres;

-- DROP SEQUENCE sub_script.subqueries_id_seq;

CREATE SEQUENCE sub_script.subqueries_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 2147483647
	START 1
	CACHE 1
	NO CYCLE;-- sub_script."_metadata" definition

-- Drop table

-- DROP TABLE sub_script."_metadata";

CREATE TABLE sub_script."_metadata" (
	"key" varchar(255) NOT NULL,
	value jsonb NULL,
	"createdAt" timestamptz NOT NULL,
	"updatedAt" timestamptz NOT NULL,
	CONSTRAINT "_metadata_pkey" PRIMARY KEY (key)
);


-- sub_script.agent_groups definition

-- Drop table

-- DROP TABLE sub_script.agent_groups;

CREATE TABLE sub_script.agent_groups (
	id text NOT NULL,
	permissions text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT agent_groups_pkey PRIMARY KEY (id)
);


-- sub_script.asset_pending_ownership_transfers definition

-- Drop table

-- DROP TABLE sub_script.asset_pending_ownership_transfers;

CREATE TABLE sub_script.asset_pending_ownership_transfers (
	id text NOT NULL,
	ticker text NOT NULL,
	"from" text NOT NULL,
	"to" text NOT NULL,
	"type" text NOT NULL,
	"data" text NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT asset_pending_ownership_transfers_pkey PRIMARY KEY (id)
);
CREATE INDEX asset_pending_ownership_transfers_from ON sub_script.asset_pending_ownership_transfers USING btree ("from");
CREATE INDEX asset_pending_ownership_transfers_ticker ON sub_script.asset_pending_ownership_transfers USING btree (ticker);
CREATE INDEX asset_pending_ownership_transfers_to ON sub_script.asset_pending_ownership_transfers USING btree ("to");
CREATE INDEX asset_pending_ownership_transfers_type ON sub_script.asset_pending_ownership_transfers USING btree (type);


-- sub_script.assets definition

-- Drop table

-- DROP TABLE sub_script.assets;

CREATE TABLE sub_script.assets (
	id text NOT NULL,
	ticker text NOT NULL,
	"name" text NULL,
	"type" text NULL,
	funding_round text NULL,
	is_divisible bool NOT NULL,
	is_frozen bool NOT NULL,
	is_uniqueness_required bool NOT NULL,
	documents jsonb NOT NULL,
	identifiers jsonb NOT NULL,
	owner_did text NOT NULL,
	total_supply text NOT NULL,
	total_transfers text NOT NULL,
	compliance jsonb NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT assets_pkey PRIMARY KEY (id)
);
CREATE INDEX assets_compliance ON sub_script.assets USING gin (compliance);
CREATE INDEX assets_documents ON sub_script.assets USING gin (documents);
CREATE INDEX assets_funding_round ON sub_script.assets USING btree (funding_round);
CREATE INDEX assets_identifiers ON sub_script.assets USING gin (identifiers);
CREATE INDEX assets_name ON sub_script.assets USING btree (name);
CREATE UNIQUE INDEX assets_ticker ON sub_script.assets USING btree (ticker);
CREATE INDEX assets_type ON sub_script.assets USING btree (type);


-- sub_script.authorizations definition

-- Drop table

-- DROP TABLE sub_script.authorizations;

CREATE TABLE sub_script.authorizations (
	id text NOT NULL,
	created_block int4 NOT NULL,
	auth_id int4 NOT NULL,
	"type" text NOT NULL,
	from_did text NOT NULL,
	to_did text NULL,
	to_key text NULL,
	"data" text NULL,
	expiry timestamp NULL,
	status text NOT NULL,
	updated_block int4 NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT authorizations_pkey PRIMARY KEY (id)
);
CREATE INDEX authorizations_auth_id ON sub_script.authorizations USING btree (auth_id);
CREATE INDEX authorizations_expiry ON sub_script.authorizations USING btree (expiry);
CREATE INDEX authorizations_from_did ON sub_script.authorizations USING btree (from_did);
CREATE INDEX authorizations_to_did ON sub_script.authorizations USING btree (to_did);
CREATE INDEX authorizations_to_key ON sub_script.authorizations USING btree (to_key);
CREATE INDEX authorizations_type ON sub_script.authorizations USING btree (type);


-- sub_script.blocks definition

-- Drop table

-- DROP TABLE sub_script.blocks;

CREATE TABLE sub_script.blocks (
	id text NOT NULL,
	block_id int4 NOT NULL,
	parent_id int4 NOT NULL,
	hash text NOT NULL,
	parent_hash text NOT NULL,
	state_root text NOT NULL,
	extrinsics_root text NOT NULL,
	count_extrinsics int4 NOT NULL,
	count_extrinsics_unsigned int4 NOT NULL,
	count_extrinsics_signed int4 NOT NULL,
	count_extrinsics_error int4 NOT NULL,
	count_extrinsics_success int4 NOT NULL,
	count_events int4 NOT NULL,
	datetime timestamp NOT NULL,
	spec_version_id int4 NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT blocks_pkey PRIMARY KEY (id)
);
CREATE INDEX blocks_block_id ON sub_script.blocks USING btree (block_id);
CREATE INDEX data_block_datetime_timestamp ON sub_script.blocks USING btree (((datetime)::timestamp(0) without time zone));
CREATE UNIQUE INDEX data_block_hash ON sub_script.blocks USING btree (hash);
CREATE UNIQUE INDEX data_block_id ON sub_script.blocks USING btree (block_id);
CREATE INDEX data_block_parent_hash ON sub_script.blocks USING btree (parent_hash);


-- sub_script.claim_scopes definition

-- Drop table

-- DROP TABLE sub_script.claim_scopes;

CREATE TABLE sub_script.claim_scopes (
	id text NOT NULL,
	target_did text NOT NULL,
	ticker text NULL,
	"scope" jsonb NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT claim_scopes_pkey PRIMARY KEY (id)
);
CREATE INDEX claim_scopes_scope ON sub_script.claim_scopes USING gin (scope);
CREATE INDEX claim_scopes_target_did ON sub_script.claim_scopes USING btree (target_did);


-- sub_script.claims definition

-- Drop table

-- DROP TABLE sub_script.claims;

CREATE TABLE sub_script.claims (
	id text NOT NULL,
	target_did text NOT NULL,
	issuer text NOT NULL,
	issuance_date numeric NOT NULL,
	last_update_date numeric NOT NULL,
	expiry numeric NULL,
	filter_expiry numeric NOT NULL,
	"type" text NOT NULL,
	jurisdiction text NULL,
	"scope" jsonb NULL,
	cdd_id text NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT claims_pkey PRIMARY KEY (id)
);
CREATE INDEX claims_filter_expiry ON sub_script.claims USING btree (filter_expiry);
CREATE INDEX claims_issuer ON sub_script.claims USING btree (issuer);
CREATE INDEX claims_scope ON sub_script.claims USING gin (scope);
CREATE INDEX claims_target_did ON sub_script.claims USING btree (target_did);
CREATE INDEX claims_type ON sub_script.claims USING btree (type);


-- sub_script.debugs definition

-- Drop table

-- DROP TABLE sub_script.debugs;

CREATE TABLE sub_script.debugs (
	id text NOT NULL,
	line text NULL,
	context text NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT debugs_pkey PRIMARY KEY (id)
);


-- sub_script.events definition

-- Drop table

-- DROP TABLE sub_script.events;

CREATE TABLE sub_script.events (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	extrinsic_idx int4 NULL,
	spec_version_id int4 NOT NULL,
	module_id text NOT NULL,
	event_id text NOT NULL,
	attributes_txt text NOT NULL,
	event_arg_0 text NULL,
	event_arg_1 text NULL,
	event_arg_2 text NULL,
	event_arg_3 text NULL,
	claim_type text NULL,
	claim_scope text NULL,
	claim_issuer text NULL,
	claim_expiry text NULL,
	corporate_action_ticker text NULL,
	fundraiser_offering_asset text NULL,
	transfer_to text NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	"attributes" jsonb NULL GENERATED ALWAYS AS (attributes_txt::jsonb) STORED,
	CONSTRAINT events_pkey PRIMARY KEY (id)
);
CREATE INDEX data_event_block_id ON sub_script.events USING btree (block_id);
CREATE INDEX data_event_claim_issuer ON sub_script.events USING btree (claim_issuer);
CREATE INDEX data_event_claim_scope ON sub_script.events USING btree (claim_scope);
CREATE INDEX data_event_claim_type ON sub_script.events USING btree (claim_type);
CREATE INDEX data_event_corporate_action_ticker ON sub_script.events USING btree (corporate_action_ticker);
CREATE INDEX data_event_event_arg_0 ON sub_script.events USING btree ("left"(event_arg_0, 100));
CREATE INDEX data_event_event_arg_1 ON sub_script.events USING btree ("left"(event_arg_1, 100));
CREATE INDEX data_event_event_arg_2 ON sub_script.events USING btree ("left"(event_arg_2, 100));
CREATE INDEX data_event_event_arg_3 ON sub_script.events USING btree ("left"(event_arg_3, 100));
CREATE INDEX data_event_event_id ON sub_script.events USING btree (event_id);
CREATE INDEX data_event_event_idx ON sub_script.events USING btree (event_idx);
CREATE INDEX data_event_extrinsic_idx ON sub_script.events USING btree (extrinsic_idx);
CREATE INDEX data_event_fundraiser_offering_asset ON sub_script.events USING btree (fundraiser_offering_asset);
CREATE UNIQUE INDEX data_event_id ON sub_script.events USING btree (block_id, event_idx);
CREATE INDEX data_event_module_id ON sub_script.events USING btree (module_id);
CREATE INDEX data_event_module_id_event_id ON sub_script.events USING btree (module_id, event_id);
CREATE INDEX data_event_module_id_event_id_event_arg_2 ON sub_script.events USING btree (module_id, event_id, "left"(event_arg_2, 100));
CREATE INDEX data_event_spec_version_id ON sub_script.events USING btree (spec_version_id);
CREATE INDEX data_event_transfer_from ON sub_script.events USING btree (btrim((attributes #>> '{2,value,did}'::text[]), '"'::text));
CREATE INDEX events_block_id ON sub_script.events USING btree (block_id);
CREATE INDEX events_event_id ON sub_script.events USING btree (event_id);
CREATE INDEX events_module_id ON sub_script.events USING btree (module_id);


-- sub_script.extrinsics definition

-- Drop table

-- DROP TABLE sub_script.extrinsics;

CREATE TABLE sub_script.extrinsics (
	id text NOT NULL,
	block_id int4 NOT NULL,
	extrinsic_idx int4 NOT NULL,
	extrinsic_length int4 NOT NULL,
	signed int4 NOT NULL,
	signedby_address int4 NOT NULL,
	address text NULL,
	module_id text NOT NULL,
	call_id text NOT NULL,
	params_txt text NOT NULL,
	success int4 NOT NULL,
	nonce int4 NULL,
	extrinsic_hash text NULL,
	spec_version_id int4 NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	params jsonb NULL GENERATED ALWAYS AS (params_txt::jsonb) STORED,
	CONSTRAINT extrinsics_pkey PRIMARY KEY (id)
);
CREATE INDEX data_extrinsic_address ON sub_script.extrinsics USING btree (address);
CREATE INDEX data_extrinsic_block_id ON sub_script.extrinsics USING btree (block_id);
CREATE INDEX data_extrinsic_call_id ON sub_script.extrinsics USING btree (call_id);
CREATE INDEX data_extrinsic_extrinsic_idx ON sub_script.extrinsics USING btree (extrinsic_idx);
CREATE UNIQUE INDEX data_extrinsic_id ON sub_script.extrinsics USING btree (block_id, extrinsic_idx);
CREATE INDEX data_extrinsic_module_id ON sub_script.extrinsics USING btree (module_id);
CREATE INDEX data_extrinsic_signed ON sub_script.extrinsics USING btree (signed);
CREATE INDEX extrinsics_block_id ON sub_script.extrinsics USING btree (block_id);
CREATE INDEX extrinsics_call_id ON sub_script.extrinsics USING btree (call_id);
CREATE INDEX extrinsics_extrinsic_hash ON sub_script.extrinsics USING btree (extrinsic_hash);
CREATE INDEX extrinsics_module_id ON sub_script.extrinsics USING btree (module_id);


-- sub_script.found_types definition

-- Drop table

-- DROP TABLE sub_script.found_types;

CREATE TABLE sub_script.found_types (
	id text NOT NULL,
	raw_type text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT found_types_pkey PRIMARY KEY (id)
);


-- sub_script.fundings definition

-- Drop table

-- DROP TABLE sub_script.fundings;

CREATE TABLE sub_script.fundings (
	id text NOT NULL,
	block_id int4 NOT NULL,
	ticker text NOT NULL,
	funding_name text NOT NULL,
	value text NOT NULL,
	total_issued_in_funding_round text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT fundings_pkey PRIMARY KEY (id)
);
CREATE INDEX fundings_funding_name ON sub_script.fundings USING btree (funding_name);
CREATE INDEX fundings_ticker ON sub_script.fundings USING btree (ticker);


-- sub_script.held_tokens definition

-- Drop table

-- DROP TABLE sub_script.held_tokens;

CREATE TABLE sub_script.held_tokens (
	id text NOT NULL,
	did text NOT NULL,
	"token" text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT held_tokens_pkey PRIMARY KEY (id)
);
CREATE INDEX held_tokens_did ON sub_script.held_tokens USING btree (did);


-- sub_script.history_of_payment_events_for_cas definition

-- Drop table

-- DROP TABLE sub_script.history_of_payment_events_for_cas;

CREATE TABLE sub_script.history_of_payment_events_for_cas (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_id text NOT NULL,
	event_idx int4 NOT NULL,
	event_did text NOT NULL,
	ticker text NOT NULL,
	local_id int4 NOT NULL,
	balance numeric NOT NULL,
	tax numeric NOT NULL,
	datetime timestamp NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT history_of_payment_events_for_cas_pkey PRIMARY KEY (id)
);
CREATE INDEX history_of_payment_events_for_cas_local_id ON sub_script.history_of_payment_events_for_cas USING btree (local_id);
CREATE INDEX history_of_payment_events_for_cas_ticker ON sub_script.history_of_payment_events_for_cas USING btree (ticker);


-- sub_script.identity_with_claims definition

-- Drop table

-- DROP TABLE sub_script.identity_with_claims;

CREATE TABLE sub_script.identity_with_claims (
	id text NOT NULL,
	did text NOT NULL,
	claims jsonb NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT identity_with_claims_pkey PRIMARY KEY (id)
);
CREATE INDEX identity_with_claims_claims ON sub_script.identity_with_claims USING gin (claims);
CREATE INDEX identity_with_claims_did ON sub_script.identity_with_claims USING btree (did);


-- sub_script.instructions definition

-- Drop table

-- DROP TABLE sub_script.instructions;

CREATE TABLE sub_script.instructions (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_id text NOT NULL,
	status text NOT NULL,
	venue_id text NOT NULL,
	settlement_type text NOT NULL,
	legs jsonb NOT NULL,
	addresses jsonb NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT instructions_pkey PRIMARY KEY (id)
);
CREATE INDEX instructions_legs ON sub_script.instructions USING gin (legs);
CREATE INDEX instructions_venue_id ON sub_script.instructions USING btree (venue_id);


-- sub_script.investments definition

-- Drop table

-- DROP TABLE sub_script.investments;

CREATE TABLE sub_script.investments (
	id text NOT NULL,
	block_id int4 NOT NULL,
	investor text NOT NULL,
	sto_id int4 NOT NULL,
	offering_token text NOT NULL,
	raise_token text NOT NULL,
	offering_token_amount numeric NOT NULL,
	raise_token_amount numeric NOT NULL,
	datetime timestamp NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT investments_pkey PRIMARY KEY (id)
);
CREATE INDEX investments_offering_token ON sub_script.investments USING btree (offering_token);
CREATE INDEX investments_sto_id ON sub_script.investments USING btree (sto_id);


-- sub_script.issuer_identity_with_claims definition

-- Drop table

-- DROP TABLE sub_script.issuer_identity_with_claims;

CREATE TABLE sub_script.issuer_identity_with_claims (
	id text NOT NULL,
	did text NOT NULL,
	claims jsonb NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT issuer_identity_with_claims_pkey PRIMARY KEY (id)
);
CREATE INDEX issuer_identity_with_claims_claims ON sub_script.issuer_identity_with_claims USING gin (claims);
CREATE INDEX issuer_identity_with_claims_did ON sub_script.issuer_identity_with_claims USING btree (did);


-- sub_script.proposals definition

-- Drop table

-- DROP TABLE sub_script.proposals;

CREATE TABLE sub_script.proposals (
	id text NOT NULL,
	block_id int4 NOT NULL,
	proposer text NOT NULL,
	state text NOT NULL,
	identity_id text NOT NULL,
	balance numeric NOT NULL,
	url text NULL,
	description text NULL,
	last_state_updated_at int4 NOT NULL,
	snapshotted bool NOT NULL,
	total_aye_weight numeric NOT NULL,
	total_nay_weight numeric NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT proposals_pkey PRIMARY KEY (id)
);
CREATE INDEX proposals_proposer ON sub_script.proposals USING btree (proposer);
CREATE INDEX proposals_state ON sub_script.proposals USING btree (state);


-- sub_script.settlements definition

-- Drop table

-- DROP TABLE sub_script.settlements;

CREATE TABLE sub_script.settlements (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_id text NOT NULL,
	addresses jsonb NOT NULL,
	"result" text NOT NULL,
	legs jsonb NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT settlements_pkey PRIMARY KEY (id)
);
CREATE INDEX settlements_addresses ON sub_script.settlements USING btree (addresses);
CREATE INDEX settlements_legs ON sub_script.settlements USING gin (legs);


-- sub_script.staking_events definition

-- Drop table

-- DROP TABLE sub_script.staking_events;

CREATE TABLE sub_script.staking_events (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	staking_event_id text NOT NULL,
	"date" timestamp NOT NULL,
	identity_id text NULL,
	stash_account text NULL,
	amount numeric NULL,
	nominated_validators jsonb NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT staking_events_pkey PRIMARY KEY (id)
);
CREATE INDEX staking_events_block_id ON sub_script.staking_events USING btree (block_id);
CREATE INDEX staking_events_date ON sub_script.staking_events USING btree (date);
CREATE INDEX staking_events_event_idx ON sub_script.staking_events USING btree (event_idx);
CREATE INDEX staking_events_staking_event_id ON sub_script.staking_events USING btree (staking_event_id);


-- sub_script.stos definition

-- Drop table

-- DROP TABLE sub_script.stos;

CREATE TABLE sub_script.stos (
	id text NOT NULL,
	offering_asset text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT stos_pkey PRIMARY KEY (id)
);


-- sub_script.subqueries definition

-- Drop table

-- DROP TABLE sub_script.subqueries;

CREATE TABLE sub_script.subqueries (
	id serial NOT NULL,
	"name" varchar(255) NOT NULL,
	db_schema varchar(255) NOT NULL,
	"version" int4 NOT NULL DEFAULT 0,
	hash varchar(255) NOT NULL,
	next_block_height int4 NOT NULL DEFAULT 1,
	network varchar(255) NULL,
	network_genesis varchar(255) NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT subqueries_name_key UNIQUE (name),
	CONSTRAINT subqueries_pkey PRIMARY KEY (id)
);


-- sub_script.ticker_external_agent_actions definition

-- Drop table

-- DROP TABLE sub_script.ticker_external_agent_actions;

CREATE TABLE sub_script.ticker_external_agent_actions (
	id text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	ticker text NOT NULL,
	pallet_name text NOT NULL,
	event_id text NOT NULL,
	caller_did text NOT NULL,
	datetime timestamp NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT ticker_external_agent_actions_pkey PRIMARY KEY (id)
);
CREATE INDEX ticker_external_agent_actions_block_id ON sub_script.ticker_external_agent_actions USING btree (block_id);
CREATE INDEX ticker_external_agent_actions_caller_did ON sub_script.ticker_external_agent_actions USING btree (caller_did);
CREATE INDEX ticker_external_agent_actions_event_id ON sub_script.ticker_external_agent_actions USING btree (event_id);
CREATE INDEX ticker_external_agent_actions_event_idx ON sub_script.ticker_external_agent_actions USING btree (event_idx);
CREATE INDEX ticker_external_agent_actions_pallet_name ON sub_script.ticker_external_agent_actions USING btree (pallet_name);
CREATE INDEX ticker_external_agent_actions_ticker ON sub_script.ticker_external_agent_actions USING btree (ticker);


-- sub_script.ticker_external_agent_addeds definition

-- Drop table

-- DROP TABLE sub_script.ticker_external_agent_addeds;

CREATE TABLE sub_script.ticker_external_agent_addeds (
	id text NOT NULL,
	ticker text NOT NULL,
	caller_did text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	datetime timestamp NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT ticker_external_agent_addeds_pkey PRIMARY KEY (id)
);
CREATE INDEX ticker_external_agent_addeds_caller_did ON sub_script.ticker_external_agent_addeds USING btree (caller_did);
CREATE INDEX ticker_external_agent_addeds_ticker ON sub_script.ticker_external_agent_addeds USING btree (ticker);


-- sub_script.ticker_external_agent_histories definition

-- Drop table

-- DROP TABLE sub_script.ticker_external_agent_histories;

CREATE TABLE sub_script.ticker_external_agent_histories (
	id text NOT NULL,
	ticker text NOT NULL,
	did text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	datetime timestamp NOT NULL,
	"type" text NOT NULL,
	permissions text NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT ticker_external_agent_histories_pkey PRIMARY KEY (id)
);
CREATE INDEX ticker_external_agent_histories_did ON sub_script.ticker_external_agent_histories USING btree (did);
CREATE INDEX ticker_external_agent_histories_ticker ON sub_script.ticker_external_agent_histories USING btree (ticker);


-- sub_script.withholding_taxes_of_cas definition

-- Drop table

-- DROP TABLE sub_script.withholding_taxes_of_cas;

CREATE TABLE sub_script.withholding_taxes_of_cas (
	id text NOT NULL,
	ticker text NOT NULL,
	local_id int4 NOT NULL,
	datetime timestamp NOT NULL,
	taxes numeric NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT withholding_taxes_of_cas_pkey PRIMARY KEY (id)
);
CREATE INDEX withholding_taxes_of_cas_local_id ON sub_script.withholding_taxes_of_cas USING btree (local_id);
CREATE INDEX withholding_taxes_of_cas_ticker ON sub_script.withholding_taxes_of_cas USING btree (ticker);


-- sub_script.agent_group_memberships definition

-- Drop table

-- DROP TABLE sub_script.agent_group_memberships;

CREATE TABLE sub_script.agent_group_memberships (
	id text NOT NULL,
	"member" text NOT NULL,
	group_id text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT agent_group_memberships_pkey PRIMARY KEY (id),
	CONSTRAINT agent_group_memberships_group_id_fkey FOREIGN KEY (group_id) REFERENCES sub_script.agent_groups(id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX agent_group_memberships_group_id ON sub_script.agent_group_memberships USING hash (group_id);
CREATE INDEX agent_group_memberships_member ON sub_script.agent_group_memberships USING btree (member);


-- sub_script.asset_holders definition

-- Drop table

-- DROP TABLE sub_script.asset_holders;

CREATE TABLE sub_script.asset_holders (
	id text NOT NULL,
	did text NOT NULL,
	ticker text NOT NULL,
	amount text NOT NULL,
	asset_id text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT asset_holders_pkey PRIMARY KEY (id),
	CONSTRAINT asset_holders_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES sub_script.assets(id) ON UPDATE CASCADE
);
CREATE INDEX asset_holders_asset_id ON sub_script.asset_holders USING hash (asset_id);
CREATE INDEX asset_holders_did ON sub_script.asset_holders USING btree (did);
CREATE INDEX asset_holders_ticker ON sub_script.asset_holders USING btree (ticker);


-- sub_script.proposal_votes definition

-- Drop table

-- DROP TABLE sub_script.proposal_votes;

CREATE TABLE sub_script.proposal_votes (
	id text NOT NULL,
	proposal_id text NOT NULL,
	block_id int4 NOT NULL,
	event_idx int4 NOT NULL,
	account text NOT NULL,
	vote bool NOT NULL,
	weight numeric NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	CONSTRAINT proposal_votes_pkey PRIMARY KEY (id),
	CONSTRAINT proposal_votes_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES sub_script.proposals(id) ON UPDATE CASCADE
);
CREATE INDEX proposal_votes_proposal_id ON sub_script.proposal_votes USING hash (proposal_id);



