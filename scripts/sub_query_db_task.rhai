// Channel to receive batches.
let channel = ARG.shift();

const DB = Postgres.connect("host=comp002 port=5433 user=postgres password=postgres");

fn build_upsert(db, schema, table, columns, on_conflict, has_created_at, has_updated_at, use_json) {
	let NL = "\n";
	let col_names = "";
	let values = "";
	let fields = "";
	let updates = "";
	let json_select = "SELECT ";
	for (col, idx) in columns {
		let val = `$${idx + 1}`;
		let name = col;
		let j_val = col;
		let j_type = "json";
		if type_of(col) == "array" {
			name = col[0];
			j_val = name;
			if use_json {
				j_type = col[1];
				if col.len() > 2 {
					col[2].replace("$$", j_val);
					j_val = col[2];
				}
			} else {
				col[1].replace("$$", val);
				val = col[1];
			}
		}
		let update = `  "${name}" = EXCLUDED."${name}"`;
		if idx == 0 {
			col_names += `"${name}"`;
			json_select += j_val;
			fields += `${name} ${j_type}`;
			values += val;
			updates += update;
		} else {
			col_names += `, "${name}"`;
			json_select += `, ${j_val}`;
			fields += `, ${name} ${j_type}`;
			values += `, ${val}`;
			updates += `,${NL}${update}`;
		}
		// insert a newline every 5 columns.
		if idx % 5 == 4 {
			col_names += NL;
			fields += NL;
			values += NL;
		}
	}
	if has_created_at {
		col_names += `, "created_at"`;
		values += `, current_timestamp`;
		json_select += `, current_timestamp`;
	}
	if has_updated_at {
		col_names += `, "updated_at"`;
		values += `, current_timestamp`;
		json_select += `, current_timestamp`;
		updates += `,${NL}  "updated_at" = EXCLUDED."updated_at"`;
	}
	let values = if use_json {
		`${json_select} FROM json_to_recordset($1) AS x(${fields})`;
	} else {
		`VALUES(${values})`
	};
	let sql = `
INSERT INTO "${schema}"."${table}"(${NL}${col_names}${NL})
${values}
   ON CONFLICT (${on_conflict})
   DO UPDATE SET${NL}${updates}`;
	//print(`sql: ${sql}`);
	return db.prepare(sql);
}

const STMT_BLOCK = build_upsert(DB, "sub_script", "blocks", [
	["id", "text"], ["block_id", "int"], ["parent_id", "int"],
	["hash", "text"], ["parent_hash", "text"], ["state_root", "text"], ["extrinsics_root", "text"],
  ["count_extrinsics", "int"],
	["count_extrinsics_unsigned", "int"], ["count_extrinsics_signed", "int"],
	["count_extrinsics_error", "int"], ["count_extrinsics_success", "int"],
  ["count_events", "int"],
	["spec_version_id", "int"],
	["datetime", "INT8", "to_timestamp($$::INT8 / 1000)" ]
], `"block_id"`, true, true, true);

const STMT_EXTRINSIC = build_upsert(DB, "sub_script", "extrinsics", [
	["id", "text"], ["block_id", "int"], ["extrinsic_idx", "int"], ["extrinsic_length", "int"],
	["signed", "int"], ["signedby_address", "int"], ["address", "text"],
	["module_id", "text"], ["call_id", "text"],
	"params_txt",
	["success", "int"], ["nonce", "int"],
	["extrinsic_hash", "text"],
	["spec_version_id", "int"],
], `"block_id", "extrinsic_idx"`, true, true, true);

const STMT_EVENT = build_upsert(DB, "sub_script", "events", [
	["id", "text"], ["block_id", "int"], ["event_idx", "int"], ["extrinsic_idx", "int"], ["spec_version_id", "int"],
	["module_id", "text"], ["event_id", "text"], "attributes_txt",
	"event_arg_0",
	"event_arg_1",
	"event_arg_2",
	"event_arg_3",
	"claim_type", "claim_scope", "claim_issuer", "claim_expiry",
	"corporate_action_ticker", "fundraiser_offering_asset", "transfer_to",
], `"block_id", "event_idx"`, true, true, true);

fn import_batch(blocks, extrinsics, events) {
	//print(`Import batch: blocks: ${blocks.len()} extrinsics: ${extrinsics.len()} events: ${events.len()}`);
	// Batch insert blocks into DB.
	let res = global::DB.execute(global::STMT_BLOCK, [blocks]);
	if res != blocks.len() {
		print(`Block import failed: res = ${res}`);
	}

	// Batch insert extrinsic into DB.
	let res = global::DB.execute(global::STMT_EXTRINSIC, [extrinsics]);
	if res != extrinsics.len() {
		print(`Extrinsic import failed: res = ${res}`);
	}

	// Batch insert events into DB.
	let res = global::DB.execute(global::STMT_EVENT, [events]);
	if res != events.len() {
		print(`Extrinsic import failed: res = ${res}`);
	}
}

let counter = 0;
let total_blocks = 0;
let total_extrinsics = 0;
let total_events = 0;
let blocks = [];
let extrinsics = [];
let events = [];
print("DB Task started.");
loop {
	let block = channel.recv();
	if block == () {
		break;
	}
	blocks += block.block;
	extrinsics += block.processed_extrinsics;
	events += block.processed_events;

	if extrinsics.len() > 20 || events.len() > 20 {
		total_blocks += blocks.len();
		total_extrinsics += extrinsics.len();
		total_events += events.len();
		import_batch(blocks, extrinsics, events);
		blocks = [];
		extrinsics = [];
		events = [];
	}
	counter += 1;
	if counter >= 1000 {
		counter = 0;
		print(`DbTask: Imported: blocks: ${total_blocks} extrinsics: ${total_extrinsics} events: ${total_events}`);
	}
}

if blocks.len() > 0 {
	import_batch(blocks, extrinsics, events);
}

print(`DbTask: Imported: blocks: ${total_blocks} extrinsics: ${total_extrinsics} events: ${total_events}`);
print(`DB Task closing`);
