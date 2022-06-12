
let id = ARG.shift();
let block_id = parse_int(ARG.shift());
let hash = ARG.shift();

let db = Postgres.connect("host=comp002 port=5433 user=postgres password=postgres");
print(`db = ${db}`);

let stmt = db.prepare(`
insert into sub_script.blocks(id, block_id, parent_id, hash, parent_hash, state_root, extrinsics_root,
  count_extrinsics, count_extrinsics_unsigned, count_extrinsics_signed, count_extrinsics_error, count_extrinsics_success,
  count_events, spec_version_id, datetime, created_at, updated_at)
  VALUES($1, $2, $3, $4, $5, $6, $7,
	$8, $9, $10, $11, $12,
  $13, $14, current_timestamp, current_timestamp, current_timestamp)
ON CONFLICT (id) DO UPDATE SET
  id = EXCLUDED.id,
  block_id = EXCLUDED.block_id,
  parent_id = EXCLUDED.parent_id,
  hash = EXCLUDED.hash,
  parent_hash = EXCLUDED.parent_hash,
  state_root = EXCLUDED.state_root,
  extrinsics_root = EXCLUDED.extrinsics_root,
  count_extrinsics = EXCLUDED.count_extrinsics,
  count_extrinsics_unsigned = EXCLUDED.count_extrinsics_unsigned,
  count_extrinsics_signed = EXCLUDED.count_extrinsics_signed,
  count_extrinsics_error = EXCLUDED.count_extrinsics_error,
  count_extrinsics_success = EXCLUDED.count_extrinsics_success,
  count_events = EXCLUDED.count_events,
  spec_version_id = EXCLUDED.spec_version_id,
  datetime = EXCLUDED.datetime,
  updated_at = EXCLUDED.updated_at
`);

let res = db.execute(stmt, [
	id, block_id, block_id, hash, hash, hash, hash,
	0, 0, 0, 0, 0,
	0, 0,
]);
print(`res = ${res}`);
