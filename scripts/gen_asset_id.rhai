let user = USER.Alice;

let gen_asset_ty = Types.resolve("GenerateAssetId");

let nonce = STORAGE.map("Asset", "AssetNonce", user);
if nonce == () {
	nonce = 0;
}
print(`user AssetNonce=${nonce}`);

let hash = CLIENT.get_block_hash(0);

let gen_asset_id = #{
	prefix: "modlpy/pallet_asset",
	genesis_hash: hash,
	account: user,
	nonce: nonce,
};
let encoded_asset = gen_asset_ty.encode(gen_asset_id);
let value = Utils.blake2_128(encoded_asset);

//let hex = Utils.to_hex(value);
//print(`raw hash = ${value}, hex=${hex}`);

// Convert to UUID.
// Set Version 8 (0x8).
value[6] = (value[6] & 0x0f) | 0x80;
// Standard RFC4122 variant (bits 10xx)
value[8] = (value[8] & 0x3f) | 0x80;

let hex = Utils.to_hex(value);
print(`raw hash = ${value}, hex=${hex}`);
