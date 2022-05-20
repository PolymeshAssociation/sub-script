#!/bin/bash
#
URL="ws://127.0.0.1:9944"
RUN="./target/release/run -u $URL"

$RUN ./scripts/setup_dev_chain.rhai PK1

#$RUN ./scripts/create_users_with_secondary_keys.rhai PK1 100 4
#$RUN ./scripts/create_asset_with_compliance.rhai ACME 100 1000000
#$RUN ./scripts/create_asset_with_transfer_managers.rhai ACME 100 1000000

