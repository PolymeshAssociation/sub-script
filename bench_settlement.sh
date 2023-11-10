#!/bin/sh
#
URL=ws://localhost:9944

time -p ./target/release/run -u $URL ./scripts/bench_settlement_01_setup.rhai $*
time -p ./target/release/run -u $URL ./scripts/bench_settlement_02_fund.rhai $*
time -p ./target/release/run -u $URL ./scripts/bench_settlement_03_orders.rhai $*
