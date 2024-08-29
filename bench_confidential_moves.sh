#!/bin/sh
#
URL=ws://localhost:9844
#URL=ws://comp002:9844

time -p ./target/release/run -u $URL ./scripts/bench_confidential_moves_01_setup.rhai $*
time -p ./target/release/run -u $URL ./scripts/bench_confidential_moves_02_fund.rhai $*
sleep 12
time -p ./target/release/run -u $URL ./scripts/bench_confidential_moves_03_run.rhai $*
