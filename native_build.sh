#!/bin/sh

RUSTFLAGS="-C target_cpu=native" \
  cargo build --release --no-default-features \
		--features std,simd_backend,rayon,discrete_log,pg,ledger,polymesh,v12,v13,v14,utils,confidential_assets
