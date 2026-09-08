# Core snapshot proofs

This crate verifies the mining-transaction format (`DASHNC02`) specified in
[DIP PR 175](https://github.com/dashpay/dips/pull/175). It uses the SDK's existing
`blst` and X11 implementations; it needs no proving service, trusted setup or GPU.

The application supplies a trusted network, height, block hash and the two
coinbase-committed state roots. A relay supplies:

1. An opening of an initial ChainLock quorum commitment in the snapshot root.
2. Increasing ChainLock certificates. Each intermediate certificate authenticates
   the next quorum's complete mining transaction through a positional Merkle path.
   When mining precedes certification, explicitly linked 80-byte ancestor headers
   connect the mining block to the certified block.
3. A final certificate, complete coinbase and transaction Merkle path, establishing
   the new masternode and quorum roots.
4. Openings of the requested Platform quorum and optional EvoNode records under
   those final roots.

`bootstrap::verify(bytes, &trusted_snapshot, minimum_height)` returns records and
state only after verifying the entire envelope. The caller must additionally
check that the opened quorum matches the requested type/hash and decode the
masternode serialization before using endpoints. The shared SDK context provider
performs those checks and publishes its cache atomically.

The transport cap is 1 MiB of decoded data. The verifier also bounds certificates,
ancestor headers, transaction sizes and Merkle paths before allocation. It rejects
noncanonical commitments, invalid BLS points, malformed transactions, ambiguous
Merkle duplication and 64-byte leaves that could represent internal Merkle nodes.

This authenticates state under the assumption that historical ChainLock quorum
keys remain honest. It does not replay DKG, independently establish exact signer
eligibility or perform full Core consensus validation. A valid historical proof
does not establish that a relay disclosed the newest global tip; applications
must also apply their independent freshness policy.

Tests include real Core testnet evidence with ancestor gaps, independent mainnet
snapshot evidence, malformed inputs, tampering, subgroup rejection and execution
in Node's WebAssembly runtime. Run `cargo test -p dash-core-proof`; WASM tests use
`wasm-bindgen-test-runner` with target `wasm32-unknown-unknown` and a WASM-capable C
compiler for the shared X11 dependency.
