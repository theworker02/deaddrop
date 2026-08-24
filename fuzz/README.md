# Fuzzing

Protocol parsers MUST NOT panic on attacker-controlled input. Unit tests cover empty/malformed CBOR (`dd-protocol` codec tests).

`cargo fuzz` targets for handshake, envelope, manifest, inventory, receipt, capabilities, and extensions are PLANNED. CI runs a decode-smoke as part of `cargo test`, not libFuzzer.
