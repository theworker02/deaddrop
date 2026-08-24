#![no_main]

use deaddrop_core::protocol::{decode_cbor, Message};
use deaddrop_core::DropEnvelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_cbor::<Message>(data);
    let _ = decode_cbor::<DropEnvelope>(data);
});
