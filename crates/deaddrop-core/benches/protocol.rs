//! Smoke benchmarks. Do not treat timings as published numbers.

use deaddrop_core::chunk::{chunk_payload, default_fixed};
use deaddrop_core::crypto::PrivateIdentity;
use deaddrop_core::protocol::{CreateDrop, build_drop};
use deaddrop_core::receipt::Receipt;
use deaddrop_core::{Destination, Ownership, Priority, ReceiptKind, RoutingPolicy};
use std::time::Instant;

fn main() {
    let sizes = [1024 * 1024usize];
    for n in sizes {
        let data = vec![7u8; n];
        let t = Instant::now();
        let c = chunk_payload(&data, default_fixed()).unwrap();
        eprintln!("chunk {n} bytes in {:?}", t.elapsed());
        assert_eq!(c.manifest.total_length, n as u64);
    }
    let alice = PrivateIdentity::generate();
    let bob = PrivateIdentity::generate();
    let t = Instant::now();
    let built = build_drop(CreateDrop {
        author: &alice,
        recipients: vec![(bob.peer_id, bob.public.clone())],
        destination: Destination::One { peer: bob.peer_id },
        plaintext: vec![1u8; 64 * 1024],
        now: 1_700_000_000,
        ttl_secs: Some(3600),
        priority: Priority::Normal,
        routing: RoutingPolicy::default(),
        application: "dd.bench".into(),
        topic: None,
        chunking: default_fixed(),
        compress: false,
        hop_limit: 8,
        public: false,
        seal_until: None,
        seal_quorum: None,
        erasure: None,
    })
    .unwrap();
    eprintln!("encrypt+sign 64KiB in {:?}", t.elapsed());
    let t = Instant::now();
    let r = Receipt::issue(ReceiptKind::Delivered, built.envelope.object_id, &alice, 1);
    r.verify(&alice.public.ed25519_pk).unwrap();
    eprintln!("receipt issue+verify in {:?}", t.elapsed());
    let _ = Ownership::Local;
}
