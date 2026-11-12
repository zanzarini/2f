//! Throughput measurement on a real database file. Not run by default:
//!   cargo test --release -p twof-server --test bench -- --ignored --nocapture

use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use twof_core::keys::ServerKey;
use twof_core::ApproverKind;
use twof_server::{Config, Service};

const THREADS: usize = 8;

fn rate(label: &str, total: usize, started: Instant) {
    let secs = started.elapsed().as_secs_f64();
    println!(
        "{label:<46} {:>9.0} ops/s   {:>7.1} us/op",
        total as f64 / secs,
        secs * 1e6 / total as f64
    );
}

fn parallel(per_thread: usize, work: impl Fn(usize, usize) + Send + Sync + 'static) -> usize {
    let work = Arc::new(work);
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let work = work.clone();
            std::thread::spawn(move || (0..per_thread).for_each(|i| work(t, i)))
        })
        .collect();
    handles.into_iter().for_each(|h| h.join().unwrap());
    THREADS * per_thread
}

#[test]
#[ignore]
fn throughput() {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-bench-{}.db", std::process::id()));
    let svc = Arc::new(Service::open(&path, ServerKey::generate(), Config::default()).unwrap());
    let now = 1_800_000_000;
    let project = svc.create_project("bench", now).unwrap();
    svc.set_policy(
        &project,
        r#"{"version":1,"rules":[
            {"name":"auto","when":{"type":["auto"]},"then":{"decision":"allow"}},
            {"name":"ask","when":{},"then":{"decision":"require","requirements":[{"count":1}]}}]}"#,
        now,
    )
    .unwrap();
    let key = svc.create_api_key(&project, "bench", now).unwrap();
    let device = ServerKey::generate();
    svc.add_approver(&project, "alice", "Alice", now).unwrap();
    let cred = svc
        .add_credential(
            &project,
            "alice",
            ApproverKind::Ed25519,
            &device.public_hex(),
            now,
        )
        .unwrap();
    let pending = svc
        .create_challenge(
            &project,
            json!({ "type": "withdraw", "amount": "5" }),
            "pending",
            now,
        )
        .unwrap();

    println!("\n{THREADS} threads, database file on disk");
    let (s, k) = (svc.clone(), key.clone());
    let started = Instant::now();
    let n = parallel(20_000, move |_, _| {
        s.authenticate(&k).unwrap();
    });
    rate("authenticate (read)", n, started);

    let (s, p, id) = (svc.clone(), project.clone(), pending.id.clone());
    let started = Instant::now();
    let n = parallel(20_000, move |_, _| {
        s.get_challenge(&p, &id, now).unwrap();
    });
    rate("get pending challenge (read)", n, started);

    let (s, id) = (svc.clone(), pending.id.clone());
    let started = Instant::now();
    let n = parallel(5_000, move |_, _| {
        s.approver_view(&id, now).unwrap();
    });
    rate("approver view (read)", n, started);

    let (s, p) = (svc.clone(), project.clone());
    let started = Instant::now();
    let n = parallel(250, move |t, i| {
        let action =
            json!({ "type": "auto", "amount": "1", "asset": "USDT", "destination": "0xaaa" });
        s.create_challenge(&p, action, &format!("a-{t}-{i}"), now)
            .unwrap();
    });
    rate("create + allow + receipt (write, fsync)", n, started);

    let (s, p) = (svc.clone(), project.clone());
    let (device, cred) = (Arc::new(device), cred.clone());
    let started = Instant::now();
    let n = parallel(125, move |t, i| {
        let action = json!({ "type": "withdraw", "amount": "9", "destination": "0xnew" });
        let ch = s
            .create_challenge(&p, action, &format!("w-{t}-{i}"), now)
            .unwrap();
        let hash = s.approver_view(&ch.id, now).unwrap().binding.hash();
        let sig = twof_core::b64(&device.sign(&hash));
        s.submit_approval(&ch.id, &cred, &sig, false, now).unwrap();
    });
    rate("create + approve + receipt (2 writes)", n, started);

    assert!(svc.audit_verify().is_ok());
    drop(svc);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
