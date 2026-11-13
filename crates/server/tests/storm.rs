//! Many threads hammering one server at once, on a real database file.
//!
//! The random model checks the rules one operation at a time. This checks
//! that they still hold when everything happens together: asking, approving,
//! refusing, reading and using receipts from many threads, with readers
//! racing the writer.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use twof_core::keys::ServerKey;
use twof_core::receipt::{self, ReceiptDecision};
use twof_core::{Action, ApproverKind};
use twof_server::{Config, Error, Service};

const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "auto", "when": { "type": ["auto"], "asset": ["USDT"], "amount_max": "10",
                                "velocity": { "window_secs": 100000, "max_total": "300" } },
      "then": { "decision": "allow" } },
    { "name": "two", "when": { "type": ["two"] }, "then": { "decision": "require", "requirements": [ { "count": 2 } ] } },
    { "name": "one", "when": { "type": ["one"] }, "then": { "decision": "require", "requirements": [ { "count": 1 } ] } } ] }"#;

const T0: u64 = 1_800_000_000;
const THREADS: usize = 12;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[derive(Default)]
struct Shared {
    /// challenge id -> (kind, action)
    challenges: Mutex<Vec<(String, &'static str, Value)>>,
    /// challenge id -> approvers whose approval the server accepted
    accepted: Mutex<BTreeMap<String, BTreeSet<usize>>>,
    /// challenge ids someone validly refused
    refused: Mutex<BTreeSet<String>>,
    /// receipt token -> how many times using it succeeded
    used: Mutex<BTreeMap<String, usize>>,
    operations: AtomicUsize,
}

fn storm(seed: u64, steps: usize) -> usize {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-storm-{}-{seed}.db", std::process::id()));
    let cleanup = |path: &std::path::Path| {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    };
    cleanup(&path);
    let config = Config {
        max_pending: 100_000,
        ..Config::default()
    };
    let svc = Arc::new(Service::open(&path, ServerKey::generate(), config).unwrap());
    let project = svc.create_project("storm", T0).unwrap();
    svc.set_policy(&project, POLICY, T0).unwrap();
    let mut approvers = Vec::new();
    for name in ["p0", "p1", "p2"] {
        let key = ServerKey::generate();
        svc.add_approver(&project, name, name, T0).unwrap();
        let credential = svc
            .add_credential(&project, name, ApproverKind::Ed25519, &key.public_hex(), T0)
            .unwrap();
        approvers.push((key.seed_hex(), credential));
    }
    let approvers = Arc::new(approvers);
    let shared = Arc::new(Shared::default());

    let handles: Vec<_> = (0..THREADS)
        .map(|thread| {
            let (svc, project, approvers, shared) =
                (svc.clone(), project.clone(), approvers.clone(), shared.clone());
            std::thread::spawn(move || {
                let mut rng = Rng((seed ^ (thread as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1);
                let keys: Vec<ServerKey> =
                    approvers.iter().map(|(seed, _)| ServerKey::from_seed_hex(seed).unwrap()).collect();
                // No operation may fail for a reason the caller did not cause.
                let sound = |what: &str, error: &Error| match error {
                    Error::Internal(detail) => panic!("seed {seed}: {what} hit an internal error: {detail}"),
                    Error::Conflict(m) if m.contains("integrity") => {
                        panic!("seed {seed}: {what} raised a false tampering alarm")
                    }
                    _ => {}
                };
                for step in 0..steps {
                    shared.operations.fetch_add(1, Ordering::Relaxed);
                    let pick = |rng: &mut Rng| {
                        let list = shared.challenges.lock().unwrap();
                        (!list.is_empty()).then(|| list[rng.below(list.len())].clone())
                    };
                    match rng.below(100) {
                        0..=24 => {
                            let kind = ["auto", "one", "two", "two"][rng.below(4)];
                            let action = json!({ "type": kind, "amount": "10", "asset": "USDT",
                                                 "destination": format!("0x{:02x}", rng.below(4)) });
                            match svc.create_challenge(&project, action.clone(), &format!("t{thread}-{step}"), T0) {
                                Ok(view) => shared.challenges.lock().unwrap().push((view.id, kind, action)),
                                Err(e) => sound("create", &e),
                            }
                        }
                        25..=59 => {
                            let Some((id, _, action)) = pick(&mut rng) else { continue };
                            let who = rng.below(3);
                            let reject = rng.below(12) == 0;
                            let hash = Action::from_value(action).unwrap().hash_hex().unwrap();
                            let binding = twof_core::Binding::new(&project, &id, &hash, T0 + 300);
                            let message = if reject { binding.reject_hash() } else { binding.hash() };
                            let signature = twof_core::b64(&keys[who].sign(&message));
                            match svc.submit_approval(&id, &approvers[who].1, &signature, reject, T0) {
                                Ok(_) if reject => {
                                    shared.refused.lock().unwrap().insert(id);
                                }
                                Ok(_) => {
                                    shared.accepted.lock().unwrap().entry(id).or_default().insert(who);
                                }
                                Err(e) => sound("approve", &e),
                            }
                        }
                        60..=84 => {
                            let Some((id, _, _)) = pick(&mut rng) else { continue };
                            match svc.get_challenge(&project, &id, T0) {
                                Ok(view) => {
                                    if let Some(token) = view.receipt {
                                        shared.used.lock().unwrap().entry(token).or_insert(0);
                                    }
                                }
                                Err(e) => sound("read", &e),
                            }
                            if let Err(e) = svc.approver_view(&id, T0) {
                                sound("approver read", &e);
                            }
                        }
                        _ => {
                            let token = {
                                let used = shared.used.lock().unwrap();
                                (!used.is_empty()).then(|| used.keys().nth(rng.below(used.len())).cloned())
                            };
                            let Some(Some(token)) = token else { continue };
                            match svc.consume_receipt(&project, &token, T0) {
                                Ok(_) => *shared.used.lock().unwrap().get_mut(&token).unwrap() += 1,
                                Err(e) => sound("use", &e),
                            }
                        }
                    }
                }
            })
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .unwrap_or_else(|_| panic!("seed {seed}: a thread failed"));
    }

    // ---- when the dust settles, everything must add up
    let server_key = svc.key();
    let lookup = |kid: &str| (kid == server_key.kid()).then(|| server_key.public());
    let challenges = shared.challenges.lock().unwrap().clone();
    let accepted = shared.accepted.lock().unwrap().clone();
    let refused = shared.refused.lock().unwrap().clone();
    let mut allowed_total = 0;
    for (id, kind, action) in &challenges {
        let view = svc
            .get_challenge(&project, id, T0)
            .unwrap_or_else(|e| panic!("seed {seed}: {id}: {e:?}"));
        let signers = accepted.get(id).map_or(0, BTreeSet::len);
        let needed = match *kind {
            "two" => 2,
            "one" => 1,
            _ => 0,
        };
        match view.state.as_str() {
            "allowed" => {
                assert_eq!(*kind, "auto", "seed {seed}: {id} allowed without a rule");
                allowed_total += 10;
            }
            "approved" => {
                assert!(
                    needed > 0 && signers >= needed,
                    "seed {seed}: {id} approved with {signers} of {needed}"
                );
                assert!(
                    !refused.contains(id),
                    "seed {seed}: {id} approved after a refusal was accepted"
                );
            }
            "rejected" => assert!(refused.contains(id), "seed {seed}: {id} rejected by nobody"),
            "pending" => {
                assert!(
                    needed > 0 && signers < needed,
                    "seed {seed}: {id} left waiting with {signers} of {needed}"
                );
                assert!(
                    !refused.contains(id),
                    "seed {seed}: {id} waiting after a refusal"
                );
            }
            "denied" => assert_eq!(*kind, "auto", "seed {seed}: {id} denied"),
            other => panic!("seed {seed}: {id} is {other}"),
        }
        match (&view.receipt, view.state.as_str()) {
            (Some(token), "allowed" | "approved") => {
                let payload = receipt::verify(
                    token,
                    &lookup,
                    &Action::from_value(action.clone()).unwrap(),
                    T0,
                )
                .unwrap_or_else(|e| panic!("seed {seed}: {id}: receipt {e:?}"));
                let approved = payload.decision == ReceiptDecision::Approved;
                assert_eq!(approved, view.state == "approved", "seed {seed}: {id}");
                let named: BTreeSet<&str> = payload
                    .approvals
                    .iter()
                    .map(|a| a.approver.as_str())
                    .collect();
                assert!(
                    named.len() >= needed,
                    "seed {seed}: {id}: receipt names {named:?}"
                );
            }
            (None, "allowed" | "approved") => {
                panic!("seed {seed}: {id} is {} without a receipt", view.state)
            }
            (Some(_), other) => panic!("seed {seed}: {id} is {other} and has a receipt"),
            _ => {}
        }
    }
    assert!(
        allowed_total <= 300,
        "seed {seed}: {allowed_total} allowed under a cap of 300"
    );
    for (token, count) in shared.used.lock().unwrap().iter() {
        assert!(
            *count <= 1,
            "seed {seed}: a receipt was used {count} times: {token:.20}"
        );
    }
    assert!(
        svc.audit_verify().is_ok(),
        "seed {seed}: audit log after the storm"
    );
    let operations = shared.operations.load(Ordering::Relaxed);
    drop(svc);
    cleanup(&path);
    operations
}

#[test]
fn a_storm_of_threads_leaves_everything_consistent() {
    let mut operations = 0;
    for seed in 1..=4 {
        operations += storm(seed * 7907, 250);
    }
    assert!(operations >= 4 * THREADS * 250);
}

#[test]
#[ignore]
fn storm_long_run() {
    let read = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let (base, rounds) = (
        read("TWOF_SOAK_SEED").unwrap_or(17),
        read("TWOF_SOAK_ROUNDS").unwrap_or(40),
    );
    let mut operations = 0;
    for round in 1..=rounds {
        operations += storm(base.wrapping_add(round.wrapping_mul(982_451_653)), 400);
    }
    println!("storm operations {operations} threads {THREADS}");
}
