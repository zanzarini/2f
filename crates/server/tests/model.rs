//! Thousands of random operations against the service, checked step by step
//! against a small independent model of what should happen.
//!
//! The model does not share code with the server: who may approve is spelled
//! out by hand here, and quorums are decided by trying every assignment. If
//! the two ever disagree, one of them is wrong.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use twof_core::keys::ServerKey;
use twof_core::{receipt, Action, ApproverKind};
use twof_server::{Config, Error, Service};

const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "auto", "when": { "type": ["auto"], "asset": ["USDT"], "amount_max": "50",
                                "velocity": { "window_secs": 1000, "max_total": "200" } },
      "then": { "decision": "allow" } },
    { "name": "two", "when": { "type": ["two"] },
      "then": { "decision": "require", "requirements": [ { "count": 2 } ] } },
    { "name": "mix", "when": { "type": ["mix"] },
      "then": { "decision": "require", "requirements": [
          { "count": 1, "kinds": ["ed25519"] }, { "count": 1, "kinds": ["cosigner"] } ] } },
    { "name": "named", "when": { "type": ["named"] },
      "then": { "decision": "require", "requirements": [
          { "count": 1, "approvers": ["p0", "p1"] }, { "count": 1 } ] } },
    { "name": "one", "when": { "type": ["one"] },
      "then": { "decision": "require", "requirements": [ { "count": 1 } ] } },
    { "name": "blocked", "when": { "type": ["blocked"] }, "then": { "decision": "deny" } } ] }"#;

const TTL: u64 = 300;
const MAX_PENDING: usize = 6;
const WINDOW: u64 = 1000;

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
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

struct Credential {
    id: String,
    key: ServerKey,
    approver: &'static str,
    cosigner: bool,
    live: bool,
}

struct Tracked {
    id: String,
    kind: &'static str,
    action: Value,
    state: &'static str,
    expires_at: u64,
    decided_at: u64,
    /// Credentials (by index) whose approval was accepted.
    approved: BTreeSet<usize>,
    receipt: Option<String>,
    amount: u64,
}

/// One slot per approver a rule asks for: can this approver fill it?
type Slot = fn(&Credential) -> bool;

fn slots(kind: &str) -> Vec<Slot> {
    let person: Slot = |c| !c.cosigner;
    match kind {
        "two" => vec![person, person],
        "mix" => vec![|c| !c.cosigner, |c| c.cosigner],
        "named" => vec![
            |c| !c.cosigner && (c.approver == "p0" || c.approver == "p1"),
            person,
        ],
        "one" => vec![person],
        _ => vec![],
    }
}

/// Tries every way of seating distinct approvers in the slots.
fn quorum(kind: &str, approved: &BTreeSet<usize>, credentials: &[Credential]) -> bool {
    fn seat(slots: &[Slot], people: &[(&str, Vec<&Credential>)], used: &mut Vec<bool>) -> bool {
        let Some((slot, rest)) = slots.split_first() else {
            return true;
        };
        for (index, (_, held)) in people.iter().enumerate() {
            if !used[index] && held.iter().any(|c| slot(c)) {
                used[index] = true;
                if seat(rest, people, used) {
                    return true;
                }
                used[index] = false;
            }
        }
        false
    }
    let mut by_person: BTreeMap<&str, Vec<&Credential>> = BTreeMap::new();
    for index in approved {
        let credential = &credentials[*index];
        if credential.live {
            by_person
                .entry(credential.approver)
                .or_default()
                .push(credential);
        }
    }
    let people: Vec<(&str, Vec<&Credential>)> = by_person.into_iter().collect();
    let wanted = slots(kind);
    !wanted.is_empty() && seat(&wanted, &people, &mut vec![false; people.len()])
}

/// How often each outcome happened, so a run that never reached a path
/// cannot pass for a run that checked it.
#[derive(Default)]
struct Seen {
    allowed: usize,
    approved: usize,
    rejected: usize,
    expired: usize,
    refused: usize,
    flood: usize,
    consumed: usize,
    reused: usize,
}

fn run(seed: u64, steps: usize, seen: &mut Seen) {
    let config = Config {
        challenge_ttl: TTL,
        max_pending: MAX_PENDING as u32,
        ..Config::default()
    };
    let svc = Service::open_in_memory(ServerKey::generate(), config).unwrap();
    let mut now = 1_800_000_000u64;
    let project = svc.create_project("model", now).unwrap();
    svc.set_policy(&project, POLICY, now).unwrap();

    let mut credentials: Vec<Credential> = Vec::new();
    // p3 holds two devices; "vault" is a machine.
    for (approver, cosigner) in [
        ("p0", false),
        ("p1", false),
        ("p2", false),
        ("p3", false),
        ("p3", false),
        ("vault", true),
    ] {
        if !credentials.iter().any(|c| c.approver == approver) {
            svc.add_approver(&project, approver, approver, now).unwrap();
        }
        let key = ServerKey::generate();
        let kind = if cosigner {
            ApproverKind::Cosigner
        } else {
            ApproverKind::Ed25519
        };
        let id = svc
            .add_credential(&project, approver, kind, &key.public_hex(), now)
            .unwrap();
        credentials.push(Credential {
            id,
            key,
            approver,
            cosigner,
            live: true,
        });
    }

    let mut rng = Rng(seed | 1);
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut consumed: BTreeSet<String> = BTreeSet::new();
    let server_key = svc.key();
    let lookup = |kid: &str| (kid == server_key.kid()).then(|| server_key.public());

    for step in 0..steps {
        let context = format!("seed {seed} step {step}");
        // Expiry is a fact of time: settle the model before each operation.
        for t in tracked.iter_mut() {
            if t.state == "pending" && now > t.expires_at {
                t.state = "expired";
                seen.expired += 1;
            }
        }
        match rng.below(100) {
            // ---- ask for something
            0..=34 => {
                let kind = *rng.pick(&[
                    "auto", "auto", "two", "mix", "named", "one", "blocked", "unknown",
                ]);
                let amount = 1 + rng.below(70) as u64;
                let action = json!({ "type": kind, "amount": amount.to_string(), "asset": "USDT",
                                     "destination": format!("0x{:04x}", rng.below(4)) });
                let waiting = tracked.iter().filter(|t| t.state == "pending").count();
                let spent: u64 = tracked
                    .iter()
                    .filter(|t| {
                        matches!(t.state, "allowed" | "approved") && t.decided_at + WINDOW >= now
                    })
                    .map(|t| t.amount)
                    .sum();
                let expected = match kind {
                    "auto" if amount <= 50 && spent + amount <= 200 => "allowed",
                    "two" | "mix" | "named" | "one" => "pending",
                    _ => "denied",
                };
                let result =
                    svc.create_challenge(&project, action.clone(), &format!("k{step}"), now);
                if expected == "pending" && waiting >= MAX_PENDING {
                    assert!(
                        matches!(result, Err(Error::RateLimited)),
                        "{context}: flood not held back"
                    );
                    seen.flood += 1;
                    continue;
                }
                let view = result.unwrap_or_else(|e| panic!("{context}: create failed: {e:?}"));
                assert_eq!(
                    view.state, expected,
                    "{context}: {kind} {amount} with {spent} spent"
                );
                assert_eq!(view.receipt.is_some(), expected == "allowed", "{context}");
                seen.allowed += usize::from(expected == "allowed");
                tracked.push(Tracked {
                    id: view.id,
                    kind,
                    action,
                    state: expected,
                    expires_at: now + TTL,
                    decided_at: now,
                    approved: BTreeSet::new(),
                    receipt: view.receipt,
                    amount,
                });
            }
            // ---- approve or refuse
            35..=74 if !tracked.is_empty() => {
                let index = rng.below(tracked.len());
                let who = rng.below(credentials.len());
                let reject = rng.below(8) == 0;
                let forged = rng.below(10) == 0;
                let t = &mut tracked[index];
                let credential = &credentials[who];
                let binding = twof_core::Binding::new(
                    &project,
                    &t.id,
                    &Action::from_value(t.action.clone())
                        .unwrap()
                        .hash_hex()
                        .unwrap(),
                    t.expires_at,
                );
                let hash = if reject {
                    binding.reject_hash()
                } else {
                    binding.hash()
                };
                let signer = if forged {
                    ServerKey::generate()
                } else {
                    ServerKey::from_seed_hex(&credential.key.seed_hex()).unwrap()
                };
                let signature = twof_core::b64(&signer.sign(&hash));
                let result = svc.submit_approval(&t.id, &credential.id, &signature, reject, now);

                let eligible = credential.live && slots(t.kind).iter().any(|slot| slot(credential));
                if t.state != "pending" {
                    assert!(
                        matches!(result, Err(Error::Conflict(_))),
                        "{context}: acted on a {} challenge",
                        t.state
                    );
                } else if forged || !eligible {
                    assert!(
                        matches!(result, Err(Error::Forbidden(_))),
                        "{context}: accepted forged={forged} eligible={eligible}"
                    );
                    seen.refused += 1;
                } else if reject {
                    assert_eq!(result.unwrap().state, "rejected", "{context}");
                    t.state = "rejected";
                    seen.rejected += 1;
                } else {
                    let view =
                        result.unwrap_or_else(|e| panic!("{context}: approval refused: {e:?}"));
                    t.approved.insert(who);
                    let done = quorum(t.kind, &t.approved, &credentials);
                    assert_eq!(
                        view.state,
                        if done { "approved" } else { "pending" },
                        "{context}: {} with {:?}",
                        t.kind,
                        t.approved
                    );
                    assert_eq!(view.receipt.is_some(), done, "{context}");
                    if done {
                        t.state = "approved";
                        seen.approved += 1;
                        t.decided_at = now;
                        t.receipt = view.receipt;
                    }
                }
            }
            // ---- use a receipt
            75..=84 if !tracked.is_empty() => {
                let t = &tracked[rng.below(tracked.len())];
                let Some(token) = &t.receipt else { continue };
                let action = Action::from_value(t.action.clone()).unwrap();
                let fresh = now <= t.decided_at + svc.config.receipt_ttl;
                let checked = receipt::verify(token, &lookup, &action, now);
                assert_eq!(checked.is_ok(), fresh, "{context}: receipt validity");
                let mut other = t.action.clone();
                other["destination"] = json!("0xdead");
                assert!(
                    receipt::verify(token, &lookup, &Action::from_value(other).unwrap(), now)
                        .is_err(),
                    "{context}: receipt covers another action"
                );
                let result = svc.consume_receipt(&project, token, now);
                if !fresh {
                    assert!(result.is_err(), "{context}: consumed an expired receipt");
                } else if consumed.insert(t.id.clone()) {
                    assert!(result.is_ok(), "{context}: first use refused: {result:?}");
                    seen.consumed += 1;
                } else {
                    assert!(
                        matches!(result, Err(Error::Conflict(_))),
                        "{context}: receipt used twice"
                    );
                    seen.reused += 1;
                }
            }
            // ---- look, and repeat a request
            85..=91 if !tracked.is_empty() => {
                let t = &tracked[rng.below(tracked.len())];
                let view = svc.get_challenge(&project, &t.id, now).unwrap();
                assert_eq!(
                    view.state, t.state,
                    "{context}: state of a {} challenge",
                    t.kind
                );
                assert_eq!(view.receipt, t.receipt, "{context}");
                let live: BTreeSet<&str> = t
                    .approved
                    .iter()
                    .filter(|i| credentials[**i].live)
                    .map(|i| credentials[*i].approver)
                    .collect();
                let shown: BTreeSet<&str> =
                    view.approvals.iter().map(|a| a.approver.as_str()).collect();
                assert_eq!(shown, live, "{context}: approvals shown");
            }
            // ---- time passes
            92..=96 => now += 1 + rng.below(220) as u64,
            // ---- someone is removed
            97 => {
                let who = rng.below(credentials.len());
                if credentials[who].live
                    && credentials.iter().filter(|c| c.live && !c.cosigner).count() > 3
                {
                    svc.revoke_credential(&project, &credentials[who].id, now)
                        .unwrap();
                    credentials[who].live = false;
                }
            }
            98 if credentials[2].live => {
                svc.disable_approver(&project, "p2", now).unwrap();
                credentials[2].live = false;
            }
            _ => {}
        }
    }
    assert!(
        svc.audit_verify().is_ok(),
        "seed {seed}: audit log after {steps} steps"
    );
}

/// Seed and size for the endless test runner (scripts/soak.sh), which wants
/// different random sequences on every pass. Unset, the long runs are the
/// same every time.
fn soak(default_seed: u64, default_rounds: u64) -> (u64, u64) {
    let read = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    (
        read("TWOF_SOAK_SEED").unwrap_or(default_seed),
        read("TWOF_SOAK_ROUNDS").unwrap_or(default_rounds),
    )
}

#[test]
fn random_operations_agree_with_the_model() {
    let mut seen = Seen::default();
    for seed in 1..=24 {
        run(seed * 7919, 600, &mut seen);
    }
    for (what, count) in [
        ("allowed by rule", seen.allowed),
        ("approved by quorum", seen.approved),
        ("rejected", seen.rejected),
        ("expired", seen.expired),
        ("refused approvals", seen.refused),
        ("flood held back", seen.flood),
        ("receipts used", seen.consumed),
        ("reuse refused", seen.reused),
    ] {
        assert!(
            count >= 10,
            "the random run reached \"{what}\" only {count} times"
        );
    }
}

#[test]
#[ignore]
fn random_operations_long_run() {
    let (base, rounds) = soak(3, 400);
    let mut seen = Seen::default();
    for round in 1..=rounds {
        run(
            base.wrapping_add(round.wrapping_mul(104_729)),
            1500,
            &mut seen,
        );
    }
    println!(
        "allowed {} approved {} rejected {} expired {} refused {} flood {} used {} reuse refused {}",
        seen.allowed,
        seen.approved,
        seen.rejected,
        seen.expired,
        seen.refused,
        seen.flood,
        seen.consumed,
        seen.reused
    );
}
