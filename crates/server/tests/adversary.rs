//! A random attacker with write access to the database file, an API key and
//! one approver's device (an insider), working against honest approvers.
//!
//! The attacker may break the service: errors are fine. What must never
//! happen, whatever is written into the tables, is a receipt that the rules
//! and real signatures do not support.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use twof_core::keys::ServerKey;
use twof_core::receipt::{self, ReceiptDecision};
use twof_core::{Action, ApproverKind, Binding};
use twof_server::{Config, Service};

const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "auto", "when": { "type": ["auto"], "asset": ["USDT"], "amount_max": "50" }, "then": { "decision": "allow" } },
    { "name": "two", "when": { "type": ["two"] }, "then": { "decision": "require", "requirements": [ { "count": 2 } ] } },
    { "name": "one", "when": { "type": ["one"] }, "then": { "decision": "require", "requirements": [ { "count": 1 } ] } } ] }"#;
const ALLOW_ALL: &str =
    r#"{"version":1,"lists":{},"rules":[{"name":"x","when":{},"then":{"decision":"allow"}}]}"#;

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

type Signed = HashMap<(String, String, u64), BTreeSet<&'static str>>;

#[derive(Default)]
struct Seen {
    receipts: usize,
    approved: usize,
    tampered: usize,
    refused: usize,
}

fn run(seed: u64, seen: &mut Seen) {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-adversary-{}-{seed}.db", std::process::id()));
    let cleanup = |path: &std::path::Path| {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    };
    cleanup(&path);
    let config = Config {
        max_pending: 1000,
        ..Config::default()
    };
    let svc = Service::open(&path, ServerKey::generate(), config).unwrap();
    let mut now = 1_800_000_000u64;
    let project = svc.create_project("bank", now).unwrap();
    svc.set_policy(&project, POLICY, now).unwrap();
    let old_key = svc.create_api_key(&project, "old", now).unwrap();
    svc.revoke_api_keys(&project, now).unwrap();
    svc.create_api_key(&project, "current", now).unwrap();

    let names: [&'static str; 3] = ["p0", "p1", "p2"];
    let keys: Vec<ServerKey> = (0..3).map(|_| ServerKey::generate()).collect();
    let mut credentials = Vec::new();
    for (name, key) in names.iter().zip(&keys) {
        svc.add_approver(&project, name, name, now).unwrap();
        credentials.push(
            svc.add_credential(
                &project,
                name,
                ApproverKind::Ed25519,
                &key.public_hex(),
                now,
            )
            .unwrap(),
        );
    }
    let attacker_key = ServerKey::generate();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    raw.execute("PRAGMA foreign_keys = OFF", []).unwrap();
    // Things the attacker copied while they were valid.
    let saved_p1: Option<String> = raw
        .query_row(
            "SELECT seal FROM credentials WHERE id = ?",
            [&credentials[1]],
            |r| r.get(0),
        )
        .unwrap();
    let saved_policy: (String, Option<String>) = raw
        .query_row("SELECT policy, policy_seal FROM projects", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();

    let server_key = svc.key();
    let lookup = |kid: &str| (kid == server_key.kid()).then(|| server_key.public());
    let mut rng = Rng(seed | 1);
    let mut actions: HashMap<String, Value> = HashMap::new();
    let mut signed: Signed = HashMap::new();
    let mut challenges: Vec<String> = Vec::new();
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut p1_revoked_at: Option<u64> = None;

    for step in 0..90 {
        now += 1;
        let context = format!("seed {seed} step {step}");
        let pick =
            |rng: &mut Rng, list: &Vec<String>| list.get(rng.below(list.len().max(1))).cloned();
        match rng.below(100) {
            // ---- the honest client (or the attacker, who holds the key too) asks
            0..=24 => {
                let kind = ["auto", "auto", "one", "two", "two"][rng.below(5)];
                let action = json!({ "type": kind, "amount": (1 + rng.below(90)).to_string(), "asset": "USDT",
                                     "destination": format!("0x{:03x}", rng.below(8)) });
                let hash = Action::from_value(action.clone())
                    .unwrap()
                    .hash_hex()
                    .unwrap();
                actions.insert(hash, action.clone());
                if let Ok(view) = svc.create_challenge(&project, action, &format!("k{step}"), now) {
                    challenges.push(view.id);
                }
            }
            // ---- an honest approver looks at a request and approves what is shown
            25..=44 => {
                let Some(id) = pick(&mut rng, &challenges) else {
                    continue;
                };
                let who = rng.below(2);
                if who == 1 && p1_revoked_at.is_some() {
                    continue; // p1's device is gone
                }
                let Ok(view) = svc.approver_view(&id, now) else {
                    continue;
                };
                // What the page and the terminal approver check before signing.
                let Ok(shown) = Action::from_value(view.action.clone()) else {
                    continue;
                };
                let hash = shown.hash_hex().unwrap();
                if view.binding.challenge != id
                    || view.binding.action_hash != hash
                    || view.state != "pending"
                {
                    continue;
                }
                actions.entry(hash.clone()).or_insert(view.action.clone());
                signed
                    .entry((id.clone(), hash, view.binding.expires_at))
                    .or_default()
                    .insert(names[who]);
                let signature = twof_core::b64(&keys[who].sign(&view.binding.hash()));
                if svc
                    .submit_approval(&id, &credentials[who], &signature, false, now)
                    .is_err()
                {
                    seen.refused += 1;
                }
            }
            // ---- the insider signs whatever is in the table, and submits or plants it
            45..=56 => {
                let Some(id) = pick(&mut rng, &challenges) else {
                    continue;
                };
                let row: Result<(String, i64), _> = raw.query_row(
                    "SELECT action_hash, expires_at FROM challenges WHERE id = ?",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                );
                let Ok((hash, expires_at)) = row else {
                    continue;
                };
                let binding = Binding::new(&project, &id, &hash, expires_at as u64);
                let signature = twof_core::b64(&keys[2].sign(&binding.hash()));
                signed
                    .entry((id.clone(), hash, expires_at as u64))
                    .or_default()
                    .insert("p2");
                if rng.below(2) == 0 {
                    let _ = svc.submit_approval(&id, &credentials[2], &signature, false, now);
                } else {
                    let _ = raw.execute(
                        "INSERT OR REPLACE INTO approvals (challenge, approver, credential, kind, sig, created_at) VALUES (?, 'p2', ?, 'ed25519', ?, 0)",
                        rusqlite::params![id, credentials[2], signature],
                    );
                }
            }
            // ---- the attacker writes into the database
            57..=84 => {
                seen.tampered += 1;
                let id = pick(&mut rng, &challenges).unwrap_or_default();
                let sql = |text: &str, values: &[&dyn rusqlite::ToSql]| {
                    let _ = raw.execute(text, values);
                };
                match rng.below(16) {
                    0 => sql(r#"UPDATE challenges SET requirements = '[{"count":1,"min_strength":"strong"}]' WHERE id = ?"#, &[&id]),
                    1 => sql("UPDATE challenges SET state = ? WHERE id = ?", &[&["pending", "approved", "allowed"][rng.below(3)], &id]),
                    2 => {
                        // A junk approval, or someone's real signature moved from another request.
                        let other = pick(&mut rng, &challenges).unwrap_or_default();
                        let stolen: Option<String> = raw
                            .query_row("SELECT sig FROM approvals WHERE challenge = ? LIMIT 1", [&other], |r| r.get(0))
                            .ok();
                        let sig = stolen.unwrap_or_else(|| twof_core::b64(&[7u8; 64]));
                        let who = rng.below(2);
                        sql(
                            "INSERT OR REPLACE INTO approvals (challenge, approver, credential, kind, sig, created_at) VALUES (?, ?, ?, 'ed25519', ?, 0)",
                            &[&id, &names[who], &credentials[who], &sig],
                        );
                    }
                    3 => {
                        // A credential of their own under an honest name, then they "approve".
                        sql(
                            "INSERT OR REPLACE INTO credentials (id, project, approver, kind, public_key, seal, created_at) \
                             SELECT 'cr_evil', project, 'p0', kind, ?, seal, 0 FROM credentials WHERE id = ?",
                            &[&attacker_key.public_hex(), &credentials[0]],
                        );
                        if let Ok(view) = svc.approver_view(&id, now) {
                            let signature = twof_core::b64(&attacker_key.sign(&view.binding.hash()));
                            let _ = svc.submit_approval(&id, "cr_evil", &signature, false, now);
                        }
                    }
                    4 => {
                        // An honest approver's key swapped for theirs.
                        sql("UPDATE credentials SET public_key = ? WHERE id = ?", &[&attacker_key.public_hex(), &credentials[0]]);
                        if let Ok(view) = svc.approver_view(&id, now) {
                            let signature = twof_core::b64(&attacker_key.sign(&view.binding.hash()));
                            let _ = svc.submit_approval(&id, &credentials[0], &signature, false, now);
                        }
                        sql("UPDATE credentials SET public_key = ? WHERE id = ?", &[&keys[0].public_hex(), &credentials[0]]);
                    }
                    5 => sql("UPDATE projects SET policy = ?", &[&ALLOW_ALL]),
                    6 => sql("UPDATE projects SET policy = ?, policy_seal = ?", &[&saved_policy.0, &saved_policy.1]),
                    7 => sql("UPDATE receipts SET consumed_at = NULL", &[]),
                    8 => sql("UPDATE credentials SET revoked_at = NULL, seal = ? WHERE id = ?", &[&saved_p1, &credentials[1]]),
                    9 => sql("UPDATE api_keys SET revoked_at = NULL, seal = (SELECT seal FROM api_keys WHERE seal IS NOT NULL LIMIT 1)", &[]),
                    10 => sql(r#"UPDATE challenges SET action = '{"amount":"1","asset":"USDT","destination":"0xfriend","type":"one"}' WHERE id = ?"#, &[&id]),
                    11 => sql("UPDATE challenges SET expires_at = expires_at + 100000 WHERE id = ?", &[&id]),
                    12 => sql("UPDATE challenges SET receipt = (SELECT receipt FROM challenges WHERE receipt IS NOT NULL LIMIT 1) WHERE id = ?", &[&id]),
                    13 => sql("UPDATE challenges SET seal = (SELECT seal FROM challenges WHERE state = 'approved' LIMIT 1), state = 'approved' WHERE id = ?", &[&id]),
                    14 if rng.below(4) == 0 => sql("DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)", &[]),
                    15 if rng.below(4) == 0 => sql(
                        "INSERT INTO audit (seq, ts, kind, data, prev, hash, sig) \
                         SELECT seq + 1, ts, 'credential.added', '{\"credential\":\"cr_evil\"}', hash, hash, sig FROM audit ORDER BY seq DESC LIMIT 1",
                        &[],
                    ),
                    _ => {}
                }
            }
            // ---- a receipt is used
            85..=92 => {
                let Some(token) = tokens.iter().nth(rng.below(tokens.len().max(1))).cloned() else {
                    continue;
                };
                if let Ok(payload) = svc.consume_receipt(&project, &token, now) {
                    *used.entry(payload.id).or_default() += 1;
                }
            }
            // ---- the owner revokes p1's device
            93..=95
                if p1_revoked_at.is_none()
                    && svc
                        .revoke_credential(&project, &credentials[1], now)
                        .is_ok() =>
            {
                p1_revoked_at = Some(now);
            }
            _ => {}
        }

        // ---- after every step: nothing unsupported exists anywhere
        assert!(
            svc.authenticate(&old_key).is_err(),
            "{context}: a revoked API key works again"
        );
        for id in &challenges {
            if let Ok(view) = svc.get_challenge(&project, id, now) {
                tokens.extend(view.receipt);
            }
        }
        let mut stmt = raw
            .prepare("SELECT receipt FROM challenges WHERE receipt IS NOT NULL")
            .unwrap();
        let stored: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .flatten()
            .collect();
        tokens.extend(stored);
        for token in &tokens {
            // Whatever is not a genuine receipt of this server opens nothing.
            let Ok(payload) = receipt::verify_signature(token, &lookup, now) else {
                continue;
            };
            let action = actions.get(&payload.action_hash).unwrap_or_else(|| {
                panic!("{context}: receipt for an action nobody asked for or was shown")
            });
            let amount: u64 = action["amount"].as_str().unwrap().parse().unwrap();
            match payload.decision {
                ReceiptDecision::Allow => {
                    assert!(
                        action["type"] == "auto" && action["asset"] == "USDT" && amount <= 50,
                        "{context}: allowed without a rule for it: {action}"
                    );
                }
                ReceiptDecision::Approved => {
                    let needed = match action["type"].as_str() {
                        Some("two") => 2,
                        Some("one") => 1,
                        other => panic!("{context}: approval receipt for {other:?}"),
                    };
                    let key = (
                        payload.challenge.clone(),
                        payload.action_hash.clone(),
                        payload.binding_expires_at,
                    );
                    let mut signers = signed.get(&key).cloned().unwrap_or_default();
                    if p1_revoked_at.is_some_and(|at| payload.issued_at > at) {
                        signers.remove("p1");
                    }
                    assert!(
                        signers.len() >= needed,
                        "{context}: approved with {signers:?} real signatures, {needed} needed, for {action}"
                    );
                    for approval in &payload.approvals {
                        assert!(
                            signers.contains(approval.approver.as_str()),
                            "{context}: receipt says {} approved, who did not sign",
                            approval.approver
                        );
                    }
                }
            }
        }
        for (receipt, count) in &used {
            assert!(
                *count <= 1,
                "{context}: receipt {receipt} was used {count} times"
            );
        }
    }
    seen.receipts += tokens.len();
    seen.approved += tokens
        .iter()
        .filter_map(|t| receipt::verify_signature(t, &lookup, now).ok())
        .filter(|p| p.decision == ReceiptDecision::Approved)
        .count();
    drop(raw);
    drop(svc);
    cleanup(&path);
}

#[test]
fn nothing_written_into_the_database_produces_an_unsupported_receipt() {
    let mut seen = Seen::default();
    for seed in 1..=24 {
        run(seed * 6151, &mut seen);
    }
    assert!(
        seen.receipts > 40,
        "only {} receipts were examined",
        seen.receipts
    );
    assert!(
        seen.approved > 8,
        "only {} approvals completed",
        seen.approved
    );
    assert!(
        seen.tampered > 200,
        "only {} tamperings were tried",
        seen.tampered
    );
}

#[test]
#[ignore]
fn adversary_long_run() {
    let mut seen = Seen::default();
    for seed in 1..=3000 {
        run(seed * 15_485_863 + 11, &mut seen);
    }
    println!(
        "receipts {} approved {} tamperings {} honest approvals refused {}",
        seen.receipts, seen.approved, seen.tampered, seen.refused
    );
}
