//! Everything the server does, as plain synchronous functions over SQLite.
//!
//! One connection behind a mutex: every operation is a single serialized
//! transaction, so "check then act" sequences (single use receipts, velocity
//! limits, the audit chain) cannot race.

use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use twof_core::audit::{self, Checkpoint, Entry};
use twof_core::canonical;
use twof_core::keys::{self, ServerKey};
use twof_core::passkey::{self, AssertionProof, RelyingParty};
use twof_core::policy::{all_satisfied, Outcome, PolicyContext};
use twof_core::receipt::{self, ReceiptDecision};
use twof_core::{
    Action, Approval, ApprovalFact, ApproverKind, Binding, Policy, ReceiptPayload, Requirement,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, policy TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, project TEXT NOT NULL REFERENCES projects(id), hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS approvers (
    project TEXT NOT NULL REFERENCES projects(id), id TEXT NOT NULL, name TEXT NOT NULL,
    created_at INTEGER NOT NULL, disabled_at INTEGER, PRIMARY KEY (project, id));
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY, project TEXT NOT NULL, approver TEXT NOT NULL, kind TEXT NOT NULL,
    public_key TEXT NOT NULL, external_id TEXT UNIQUE, counter INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, revoked_at INTEGER,
    FOREIGN KEY (project, approver) REFERENCES approvers(project, id));
CREATE TABLE IF NOT EXISTS enrollments (
    token_hash TEXT PRIMARY KEY, project TEXT NOT NULL, approver TEXT NOT NULL,
    challenge TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER,
    FOREIGN KEY (project, approver) REFERENCES approvers(project, id));
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY, project TEXT NOT NULL REFERENCES projects(id),
    idempotency_key TEXT NOT NULL, action TEXT NOT NULL, action_hash TEXT NOT NULL,
    amount TEXT, asset TEXT, state TEXT NOT NULL, rule TEXT, requirements TEXT,
    expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, decided_at INTEGER, receipt TEXT,
    UNIQUE (project, idempotency_key));
CREATE INDEX IF NOT EXISTS challenges_velocity ON challenges (project, asset, decided_at);
CREATE TABLE IF NOT EXISTS approvals (
    challenge TEXT NOT NULL REFERENCES challenges(id), approver TEXT NOT NULL,
    credential TEXT NOT NULL, kind TEXT NOT NULL, sig TEXT NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY (challenge, credential));
CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY, challenge TEXT NOT NULL REFERENCES challenges(id),
    project TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL,
    prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (
    seq INTEGER NOT NULL, hash TEXT NOT NULL, ts INTEGER NOT NULL, kid TEXT NOT NULL,
    sig TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS channels (
    project TEXT PRIMARY KEY REFERENCES projects(id), webhook_url TEXT, telegram_chat TEXT);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, kind TEXT NOT NULL,
    target TEXT NOT NULL, body TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL, done_at INTEGER, failed INTEGER NOT NULL DEFAULT 0);
";

/// Deliveries are retried this many times before being given up on.
pub const OUTBOX_MAX_ATTEMPTS: i64 = 10;

/// A notification waiting to be delivered.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboxItem {
    pub id: i64,
    pub kind: String,
    pub target: String,
    pub body: String,
}

/// Queues notifications for an event, inside the caller's transaction.
fn emit(conn: &Connection, now: u64, project: &str, event: &str, data: Value) -> Result<()> {
    let channels: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT webhook_url, telegram_chat FROM channels WHERE project = ?",
            [project],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((webhook, telegram)) = channels else {
        return Ok(());
    };
    let queue = |kind: &str, target: &str, body: &str| {
        conn.execute(
            "INSERT INTO outbox (project, kind, target, body, next_at) VALUES (?, ?, ?, ?, ?)",
            params![project, kind, target, body, now as i64],
        )
    };
    if let (Some(chat), "challenge.pending") = (&telegram, event) {
        let text = |name: &str| data["action"][name].as_str().unwrap_or("").to_owned();
        let message = format!(
            "2F: approval needed\n{} {} {}\nto: {}\n{}",
            text("type"),
            text("amount"),
            text("asset"),
            text("destination"),
            data["approve_url"].as_str().unwrap_or("")
        );
        queue("telegram", chat, &message)?;
    }
    if let Some(url) = &webhook {
        let body = json!({ "event": event, "ts": now, "project": project, "data": data });
        queue("webhook", url, &canonical::to_canonical(&body)?)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Config {
    /// How long approvers have to act on a challenge, in seconds.
    pub challenge_ttl: u64,
    /// How long a receipt stays valid after it is issued, in seconds.
    pub receipt_ttl: u64,
    /// Base URL approvers reach the server at, used to build approval links.
    pub public_url: String,
    /// Requests allowed per client address per minute. Zero disables the limit.
    pub rate_per_minute: u32,
    /// Take the client address from the last `X-Forwarded-For` entry. Only
    /// enable behind a reverse proxy that sets that header itself.
    pub trust_proxy: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            challenge_ttl: 300,
            receipt_ttl: 300,
            public_url: "http://localhost:8722".into(),
            rate_per_minute: 600,
            trust_proxy: false,
        }
    }
}

impl Config {
    /// The WebAuthn relying party, derived from the public URL.
    pub fn relying_party(&self) -> Result<RelyingParty> {
        RelyingParty::from_url(&self.public_url)
            .ok_or_else(|| Error::Internal("public_url is not a valid http(s) URL".into()))
    }
}

/// How long an enrollment link stays usable, in seconds.
pub const ENROLLMENT_TTL: u64 = 15 * 60;

/// What an approver presents to approve or refuse.
#[derive(Clone, Debug)]
pub enum Proof {
    /// Ed25519 signature (base64url) by a device key or a co-signer.
    Signature {
        credential: String,
        signature: String,
    },
    /// WebAuthn assertion. `credential_id` is the authenticator's own id, base64url.
    Passkey {
        credential_id: String,
        assertion: AssertionProof,
    },
}

/// What the enrollment page needs to call `navigator.credentials.create`.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct EnrollmentView {
    pub project_name: String,
    pub approver: String,
    pub approver_name: String,
    pub rp_id: String,
    pub challenge: String,
    pub user_id: String,
    pub expires_at: u64,
}

/// What the enrollment page sends back, all base64url.
#[derive(Clone, Debug)]
pub struct Registration {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub public_key: String,
    pub algorithm: i64,
}

pub struct Service {
    conn: Mutex<Connection>,
    key: ServerKey,
    pub config: Config,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ApprovalView {
    pub approver: String,
    pub kind: ApproverKind,
}

/// What the client that created a challenge sees.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ChallengeView {
    pub id: String,
    pub state: String,
    pub action_hash: String,
    pub rule: Option<String>,
    pub requirements: Option<Vec<Requirement>>,
    pub approvals: Vec<ApprovalView>,
    pub expires_at: u64,
    pub approve_url: Option<String>,
    pub receipt: Option<String>,
}

/// What an approver sees before signing: the action itself and the binding.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ApproverView {
    pub id: String,
    pub project: String,
    pub project_name: String,
    pub state: String,
    pub action: Value,
    pub binding: Binding,
    /// base64url of the 32 bytes an approver signs to approve.
    pub binding_hash: String,
    /// base64url of the 32 bytes an approver signs to refuse.
    pub reject_hash: String,
    pub requirements: Vec<Requirement>,
    pub approvals: Vec<ApprovalView>,
    pub expires_at: u64,
    /// WebAuthn relying party id for passkey approvals.
    pub rp_id: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PublicKeyView {
    pub kid: String,
    pub alg: &'static str,
    pub public_key: String,
}

struct ChallengeRow {
    id: String,
    project: String,
    action: String,
    action_hash: String,
    state: String,
    rule: Option<String>,
    requirements: Option<String>,
    expires_at: u64,
    receipt: Option<String>,
}

impl ChallengeRow {
    fn binding(&self) -> Binding {
        Binding::new(&self.project, &self.id, &self.action_hash, self.expires_at)
    }

    fn requirements(&self) -> Result<Vec<Requirement>> {
        match &self.requirements {
            Some(text) => serde_json::from_str(text)
                .map_err(|e| Error::Internal(format!("stored requirements: {e}"))),
            None => Ok(Vec::new()),
        }
    }
}

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

fn internal(e: impl std::fmt::Display) -> Error {
    Error::Internal(e.to_string())
}

fn check_slug(what: &str, value: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{what} must be 1 to 64 characters of a-z, 0-9, - or _"
        )))
    }
}

fn check_label(what: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "{what} must have 1 to {max} printable characters"
        )));
    }
    Ok(())
}

/// Appends to the audit chain inside the caller's transaction, so a state
/// change and its audit entry are committed together or not at all.
fn audit_append(conn: &Connection, now: u64, kind: &str, data: Value) -> Result<()> {
    let prev: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let prev_ref = prev
        .as_ref()
        .map(|(seq, hash)| (*seq as u64, hash.as_str()));
    let entry = audit::next_entry(prev_ref, now, kind, data)?;
    conn.execute(
        "INSERT INTO audit (seq, ts, kind, data, prev, hash) VALUES (?, ?, ?, ?, ?, ?)",
        params![
            entry.seq as i64,
            entry.ts as i64,
            entry.kind,
            canonical::to_canonical(&entry.data)?,
            entry.prev,
            entry.hash
        ],
    )?;
    Ok(())
}

struct VelocityCtx<'a> {
    conn: &'a Connection,
    project: &'a str,
    now: u64,
}

impl VelocityCtx<'_> {
    fn total(&self, asset: &str, window_secs: u64) -> rusqlite::Result<Option<Decimal>> {
        let since = self.now.saturating_sub(window_secs) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT amount FROM challenges WHERE project = ? AND asset = ? \
             AND state IN ('allowed', 'approved') AND decided_at >= ? AND amount IS NOT NULL",
        )?;
        let rows = stmt.query_map(params![self.project, asset, since], |r| {
            r.get::<_, String>(0)
        })?;
        let mut total = Decimal::ZERO;
        for amount in rows {
            let Ok(amount) = amount?.parse::<Decimal>() else {
                return Ok(None);
            };
            let Some(sum) = total.checked_add(amount) else {
                return Ok(None);
            };
            total = sum;
        }
        Ok(Some(total))
    }
}

impl PolicyContext for VelocityCtx<'_> {
    fn now_unix(&self) -> u64 {
        self.now
    }
    fn velocity_total(&self, asset: &str, window_secs: u64) -> Option<Decimal> {
        // Any failure reads as "unknown", which never matches a rule.
        self.total(asset, window_secs).ok().flatten()
    }
}

impl Service {
    pub fn open(path: &Path, key: ServerKey, config: Config) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::with_connection(conn, key, config)
    }

    pub fn open_in_memory(key: ServerKey, config: Config) -> Result<Self> {
        Self::with_connection(Connection::open_in_memory()?, key, config)
    }

    fn with_connection(conn: Connection, key: ServerKey, config: Config) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Service {
            conn: Mutex::new(conn),
            key,
            config,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock rolled its transaction back, so the
        // connection is still consistent.
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn key(&self) -> &ServerKey {
        &self.key
    }

    // ---- administration (reached through the CLI, never through HTTP) ----

    pub fn create_project(&self, name: &str, now: u64) -> Result<String> {
        check_label("project name", name, 100)?;
        let id = new_id("pj");
        let policy = serde_json::to_string(&Policy::deny_all()).map_err(internal)?;
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO projects (id, name, policy, created_at) VALUES (?, ?, ?, ?)",
            params![id, name, policy, now as i64],
        )?;
        audit_append(
            &tx,
            now,
            "project.created",
            json!({ "project": id, "name": name }),
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn list_projects(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT id, name FROM projects ORDER BY created_at")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Returns the API key. It is shown once: only its hash is stored.
    pub fn create_api_key(&self, project: &str, label: &str, now: u64) -> Result<String> {
        check_label("label", label, 100)?;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = format!("2f_{}", B64.encode(secret));
        let id = new_id("ak");
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        project_exists(&tx, project)?;
        tx.execute(
            "INSERT INTO api_keys (id, project, hash, label, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, project, token_hash(&token), label, now as i64],
        )?;
        audit_append(
            &tx,
            now,
            "apikey.created",
            json!({ "project": project, "key": id, "label": label }),
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn set_policy(&self, project: &str, policy_json: &str, now: u64) -> Result<()> {
        let policy = Policy::parse(policy_json).map_err(|e| Error::Invalid(e.to_string()))?;
        let stored = serde_json::to_string(&policy).map_err(internal)?;
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        project_exists(&tx, project)?;
        tx.execute(
            "UPDATE projects SET policy = ? WHERE id = ?",
            params![stored, project],
        )?;
        let value = serde_json::to_value(&policy).map_err(internal)?;
        audit_append(
            &tx,
            now,
            "policy.set",
            json!({ "project": project, "policy": value }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_policy(&self, project: &str) -> Result<String> {
        let conn = self.lock();
        conn.query_row("SELECT policy FROM projects WHERE id = ?", [project], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or(Error::NotFound)
    }

    pub fn add_approver(&self, project: &str, id: &str, name: &str, now: u64) -> Result<()> {
        check_slug("approver id", id)?;
        check_label("approver name", name, 100)?;
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        project_exists(&tx, project)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO approvers (project, id, name, created_at) VALUES (?, ?, ?, ?)",
            params![project, id, name, now as i64],
        )?;
        if inserted == 0 {
            return Err(Error::Conflict(format!("approver \"{id}\" already exists")));
        }
        audit_append(
            &tx,
            now,
            "approver.added",
            json!({ "project": project, "approver": id, "name": name }),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Enrolls a public key for an approver. Returns the credential id.
    pub fn add_credential(
        &self,
        project: &str,
        approver: &str,
        kind: ApproverKind,
        public_key_hex: &str,
        now: u64,
    ) -> Result<String> {
        if !matches!(kind, ApproverKind::Ed25519 | ApproverKind::Cosigner) {
            return Err(Error::Invalid(format!(
                "{} credentials are not enrolled this way",
                kind.as_str()
            )));
        }
        let key = keys::public_from_hex(public_key_hex)
            .map_err(|_| Error::Invalid("public key must be 32 bytes of hex (Ed25519)".into()))?;
        let public_key = hex::encode(key.as_bytes());
        let id = new_id("cr");
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM approvers WHERE project = ? AND id = ? AND disabled_at IS NULL",
                params![project, approver],
                |r| r.get(0),
            )
            .optional()?;
        if known.is_none() {
            return Err(Error::NotFound);
        }
        tx.execute(
            "INSERT INTO credentials (id, project, approver, kind, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![id, project, approver, kind.as_str(), public_key, now as i64],
        )?;
        audit_append(
            &tx,
            now,
            "credential.added",
            json!({ "project": project, "approver": approver, "credential": id,
                    "kind": kind.as_str(), "public_key": public_key }),
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn revoke_credential(&self, project: &str, credential: &str, now: u64) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE credentials SET revoked_at = ? WHERE id = ? AND project = ? AND revoked_at IS NULL",
            params![now as i64, credential, project],
        )?;
        if changed == 0 {
            return Err(Error::NotFound);
        }
        audit_append(
            &tx,
            now,
            "credential.revoked",
            json!({ "project": project, "credential": credential }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_api_keys(&self, project: &str, now: u64) -> Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE project = ? AND revoked_at IS NULL",
            params![now as i64, project],
        )?;
        audit_append(
            &tx,
            now,
            "apikey.revoked_all",
            json!({ "project": project, "count": changed }),
        )?;
        tx.commit()?;
        Ok(changed)
    }

    /// Creates a one time link for an approver to enroll a passkey. Returns
    /// the token; the link is `{public_url}/enroll/{token}`.
    pub fn create_enrollment(&self, project: &str, approver: &str, now: u64) -> Result<String> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = B64.encode(secret);
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM approvers WHERE project = ? AND id = ? AND disabled_at IS NULL",
                params![project, approver],
                |r| r.get(0),
            )
            .optional()?;
        if known.is_none() {
            return Err(Error::NotFound);
        }
        tx.execute(
            "INSERT INTO enrollments (token_hash, project, approver, challenge, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![token_hash(&token), project, approver, B64.encode(challenge), (now + ENROLLMENT_TTL) as i64],
        )?;
        audit_append(
            &tx,
            now,
            "enrollment.created",
            json!({ "project": project, "approver": approver }),
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn enrollment_url(&self, token: &str) -> String {
        format!(
            "{}/enroll/{token}",
            self.config.public_url.trim_end_matches('/')
        )
    }

    pub fn enrollment_view(&self, token: &str, now: u64) -> Result<EnrollmentView> {
        let conn = self.lock();
        let (project, approver, challenge, expires_at) = open_enrollment(&conn, token, now)?;
        let project_name: String =
            conn.query_row("SELECT name FROM projects WHERE id = ?", [&project], |r| {
                r.get(0)
            })?;
        let approver_name: String = conn.query_row(
            "SELECT name FROM approvers WHERE project = ? AND id = ?",
            params![project, approver],
            |r| r.get(0),
        )?;
        let user_id = Sha256::digest(format!("{project}/{approver}").as_bytes());
        Ok(EnrollmentView {
            project_name,
            approver_name,
            rp_id: self.config.relying_party()?.id,
            challenge,
            user_id: B64.encode(&user_id[..16]),
            expires_at,
            approver,
        })
    }

    /// Finishes a passkey enrollment. The link stops working afterwards.
    pub fn complete_enrollment(&self, token: &str, reg: &Registration, now: u64) -> Result<String> {
        let invalid = |what: &str| Error::Invalid(format!("{what} is not valid base64url"));
        let authenticator_data = B64
            .decode(&reg.authenticator_data)
            .map_err(|_| invalid("authenticator_data"))?;
        let client_data_json = B64
            .decode(&reg.client_data_json)
            .map_err(|_| invalid("client_data_json"))?;
        let public_key = B64
            .decode(&reg.public_key)
            .map_err(|_| invalid("public_key"))?;
        let rp = self.config.relying_party()?;

        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (project, approver, challenge, _) = open_enrollment(&tx, token, now)?;
        let challenge = B64.decode(challenge).map_err(internal)?;
        let external_id = passkey::verify_registration(
            &rp,
            &challenge,
            &authenticator_data,
            &client_data_json,
            &public_key,
            reg.algorithm,
        )
        .map_err(|e| Error::Forbidden(e.to_string()))?;
        let id = new_id("cr");
        let external_id = B64.encode(external_id);
        let public_key = hex::encode(public_key);
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO credentials (id, project, approver, kind, public_key, external_id, created_at) \
             VALUES (?, ?, ?, 'passkey', ?, ?, ?)",
            params![id, project, approver, public_key, external_id, now as i64],
        )?;
        if inserted == 0 {
            return Err(Error::Conflict("this passkey is already enrolled".into()));
        }
        tx.execute(
            "UPDATE enrollments SET used_at = ? WHERE token_hash = ?",
            params![now as i64, token_hash(token)],
        )?;
        audit_append(
            &tx,
            now,
            "credential.added",
            json!({ "project": project, "approver": approver, "credential": id, "kind": "passkey",
                    "public_key": public_key, "external_id": external_id }),
        )?;
        tx.commit()?;
        Ok(id)
    }

    // ---- client API ----

    /// Resolves an API key to its project.
    pub fn authenticate(&self, token: &str) -> Result<String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT project FROM api_keys WHERE hash = ? AND revoked_at IS NULL",
            [token_hash(token)],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(Error::Unauthorized)
    }

    pub fn create_challenge(
        &self,
        project: &str,
        action: Value,
        idempotency_key: &str,
        now: u64,
    ) -> Result<ChallengeView> {
        let action = Action::from_value(action)?;
        check_label("idempotency_key", idempotency_key, 128)?;
        let action_hash = action.hash_hex()?;
        let action_text = action.canonical()?;

        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT id, action_hash FROM challenges WHERE project = ? AND idempotency_key = ?",
                params![project, idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, existing_hash)) = existing {
            if existing_hash != action_hash {
                return Err(Error::Conflict(
                    "idempotency_key was already used for a different action".into(),
                ));
            }
            let row = load(&tx, &id, now)?;
            let view = self.view(&tx, row)?;
            tx.commit()?;
            return Ok(view);
        }

        let policy_text: String = tx
            .query_row("SELECT policy FROM projects WHERE id = ?", [project], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or(Error::NotFound)?;
        // A stored policy that no longer parses must refuse, not allow.
        let policy = Policy::parse(&policy_text).unwrap_or_else(|_| Policy::deny_all());
        let decision = policy.evaluate(
            &action,
            &VelocityCtx {
                conn: &tx,
                project,
                now,
            },
        );

        let (state, requirements) = match &decision.outcome {
            Outcome::Allow => ("allowed", None),
            Outcome::Deny => ("denied", None),
            Outcome::Require { requirements } => (
                "pending",
                Some(serde_json::to_string(requirements).map_err(internal)?),
            ),
        };
        let id = new_id("ch");
        let expires_at = now + self.config.challenge_ttl;
        let decided_at = (state != "pending").then_some(now as i64);
        tx.execute(
            "INSERT INTO challenges (id, project, idempotency_key, action, action_hash, amount, asset, \
             state, rule, requirements, expires_at, created_at, decided_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                project,
                idempotency_key,
                action_text,
                action_hash,
                action.amount,
                action.asset,
                state,
                decision.rule,
                requirements,
                expires_at as i64,
                now as i64,
                decided_at
            ],
        )?;
        audit_append(
            &tx,
            now,
            "challenge.created",
            json!({ "project": project, "challenge": id, "action_hash": action_hash,
                    "action": serde_json::to_value(&action).map_err(internal)?,
                    "state": state, "rule": decision.rule }),
        )?;
        let mut row = load(&tx, &id, now)?;
        if state == "pending" {
            let binding = row.binding();
            let data = json!({
                "challenge": row.id,
                "action": serde_json::to_value(&action).map_err(internal)?,
                "binding_hash": B64.encode(binding.hash()),
                "reject_hash": B64.encode(binding.reject_hash()),
                "binding": serde_json::to_value(&binding).map_err(internal)?,
                "approve_url": self.approve_url(&row.id),
                "rule": row.rule,
            });
            emit(&tx, now, project, "challenge.pending", data)?;
        }
        if state == "allowed" {
            let token = self.issue_receipt(&tx, &row, ReceiptDecision::Allow, Vec::new(), now)?;
            row.receipt = Some(token);
        }
        let view = self.view(&tx, row)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn get_challenge(&self, project: &str, id: &str, now: u64) -> Result<ChallengeView> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = load(&tx, id, now)?;
        if row.project != project {
            return Err(Error::NotFound);
        }
        let view = self.view(&tx, row)?;
        tx.commit()?;
        Ok(view)
    }

    /// The challenge as an approver needs to see it. Reachable by anyone who
    /// holds the challenge id, which is 128 random bits.
    pub fn approver_view(&self, id: &str, now: u64) -> Result<ApproverView> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = load(&tx, id, now)?;
        let project_name: String = tx.query_row(
            "SELECT name FROM projects WHERE id = ?",
            [&row.project],
            |r| r.get(0),
        )?;
        let binding = row.binding();
        let view = ApproverView {
            id: row.id.clone(),
            project: row.project.clone(),
            project_name,
            state: row.state.clone(),
            action: canonical::parse_strict(&row.action)?,
            binding_hash: B64.encode(binding.hash()),
            reject_hash: B64.encode(binding.reject_hash()),
            expires_at: row.expires_at,
            rp_id: self.config.relying_party()?.id,
            binding,
            requirements: row.requirements()?,
            approvals: approvals_of(&tx, &row.id)?
                .into_iter()
                .map(|a| a.0)
                .collect(),
        };
        tx.commit()?;
        Ok(view)
    }

    /// Records an approval or refusal signed by an Ed25519 key.
    pub fn submit_approval(
        &self,
        id: &str,
        credential: &str,
        signature_b64: &str,
        reject: bool,
        now: u64,
    ) -> Result<ChallengeView> {
        let proof = Proof::Signature {
            credential: credential.into(),
            signature: signature_b64.into(),
        };
        self.submit(id, &proof, reject, now)
    }

    /// Records an approver's decision. The proof is the authentication: it
    /// must verify against a credential enrolled in the challenge's project.
    pub fn submit(&self, id: &str, proof: &Proof, reject: bool, now: u64) -> Result<ChallengeView> {
        let denied = || Error::Forbidden("credential or signature not accepted".into());

        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut row = load(&tx, id, now)?;
        if row.state != "pending" {
            let state = row.state.clone();
            tx.commit()?; // keeps a lazily recorded expiry
            return Err(Error::Conflict(format!("challenge is {state}")));
        }
        let (column, lookup) = match proof {
            Proof::Signature { credential, .. } => ("c.id", credential),
            Proof::Passkey { credential_id, .. } => ("c.external_id", credential_id),
        };
        let found: Option<(String, String, String, String, i64)> = tx
            .query_row(
                &format!(
                    "SELECT c.id, c.approver, c.kind, c.public_key, c.counter FROM credentials c \
                     JOIN approvers a ON a.project = c.project AND a.id = c.approver \
                     WHERE {column} = ? AND c.project = ? AND c.revoked_at IS NULL AND a.disabled_at IS NULL"
                ),
                params![lookup, row.project],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let (credential, approver, kind, public_key, counter) = found.ok_or_else(denied)?;
        let credential = credential.as_str();
        let kind = ApproverKind::parse(&kind).ok_or_else(|| internal("stored credential kind"))?;
        let requirements = row.requirements()?;
        let fact = ApprovalFact {
            approver: approver.clone(),
            kind,
        };
        if !requirements.iter().any(|r| r.accepts(&fact)) {
            return Err(denied());
        }

        let binding = row.binding();
        let message = if reject {
            binding.reject_hash()
        } else {
            binding.hash()
        };
        // The proof as it is kept in the audit log and carried in the receipt.
        let stored_proof = match (kind, proof) {
            (
                ApproverKind::Ed25519 | ApproverKind::Cosigner,
                Proof::Signature { signature, .. },
            ) => {
                let bytes = B64.decode(signature).map_err(|_| denied())?;
                let valid = keys::public_from_hex(&public_key)
                    .is_ok_and(|key| keys::verify(&key, &message, &bytes));
                if !valid {
                    return Err(denied());
                }
                signature.clone()
            }
            (ApproverKind::Passkey, Proof::Passkey { assertion, .. }) => {
                let rp = self.config.relying_party()?;
                let spki = hex::decode(&public_key).map_err(internal)?;
                let received =
                    passkey::verify_proof(&rp, &spki, &message, assertion).map_err(|_| denied())?;
                passkey::check_counter(counter as u32, received).map_err(|_| denied())?;
                tx.execute(
                    "UPDATE credentials SET counter = ? WHERE id = ?",
                    params![i64::from(received), credential],
                )?;
                assertion.encode()
            }
            _ => return Err(denied()),
        };
        let signature_b64 = stored_proof.as_str();

        let evidence = json!({ "project": row.project, "challenge": row.id, "approver": approver,
                               "credential": credential, "kind": kind.as_str(), "sig": signature_b64 });
        if reject {
            tx.execute(
                "UPDATE challenges SET state = 'rejected', decided_at = ? WHERE id = ?",
                params![now as i64, row.id],
            )?;
            audit_append(&tx, now, "challenge.rejected", evidence)?;
            row.state = "rejected".into();
            emit(
                &tx,
                now,
                &row.project,
                "challenge.rejected",
                json!({ "challenge": row.id, "approver": approver }),
            )?;
        } else {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO approvals (challenge, approver, credential, kind, sig, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![row.id, approver, credential, kind.as_str(), signature_b64, now as i64],
            )?;
            if inserted == 1 {
                audit_append(&tx, now, "approval.accepted", evidence)?;
            }
            let approvals = approvals_of(&tx, &row.id)?;
            let facts: Vec<ApprovalFact> = approvals
                .iter()
                .map(|(a, _)| ApprovalFact {
                    approver: a.approver.clone(),
                    kind: a.kind,
                })
                .collect();
            if all_satisfied(&requirements, &facts) {
                let proofs = approvals
                    .into_iter()
                    .map(|(a, sig)| Approval {
                        approver: a.approver,
                        kind: a.kind,
                        strength: a.kind.strength(),
                        sig,
                    })
                    .collect();
                tx.execute(
                    "UPDATE challenges SET state = 'approved', decided_at = ? WHERE id = ?",
                    params![now as i64, row.id],
                )?;
                row.state = "approved".into();
                emit(
                    &tx,
                    now,
                    &row.project,
                    "challenge.approved",
                    json!({ "challenge": row.id }),
                )?;
                let token =
                    self.issue_receipt(&tx, &row, ReceiptDecision::Approved, proofs, now)?;
                row.receipt = Some(token);
            }
        }
        let view = self.view(&tx, row)?;
        tx.commit()?;
        Ok(view)
    }

    /// Marks a receipt as used. Succeeds exactly once per receipt.
    pub fn consume_receipt(&self, project: &str, token: &str, now: u64) -> Result<ReceiptPayload> {
        let lookup = |kid: &str| (kid == self.key.kid()).then(|| self.key.public());
        let payload = receipt::verify_signature(token, &lookup, now)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if payload.project != project {
            return Err(Error::NotFound);
        }
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE receipts SET consumed_at = ? WHERE id = ? AND project = ? AND consumed_at IS NULL",
            params![now as i64, payload.id, project],
        )?;
        if changed == 0 {
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM receipts WHERE id = ? AND project = ?",
                    params![payload.id, project],
                    |r| r.get(0),
                )
                .optional()?;
            return Err(match exists {
                Some(_) => Error::Conflict("receipt was already used".into()),
                None => Error::NotFound,
            });
        }
        audit_append(
            &tx,
            now,
            "receipt.consumed",
            json!({ "project": project, "receipt": payload.id, "challenge": payload.challenge }),
        )?;
        tx.commit()?;
        Ok(payload)
    }

    pub fn public_keys(&self) -> Vec<PublicKeyView> {
        vec![PublicKeyView {
            kid: self.key.kid(),
            alg: "ed25519",
            public_key: self.key.public_hex(),
        }]
    }

    // ---- audit ----

    pub fn audit_entries(&self) -> Result<Vec<Entry>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT seq, ts, kind, data, prev, hash FROM audit ORDER BY seq")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, ts, kind, data, prev, hash) = row?;
            // Unparseable data is kept as a string so verification reports
            // the entry as altered instead of failing to run.
            let data = canonical::parse_strict(&data).unwrap_or(Value::String(data));
            out.push(Entry {
                seq: seq as u64,
                ts: ts as u64,
                kind,
                data,
                prev,
                hash,
            });
        }
        Ok(out)
    }

    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT seq, hash, ts, kid, sig FROM checkpoints ORDER BY seq")?;
        let rows = stmt.query_map([], |r| {
            Ok(Checkpoint {
                seq: r.get::<_, i64>(0)? as u64,
                hash: r.get(1)?,
                ts: r.get::<_, i64>(2)? as u64,
                kid: r.get(3)?,
                sig: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Verifies the whole chain and every stored checkpoint. Returns the head.
    pub fn audit_verify(&self) -> Result<Option<(u64, String)>> {
        let entries = self.audit_entries()?;
        let head = audit::verify_chain(&entries).map_err(|e| Error::Conflict(e.to_string()))?;
        for checkpoint in self.checkpoints()? {
            let signed =
                checkpoint.kid == self.key.kid() && checkpoint.signature_valid(&self.key.public());
            if !signed {
                return Err(Error::Conflict(format!(
                    "checkpoint at {} has an invalid signature",
                    checkpoint.seq
                )));
            }
            checkpoint
                .matches(&entries)
                .map_err(|e| Error::Conflict(e.to_string()))?;
        }
        Ok(head)
    }

    /// Signs the current head of the log. Export the result somewhere the
    /// server cannot rewrite; that is what makes truncation detectable.
    pub fn checkpoint(&self, now: u64) -> Result<Option<Checkpoint>> {
        let Some((seq, hash)) = self.audit_verify()? else {
            return Ok(None);
        };
        let checkpoint = Checkpoint::sign(seq, &hash, now, &self.key);
        let conn = self.lock();
        conn.execute(
            "INSERT INTO checkpoints (seq, hash, ts, kid, sig) VALUES (?, ?, ?, ?, ?)",
            params![
                seq as i64,
                checkpoint.hash,
                now as i64,
                checkpoint.kid,
                checkpoint.sig
            ],
        )?;
        Ok(Some(checkpoint))
    }

    // ---- notifications ----

    /// Sets or clears the URL that receives signed event notifications.
    pub fn set_webhook(&self, project: &str, url: Option<&str>, now: u64) -> Result<()> {
        if let Some(url) = url {
            let ok = (url.starts_with("https://") || url.starts_with("http://"))
                && url.len() <= 2000
                && !url.chars().any(|c| c.is_control() || c.is_whitespace());
            if !ok {
                return Err(Error::Invalid("webhook must be an http(s) URL".into()));
            }
        }
        self.set_channel(project, "webhook_url", url, now)
    }

    /// Sets or clears the Telegram chat that is told about pending approvals.
    pub fn set_telegram(&self, project: &str, chat: Option<&str>, now: u64) -> Result<()> {
        if let Some(chat) = chat {
            check_label("telegram chat", chat, 64)?;
        }
        self.set_channel(project, "telegram_chat", chat, now)
    }

    fn set_channel(
        &self,
        project: &str,
        column: &str,
        value: Option<&str>,
        now: u64,
    ) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        project_exists(&tx, project)?;
        tx.execute(
            "INSERT OR IGNORE INTO channels (project) VALUES (?)",
            [project],
        )?;
        tx.execute(
            &format!("UPDATE channels SET {column} = ? WHERE project = ?"),
            params![value, project],
        )?;
        audit_append(
            &tx,
            now,
            "channel.set",
            json!({ "project": project, "channel": column, "value": value }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn outbox_due(&self, now: u64, limit: u32) -> Result<Vec<OutboxItem>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, kind, target, body FROM outbox WHERE done_at IS NULL AND next_at <= ? \
             ORDER BY id LIMIT ?",
        )?;
        let rows = stmt.query_map(params![now as i64, limit], |r| {
            Ok(OutboxItem {
                id: r.get(0)?,
                kind: r.get(1)?,
                target: r.get(2)?,
                body: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records a delivery attempt. Failures are retried with growing delays.
    pub fn outbox_result(&self, id: i64, delivered: bool, now: u64) -> Result<()> {
        let conn = self.lock();
        if delivered {
            conn.execute(
                "UPDATE outbox SET done_at = ? WHERE id = ?",
                params![now as i64, id],
            )?;
            return Ok(());
        }
        let attempts: i64 =
            conn.query_row("SELECT attempts FROM outbox WHERE id = ?", [id], |r| {
                r.get::<_, i64>(0)
            })? + 1;
        if attempts >= OUTBOX_MAX_ATTEMPTS {
            conn.execute(
                "UPDATE outbox SET attempts = ?, failed = 1, done_at = ? WHERE id = ?",
                params![attempts, now as i64, id],
            )?;
        } else {
            let delay = (5i64 << attempts.min(10)).min(3600);
            conn.execute(
                "UPDATE outbox SET attempts = ?, next_at = ? WHERE id = ?",
                params![attempts, now as i64 + delay, id],
            )?;
        }
        Ok(())
    }

    fn approve_url(&self, challenge: &str) -> String {
        format!(
            "{}/approve/{challenge}",
            self.config.public_url.trim_end_matches('/')
        )
    }

    // ---- internals ----

    fn issue_receipt(
        &self,
        conn: &Connection,
        row: &ChallengeRow,
        decision: ReceiptDecision,
        approvals: Vec<Approval>,
        now: u64,
    ) -> Result<String> {
        let payload = ReceiptPayload {
            v: 1,
            id: new_id("rc"),
            project: row.project.clone(),
            challenge: row.id.clone(),
            action_hash: row.action_hash.clone(),
            decision,
            rule: row.rule.clone().unwrap_or_default(),
            approvals,
            binding_expires_at: row.expires_at,
            issued_at: now,
            expires_at: now + self.config.receipt_ttl,
            kid: self.key.kid(),
        };
        let token = payload.issue(&self.key);
        conn.execute(
            "INSERT INTO receipts (id, challenge, project, expires_at) VALUES (?, ?, ?, ?)",
            params![payload.id, row.id, row.project, payload.expires_at as i64],
        )?;
        conn.execute(
            "UPDATE challenges SET receipt = ? WHERE id = ?",
            params![token, row.id],
        )?;
        audit_append(
            conn,
            now,
            "receipt.issued",
            json!({ "project": row.project, "challenge": row.id, "receipt": payload.id,
                    "action_hash": row.action_hash }),
        )?;
        Ok(token)
    }

    fn view(&self, conn: &Connection, row: ChallengeRow) -> Result<ChallengeView> {
        let pending = row.state == "pending";
        Ok(ChallengeView {
            approvals: approvals_of(conn, &row.id)?
                .into_iter()
                .map(|a| a.0)
                .collect(),
            requirements: row
                .requirements
                .is_some()
                .then(|| row.requirements())
                .transpose()?,
            approve_url: pending.then(|| self.approve_url(&row.id)),
            id: row.id,
            state: row.state,
            action_hash: row.action_hash,
            rule: row.rule,
            expires_at: row.expires_at,
            receipt: row.receipt,
        })
    }
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Finds an enrollment that is neither used nor expired.
fn open_enrollment(
    conn: &Connection,
    token: &str,
    now: u64,
) -> Result<(String, String, String, u64)> {
    let found: Option<(String, String, String, i64)> = conn
        .query_row(
            "SELECT project, approver, challenge, expires_at FROM enrollments \
             WHERE token_hash = ? AND used_at IS NULL",
            [token_hash(token)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    match found {
        Some((project, approver, challenge, expires_at)) if now <= expires_at as u64 => {
            Ok((project, approver, challenge, expires_at as u64))
        }
        _ => Err(Error::NotFound),
    }
}

fn project_exists(conn: &Connection, project: &str) -> Result<()> {
    conn.query_row("SELECT 1 FROM projects WHERE id = ?", [project], |r| {
        r.get::<_, i64>(0)
    })
    .optional()?
    .map(|_| ())
    .ok_or(Error::NotFound)
}

fn approvals_of(conn: &Connection, challenge: &str) -> Result<Vec<(ApprovalView, String)>> {
    let mut stmt = conn.prepare(
        "SELECT approver, kind, sig FROM approvals WHERE challenge = ? ORDER BY created_at, credential",
    )?;
    let rows = stmt.query_map([challenge], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (approver, kind, sig) = row?;
        let kind = ApproverKind::parse(&kind).ok_or_else(|| internal("stored approval kind"))?;
        out.push((ApprovalView { approver, kind }, sig));
    }
    Ok(out)
}

/// Loads a challenge, recording its expiry if the deadline has passed.
fn load(conn: &Connection, id: &str, now: u64) -> Result<ChallengeRow> {
    let mut row = conn
        .query_row(
            "SELECT id, project, action, action_hash, state, rule, requirements, expires_at, receipt \
             FROM challenges WHERE id = ?",
            [id],
            |r| {
                Ok(ChallengeRow {
                    id: r.get(0)?,
                    project: r.get(1)?,
                    action: r.get(2)?,
                    action_hash: r.get(3)?,
                    state: r.get(4)?,
                    rule: r.get(5)?,
                    requirements: r.get(6)?,
                    expires_at: r.get::<_, i64>(7)? as u64,
                    receipt: r.get(8)?,
                })
            },
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if row.state == "pending" && now > row.expires_at {
        conn.execute(
            "UPDATE challenges SET state = 'expired', decided_at = ? WHERE id = ?",
            params![now as i64, row.id],
        )?;
        audit_append(
            conn,
            now,
            "challenge.expired",
            json!({ "project": row.project, "challenge": row.id }),
        )?;
        row.state = "expired".into();
        emit(
            conn,
            now,
            &row.project,
            "challenge.expired",
            json!({ "challenge": row.id }),
        )?;
    }
    Ok(row)
}
