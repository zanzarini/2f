//! Everything the server does, as plain synchronous functions.
//!
//! Writes go through `Store::write` (serialized, batched, durable before the
//! caller hears back). Reads go through `Store::read`. Rows that grant power
//! carry a seal and are ignored when it does not verify; see `twof_core::seal`.

use crate::error::{Error, Result};
use crate::store::Store;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Params, Row};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use twof_core::audit::{self, Checkpoint, Entry};
use twof_core::keys::{self, ServerKey};
use twof_core::passkey::{self, AssertionProof, RelyingParty};
use twof_core::policy::{all_satisfied, Outcome, PolicyContext};
use twof_core::receipt::{self, ReceiptDecision};
use twof_core::{canonical, seal};
use twof_core::{
    Action, Approval, ApprovalFact, ApproverKind, Binding, Policy, ReceiptPayload, Requirement,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, policy TEXT NOT NULL, policy_seal TEXT,
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, project TEXT NOT NULL REFERENCES projects(id), hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL, seal TEXT, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS approvers (
    project TEXT NOT NULL REFERENCES projects(id), id TEXT NOT NULL, name TEXT NOT NULL,
    created_at INTEGER NOT NULL, disabled_at INTEGER, PRIMARY KEY (project, id));
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY, project TEXT NOT NULL, approver TEXT NOT NULL, kind TEXT NOT NULL,
    public_key TEXT NOT NULL, external_id TEXT UNIQUE, counter INTEGER NOT NULL DEFAULT 0,
    seal TEXT, created_at INTEGER NOT NULL, revoked_at INTEGER,
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
    prev TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (
    seq INTEGER NOT NULL, hash TEXT NOT NULL, ts INTEGER NOT NULL, kid TEXT NOT NULL,
    sig TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS channels (
    project TEXT PRIMARY KEY REFERENCES projects(id), webhook_url TEXT, telegram_chat TEXT);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, kind TEXT NOT NULL,
    target TEXT NOT NULL, body TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL, done_at INTEGER, failed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_at) WHERE done_at IS NULL;
";

/// Deliveries are retried this many times before being given up on.
pub const OUTBOX_MAX_ATTEMPTS: i64 = 10;
/// How long an enrollment link stays usable, in seconds.
pub const ENROLLMENT_TTL: u64 = 15 * 60;
const SEAL_CACHE_MAX: usize = 100_000;

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

/// A notification waiting to be delivered.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboxItem {
    pub id: i64,
    pub kind: String,
    pub target: String,
    pub body: String,
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

    fn overdue(&self, now: u64) -> bool {
        self.state == "pending" && now > self.expires_at
    }
}

// ---- small helpers ----

fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

fn internal(e: impl std::fmt::Display) -> Error {
    Error::Internal(e.to_string())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Runs a cached query expecting at most one row.
fn one<T>(
    conn: &Connection,
    sql: &str,
    params: impl Params,
    map: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Option<T>> {
    Ok(conn
        .prepare_cached(sql)?
        .query_row(params, map)
        .optional()?)
}

/// Runs a cached statement. Returns the number of rows changed.
fn exec(conn: &Connection, sql: &str, params: impl Params) -> Result<usize> {
    Ok(conn.prepare_cached(sql)?.execute(params)?)
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

fn project_exists(conn: &Connection, project: &str) -> Result<()> {
    one(
        conn,
        "SELECT 1 FROM projects WHERE id = ?",
        [project],
        |r| r.get::<_, i64>(0),
    )?
    .map(|_| ())
    .ok_or(Error::NotFound)
}

fn approver_active(conn: &Connection, project: &str, approver: &str) -> Result<()> {
    one(
        conn,
        "SELECT 1 FROM approvers WHERE project = ? AND id = ? AND disabled_at IS NULL",
        params![project, approver],
        |r| r.get::<_, i64>(0),
    )?
    .map(|_| ())
    .ok_or(Error::NotFound)
}

fn policy_fields(project: &str, policy: &str) -> Value {
    json!({ "t": "policy", "project": project, "policy": policy })
}

fn apikey_fields(project: &str, id: &str, hash: &str) -> Value {
    json!({ "t": "apikey", "project": project, "id": id, "hash": hash })
}

fn credential_fields(
    project: &str,
    approver: &str,
    id: &str,
    kind: &str,
    public_key: &str,
    external_id: Option<&str>,
) -> Value {
    json!({ "t": "credential", "project": project, "approver": approver, "id": id,
            "kind": kind, "public_key": public_key, "external_id": external_id })
}

/// The parts of the service that operations need while they run.
struct Inner {
    key: ServerKey,
    public: VerifyingKey,
    config: Config,
    /// Seals already verified, so hot paths do not repeat the signature check.
    verified: Mutex<HashSet<[u8; 32]>>,
}

impl Inner {
    fn seal(&self, fields: &Value) -> String {
        seal::sign(&self.key, fields)
    }

    /// True when `seal` is this server's seal over `fields`.
    fn sealed(&self, fields: &Value, seal: Option<&str>) -> bool {
        let Some(seal) = seal else { return false };
        let mut hasher = Sha256::new();
        hasher.update(seal::message(fields));
        hasher.update([0]);
        hasher.update(seal.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        if self
            .verified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&digest)
        {
            return true;
        }
        if !seal::verify(&self.public, fields, seal) {
            return false;
        }
        let mut cache = self.verified.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= SEAL_CACHE_MAX {
            cache.clear();
        }
        cache.insert(digest);
        true
    }

    fn approve_url(&self, challenge: &str) -> String {
        format!(
            "{}/approve/{challenge}",
            self.config.public_url.trim_end_matches('/')
        )
    }

    /// Appends to the audit chain inside the caller's transaction, so a state
    /// change and its audit entry are committed together or not at all.
    fn audit(&self, conn: &Connection, now: u64, kind: &str, data: Value) -> Result<()> {
        let prev = one(
            conn,
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )?;
        let prev_ref = prev
            .as_ref()
            .map(|(seq, hash)| (*seq as u64, hash.as_str()));
        let entry = audit::next_entry(prev_ref, now, kind, data)?;
        exec(
            conn,
            "INSERT INTO audit (seq, ts, kind, data, prev, hash, sig) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                entry.seq as i64,
                entry.ts as i64,
                entry.kind,
                canonical::to_canonical(&entry.data)?,
                entry.prev,
                entry.hash,
                audit::sign_entry(&self.key, &entry.hash)
            ],
        )?;
        Ok(())
    }

    /// The project's policy, or deny-all when it is missing, unparseable or
    /// its seal does not verify.
    fn policy(&self, conn: &Connection, project: &str) -> Result<Policy> {
        let (text, seal) = one(
            conn,
            "SELECT policy, policy_seal FROM projects WHERE id = ?",
            [project],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )?
        .ok_or(Error::NotFound)?;
        if !self.sealed(&policy_fields(project, &text), seal.as_deref()) {
            return Ok(Policy::deny_all());
        }
        Ok(Policy::parse(&text).unwrap_or_else(|_| Policy::deny_all()))
    }

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
        exec(
            conn,
            "INSERT INTO receipts (id, challenge, project, expires_at) VALUES (?, ?, ?, ?)",
            params![payload.id, row.id, row.project, payload.expires_at as i64],
        )?;
        exec(
            conn,
            "UPDATE challenges SET receipt = ? WHERE id = ?",
            params![token, row.id],
        )?;
        self.audit(
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

    fn approver_view(&self, conn: &Connection, row: ChallengeRow) -> Result<ApproverView> {
        let project_name = one(
            conn,
            "SELECT name FROM projects WHERE id = ?",
            [&row.project],
            |r| r.get(0),
        )?
        .ok_or(Error::NotFound)?;
        let binding = row.binding();
        Ok(ApproverView {
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
            approvals: approvals_of(conn, &row.id)?
                .into_iter()
                .map(|a| a.0)
                .collect(),
        })
    }

    /// Loads a challenge, recording its expiry if the deadline has passed.
    fn load(&self, conn: &Connection, id: &str, now: u64) -> Result<ChallengeRow> {
        let mut row = fetch(conn, id)?;
        if row.overdue(now) {
            exec(
                conn,
                "UPDATE challenges SET state = 'expired', decided_at = ? WHERE id = ?",
                params![now as i64, row.id],
            )?;
            self.audit(
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
}

fn fetch(conn: &Connection, id: &str) -> Result<ChallengeRow> {
    one(
        conn,
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
    )?
    .ok_or(Error::NotFound)
}

/// Approvals that still count: given through a credential that has not been
/// revoked, by an approver that has not been disabled since.
fn approvals_of(conn: &Connection, challenge: &str) -> Result<Vec<(ApprovalView, String)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.approver, a.kind, a.sig FROM approvals a \
         JOIN credentials c ON c.id = a.credential \
         JOIN approvers p ON p.project = c.project AND p.id = c.approver \
         WHERE a.challenge = ? AND c.revoked_at IS NULL AND p.disabled_at IS NULL \
         ORDER BY a.created_at, a.credential",
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

/// Queues notifications for an event, inside the caller's transaction.
fn emit(conn: &Connection, now: u64, project: &str, event: &str, data: Value) -> Result<()> {
    let channels = one(
        conn,
        "SELECT webhook_url, telegram_chat FROM channels WHERE project = ?",
        [project],
        |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        },
    )?;
    let Some((webhook, telegram)) = channels else {
        return Ok(());
    };
    let queue = |kind: &str, target: &str, body: &str| {
        exec(
            conn,
            "INSERT INTO outbox (project, kind, target, body, next_at) VALUES (?, ?, ?, ?, ?)",
            params![project, kind, target, body, now as i64],
        )
    };
    if let (Some(chat), "challenge.pending") = (&telegram, event) {
        let text = |name: &str| data["action"][name].as_str().unwrap_or("-").to_owned();
        let message = format!(
            "2F: approval needed\nOperation: {}\nAmount: {} {}\nDestination: {}\nOpen: {}",
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

/// Finds an enrollment that is neither used nor expired.
fn open_enrollment(
    conn: &Connection,
    token: &str,
    now: u64,
) -> Result<(String, String, String, u64)> {
    let found = one(
        conn,
        "SELECT project, approver, challenge, expires_at FROM enrollments \
         WHERE token_hash = ? AND used_at IS NULL",
        [token_hash(token)],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? as u64,
            ))
        },
    )?;
    match found {
        Some(enrollment) if now <= enrollment.3 => Ok(enrollment),
        _ => Err(Error::NotFound),
    }
}

struct VelocityCtx<'a> {
    conn: &'a Connection,
    project: &'a str,
    now: u64,
}

impl VelocityCtx<'_> {
    fn total(&self, asset: &str, window_secs: u64) -> rusqlite::Result<Option<Decimal>> {
        let since = self.now.saturating_sub(window_secs) as i64;
        let mut stmt = self.conn.prepare_cached(
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

type CredentialRecord = (String, String, String, String);

pub struct Service {
    inner: Arc<Inner>,
    store: Store,
    pub config: Config,
}

impl Service {
    pub fn open(path: &Path, key: ServerKey, config: Config) -> Result<Self> {
        Self::with_store(Store::open(Some(path), SCHEMA)?, key, config)
    }

    pub fn open_in_memory(key: ServerKey, config: Config) -> Result<Self> {
        Self::with_store(Store::open(None, SCHEMA)?, key, config)
    }

    fn with_store(store: Store, key: ServerKey, config: Config) -> Result<Self> {
        let inner = Inner {
            public: key.public(),
            key,
            config: config.clone(),
            verified: Mutex::new(HashSet::new()),
        };
        Ok(Service {
            inner: Arc::new(inner),
            store,
            config,
        })
    }

    pub fn key(&self) -> &ServerKey {
        &self.inner.key
    }

    /// Notified after every committed change; used for long polling.
    pub fn changed(&self) -> Arc<Notify> {
        self.store.changed.clone()
    }

    // ---- administration (reached through the CLI, never through HTTP) ----

    pub fn create_project(&self, name: &str, now: u64) -> Result<String> {
        check_label("project name", name, 100)?;
        let (inner, name) = (self.inner.clone(), name.to_owned());
        self.store.write(move |conn| {
            let id = new_id("pj");
            let policy = serde_json::to_string(&Policy::deny_all()).map_err(internal)?;
            exec(
                conn,
                "INSERT INTO projects (id, name, policy, policy_seal, created_at) VALUES (?, ?, ?, ?, ?)",
                params![id, name, policy, inner.seal(&policy_fields(&id, &policy)), now as i64],
            )?;
            inner.audit(conn, now, "project.created", json!({ "project": id, "name": name }))?;
            Ok(id)
        })
    }

    pub fn list_projects(&self) -> Result<Vec<(String, String)>> {
        self.store.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT id, name FROM projects ORDER BY created_at, id")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Returns the API key. It is shown once: only its hash is stored.
    pub fn create_api_key(&self, project: &str, label: &str, now: u64) -> Result<String> {
        check_label("label", label, 100)?;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = format!("2f_{}", B64.encode(secret));
        let hash = token_hash(&token);
        let (inner, project, label) = (self.inner.clone(), project.to_owned(), label.to_owned());
        self.store.write(move |conn| {
            project_exists(conn, &project)?;
            let id = new_id("ak");
            let seal = inner.seal(&apikey_fields(&project, &id, &hash));
            exec(
                conn,
                "INSERT INTO api_keys (id, project, hash, label, seal, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                params![id, project, hash, label, seal, now as i64],
            )?;
            inner.audit(
                conn,
                now,
                "apikey.created",
                json!({ "project": project, "key": id, "label": label }),
            )
        })?;
        Ok(token)
    }

    pub fn revoke_api_keys(&self, project: &str, now: u64) -> Result<usize> {
        let (inner, project) = (self.inner.clone(), project.to_owned());
        self.store.write(move |conn| {
            let changed = exec(
                conn,
                "UPDATE api_keys SET revoked_at = ?, seal = NULL WHERE project = ? AND revoked_at IS NULL",
                params![now as i64, project],
            )?;
            inner.audit(
                conn,
                now,
                "apikey.revoked_all",
                json!({ "project": project, "count": changed }),
            )?;
            Ok(changed)
        })
    }

    pub fn set_policy(&self, project: &str, policy_json: &str, now: u64) -> Result<()> {
        let policy = Policy::parse(policy_json).map_err(|e| Error::Invalid(e.to_string()))?;
        let stored = serde_json::to_string(&policy).map_err(internal)?;
        let value = serde_json::to_value(&policy).map_err(internal)?;
        let (inner, project) = (self.inner.clone(), project.to_owned());
        self.store.write(move |conn| {
            project_exists(conn, &project)?;
            exec(
                conn,
                "UPDATE projects SET policy = ?, policy_seal = ? WHERE id = ?",
                params![
                    stored,
                    inner.seal(&policy_fields(&project, &stored)),
                    project
                ],
            )?;
            inner.audit(
                conn,
                now,
                "policy.set",
                json!({ "project": project, "policy": value }),
            )
        })
    }

    pub fn get_policy(&self, project: &str) -> Result<String> {
        let project = project.to_owned();
        self.store.read(move |conn| {
            one(
                conn,
                "SELECT policy FROM projects WHERE id = ?",
                [&project],
                |r| r.get(0),
            )?
            .ok_or(Error::NotFound)
        })
    }

    pub fn add_approver(&self, project: &str, id: &str, name: &str, now: u64) -> Result<()> {
        check_slug("approver id", id)?;
        check_label("approver name", name, 100)?;
        let (inner, project, id, name) = (
            self.inner.clone(),
            project.to_owned(),
            id.to_owned(),
            name.to_owned(),
        );
        self.store.write(move |conn| {
            project_exists(conn, &project)?;
            let inserted = exec(
                conn,
                "INSERT OR IGNORE INTO approvers (project, id, name, created_at) VALUES (?, ?, ?, ?)",
                params![project, id, name, now as i64],
            )?;
            if inserted == 0 {
                return Err(Error::Conflict(format!("approver \"{id}\" already exists")));
            }
            inner.audit(
                conn,
                now,
                "approver.added",
                json!({ "project": project, "approver": id, "name": name }),
            )
        })
    }

    /// Disables an approver for good and revokes every credential they hold.
    /// Approvals they gave on challenges still pending stop counting.
    pub fn disable_approver(&self, project: &str, id: &str, now: u64) -> Result<()> {
        let (inner, project, id) = (self.inner.clone(), project.to_owned(), id.to_owned());
        self.store.write(move |conn| {
            let changed = exec(
                conn,
                "UPDATE approvers SET disabled_at = ? WHERE project = ? AND id = ? AND disabled_at IS NULL",
                params![now as i64, project, id],
            )?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            exec(
                conn,
                "UPDATE credentials SET revoked_at = ?, seal = NULL \
                 WHERE project = ? AND approver = ? AND revoked_at IS NULL",
                params![now as i64, project, id],
            )?;
            inner.audit(
                conn,
                now,
                "approver.disabled",
                json!({ "project": project, "approver": id }),
            )
        })
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
        let (inner, project, approver) =
            (self.inner.clone(), project.to_owned(), approver.to_owned());
        self.store.write(move |conn| {
            approver_active(conn, &project, &approver)?;
            let id = new_id("cr");
            let fields =
                credential_fields(&project, &approver, &id, kind.as_str(), &public_key, None);
            exec(
                conn,
                "INSERT INTO credentials (id, project, approver, kind, public_key, seal, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![id, project, approver, kind.as_str(), public_key, inner.seal(&fields), now as i64],
            )?;
            inner.audit(
                conn,
                now,
                "credential.added",
                json!({ "project": project, "approver": approver, "credential": id,
                        "kind": kind.as_str(), "public_key": public_key }),
            )?;
            Ok(id)
        })
    }

    pub fn revoke_credential(&self, project: &str, credential: &str, now: u64) -> Result<()> {
        let (inner, project, credential) = (
            self.inner.clone(),
            project.to_owned(),
            credential.to_owned(),
        );
        self.store.write(move |conn| {
            let changed = exec(
                conn,
                "UPDATE credentials SET revoked_at = ?, seal = NULL \
                 WHERE id = ? AND project = ? AND revoked_at IS NULL",
                params![now as i64, credential, project],
            )?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            inner.audit(
                conn,
                now,
                "credential.revoked",
                json!({ "project": project, "credential": credential }),
            )
        })
    }

    /// Creates a one time link for an approver to enroll a passkey. Returns
    /// the token; the link is `{public_url}/enroll/{token}`.
    pub fn create_enrollment(&self, project: &str, approver: &str, now: u64) -> Result<String> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = B64.encode(secret);
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        let hash = token_hash(&token);
        let (inner, project, approver) =
            (self.inner.clone(), project.to_owned(), approver.to_owned());
        self.store.write(move |conn| {
            approver_active(conn, &project, &approver)?;
            exec(
                conn,
                "INSERT INTO enrollments (token_hash, project, approver, challenge, expires_at) VALUES (?, ?, ?, ?, ?)",
                params![hash, project, approver, B64.encode(challenge), (now + ENROLLMENT_TTL) as i64],
            )?;
            inner.audit(
                conn,
                now,
                "enrollment.created",
                json!({ "project": project, "approver": approver }),
            )
        })?;
        Ok(token)
    }

    pub fn enrollment_url(&self, token: &str) -> String {
        format!(
            "{}/enroll/{token}",
            self.config.public_url.trim_end_matches('/')
        )
    }

    pub fn enrollment_view(&self, token: &str, now: u64) -> Result<EnrollmentView> {
        let (inner, token) = (self.inner.clone(), token.to_owned());
        self.store.read(move |conn| {
            let (project, approver, challenge, expires_at) = open_enrollment(conn, &token, now)?;
            let project_name = one(
                conn,
                "SELECT name FROM projects WHERE id = ?",
                [&project],
                |r| r.get(0),
            )?
            .ok_or(Error::NotFound)?;
            let approver_name = one(
                conn,
                "SELECT name FROM approvers WHERE project = ? AND id = ? AND disabled_at IS NULL",
                params![project, approver],
                |r| r.get(0),
            )?
            .ok_or(Error::NotFound)?;
            let user_id = Sha256::digest(format!("{project}/{approver}").as_bytes());
            Ok(EnrollmentView {
                project_name,
                approver_name,
                rp_id: inner.config.relying_party()?.id,
                challenge,
                user_id: B64.encode(&user_id[..16]),
                expires_at,
                approver,
            })
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
        let algorithm = reg.algorithm;
        let (inner, token) = (self.inner.clone(), token.to_owned());
        self.store.write(move |conn| {
            let rp = inner.config.relying_party()?;
            let (project, approver, challenge, _) = open_enrollment(conn, &token, now)?;
            approver_active(conn, &project, &approver)?;
            let challenge = B64.decode(challenge).map_err(internal)?;
            let external_id = passkey::verify_registration(
                &rp,
                &challenge,
                &authenticator_data,
                &client_data_json,
                &public_key,
                algorithm,
            )
            .map_err(|e| Error::Forbidden(e.to_string()))?;
            let id = new_id("cr");
            let external_id = B64.encode(external_id);
            let public_key = hex::encode(public_key);
            let fields = credential_fields(
                &project,
                &approver,
                &id,
                "passkey",
                &public_key,
                Some(&external_id),
            );
            let inserted = exec(
                conn,
                "INSERT OR IGNORE INTO credentials (id, project, approver, kind, public_key, external_id, seal, created_at) \
                 VALUES (?, ?, ?, 'passkey', ?, ?, ?, ?)",
                params![id, project, approver, public_key, external_id, inner.seal(&fields), now as i64],
            )?;
            if inserted == 0 {
                return Err(Error::Conflict("this passkey is already enrolled".into()));
            }
            exec(
                conn,
                "UPDATE enrollments SET used_at = ? WHERE token_hash = ?",
                params![now as i64, token_hash(&token)],
            )?;
            inner.audit(
                conn,
                now,
                "credential.added",
                json!({ "project": project, "approver": approver, "credential": id, "kind": "passkey",
                        "public_key": public_key, "external_id": external_id }),
            )?;
            Ok(id)
        })
    }

    // ---- client API ----

    /// Resolves an API key to its project.
    pub fn authenticate(&self, token: &str) -> Result<String> {
        let (inner, hash) = (self.inner.clone(), token_hash(token));
        self.store.read(move |conn| {
            let (project, id, seal) = one(
                conn,
                "SELECT project, id, seal FROM api_keys WHERE hash = ? AND revoked_at IS NULL",
                [&hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )?
            .ok_or(Error::Unauthorized)?;
            // A row someone wrote into the table without the signing key is not a key.
            if !inner.sealed(&apikey_fields(&project, &id, &hash), seal.as_deref()) {
                return Err(Error::Unauthorized);
            }
            Ok(project)
        })
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
        let action_value = serde_json::to_value(&action).map_err(internal)?;
        let (inner, project, idempotency_key) = (
            self.inner.clone(),
            project.to_owned(),
            idempotency_key.to_owned(),
        );

        self.store.write(move |conn| {
            let existing = one(
                conn,
                "SELECT id, action_hash FROM challenges WHERE project = ? AND idempotency_key = ?",
                params![project, idempotency_key],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?;
            if let Some((id, existing_hash)) = existing {
                if existing_hash != action_hash {
                    return Err(Error::Conflict(
                        "idempotency_key was already used for a different action".into(),
                    ));
                }
                let row = inner.load(conn, &id, now)?;
                return inner.view(conn, row);
            }

            let policy = inner.policy(conn, &project)?;
            let decision = policy.evaluate(&action, &VelocityCtx { conn, project: &project, now });
            let (state, requirements) = match &decision.outcome {
                Outcome::Allow => ("allowed", None),
                Outcome::Deny => ("denied", None),
                Outcome::Require { requirements } => {
                    ("pending", Some(serde_json::to_string(requirements).map_err(internal)?))
                }
            };
            let id = new_id("ch");
            let expires_at = now + inner.config.challenge_ttl;
            let decided_at = (state != "pending").then_some(now as i64);
            exec(
                conn,
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
            inner.audit(
                conn,
                now,
                "challenge.created",
                json!({ "project": project, "challenge": id, "action_hash": action_hash,
                        "action": action_value, "state": state, "rule": decision.rule }),
            )?;
            let mut row = ChallengeRow {
                id,
                project,
                action: action_text,
                action_hash,
                state: state.to_owned(),
                rule: decision.rule,
                requirements,
                expires_at,
                receipt: None,
            };
            if state == "pending" {
                let binding = row.binding();
                let data = json!({
                    "challenge": row.id,
                    "action": action_value,
                    "binding_hash": B64.encode(binding.hash()),
                    "reject_hash": B64.encode(binding.reject_hash()),
                    "binding": serde_json::to_value(&binding).map_err(internal)?,
                    "approve_url": inner.approve_url(&row.id),
                    "rule": row.rule,
                });
                emit(conn, now, &row.project, "challenge.pending", data)?;
            }
            if state == "allowed" {
                let token =
                    inner.issue_receipt(conn, &row, ReceiptDecision::Allow, Vec::new(), now)?;
                row.receipt = Some(token);
            }
            inner.view(conn, row)
        })
    }

    pub fn get_challenge(&self, project: &str, id: &str, now: u64) -> Result<ChallengeView> {
        let (inner, project_ro, id_ro) = (self.inner.clone(), project.to_owned(), id.to_owned());
        let fresh = self.store.read(move |conn| {
            let row = fetch(conn, &id_ro)?;
            if row.project != project_ro {
                return Err(Error::NotFound);
            }
            if row.overdue(now) {
                return Ok(None); // the expiry has to be recorded first
            }
            inner.view(conn, row).map(Some)
        })?;
        if let Some(view) = fresh {
            return Ok(view);
        }
        let (inner, project, id) = (self.inner.clone(), project.to_owned(), id.to_owned());
        self.store.write(move |conn| {
            let row = inner.load(conn, &id, now)?;
            if row.project != project {
                return Err(Error::NotFound);
            }
            inner.view(conn, row)
        })
    }

    /// The challenge as an approver needs to see it. Reachable by anyone who
    /// holds the challenge id, which is 128 random bits.
    pub fn approver_view(&self, id: &str, now: u64) -> Result<ApproverView> {
        let (inner, id_ro) = (self.inner.clone(), id.to_owned());
        let fresh = self.store.read(move |conn| {
            let row = fetch(conn, &id_ro)?;
            if row.overdue(now) {
                return Ok(None);
            }
            inner.approver_view(conn, row).map(Some)
        })?;
        if let Some(view) = fresh {
            return Ok(view);
        }
        let (inner, id) = (self.inner.clone(), id.to_owned());
        self.store.write(move |conn| {
            let row = inner.load(conn, &id, now)?;
            inner.approver_view(conn, row)
        })
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
    /// must verify against a sealed credential of the challenge's project.
    pub fn submit(&self, id: &str, proof: &Proof, reject: bool, now: u64) -> Result<ChallengeView> {
        let (inner, id, proof) = (self.inner.clone(), id.to_owned(), proof.clone());
        self.store.write(move |conn| {
            let denied = || Error::Forbidden("credential or signature not accepted".into());
            let mut row = fetch(conn, &id)?;
            if row.overdue(now) {
                return Err(Error::Conflict("challenge is expired".into()));
            }
            if row.state != "pending" {
                return Err(Error::Conflict(format!("challenge is {}", row.state)));
            }
            let (column, lookup) = match &proof {
                Proof::Signature { credential, .. } => ("c.id", credential),
                Proof::Passkey { credential_id, .. } => ("c.external_id", credential_id),
            };
            let found = one(
                conn,
                &format!(
                    "SELECT c.id, c.approver, c.kind, c.public_key, c.external_id, c.counter, c.seal \
                     FROM credentials c JOIN approvers a ON a.project = c.project AND a.id = c.approver \
                     WHERE {column} = ? AND c.project = ? AND c.revoked_at IS NULL AND a.disabled_at IS NULL"
                ),
                params![lookup, row.project],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                },
            )?;
            let (credential, approver, kind_text, public_key, external_id, counter, seal) =
                found.ok_or_else(denied)?;
            // A credential row written without the signing key is not a credential.
            let fields = credential_fields(
                &row.project,
                &approver,
                &credential,
                &kind_text,
                &public_key,
                external_id.as_deref(),
            );
            if !inner.sealed(&fields, seal.as_deref()) {
                return Err(denied());
            }
            let kind = ApproverKind::parse(&kind_text)
                .ok_or_else(|| internal("stored credential kind"))?;
            let requirements = row.requirements()?;
            let fact = ApprovalFact { approver: approver.clone(), kind };
            if !requirements.iter().any(|r| r.accepts(&fact)) {
                return Err(denied());
            }

            let binding = row.binding();
            let message = if reject { binding.reject_hash() } else { binding.hash() };
            // The proof as it is kept in the audit log and carried in the receipt.
            let stored_proof = match (kind, &proof) {
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
                    let rp = inner.config.relying_party()?;
                    let spki = hex::decode(&public_key).map_err(internal)?;
                    let received = passkey::verify_proof(&rp, &spki, &message, assertion)
                        .map_err(|_| denied())?;
                    let stored = u32::try_from(counter).map_err(internal)?;
                    passkey::check_counter(stored, received).map_err(|_| denied())?;
                    exec(
                        conn,
                        "UPDATE credentials SET counter = ? WHERE id = ?",
                        params![i64::from(received), credential],
                    )?;
                    assertion.encode()
                }
                _ => return Err(denied()),
            };

            let evidence = json!({ "project": row.project, "challenge": row.id, "approver": approver,
                                   "credential": credential, "kind": kind.as_str(), "sig": stored_proof });
            if reject {
                exec(
                    conn,
                    "UPDATE challenges SET state = 'rejected', decided_at = ? WHERE id = ?",
                    params![now as i64, row.id],
                )?;
                inner.audit(conn, now, "challenge.rejected", evidence)?;
                row.state = "rejected".into();
                emit(
                    conn,
                    now,
                    &row.project,
                    "challenge.rejected",
                    json!({ "challenge": row.id, "approver": approver }),
                )?;
            } else {
                let inserted = exec(
                    conn,
                    "INSERT OR IGNORE INTO approvals (challenge, approver, credential, kind, sig, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                    params![row.id, approver, credential, kind.as_str(), stored_proof, now as i64],
                )?;
                if inserted == 1 {
                    inner.audit(conn, now, "approval.accepted", evidence)?;
                }
                let approvals = approvals_of(conn, &row.id)?;
                let facts: Vec<ApprovalFact> = approvals
                    .iter()
                    .map(|(a, _)| ApprovalFact { approver: a.approver.clone(), kind: a.kind })
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
                    exec(
                        conn,
                        "UPDATE challenges SET state = 'approved', decided_at = ? WHERE id = ?",
                        params![now as i64, row.id],
                    )?;
                    row.state = "approved".into();
                    emit(
                        conn,
                        now,
                        &row.project,
                        "challenge.approved",
                        json!({ "challenge": row.id }),
                    )?;
                    let token =
                        inner.issue_receipt(conn, &row, ReceiptDecision::Approved, proofs, now)?;
                    row.receipt = Some(token);
                }
            }
            inner.view(conn, row)
        })
    }

    /// Marks a receipt as used. Succeeds exactly once per receipt.
    pub fn consume_receipt(&self, project: &str, token: &str, now: u64) -> Result<ReceiptPayload> {
        let key = &self.inner.key;
        let lookup = |kid: &str| (kid == key.kid()).then(|| key.public());
        let payload = receipt::verify_signature(token, &lookup, now)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if payload.project != project {
            return Err(Error::NotFound);
        }
        let (inner, project) = (self.inner.clone(), project.to_owned());
        self.store.write(move |conn| {
            let changed = exec(
                conn,
                "UPDATE receipts SET consumed_at = ? WHERE id = ? AND project = ? AND consumed_at IS NULL",
                params![now as i64, payload.id, project],
            )?;
            if changed == 0 {
                let exists = one(
                    conn,
                    "SELECT 1 FROM receipts WHERE id = ? AND project = ?",
                    params![payload.id, project],
                    |r| r.get::<_, i64>(0),
                )?;
                return Err(match exists {
                    Some(_) => Error::Conflict("receipt was already used".into()),
                    None => Error::NotFound,
                });
            }
            inner.audit(
                conn,
                now,
                "receipt.consumed",
                json!({ "project": project, "receipt": payload.id, "challenge": payload.challenge }),
            )?;
            Ok(payload)
        })
    }

    pub fn public_keys(&self) -> Vec<PublicKeyView> {
        let key = &self.inner.key;
        vec![PublicKeyView {
            kid: key.kid(),
            alg: "ed25519",
            public_key: key.public_hex(),
        }]
    }

    // ---- audit ----

    pub fn audit_entries(&self) -> Result<Vec<Entry>> {
        Ok(self
            .audit_rows()?
            .into_iter()
            .map(|(entry, _)| entry)
            .collect())
    }

    fn audit_rows(&self) -> Result<Vec<(Entry, String)>> {
        self.store.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT seq, ts, kind, data, prev, hash, sig FROM audit ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (seq, ts, kind, data, prev, hash, sig) = row?;
                // Unparseable data is kept as a string so verification reports
                // the entry as altered instead of failing to run.
                let data = canonical::parse_strict(&data).unwrap_or(Value::String(data));
                out.push((
                    Entry {
                        seq: seq as u64,
                        ts: ts as u64,
                        kind,
                        data,
                        prev,
                        hash,
                    },
                    sig,
                ));
            }
            Ok(out)
        })
    }

    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        self.store.read(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT seq, hash, ts, kid, sig FROM checkpoints ORDER BY seq")?;
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
        })
    }

    /// Verifies the hash chain, every entry signature, every stored
    /// checkpoint, and that the credentials and API keys in use are exactly
    /// the ones the log says were granted. Returns the head of the log.
    pub fn audit_verify(&self) -> Result<Option<(u64, String)>> {
        let rows = self.audit_rows()?;
        let public = &self.inner.public;
        for (entry, sig) in &rows {
            if !audit::entry_signature_valid(public, &entry.hash, sig) {
                return Err(Error::Conflict(format!(
                    "entry {}: not signed by this server",
                    entry.seq
                )));
            }
        }
        let entries: Vec<Entry> = rows.into_iter().map(|(entry, _)| entry).collect();
        let head = audit::verify_chain(&entries).map_err(|e| Error::Conflict(e.to_string()))?;
        for checkpoint in self.checkpoints()? {
            let signed =
                checkpoint.kid == self.inner.key.kid() && checkpoint.signature_valid(public);
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

        // Replay the log into the set of grants that should be active now.
        let text = |entry: &Entry, field: &str| entry.data[field].as_str().unwrap_or("").to_owned();
        let mut credentials: BTreeMap<String, CredentialRecord> = BTreeMap::new();
        let mut api_keys: BTreeSet<(String, String)> = BTreeSet::new();
        for entry in &entries {
            match entry.kind.as_str() {
                "credential.added" => {
                    credentials.insert(
                        text(entry, "credential"),
                        (
                            text(entry, "project"),
                            text(entry, "approver"),
                            text(entry, "kind"),
                            text(entry, "public_key"),
                        ),
                    );
                }
                "credential.revoked" => {
                    credentials.remove(&text(entry, "credential"));
                }
                "approver.disabled" => {
                    let (project, approver) = (text(entry, "project"), text(entry, "approver"));
                    credentials.retain(|_, c| !(c.0 == project && c.1 == approver));
                }
                "apikey.created" => {
                    api_keys.insert((text(entry, "project"), text(entry, "key")));
                }
                "apikey.revoked_all" => {
                    let project = text(entry, "project");
                    api_keys.retain(|(p, _)| *p != project);
                }
                _ => {}
            }
        }
        let (stored_credentials, stored_keys) = self.store.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT c.id, c.project, c.approver, c.kind, c.public_key FROM credentials c \
                 JOIN approvers a ON a.project = c.project AND a.id = c.approver \
                 WHERE c.revoked_at IS NULL AND a.disabled_at IS NULL",
            )?;
            let credentials = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                })?
                .collect::<rusqlite::Result<BTreeMap<String, CredentialRecord>>>()?;
            let mut stmt =
                conn.prepare_cached("SELECT project, id FROM api_keys WHERE revoked_at IS NULL")?;
            let keys = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<BTreeSet<(String, String)>>>()?;
            Ok((credentials, keys))
        })?;
        if stored_credentials != credentials {
            return Err(Error::Conflict(
                "approver credentials do not match the audit log".into(),
            ));
        }
        if stored_keys != api_keys {
            return Err(Error::Conflict(
                "API keys do not match the audit log".into(),
            ));
        }
        Ok(head)
    }

    /// Signs the current head of the log. Export the result somewhere the
    /// server cannot rewrite; that is what makes truncation detectable.
    pub fn checkpoint(&self, now: u64) -> Result<Option<Checkpoint>> {
        let Some((seq, hash)) = self.audit_verify()? else {
            return Ok(None);
        };
        let checkpoint = Checkpoint::sign(seq, &hash, now, &self.inner.key);
        let stored = checkpoint.clone();
        self.store.write(move |conn| {
            exec(
                conn,
                "INSERT INTO checkpoints (seq, hash, ts, kid, sig) VALUES (?, ?, ?, ?, ?)",
                params![
                    stored.seq as i64,
                    stored.hash,
                    stored.ts as i64,
                    stored.kid,
                    stored.sig
                ],
            )
        })?;
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
        column: &'static str,
        value: Option<&str>,
        now: u64,
    ) -> Result<()> {
        let (inner, project, value) = (
            self.inner.clone(),
            project.to_owned(),
            value.map(str::to_owned),
        );
        self.store.write(move |conn| {
            project_exists(conn, &project)?;
            exec(
                conn,
                "INSERT OR IGNORE INTO channels (project) VALUES (?)",
                [&project],
            )?;
            exec(
                conn,
                &format!("UPDATE channels SET {column} = ? WHERE project = ?"),
                params![value, project],
            )?;
            inner.audit(
                conn,
                now,
                "channel.set",
                json!({ "project": project, "channel": column, "value": value }),
            )
        })
    }

    pub fn outbox_due(&self, now: u64, limit: u32) -> Result<Vec<OutboxItem>> {
        self.store.read(move |conn| {
            let mut stmt = conn.prepare_cached(
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
        })
    }

    /// Records a delivery attempt. Failures are retried with growing delays.
    pub fn outbox_result(&self, id: i64, delivered: bool, now: u64) -> Result<()> {
        self.store.write(move |conn| {
            if delivered {
                exec(
                    conn,
                    "UPDATE outbox SET done_at = ? WHERE id = ?",
                    params![now as i64, id],
                )?;
                return Ok(());
            }
            let attempts = one(
                conn,
                "SELECT attempts FROM outbox WHERE id = ?",
                [id],
                |r| r.get::<_, i64>(0),
            )?
            .ok_or(Error::NotFound)?
                + 1;
            if attempts >= OUTBOX_MAX_ATTEMPTS {
                exec(
                    conn,
                    "UPDATE outbox SET attempts = ?, failed = 1, done_at = ? WHERE id = ?",
                    params![attempts, now as i64, id],
                )?;
            } else {
                let delay = (5i64 << attempts.min(10)).min(3600);
                exec(
                    conn,
                    "UPDATE outbox SET attempts = ?, next_at = ? WHERE id = ?",
                    params![attempts, now as i64 + delay, id],
                )?;
            }
            Ok(())
        })
    }
}
