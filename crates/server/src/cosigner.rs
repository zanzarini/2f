//! An independent co-signer: a second machine with its own key and its own
//! policy. It receives the server's `challenge.pending` webhook, checks the
//! action against its own rules, and approves or vetoes by signing.
//!
//! Its value is independence: taking over the 2F server is not enough to get
//! its signature on an action its policy refuses. Run it on another machine.
//!
//! It keeps its own count of what it has signed, so a velocity limit in its
//! policy also holds against a server that asks for many small approvals.
//! That count lives in memory: it starts from zero when the process restarts.

use crate::error::{Error, Result};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use twof_core::keys::ServerKey;
use twof_core::policy::{Outcome, PolicyContext};
use twof_core::{canonical, webhook, Action, Binding, Policy};

/// How long a signed approval is remembered for velocity limits.
const HISTORY_SECS: u64 = 31 * 24 * 3600;

struct Signed {
    challenge: String,
    asset: String,
    amount: Decimal,
    at: u64,
}

pub struct Cosigner {
    /// The co-signer's own signing key.
    pub key: ServerKey,
    /// Id of the credential this key is enrolled under on the 2F server.
    pub credential: String,
    /// The co-signer's own rules. `allow` signs, `deny` vetoes, `require` abstains.
    pub policy: Policy,
    /// Where to send the decision.
    pub server_url: String,
    /// The 2F server key, pinned. Webhooks signed by anything else are dropped.
    pub server_key: VerifyingKey,
    signed: Mutex<Vec<Signed>>,
}

/// What the co-signer decided to send back to the server.
#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub challenge: String,
    pub reject: bool,
    pub signature: String,
}

struct History<'a> {
    now: u64,
    signed: &'a [Signed],
    /// The challenge being decided, so deciding it twice does not count twice.
    current: &'a str,
}

impl PolicyContext for History<'_> {
    fn now_unix(&self) -> u64 {
        self.now
    }
    fn velocity_total(&self, asset: &str, window_secs: u64) -> Option<Decimal> {
        let since = self.now.saturating_sub(window_secs);
        let mut total = Decimal::ZERO;
        for entry in self.signed {
            if entry.asset == asset && entry.at >= since && entry.challenge != self.current {
                total = total.checked_add(entry.amount)?;
            }
        }
        Some(total)
    }
}

impl Cosigner {
    pub fn new(
        key: ServerKey,
        credential: String,
        policy: Policy,
        server_url: String,
        server_key: VerifyingKey,
    ) -> Self {
        Cosigner {
            key,
            credential,
            policy,
            server_url,
            server_key,
            signed: Mutex::new(Vec::new()),
        }
    }

    /// Decides on one webhook delivery. No network involved.
    pub fn decide(&self, body: &str, signature: &str, now: u64) -> Result<Option<Verdict>> {
        if !webhook::verify(&self.server_key, body.as_bytes(), signature) {
            return Err(Error::Forbidden("webhook signature is invalid".into()));
        }
        let event = canonical::parse_strict(body)?;
        let ts = event.get("ts").and_then(Value::as_u64).unwrap_or(0);
        if now.abs_diff(ts) > webhook::MAX_AGE {
            return Err(Error::Invalid("webhook is too old".into()));
        }
        if event.get("event").and_then(Value::as_str) != Some("challenge.pending") {
            return Ok(None);
        }
        let data = event
            .get("data")
            .ok_or_else(|| Error::Invalid("missing data".into()))?;
        let field = |name: &str| {
            data.get(name)
                .cloned()
                .ok_or_else(|| Error::Invalid(format!("missing data.{name}")))
        };
        let action = Action::from_value(field("action")?)?;
        let binding: Binding = serde_json::from_value(field("binding")?)
            .map_err(|e| Error::Invalid(format!("binding: {e}")))?;

        // Never sign a binding that is not provably for the action shown.
        if binding.v != 1 || binding.action_hash != action.hash_hex()? {
            return Err(Error::Invalid("binding does not match the action".into()));
        }
        if binding.expires_at <= now {
            return Err(Error::Invalid("challenge has expired".into()));
        }

        // Decide and record under one lock, so two deliveries arriving
        // together cannot both fit under the same limit.
        let mut signed = self.signed.lock().unwrap_or_else(|p| p.into_inner());
        signed.retain(|entry| entry.at + HISTORY_SECS >= now);
        let context = History {
            now,
            signed: &signed,
            current: &binding.challenge,
        };
        let (hash, reject) = match self.policy.evaluate(&action, &context).outcome {
            Outcome::Allow => (binding.hash(), false),
            Outcome::Deny => (binding.reject_hash(), true),
            Outcome::Require { .. } => return Ok(None),
        };
        if !reject
            && !signed
                .iter()
                .any(|entry| entry.challenge == binding.challenge)
        {
            if let (Some(asset), Ok(Some(amount))) = (&action.asset, action.amount_decimal()) {
                signed.push(Signed {
                    challenge: binding.challenge.clone(),
                    asset: asset.clone(),
                    amount,
                    at: now,
                });
            }
        }
        Ok(Some(Verdict {
            challenge: binding.challenge,
            reject,
            signature: B64.encode(self.key.sign(&hash)),
        }))
    }

    fn send(&self, verdict: &Verdict) -> std::result::Result<(), String> {
        let url = format!(
            "{}/v1/challenges/{}/approvals",
            self.server_url.trim_end_matches('/'),
            verdict.challenge
        );
        let body = json!({
            "credential": self.credential,
            "signature": verdict.signature,
            "decision": if verdict.reject { "reject" } else { "approve" },
        });
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .redirects(0)
            .build()
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

pub fn router(cosigner: Arc<Cosigner>) -> Router {
    Router::new()
        .route("/webhook", post(receive))
        .with_state(cosigner)
}

async fn receive(
    State(cosigner): State<Arc<Cosigner>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>> {
    let signature = headers
        .get(webhook::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthorized)?
        .to_owned();
    let verdict = cosigner.decide(&body, &signature, crate::http::now())?;
    let outcome = match &verdict {
        None => "abstained",
        Some(v) if v.reject => "vetoed",
        Some(_) => "approved",
    };
    if let Some(verdict) = verdict {
        // The challenge id came from a signed webhook, but it still goes
        // into a URL: only the shape the server generates is accepted.
        if !crate::device::valid_challenge_id(&verdict.challenge) {
            return Err(Error::Invalid("unexpected challenge id".into()));
        }
        tokio::task::spawn_blocking(move || {
            if let Err(e) = cosigner.send(&verdict) {
                eprintln!(
                    "co-signer: could not deliver decision for {}: {e}",
                    verdict.challenge
                );
            }
        });
    }
    Ok(Json(json!({ "outcome": outcome })))
}

pub async fn serve(cosigner: Arc<Cosigner>, listen: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(cosigner))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
