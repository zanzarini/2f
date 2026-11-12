//! An independent co-signer: a second machine with its own key and its own
//! policy. It receives the server's `challenge.pending` webhook, checks the
//! action against its own rules, and approves or vetoes by signing.
//!
//! Its value is independence: taking over the 2F server is not enough to get
//! its signature on an action its policy refuses. Run it on another machine.

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
use std::sync::Arc;
use std::time::Duration;
use twof_core::keys::ServerKey;
use twof_core::policy::{Outcome, PolicyContext};
use twof_core::{canonical, webhook, Action, Binding, Policy};

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
}

/// What the co-signer decided to send back to the server.
#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub challenge: String,
    pub reject: bool,
    pub signature: String,
}

struct Clock(u64);

impl PolicyContext for Clock {
    fn now_unix(&self) -> u64 {
        self.0
    }
    /// The co-signer keeps no history, so velocity conditions never match.
    fn velocity_total(&self, _asset: &str, _window_secs: u64) -> Option<Decimal> {
        None
    }
}

impl Cosigner {
    /// Decides on one webhook delivery. Pure: no network, no clock.
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
        let (hash, reject) = match self.policy.evaluate(&action, &Clock(now)).outcome {
            Outcome::Allow => (binding.hash(), false),
            Outcome::Deny => (binding.reject_hash(), true),
            Outcome::Require { .. } => return Ok(None),
        };
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
