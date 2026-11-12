//! HTTP API. A thin layer: parse strictly, authenticate, call the service.

use crate::error::{Error, Result};
use crate::limit::Limiter;
use crate::service::{Proof, Registration, Service};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use twof_core::canonical;
use twof_core::passkey::AssertionProof;

const PAGE_HTML: &str = include_str!("../../../web/index.html");
const PAGE_JS: &str = include_str!("../../../web/app.js");
const PAGE_CSS: &str = include_str!("../../../web/app.css");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub type Shared = Arc<Service>;

const MAX_BODY: usize = 64 * 1024;
const MAX_WAIT_SECS: u64 = 30;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Guard {
    limiter: Limiter,
    trust_proxy: bool,
    /// The public address is HTTPS, so browsers are told to insist on it.
    https: bool,
}

fn client_address(request: &Request, trust_proxy: bool) -> Option<IpAddr> {
    if trust_proxy {
        // The last entry is the one our own proxy appended; earlier ones are
        // whatever the client chose to send.
        let forwarded = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok());
        if forwarded.is_some() {
            return forwarded;
        }
    }
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

async fn rate_limit(State(guard): State<Arc<Guard>>, request: Request, next: Next) -> Response {
    match client_address(&request, guard.trust_proxy) {
        Some(address) if !guard.limiter.allow(address, Instant::now()) => {
            Error::RateLimited.into_response()
        }
        _ => next.run(request).await,
    }
}

pub fn router(service: Shared) -> Router {
    let guard = Arc::new(Guard {
        limiter: Limiter::new(service.config.rate_per_minute),
        trust_proxy: service.config.trust_proxy,
        https: service.config.public_url.starts_with("https://"),
    });
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/keys", get(public_keys))
        .route("/v1/challenges", post(create_challenge))
        .route("/v1/challenges/{id}", get(get_challenge))
        .route("/v1/challenges/{id}/approvals", post(submit_approval))
        .route("/v1/approvals/{id}", get(approver_view))
        .route("/v1/receipts/consume", post(consume_receipt))
        .route(
            "/v1/enrollments/{token}",
            get(enrollment_view).post(complete_enrollment),
        )
        .route("/approve/{id}", get(page))
        .route("/enroll/{token}", get(page))
        .route(
            "/assets/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", PAGE_JS) }),
        )
        .route(
            "/assets/app.css",
            get(|| async { asset("text/css; charset=utf-8", PAGE_CSS) }),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(guard.clone(), rate_limit))
        .layer(middleware::from_fn_with_state(guard, security_headers))
        .with_state(service)
}

/// Serves the API until Ctrl+C. TLS is expected to be terminated by a
/// reverse proxy in front of this process.
pub async fn serve(service: Shared, listen: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let app = router(service).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

async fn security_headers(
    State(guard): State<Arc<Guard>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let mut set = |name, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(header::CACHE_CONTROL, "no-store");
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "no-referrer");
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    set(
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    if guard.https {
        set(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        );
    }
    response
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Forbidden(_) => StatusCode::FORBIDDEN,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::Invalid(_) => StatusCode::BAD_REQUEST,
            Error::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Error::Internal(detail) => {
                eprintln!("internal error: {detail}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = json!({ "error": { "code": self.code(), "message": self.to_string() } });
        (status, Json(body)).into_response()
    }
}

/// Runs a service call off the async threads: SQLite calls block.
async fn blocking<T, F>(service: Shared, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Service) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || f(&service))
        .await
        .map_err(|e| Error::Internal(format!("task: {e}")))?
}

fn bearer(headers: &HeaderMap) -> Result<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(Error::Unauthorized)
}

/// Resolves the caller's project. Always the first thing an authenticated
/// handler does, so unauthenticated callers learn nothing from later checks.
async fn authenticate(service: &Shared, headers: &HeaderMap) -> Result<String> {
    let token = bearer(headers)?;
    blocking(service.clone(), move |s| s.authenticate(&token)).await
}

/// Parses a JSON object body strictly and refuses fields it does not know.
fn object(body: &str, allowed: &[&str]) -> Result<Map<String, Value>> {
    let Value::Object(map) = canonical::parse_strict(body)? else {
        return Err(Error::Invalid("body must be a JSON object".into()));
    };
    if let Some(unknown) = map.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(Error::Invalid(format!("unknown field: {unknown}")));
    }
    Ok(map)
}

fn text(map: &Map<String, Value>, field: &str) -> Result<String> {
    match map.get(field) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(Error::Invalid(format!(
            "{field} is required and must be a string"
        ))),
    }
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// The approval and enrollment pages are one static shell; the script reads
/// the id from the address and talks to the API.
async fn page() -> Response {
    asset("text/html; charset=utf-8", PAGE_HTML)
}

async fn enrollment_view(
    State(service): State<Shared>,
    Path(token): Path<String>,
) -> Result<Json<Value>> {
    let view = blocking(service, move |s| s.enrollment_view(&token, now())).await?;
    Ok(Json(json!(view)))
}

async fn complete_enrollment(
    State(service): State<Shared>,
    Path(token): Path<String>,
    body: String,
) -> Result<Json<Value>> {
    let map = object(
        &body,
        &[
            "authenticator_data",
            "client_data_json",
            "public_key",
            "algorithm",
        ],
    )?;
    let registration = Registration {
        authenticator_data: text(&map, "authenticator_data")?,
        client_data_json: text(&map, "client_data_json")?,
        public_key: text(&map, "public_key")?,
        algorithm: map
            .get("algorithm")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Invalid("algorithm is required and must be an integer".into()))?,
    };
    blocking(service, move |s| {
        s.complete_enrollment(&token, &registration, now())
    })
    .await?;
    Ok(Json(json!({ "enrolled": true })))
}

async fn public_keys(State(service): State<Shared>) -> Json<Value> {
    Json(json!({ "keys": service.public_keys() }))
}

async fn create_challenge(
    State(service): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>> {
    let project = authenticate(&service, &headers).await?;
    let mut map = object(&body, &["action", "idempotency_key"])?;
    let idempotency_key = text(&map, "idempotency_key")?;
    let action = map
        .remove("action")
        .ok_or_else(|| Error::Invalid("action is required".into()))?;
    let view = blocking(service, move |s| {
        s.create_challenge(&project, action, &idempotency_key, now())
    })
    .await?;
    Ok(Json(json!(view)))
}

#[derive(Deserialize)]
struct WaitQuery {
    wait: Option<u64>,
}

async fn get_challenge(
    State(service): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<WaitQuery>,
) -> Result<Json<Value>> {
    let project = authenticate(&service, &headers).await?;
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(query.wait.unwrap_or(0).min(MAX_WAIT_SECS));
    let changed = service.changed();
    loop {
        // Register interest before reading, so a change that lands between
        // the read and the wait is not missed.
        let notified = changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let (project, id) = (project.clone(), id.clone());
        let view = blocking(service.clone(), move |s| {
            s.get_challenge(&project, &id, now())
        })
        .await?;
        let now_instant = tokio::time::Instant::now();
        if view.state != "pending" || now_instant >= deadline {
            return Ok(Json(json!(view)));
        }
        // Wake on the next committed change, at the deadline, or when the
        // challenge itself is due to expire, whichever comes first.
        let until_expiry = Duration::from_secs(view.expires_at.saturating_sub(now()) + 1);
        let wake = deadline.min(now_instant + until_expiry);
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep_until(wake) => {}
        }
    }
}

async fn approver_view(
    State(service): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let view = blocking(service, move |s| s.approver_view(&id, now())).await?;
    Ok(Json(json!(view)))
}

async fn submit_approval(
    State(service): State<Shared>,
    Path(id): Path<String>,
    body: String,
) -> Result<Json<Value>> {
    let map = object(&body, &["credential", "signature", "decision", "passkey"])?;
    let proof = match map.get("passkey") {
        Some(Value::Object(passkey)) => {
            if map.contains_key("credential") || map.contains_key("signature") {
                return Err(Error::Invalid(
                    "send either passkey or credential and signature".into(),
                ));
            }
            let fields = ["id", "authenticator_data", "client_data_json", "signature"];
            if let Some(unknown) = passkey.keys().find(|k| !fields.contains(&k.as_str())) {
                return Err(Error::Invalid(format!("unknown field: passkey.{unknown}")));
            }
            Proof::Passkey {
                credential_id: text(passkey, "id")?,
                assertion: AssertionProof {
                    authenticator_data: text(passkey, "authenticator_data")?,
                    client_data_json: text(passkey, "client_data_json")?,
                    signature: text(passkey, "signature")?,
                },
            }
        }
        Some(_) => return Err(Error::Invalid("passkey must be an object".into())),
        None => Proof::Signature {
            credential: text(&map, "credential")?,
            signature: text(&map, "signature")?,
        },
    };
    let reject = match map.get("decision") {
        None => false,
        Some(Value::String(s)) if s == "approve" => false,
        Some(Value::String(s)) if s == "reject" => true,
        _ => {
            return Err(Error::Invalid(
                "decision must be \"approve\" or \"reject\"".into(),
            ))
        }
    };
    let view = blocking(service, move |s| s.submit(&id, &proof, reject, now())).await?;
    // The approver learns the outcome, never the receipt: that belongs to the client.
    Ok(Json(
        json!({ "id": view.id, "state": view.state, "approvals": view.approvals }),
    ))
}

async fn consume_receipt(
    State(service): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>> {
    let project = authenticate(&service, &headers).await?;
    let map = object(&body, &["receipt"])?;
    let receipt = text(&map, "receipt")?;
    let payload = blocking(service, move |s| {
        s.consume_receipt(&project, &receipt, now())
    })
    .await?;
    Ok(Json(json!({ "consumed": true, "receipt": payload })))
}
