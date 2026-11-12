//! The HTTP layer: authentication order, strict parsing, headers, limits.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;
use twof_core::keys::ServerKey;
use twof_server::http::{now, router};
use twof_server::{Config, Service};

struct App {
    service: Arc<Service>,
    key: String,
}

fn app(config: Config) -> App {
    let service = Arc::new(Service::open_in_memory(ServerKey::generate(), config).unwrap());
    let project = service.create_project("exchange", now()).unwrap();
    let policy = r#"{"version":1,"rules":[{"name":"ask","when":{},"then":{"decision":"require","requirements":[{"count":1}]}}]}"#;
    service.set_policy(&project, policy, now()).unwrap();
    let key = service.create_api_key(&project, "bot", now()).unwrap();
    App { service, key }
}

async fn send(app: &App, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = router(app.service.clone()).oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
    (parts.status, parts.headers, value)
}

fn post(path: &str, key: Option<&str>, body: &str) -> Request<Body> {
    let mut request = Request::post(path);
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    request.body(Body::from(body.to_owned())).unwrap()
}

fn get(path: &str, key: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path);
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    request.body(Body::empty()).unwrap()
}

const CREATE: &str = r#"{"idempotency_key":"k1","action":{"type":"withdraw","amount":"10"}}"#;

#[tokio::test]
async fn authentication_comes_before_everything_else() {
    let app = app(Config::default());
    for key in [None, Some("2f_wrong"), Some("")] {
        // Even a body that would be a parse error answers 401 first.
        for body in [CREATE, "not json", "{}"] {
            let (status, _, value) = send(&app, post("/v1/challenges", key, body)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(value["error"]["code"], "unauthorized");
        }
        let (status, _, _) = send(&app, get("/v1/challenges/ch_x", key)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = send(
            &app,
            post("/v1/receipts/consume", key, r#"{"receipt":"a.b"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn strict_parsing_and_error_shapes() {
    let app = app(Config::default());
    let key = Some(app.key.as_str());
    for bad in [
        "not json",
        "[]",
        r#"{"idempotency_key":"k","action":{"type":"x"},"extra":1}"#,
        r#"{"idempotency_key":"k","action":{"type":"x","type":"y"}}"#,
        r#"{"idempotency_key":"k","idempotency_key":"z","action":{"type":"x"}}"#,
        r#"{"idempotency_key":"k","action":{"type":"x","amount":1.5}}"#,
        r#"{"idempotency_key":7,"action":{"type":"x"}}"#,
        r#"{"action":{"type":"x"}}"#,
        r#"{"idempotency_key":"k"}"#,
    ] {
        let (status, _, value) = send(&app, post("/v1/challenges", key, bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(value["error"]["code"], "invalid");
    }

    let (status, _, created) = send(&app, post("/v1/challenges", key, CREATE)).await;
    assert_eq!(
        (status, created["state"].as_str()),
        (StatusCode::OK, Some("pending"))
    );
    let id = created["id"].as_str().unwrap();

    let path = format!("/v1/challenges/{id}/approvals");
    for bad in [
        r#"{"credential":"c"}"#,
        r#"{"credential":"c","signature":"s","decision":"maybe"}"#,
        r#"{"credential":"c","signature":"s","passkey":{}}"#,
        r#"{"passkey":"x"}"#,
        r#"{"passkey":{"id":"a","authenticator_data":"a","client_data_json":"a","signature":"a","more":1}}"#,
    ] {
        let (status, _, _) = send(&app, post(&path, None, bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _, _) = send(
        &app,
        post(&path, None, r#"{"credential":"cr_x","signature":"AAAA"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let huge = format!(
        r#"{{"idempotency_key":"k","action":{{"type":"x","meta":{{"pad":"{}"}}}}}}"#,
        "a".repeat(70_000)
    );
    let (status, _, _) = send(&app, post("/v1/challenges", key, &huge)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn approver_view_shows_the_action_but_never_the_receipt() {
    let app = app(Config::default());
    let (_, _, created) = send(&app, post("/v1/challenges", Some(&app.key), CREATE)).await;
    let id = created["id"].as_str().unwrap();
    let (status, _, view) = send(&app, get(&format!("/v1/approvals/{id}"), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        view["action"],
        json!({ "type": "withdraw", "amount": "10" })
    );
    assert!(view.get("receipt").is_none());
    assert!(view["binding_hash"].as_str().unwrap().len() == 43);
    let (status, _, _) = send(&app, get("/v1/approvals/ch_guess", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(&app, get("/v1/enrollments/guess", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let app = app(Config::default());
    for request in [
        get("/approve/ch_x", None),
        get("/assets/app.js", None),
        get("/v1/keys", None),
        get("/nope", None),
    ] {
        let (_, headers, _) = send(&app, request).await;
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
    }
    let (status, headers, page) = send(&app, get("/approve/ch_x", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    // The page has no inline script, so the policy above is enough.
    assert!(!page.as_str().unwrap().contains("<script>"));
}

#[tokio::test]
async fn clients_are_rate_limited_by_address() {
    let app = app(Config {
        rate_per_minute: 5,
        ..Config::default()
    });
    let from = |ip: &str, forwarded: Option<&str>| {
        let mut request = Request::get("/healthz");
        if let Some(value) = forwarded {
            request = request.header("x-forwarded-for", value);
        }
        let mut request = request.body(Body::empty()).unwrap();
        let address: SocketAddr = format!("{ip}:5000").parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(address));
        request
    };
    // The budget lives in the router, so every request goes through the same one.
    async fn hit(router: &axum::Router, request: Request<Body>) -> StatusCode {
        router.clone().oneshot(request).await.unwrap().status()
    }
    let routes = router(app.service.clone());
    for _ in 0..5 {
        assert_eq!(hit(&routes, from("10.0.0.1", None)).await, StatusCode::OK);
    }
    // A forged X-Forwarded-For does not buy a fresh budget when the proxy is not trusted.
    assert_eq!(
        hit(&routes, from("10.0.0.1", Some("1.2.3.4"))).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(hit(&routes, from("10.0.0.2", None)).await, StatusCode::OK);

    // Behind a trusted proxy the last forwarded entry is the client.
    let app = self::app(Config {
        rate_per_minute: 2,
        trust_proxy: true,
        ..Config::default()
    });
    let routes = router(app.service.clone());
    for _ in 0..2 {
        assert_eq!(
            hit(&routes, from("10.0.0.9", Some("6.6.6.6, 7.7.7.7"))).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        hit(&routes, from("10.0.0.9", Some("9.9.9.9, 7.7.7.7"))).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        hit(&routes, from("10.0.0.9", Some("7.7.7.7, 8.8.8.8"))).await,
        StatusCode::OK
    );
}
