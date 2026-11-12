//! A real server on a real socket, with many clients at once.

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use twof_core::keys::ServerKey;
use twof_core::{receipt, Action, ApproverKind};
use twof_server::http::{now, router};
use twof_server::{Config, Service};

const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "auto", "when": { "type": ["auto"], "asset": ["USDT"], "amount_max": "10",
                                "velocity": { "window_secs": 3600, "max_total": "100" } },
      "then": { "decision": "allow" } },
    { "name": "ask", "when": { "type": ["ask"] },
      "then": { "decision": "require", "requirements": [ { "count": 1 } ] } } ] }"#;

struct Live {
    service: Arc<Service>,
    url: String,
    key: String,
    device: ServerKey,
    credential: String,
    path: std::path::PathBuf,
    _runtime: tokio::runtime::Runtime,
}

impl Drop for Live {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn start(name: &str, config: Config) -> Live {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-live-{name}-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let service = Arc::new(Service::open(&path, ServerKey::generate(), config).unwrap());
    let project = service.create_project("live", now()).unwrap();
    service.set_policy(&project, POLICY, now()).unwrap();
    let key = service.create_api_key(&project, "bot", now()).unwrap();
    let device = ServerKey::generate();
    service
        .add_approver(&project, "alice", "Alice", now())
        .unwrap();
    let credential = service
        .add_credential(
            &project,
            "alice",
            ApproverKind::Ed25519,
            &device.public_hex(),
            now(),
        )
        .unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(service.clone()).into_make_service_with_connect_info::<SocketAddr>();
    runtime.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Live {
        service,
        url,
        key,
        device,
        credential,
        path,
        _runtime: runtime,
    }
}

/// One HTTP call. Returns the status and the JSON body.
fn call(method: &str, url: &str, key: Option<&str>, body: Option<&Value>) -> (u16, Value) {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(40))
        .build();
    let mut request = agent.request(method, url);
    if let Some(key) = key {
        request = request.set("Authorization", &format!("Bearer {key}"));
    }
    let outcome = match body {
        Some(body) => request
            .set("Content-Type", "application/json")
            .send_string(&body.to_string()),
        None => request.call(),
    };
    let (status, text) = match outcome {
        Ok(response) => (
            response.status(),
            response.into_string().unwrap_or_default(),
        ),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_string().unwrap_or_default())
        }
        Err(other) => panic!("{method} {url}: {other}"),
    };
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn create(live: &Live, kind: &str, amount: &str, key: &str) -> (u16, Value) {
    let body = json!({ "idempotency_key": key,
                       "action": { "type": kind, "amount": amount, "asset": "USDT", "destination": "0xaaa" } });
    call(
        "POST",
        &format!("{}/v1/challenges", live.url),
        Some(&live.key),
        Some(&body),
    )
}

#[test]
fn many_clients_at_once_cannot_overspend_or_reuse() {
    let live = Arc::new(start(
        "crowd",
        Config {
            rate_per_minute: 0,
            ..Config::default()
        },
    ));

    // 16 clients race for a budget that fits exactly 10 transfers of 10.
    let handles: Vec<_> = (0..16)
        .map(|t| {
            let live = live.clone();
            std::thread::spawn(move || {
                let mut receipts = Vec::new();
                for i in 0..5 {
                    let (status, view) = create(&live, "auto", "10", &format!("c-{t}-{i}"));
                    assert!(status < 500, "server error {status}: {view}");
                    if status == 200 && view["state"] == "allowed" {
                        receipts.push(view["receipt"].as_str().unwrap().to_owned());
                    } else {
                        assert!(
                            view["receipt"].is_null(),
                            "a receipt without an allowance: {view}"
                        );
                    }
                }
                receipts
            })
        })
        .collect();
    let receipts: Vec<String> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(
        receipts.len(),
        10,
        "the velocity cap held with clients racing over HTTP"
    );

    // Every receipt is real, and 8 clients racing to use each one get it once.
    let server_key = live.service.key();
    let lookup = |kid: &str| (kid == server_key.kid()).then(|| server_key.public());
    let action = Action::from_value(
        json!({ "type": "auto", "amount": "10", "asset": "USDT", "destination": "0xaaa" }),
    )
    .unwrap();
    for token in &receipts {
        assert!(receipt::verify(token, &lookup, &action, now()).is_ok());
    }
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (live, receipts) = (live.clone(), receipts.clone());
            std::thread::spawn(move || {
                receipts
                    .iter()
                    .filter(|token| {
                        let (status, _) = call(
                            "POST",
                            &format!("{}/v1/receipts/consume", live.url),
                            Some(&live.key),
                            Some(&json!({ "receipt": token })),
                        );
                        assert!(status == 200 || status == 409, "unexpected {status}");
                        status == 200
                    })
                    .count()
            })
        })
        .collect();
    let used: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        used,
        receipts.len(),
        "each receipt was accepted exactly once"
    );
    assert!(live.service.audit_verify().is_ok());
}

#[test]
fn a_waiting_client_hears_the_decision_at_once() {
    let live = Arc::new(start(
        "wait",
        Config {
            rate_per_minute: 0,
            ..Config::default()
        },
    ));
    let (status, pending) = create(&live, "ask", "500", "w1");
    assert_eq!((status, pending["state"].as_str()), (200, Some("pending")));
    let id = pending["id"].as_str().unwrap().to_owned();

    let waiter = {
        let (live, id) = (live.clone(), id.clone());
        std::thread::spawn(move || {
            let started = Instant::now();
            let (status, view) = call(
                "GET",
                &format!("{}/v1/challenges/{id}?wait=25", live.url),
                Some(&live.key),
                None,
            );
            (status, view, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(400));

    // The approver fetches what to sign, with no API key, and signs it.
    let (status, view) = call(
        "GET",
        &format!("{}/v1/approvals/{id}", live.url),
        None,
        None,
    );
    assert_eq!(status, 200);
    let hash = twof_core::unb64(view["binding_hash"].as_str().unwrap()).unwrap();
    let approval = json!({ "credential": live.credential, "signature": twof_core::b64(&live.device.sign(&hash)) });
    let (status, answer) = call(
        "POST",
        &format!("{}/v1/challenges/{id}/approvals", live.url),
        None,
        Some(&approval),
    );
    assert_eq!((status, answer["state"].as_str()), (200, Some("approved")));
    assert!(
        answer.get("receipt").is_none(),
        "the approver is never handed the receipt"
    );

    let (status, view, waited) = waiter.join().unwrap();
    assert_eq!((status, view["state"].as_str()), (200, Some("approved")));
    assert!(
        waited < Duration::from_secs(5),
        "the waiting client was told after {waited:?}"
    );
    assert!(
        waited >= Duration::from_millis(300),
        "it really was waiting ({waited:?})"
    );
    assert!(view["receipt"].is_string());

    // Without the key, the challenge and its receipt are out of reach.
    assert_eq!(
        call(
            "GET",
            &format!("{}/v1/challenges/{id}", live.url),
            None,
            None
        )
        .0,
        401
    );
    assert_eq!(
        call(
            "GET",
            &format!("{}/v1/challenges/{id}", live.url),
            Some("2f_guess"),
            None
        )
        .0,
        401
    );
}

#[test]
fn a_waiting_client_is_released_when_the_request_expires() {
    let config = Config {
        rate_per_minute: 0,
        challenge_ttl: 2,
        ..Config::default()
    };
    let live = start("expire", config);
    let (_, pending) = create(&live, "ask", "500", "e1");
    let id = pending["id"].as_str().unwrap();
    let started = Instant::now();
    let (status, view) = call(
        "GET",
        &format!("{}/v1/challenges/{id}?wait=25", live.url),
        Some(&live.key),
        None,
    );
    assert_eq!((status, view["state"].as_str()), (200, Some("expired")));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "released after {:?}",
        started.elapsed()
    );
    assert!(view["receipt"].is_null());
    // Too late to approve.
    let (_, shown) = call(
        "GET",
        &format!("{}/v1/approvals/{id}", live.url),
        None,
        None,
    );
    let hash = twof_core::unb64(shown["binding_hash"].as_str().unwrap()).unwrap();
    let approval = json!({ "credential": live.credential, "signature": twof_core::b64(&live.device.sign(&hash)) });
    assert_eq!(
        call(
            "POST",
            &format!("{}/v1/challenges/{id}/approvals", live.url),
            None,
            Some(&approval)
        )
        .0,
        409
    );
}
