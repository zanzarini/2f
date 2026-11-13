//! Publicly known ways of getting around a second factor, tried one by one.
//!
//! The list comes from the OWASP Transaction Authorization Cheat Sheet (TA),
//! the OWASP Web Security Testing Guide chapter on multi-factor authentication
//! and the HackTricks collection of 2FA bypasses (HT). Each test names the
//! entry it answers. Entries about SMS, e-mail codes, passwords, sessions and
//! "remember me" cookies have nothing to hold on to here: none of those exist.
//!
//! The endless runner (scripts/soak.sh) repeats the random parts with a new
//! seed on every pass.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;
use twof_core::keys::ServerKey;
use twof_core::{b64, receipt, unb64, Action, ApproverKind};
use twof_server::http::{now, router};
use twof_server::{Config, Service};

const POLICY: &str = r#"{"version":1,"rules":[
  {"name":"two","when":{"type":["two"]},"then":{"decision":"require","requirements":[{"count":2}]}},
  {"name":"pass","when":{"type":["pass"]},"then":{"decision":"require","requirements":[{"count":1,"kinds":["passkey"]}]}},
  {"name":"one","when":{},"then":{"decision":"require","requirements":[{"count":1}]}}]}"#;

struct App {
    service: Arc<Service>,
    project: String,
    key: String,
    /// (signing key, credential id) of approvers "a" and "b"
    people: Vec<(ServerKey, String)>,
}

fn app(config: Config) -> App {
    let service = Arc::new(Service::open_in_memory(ServerKey::generate(), config).unwrap());
    let project = service.create_project("exchange", now()).unwrap();
    service.set_policy(&project, POLICY, now()).unwrap();
    let key = service.create_api_key(&project, "bot", now()).unwrap();
    let mut people = Vec::new();
    for name in ["a", "b"] {
        let signer = ServerKey::generate();
        service.add_approver(&project, name, name, now()).unwrap();
        let credential = service
            .add_credential(
                &project,
                name,
                ApproverKind::Ed25519,
                &signer.public_hex(),
                now(),
            )
            .unwrap();
        people.push((signer, credential));
    }
    App {
        service,
        project,
        key,
        people,
    }
}

fn open() -> App {
    app(Config {
        rate_per_minute: 0,
        ..Config::default()
    })
}

struct Rng(u64);
impl Rng {
    fn seeded() -> Self {
        let seed = std::env::var("TWOF_SOAK_SEED")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0x51ed_270b_0f3a_91c7);
        Rng(seed | 1)
    }
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

async fn send(app: &App, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = router(app.service.clone()).oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
    (parts.status, parts.headers, value)
}

fn request(method: &str, path: &str, key: Option<&str>, body: &str) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    request.body(Body::from(body.to_owned())).unwrap()
}

fn action(kind: &str) -> Value {
    json!({ "type": kind, "amount": "10", "asset": "USDT", "destination": "0xabc" })
}

async fn create(app: &App, kind: &str, idempotency: &str) -> String {
    let body = json!({ "idempotency_key": idempotency, "action": action(kind) }).to_string();
    let (status, _, view) = send(
        app,
        request("POST", "/v1/challenges", Some(&app.key), &body),
    )
    .await;
    assert_eq!(
        (status, view["state"].as_str()),
        (StatusCode::OK, Some("pending")),
        "{view}"
    );
    view["id"].as_str().unwrap().to_owned()
}

/// What the client that asked would be told right now.
fn told(app: &App, id: &str) -> (String, Option<String>) {
    let view = app.service.get_challenge(&app.project, id, now()).unwrap();
    (view.state, view.receipt)
}

fn signature(app: &App, id: &str, who: usize, reject: bool) -> String {
    let view = app.service.approver_view(id, now()).unwrap();
    let hash = if reject {
        view.reject_hash
    } else {
        view.binding_hash
    };
    b64(&app.people[who].0.sign(&unb64(&hash).unwrap()))
}

fn approval(app: &App, id: &str, who: usize, reject: bool) -> String {
    json!({
        "credential": app.people[who].1,
        "signature": signature(app, id, who, reject),
        "decision": if reject { "reject" } else { "approve" },
    })
    .to_string()
}

async fn decide(app: &App, id: &str, who: usize, reject: bool) -> StatusCode {
    let path = format!("/v1/challenges/{id}/approvals");
    send(
        app,
        request("POST", &path, None, &approval(app, id, who, reject)),
    )
    .await
    .0
}

async fn consume(app: &App, token: &str) -> StatusCode {
    let body = json!({ "receipt": token }).to_string();
    send(
        app,
        request("POST", "/v1/receipts/consume", Some(&app.key), &body),
    )
    .await
    .0
}

/// An approved request of kind "one" and its receipt.
async fn approved(app: &App, idempotency: &str) -> (String, String) {
    let id = create(app, "one", idempotency).await;
    assert_eq!(decide(app, &id, 0, false).await, StatusCode::OK);
    let (state, token) = told(app, &id);
    assert_eq!(state, "approved");
    (id, token.unwrap())
}

// HT "Direct endpoint access"; TA 2.5 "skipping transaction authorization";
// TA 2.8 "check each execution was properly authorized".
#[tokio::test]
async fn skipping_the_approval_step_gets_nothing() {
    let app = open();
    let (other, real) = approved(&app, "done").await;
    let id = create(&app, "one", "waiting").await;
    assert_eq!(told(&app, &id), ("pending".into(), None));

    let view = app.service.approver_view(&id, now()).unwrap();
    let (payload, signed) = real.split_once('.').unwrap();
    // The genuine receipt of another request, pointed at this one.
    let moved = String::from_utf8(unb64(payload).unwrap())
        .unwrap()
        .replace(&other, &id);
    assert!(moved.contains(&id));
    let attacker = ServerKey::generate();
    let own = b64(&attacker.sign(moved.as_bytes()));
    for token in [
        String::new(),
        "a.b".into(),
        id.clone(),
        view.binding_hash.clone(),
        format!("{}.{}", view.binding_hash, view.binding_hash),
        format!("{}.{signed}", b64(moved.as_bytes())),
        format!("{}.{own}", b64(moved.as_bytes())),
    ] {
        assert_ne!(consume(&app, &token).await, StatusCode::OK, "{token}");
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));
    // None of that spent the genuine one.
    assert_eq!(consume(&app, &real).await, StatusCode::OK);
}

// TA 2.1 "adding/removing parameters which will disable the check";
// TA 2.2 "method enforced server-side"; HT "client-side flag".
#[tokio::test]
async fn extra_parameters_and_headers_do_not_switch_the_check_off() {
    let app = open();
    for (index, extra) in [
        r#""decision":"allow""#,
        r#""state":"approved""#,
        r#""requirements":[]"#,
        r#""policy":{"version":1,"rules":[]}"#,
        r#""project":"other""#,
        r#""approved":true"#,
        r#""skip_2fa":true"#,
    ]
    .iter()
    .enumerate()
    {
        let body = format!(
            r#"{{"idempotency_key":"x{index}","action":{{"type":"one","amount":"10"}},{extra}}}"#
        );
        let (status, _, view) = send(
            &app,
            request("POST", "/v1/challenges", Some(&app.key), &body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}");
        assert!(view.get("receipt").is_none());
    }

    let id = create(&app, "one", "p").await;
    let path = format!("/v1/challenges/{id}/approvals");
    let good = signature(&app, &id, 0, false);
    let credential = &app.people[0].1;
    // A genuine signature does not carry unknown fields through with it.
    for extra in [
        r#""approved":true"#,
        r#""state":"approved""#,
        r#""kind":"passkey""#,
        r#""approver":"b""#,
        r#""count":2"#,
        r#""decision":"reject","decision":"approve""#,
    ] {
        let body = format!(r#"{{"credential":"{credential}","signature":"{good}",{extra}}}"#);
        let (status, _, _) = send(&app, request("POST", &path, None, &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}");
        assert_eq!(told(&app, &id).0, "pending", "{extra}");
    }

    // Headers and query strings that some systems take as proof.
    let wrong = b64(&[7u8; 64]);
    let body = format!(r#"{{"credential":"{credential}","signature":"{wrong}"}}"#);
    for (name, value) in [
        ("x-2fa-verified", "true"),
        ("x-mfa", "passed"),
        ("referer", "https://localhost/approved"),
        ("x-forwarded-for", "127.0.0.1"),
        ("x-original-url", "/v1/receipts/consume"),
        ("x-rewrite-url", "/healthz"),
        ("x-http-method-override", "GET"),
        ("cookie", "mfa=1; approved=true"),
        ("user-agent", "Mozilla/4.0 (no passkeys here)"),
    ] {
        for query in ["", "?approved=true", "?decision=approve&force=1"] {
            let mut bent = request("POST", &format!("{path}{query}"), Some(&app.key), &body);
            bent.headers_mut().insert(name, value.parse().unwrap());
            let (status, _, _) = send(&app, bent).await;
            assert!(!status.is_success(), "{name} {query}");
        }
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));

    // A device key stays a device key whatever the caller says about it.
    let passkey_only = create(&app, "pass", "pk").await;
    assert_ne!(
        decide(&app, &passkey_only, 0, false).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(told(&app, &passkey_only), ("pending".into(), None));
}

/// The same signature with the group order added to its second half: valid
/// for a careless verifier, different bytes.
fn malleated(signature: &str) -> String {
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut bytes = unb64(signature).unwrap();
    let mut carry = 0u16;
    for (byte, add) in bytes[32..].iter_mut().zip(ORDER) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    b64(&bytes)
}

// TA 2.1 "causing an error"; TA 2.4 and HT "brute force", "rate limit absence";
// WSTG "lockout": guessing neither works nor locks the real approver out.
#[tokio::test]
async fn guessing_and_errors_never_end_in_approval_nor_lock_the_approver_out() {
    let app = open();
    let id = create(&app, "one", "g").await;
    let path = format!("/v1/challenges/{id}/approvals");
    let credential = app.people[0].1.clone();
    let good = signature(&app, &id, 0, false);
    let mut rng = Rng::seeded();

    for round in 0..400 {
        let mut guess = unb64(&good).unwrap();
        match round % 4 {
            // one bit off the real signature
            0 => guess[rng.below(64)] ^= 1 << rng.below(8),
            // pure noise
            1 => guess.iter_mut().for_each(|b| *b = rng.next() as u8),
            // the right signature, cut or padded
            2 => guess.truncate(rng.below(64)),
            _ => guess.push(rng.next() as u8),
        }
        let body = json!({ "credential": credential, "signature": b64(&guess) }).to_string();
        let (status, _, _) = send(&app, request("POST", &path, None, &body)).await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
            "round {round}: {status}"
        );
    }
    for body in [
        json!({ "credential": credential, "signature": malleated(&good) }).to_string(),
        json!({ "credential": credential, "signature": signature(&app, &id, 0, true) }).to_string(),
        json!({ "credential": credential, "signature": signature(&app, &id, 1, false) })
            .to_string(),
        json!({ "credential": app.key, "signature": good }).to_string(),
        json!({ "credential": credential, "signature": app.key }).to_string(),
        json!({ "credential": credential, "signature": "" }).to_string(),
        json!({ "credential": "", "signature": good }).to_string(),
        "{".into(),
        "null".into(),
        String::new(),
    ] {
        let (status, _, _) = send(&app, request("POST", &path, None, &body)).await;
        assert!(status.is_client_error(), "{status} for {body}");
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));

    // After all that noise the real approver still gets through, once.
    let body = json!({ "credential": credential, "signature": good }).to_string();
    assert_eq!(
        send(&app, request("POST", &path, None, &body)).await.0,
        StatusCode::OK
    );
    assert_eq!(told(&app, &id).0, "approved");
    assert!(app.service.audit_verify().is_ok());
}

// Known weakness of careless Ed25519 verification: a public key of small
// order accepts a fixed signature for every message.
#[test]
fn a_weak_public_key_approves_nothing() {
    let app = open();
    let identity = format!("01{}", "00".repeat(31));
    let minus_one = format!("ec{}7f", "ff".repeat(30));
    for (index, weak) in [identity, minus_one].iter().enumerate() {
        let enrolled =
            app.service
                .add_credential(&app.project, "a", ApproverKind::Ed25519, weak, now());
        let Ok(credential) = enrolled else { continue };
        let body = json!({ "idempotency_key": format!("w{index}"), "action": action("one") });
        let view = app
            .service
            .create_challenge(
                &app.project,
                body["action"].clone(),
                &format!("w{index}"),
                now(),
            )
            .unwrap();
        // R is the neutral point and S is zero: "valid" for any message under
        // such a key unless the verifier is strict.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        for signature in [b64(&forged), b64(&[0u8; 64])] {
            for reject in [false, true] {
                assert!(app
                    .service
                    .submit_approval(&view.id, &credential, &signature, reject, now())
                    .is_err());
            }
        }
        assert_eq!(told(&app, &view.id), ("pending".into(), None));
    }
}

// HT "Race condition exploitation"; TA 1.5 "accept each credential only once,
// atomically".
#[test]
fn many_hands_at_once_get_one_use_and_one_vote() {
    let app = Arc::new(open());
    let make = |kind: &str, idempotency: &str| {
        app.service
            .create_challenge(&app.project, action(kind), idempotency, now())
            .unwrap()
            .id
    };

    // One person sending the same approval from sixteen threads is one person.
    let two = make("two", "race-two");
    let vote = signature(&app, &two, 0, false);
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (app, two, vote) = (app.clone(), two.clone(), vote.clone());
            std::thread::spawn(move || {
                let _ = app
                    .service
                    .submit_approval(&two, &app.people[0].1, &vote, false, now());
            })
        })
        .collect();
    threads.into_iter().for_each(|t| t.join().unwrap());
    assert_eq!(told(&app, &two), ("pending".into(), None));

    // Sixteen threads spending one receipt: one of them gets it.
    let one = make("one", "race-one");
    let vote = signature(&app, &one, 0, false);
    app.service
        .submit_approval(&one, &app.people[0].1, &vote, false, now())
        .unwrap();
    let token = told(&app, &one).1.unwrap();
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (app, token) = (app.clone(), token.clone());
            std::thread::spawn(move || {
                app.service
                    .consume_receipt(&app.project, &token, now())
                    .is_ok()
            })
        })
        .collect();
    let spent = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(spent, 1);

    // An approval and a refusal racing: whichever lands, the answer is one
    // of the two and it does not change afterwards.
    for round in 0..20 {
        let id = make("one", &format!("race-mixed-{round}"));
        let yes = signature(&app, &id, 0, false);
        let no = signature(&app, &id, 1, true);
        let threads: Vec<_> = [(0, yes, false), (1, no, true)]
            .into_iter()
            .map(|(who, signed, reject)| {
                let (app, id) = (app.clone(), id.clone());
                std::thread::spawn(move || {
                    let _ = app.service.submit_approval(
                        &id,
                        &app.people[who].1,
                        &signed,
                        reject,
                        now(),
                    );
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        let (state, token) = told(&app, &id);
        match state.as_str() {
            "approved" => assert!(token.is_some()),
            "rejected" => assert!(token.is_none()),
            other => panic!("round {round}: {other}"),
        }
        assert_eq!(told(&app, &id).0, state);
    }
    assert!(app.service.audit_verify().is_ok());
}

// HT "Rate limit: the valid code still answers 200", "IP impersonation through
// X-Forwarded-For", "decoy requests".
#[tokio::test]
async fn a_blocked_client_is_blocked_for_the_right_answer_too() {
    let app = app(Config {
        rate_per_minute: 5,
        ..Config::default()
    });
    let id = app
        .service
        .create_challenge(&app.project, action("one"), "limited", now())
        .unwrap()
        .id;
    let path = format!("/v1/challenges/{id}/approvals");
    let from = |ip: &str, body: String, header: Option<(&'static str, &'static str)>| {
        let mut request = request("POST", &path, None, &body);
        if let Some((name, value)) = header {
            request.headers_mut().insert(name, value.parse().unwrap());
        }
        let address: SocketAddr = format!("{ip}:4000").parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(address));
        request
    };
    let routes = router(app.service.clone());
    let wrong = json!({ "credential": app.people[0].1, "signature": b64(&[9u8; 64]) }).to_string();
    for _ in 0..5 {
        let response = routes
            .clone()
            .oneshot(from("10.1.1.1", wrong.clone(), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    // The budget is gone. The correct signature is answered like any other
    // request, whatever address the caller claims to have.
    let right = approval(&app, &id, 0, false);
    for header in [
        None,
        Some(("x-forwarded-for", "8.8.8.8")),
        Some(("x-real-ip", "8.8.8.8")),
        Some(("x-client-ip", "8.8.8.8")),
        Some(("true-client-ip", "8.8.8.8")),
        Some(("x-originating-ip", "8.8.8.8")),
        Some(("forwarded", "for=8.8.8.8")),
        Some(("cf-connecting-ip", "8.8.8.8")),
    ] {
        let response = routes
            .clone()
            .oneshot(from("10.1.1.1", right.clone(), header))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{header:?}"
        );
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));
    // Somebody else is not affected.
    let response = routes
        .clone()
        .oneshot(from("10.1.1.2", right, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// HT "Utilizing older versions: API endpoints"; TA 1.2 and 1.3 "changing the
// token or the method needs the current one"; TA 2.5 "state transitions";
// TA 2.6 "transaction data protected against modification".
#[tokio::test]
async fn there_is_no_other_door() {
    let app = open();
    let id = create(&app, "two", "door").await;
    let paths = [
        "/v0/challenges".to_owned(),
        "/v2/challenges".to_owned(),
        "/api/v1/challenges".to_owned(),
        "/v1/challenge".to_owned(),
        "/v1/admin".to_owned(),
        "/v1/projects".to_owned(),
        "/v1/policy".to_owned(),
        "/v1/policies".to_owned(),
        "/v1/approvers".to_owned(),
        "/v1/credentials".to_owned(),
        "/v1/apikeys".to_owned(),
        "/v1/enrollments".to_owned(),
        "/v1/audit".to_owned(),
        "/v1/receipts".to_owned(),
        "/v1/receipts/issue".to_owned(),
        "/v1/keys".to_owned(),
        "/debug".to_owned(),
        "/metrics".to_owned(),
        "/.env".to_owned(),
        format!("/v1/challenges/{id}/approve"),
        format!("/v1/challenges/{id}/receipt"),
        format!("/v1/challenges/{id}/state"),
        format!("/v1/challenges/{id}/action"),
        format!("/v1/approvals/{id}/approve"),
        format!("/v1/challenges/{id}"),
        format!("/v1/challenges/{id}/approvals"),
        format!("/v1/approvals/{id}"),
        "/v1/receipts/consume".to_owned(),
    ];
    let bodies = [
        String::new(),
        json!({ "state": "approved", "action": action("one"), "requirements": [] }).to_string(),
        json!({ "approver": "a", "kind": "ed25519", "public_key": ServerKey::generate().public_hex() })
            .to_string(),
    ];
    for path in &paths {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            for key in [None, Some(app.key.as_str())] {
                for body in &bodies {
                    let (status, _, view) = send(&app, request(method, path, key, body)).await;
                    assert!(!status.is_success(), "{method} {path}: {status}");
                    assert!(view.get("receipt").is_none(), "{method} {path}");
                }
            }
        }
    }
    // Nothing moved: same request, same action, still waiting for two people.
    let view = app.service.approver_view(&id, now()).unwrap();
    assert_eq!(
        (view.state.as_str(), &view.action),
        ("pending", &action("two"))
    );
    assert_eq!(told(&app, &id), ("pending".into(), None));

    // Asking again under the same key with other data does not replace it.
    let swapped = json!({ "idempotency_key": "door", "action": action("one") }).to_string();
    let (status, _, _) = send(
        &app,
        request("POST", "/v1/challenges", Some(&app.key), &swapped),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        app.service.approver_view(&id, now()).unwrap().action,
        action("two")
    );

    // The API key asks; it never approves and never enrols a device.
    let path = format!("/v1/challenges/{id}/approvals");
    for body in [
        json!({ "credential": app.key, "signature": app.key }).to_string(),
        json!({ "credential": app.people[0].1, "signature": b64(app.key.as_bytes()) }).to_string(),
    ] {
        let (status, _, _) = send(&app, request("POST", &path, Some(&app.key), &body)).await;
        assert!(status.is_client_error());
    }
    for token in ["guess", app.key.as_str(), id.as_str()] {
        let path = format!("/v1/enrollments/{token}");
        assert_eq!(
            send(&app, request("GET", &path, Some(&app.key), ""))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (status, _, _) = send(&app, request("POST", &path, Some(&app.key), "{}")).await;
        assert!(status.is_client_error());
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));
}

// HT "CSRF/clickjacking"; "backup codes read through CORS misconfiguration".
#[tokio::test]
async fn another_site_cannot_drive_or_read_the_approval() {
    let app = open();
    let id = create(&app, "one", "csrf").await;
    let targets = [
        ("GET", format!("/v1/approvals/{id}")),
        ("GET", format!("/approve/{id}")),
        ("GET", format!("/v1/challenges/{id}")),
        ("GET", "/v1/keys".to_owned()),
        ("POST", format!("/v1/challenges/{id}/approvals")),
        ("POST", "/v1/receipts/consume".to_owned()),
        ("OPTIONS", format!("/v1/challenges/{id}/approvals")),
        ("OPTIONS", "/v1/challenges".to_owned()),
    ];
    for (method, path) in &targets {
        let mut foreign = request(method, path, Some(&app.key), "");
        let headers = foreign.headers_mut();
        headers.insert("origin", "https://evil.example".parse().unwrap());
        headers.insert("access-control-request-method", "POST".parse().unwrap());
        headers.insert(
            "access-control-request-headers",
            "authorization".parse().unwrap(),
        );
        let (status, headers, _) = send(&app, foreign).await;
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-headers",
            "set-cookie",
        ] {
            assert!(
                headers.get(name).is_none(),
                "{method} {path} answers {name}"
            );
        }
        assert_eq!(headers["x-frame-options"], "DENY");
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("form-action 'none'"));
        if *method == "OPTIONS" {
            assert!(!status.is_success());
        }
    }
    assert_eq!(told(&app, &id), ("pending".into(), None));
}

// HT "Response manipulation", "Token reuse", "OTP construction errors";
// JWT style confusion ("alg none", foreign key id).
#[tokio::test]
async fn a_receipt_cannot_be_reshaped_and_is_spent_once() {
    let app = open();
    let (_, token) = approved(&app, "shape").await;
    let server = app.service.key();
    let lookup = |kid: &str| (kid == server.kid()).then(|| server.public());
    let asked = Action::from_value(action("one")).unwrap();
    assert!(receipt::verify(&token, &lookup, &asked, now()).is_ok());
    // The same receipt does not cover a transaction that differs in anything.
    for other in [
        json!({ "type": "one", "amount": "11", "asset": "USDT", "destination": "0xabc" }),
        json!({ "type": "one", "amount": "10", "asset": "USDT", "destination": "0xabd" }),
        json!({ "type": "one", "amount": "10", "asset": "USDC", "destination": "0xabc" }),
        json!({ "type": "one", "amount": "10", "asset": "USDT", "destination": "0xabc", "meta": { "memo": "x" } }),
    ] {
        let other = Action::from_value(other).unwrap();
        assert!(receipt::verify(&token, &lookup, &other, now()).is_err());
    }

    let (payload, signed) = token.split_once('.').unwrap();
    let text = String::from_utf8(unb64(payload).unwrap()).unwrap();
    let attacker = ServerKey::generate();
    let renamed = text.replace(&server.kid(), &attacker.kid());
    let mut bent = vec![
        format!("{payload}."),
        format!(".{signed}"),
        format!("{payload}.{}", b64(&[0u8; 64])),
        format!("{payload}.{}", malleated(signed)),
        format!("{signed}.{payload}"),
        format!("{token}.{signed}"),
        format!("{token}A"),
        format!(" {token}"),
        format!("{token}\n"),
        format!(
            "{}.{signed}",
            b64(text.replacen('{', "{\"alg\":\"none\",", 1).as_bytes())
        ),
        format!(
            "{}.",
            b64(text.replacen('{', "{\"alg\":\"none\",", 1).as_bytes())
        ),
        format!("{}.{signed}", b64(format!(" {text}").as_bytes())),
        format!(
            "{}.{}",
            b64(renamed.as_bytes()),
            b64(&attacker.sign(renamed.as_bytes()))
        ),
        format!(
            "{}.{}",
            b64(text.as_bytes()),
            b64(&attacker.sign(text.as_bytes()))
        ),
    ];
    // And random damage, new on every pass of the endless runner.
    let mut rng = Rng::seeded();
    for _ in 0..300 {
        let mut bytes = token.clone().into_bytes();
        let at = rng.below(bytes.len());
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
        let new = alphabet[rng.below(alphabet.len())];
        if bytes[at] == new {
            continue;
        }
        bytes[at] = new;
        bent.push(String::from_utf8(bytes).unwrap());
    }
    for token in &bent {
        // Base64 has spare bits in its last character: a changed token that
        // decodes to the very same bytes is the same receipt, not a forgery.
        let same = token.split_once('.').is_some_and(|(p, s)| {
            !token.contains(char::is_whitespace)
                && unb64(p) == unb64(payload)
                && unb64(s) == unb64(signed)
                && unb64(p).is_some()
        });
        if same {
            continue;
        }
        assert!(
            receipt::verify(token, &lookup, &asked, now()).is_err(),
            "accepted offline: {token:?}"
        );
        assert_ne!(consume(&app, token).await, StatusCode::OK, "{token:?}");
    }
    // Still good after all the forgeries, and then spent.
    assert_eq!(consume(&app, &token).await, StatusCode::OK);
    assert_ne!(consume(&app, &token).await, StatusCode::OK);
    assert!(app.service.audit_verify().is_ok());
}

// HT "Utilization of unused tokens (another account)", "Session manipulation";
// TA 1.5 "unique credentials per transaction"; TA 2.5 "allowed transitions".
#[tokio::test]
async fn an_answer_belongs_to_one_request_and_stays_what_it_was() {
    let app = open();
    let first = create(&app, "one", "first").await;
    let second = create(&app, "one", "second").await;
    // A signature made for the first request, sent to the second: same
    // action, same approver, other request.
    let path = format!("/v1/challenges/{second}/approvals");
    let (status, _, _) = send(
        &app,
        request("POST", &path, None, &approval(&app, &first, 0, false)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(told(&app, &second), ("pending".into(), None));

    // A refusal is final: nobody approves it afterwards.
    assert_eq!(decide(&app, &first, 1, true).await, StatusCode::OK);
    assert_eq!(told(&app, &first), ("rejected".into(), None));
    let late = json!({
        "credential": app.people[0].1,
        "signature": b64(&app.people[0].0.sign(&unb64(&app.service.approver_view(&first, now()).unwrap().binding_hash).unwrap())),
    })
    .to_string();
    let path = format!("/v1/challenges/{first}/approvals");
    assert!(!send(&app, request("POST", &path, None, &late))
        .await
        .0
        .is_success());
    assert_eq!(told(&app, &first), ("rejected".into(), None));

    // An approval is final too: a later refusal does not take the receipt back
    // into "pending", and does not mint a second receipt.
    assert_eq!(decide(&app, &second, 0, false).await, StatusCode::OK);
    let (state, token) = told(&app, &second);
    assert_eq!(state, "approved");
    let refuse = json!({
        "credential": app.people[1].1,
        "signature": b64(&app.people[1].0.sign(&unb64(&app.service.approver_view(&second, now()).unwrap().reject_hash).unwrap())),
        "decision": "reject",
    })
    .to_string();
    let path = format!("/v1/challenges/{second}/approvals");
    assert!(!send(&app, request("POST", &path, None, &refuse))
        .await
        .0
        .is_success());
    assert_eq!(told(&app, &second), (state, token.clone()));

    // Another project: its key learns nothing and spends nothing.
    let foreign = app.service.create_project("other", now()).unwrap();
    app.service.set_policy(&foreign, POLICY, now()).unwrap();
    let foreign_key = app.service.create_api_key(&foreign, "bot", now()).unwrap();
    let theirs = send(
        &app,
        request(
            "GET",
            &format!("/v1/challenges/{second}"),
            Some(&foreign_key),
            "",
        ),
    )
    .await;
    let nothing = send(
        &app,
        request(
            "GET",
            "/v1/challenges/ch_does_not_exist",
            Some(&foreign_key),
            "",
        ),
    )
    .await;
    assert_eq!((theirs.0, &theirs.2), (nothing.0, &nothing.2));
    let body = json!({ "receipt": token }).to_string();
    let (status, _, _) = send(
        &app,
        request("POST", "/v1/receipts/consume", Some(&foreign_key), &body),
    )
    .await;
    assert!(!status.is_success());
    assert_eq!(consume(&app, &token.unwrap()).await, StatusCode::OK);
}

// HT "Exposure of token", "Information disclosure on the 2FA page",
// "predictable values".
#[tokio::test]
async fn nothing_secret_is_shown_and_nothing_is_guessable() {
    let app = app(Config {
        rate_per_minute: 0,
        max_pending: 1000,
        ..Config::default()
    });
    let (done, token) = approved(&app, "shown").await;
    let waiting = create(&app, "two", "shown-too").await;
    assert_eq!(decide(&app, &waiting, 0, false).await, StatusCode::OK);
    let signed = token.split_once('.').unwrap().1.to_owned();
    for path in [
        format!("/v1/approvals/{done}"),
        format!("/v1/approvals/{waiting}"),
        format!("/approve/{done}"),
        "/v1/keys".to_owned(),
        "/v1/approvals/ch_nope".to_owned(),
        "/assets/app.js".to_owned(),
    ] {
        let (_, headers, body) = send(&app, request("GET", &path, None, "")).await;
        let text = format!("{body} {headers:?}");
        for secret in [
            app.key.as_str(),
            token.as_str(),
            signed.as_str(),
            "shown-too",
        ] {
            assert!(!text.contains(secret), "{path} shows {secret:.12}");
        }
        assert!(!text.contains(&app.service.key().seed_hex()));
    }
    // Answers to the caller with the key do not echo the key either.
    let (_, _, body) = send(
        &app,
        request("GET", &format!("/v1/challenges/{done}"), Some(&app.key), ""),
    )
    .await;
    assert!(!body.to_string().contains(&app.key));

    // Identifiers are long and unrelated to each other.
    let mut seen = BTreeSet::new();
    for index in 0..200 {
        let id = create(&app, "one", &format!("id{index}")).await;
        assert!(id.len() >= 24, "{id}");
        assert!(seen.insert(id));
    }
    let ids: Vec<&String> = seen.iter().collect();
    for pair in ids.windows(2) {
        let shared = pair[0]
            .bytes()
            .zip(pair[1].bytes())
            .take_while(|(a, b)| a == b)
            .count();
        assert!(shared < 12, "{} and {} look related", pair[0], pair[1]);
    }
}
