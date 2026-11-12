//! Cross language test vectors. The same file is checked by the TypeScript
//! and Python SDK tests, which pins all three implementations together.
//!
//! Regenerate with: TWOF_WRITE_VECTORS=1 cargo test -p twof-core --test vectors

use serde_json::{json, Value};
use twof_core::canonical::{parse_strict, to_canonical};
use twof_core::keys::ServerKey;
use twof_core::policy::{ApproverKind, Strength};
use twof_core::receipt::ReceiptDecision;
use twof_core::{b64, Action, Approval, Binding, ReceiptPayload};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../sdk/vectors.json");

fn build() -> Value {
    let server = ServerKey::from_seed_hex(&"11".repeat(32)).unwrap();
    let alice = ServerKey::from_seed_hex(&"22".repeat(32)).unwrap();

    let canonical_inputs = [
        r#"{"b":2,"a":1}"#,
        r#"{ "z": [true, false, null, -7, 9007199254740991], "a": { "y": "", "x": [] } }"#,
        "{\"\\u20ac\":\"Euro\",\"\\r\":\"CR\",\"\\ufb33\":\"Dalet\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji\",\"\\u0080\":\"Control\",\"\\u00f6\":\"o\"}",
        r#""\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/""#,
        r#"{"text":"tab\there \"quoted\" \\ back \u0001 \u007f é 日本"}"#,
    ];
    let canonical: Vec<Value> = canonical_inputs
        .iter()
        .map(|input| json!({ "input": input, "output": to_canonical(&parse_strict(input).unwrap()).unwrap() }))
        .collect();

    let rejected = [
        r#"{"a":1.5}"#,
        r#"{"a":1e3}"#,
        r#"{"a":9007199254740992}"#,
        r#"{"a":1,"a":2}"#,
    ];

    let action_inputs = [
        json!({ "type": "withdraw", "amount": "1500.25", "asset": "USDT", "destination": "0xAbC123", "meta": { "order": "A-991", "n": 3 } }),
        json!({ "type": "trade" }),
        json!({ "type": "pix", "amount": "0.01", "asset": "BRL", "destination": "chave@exemplo.com.br", "meta": { "nome": "João Ação" } }),
    ];
    let actions: Vec<Value> = action_inputs
        .iter()
        .map(|value| {
            let action = Action::from_value(value.clone()).unwrap();
            json!({ "action": value, "canonical": action.canonical().unwrap(), "hash": action.hash_hex().unwrap() })
        })
        .collect();

    let action = Action::from_value(action_inputs[0].clone()).unwrap();
    let binding = Binding::new(
        "pj_test",
        "ch_test",
        &action.hash_hex().unwrap(),
        2_000_000_600,
    );
    let payload = ReceiptPayload {
        v: 1,
        id: "rc_test".into(),
        project: "pj_test".into(),
        challenge: "ch_test".into(),
        action_hash: action.hash_hex().unwrap(),
        decision: ReceiptDecision::Approved,
        rule: "needs a person".into(),
        approvals: vec![Approval {
            approver: "alice".into(),
            kind: ApproverKind::Ed25519,
            strength: Strength::Strong,
            sig: b64(&alice.sign(&binding.hash())),
        }],
        binding_expires_at: binding.expires_at,
        issued_at: 2_000_000_000,
        expires_at: 2_000_000_300,
        kid: server.kid(),
    };

    json!({
        "canonical": canonical,
        "canonical_rejected": rejected,
        "actions": actions,
        "binding": { "binding": binding, "hash": b64(&binding.hash()), "reject_hash": b64(&binding.reject_hash()) },
        "receipt": {
            "token": payload.issue(&server),
            "action": action_inputs[0],
            "other_action": action_inputs[2],
            "server_kid": server.kid(),
            "server_public_key": server.public_hex(),
            "approver": "alice",
            "approver_public_key": alice.public_hex(),
            "valid_at": 2_000_000_100u64,
            "expired_at": 2_000_000_301u64,
        },
    })
}

#[test]
fn vectors_file_is_current() {
    let expected = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var("TWOF_WRITE_VECTORS").is_ok() {
        std::fs::write(PATH, &expected).unwrap();
    }
    let actual = std::fs::read_to_string(PATH)
        .expect("sdk/vectors.json exists")
        .replace("\r\n", "\n");
    assert_eq!(actual, expected, "regenerate with TWOF_WRITE_VECTORS=1");
}
