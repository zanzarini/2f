//! A large random corpus for checking the three implementations (Rust,
//! TypeScript, Python) against each other on inputs nobody chose by hand.
//!
//! Always checks the Rust side against itself. With TWOF_WRITE_CORPUS set it
//! also writes `sdk/corpus.json`, which `scripts/crosscheck.sh` feeds to the
//! two SDKs.

use serde_json::{json, Map, Value};
use twof_core::canonical::{parse_strict, to_canonical, MAX_SAFE_INTEGER};
use twof_core::{b64, Action, Binding};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../sdk/corpus.json");

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Strings built from the characters most likely to be encoded differently:
/// escapes, control characters, both sides of the surrogate range, astral
/// characters, and keys that sort differently by byte, code point and UTF-16.
fn string(rng: &mut Rng) -> String {
    const PIECES: &[&str] = &[
        "a",
        "Z",
        "0",
        " ",
        "\"",
        "\\",
        "/",
        "\n",
        "\r",
        "\t",
        "\u{8}",
        "\u{c}",
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{80}",
        "\u{ff}",
        "é",
        "ß",
        "€",
        "\u{2028}",
        "\u{2029}",
        "\u{d7ff}",
        "\u{e000}",
        "\u{fb33}",
        "\u{ffff}",
        "\u{10000}",
        "😀",
        "\u{10ffff}",
        "日本",
        "ação",
        "<",
        ">",
        "&",
        "'",
    ];
    let mut out = String::new();
    for _ in 0..rng.below(7) {
        out.push_str(PIECES[rng.below(PIECES.len() as u64) as usize]);
    }
    out
}

fn value(rng: &mut Rng, depth: u32) -> Value {
    let leaf = depth >= 3 || rng.below(3) == 0;
    match if leaf { rng.below(5) } else { 5 + rng.below(2) } {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => {
            let edge = [0, 1, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER - 1, 4_294_967_296];
            let magnitude = if rng.below(3) == 0 {
                edge[rng.below(edge.len() as u64) as usize]
            } else {
                rng.below(1_000_000)
            };
            if rng.below(2) == 0 {
                json!(magnitude)
            } else {
                json!(-(magnitude as i64))
            }
        }
        3 | 4 => Value::String(string(rng)),
        5 => Value::Array((0..rng.below(5)).map(|_| value(rng, depth + 1)).collect()),
        _ => {
            let mut map = Map::new();
            for _ in 0..rng.below(6) {
                map.insert(string(rng), value(rng, depth + 1));
            }
            Value::Object(map)
        }
    }
}

fn action(rng: &mut Rng) -> Option<Value> {
    let mut map = Map::new();
    map.insert(
        "type".into(),
        json!(["withdraw", "pix", "trade", "payout"][rng.below(4) as usize]),
    );
    if rng.below(4) != 0 {
        let whole = rng.below(10_000_000);
        let text = match rng.below(3) {
            0 => whole.to_string(),
            1 => format!("{whole}.{:02}", rng.below(100)),
            _ => format!("{whole}.{:018}", rng.below(1_000_000_000_000_000_000)),
        };
        map.insert("amount".into(), json!(text));
    }
    if rng.below(4) != 0 {
        map.insert(
            "asset".into(),
            json!(["USDT", "BRL", "BTC", "ação"][rng.below(4) as usize]),
        );
    }
    if rng.below(4) != 0 {
        map.insert(
            "destination".into(),
            json!(format!("0x{:040x}", rng.next())),
        );
    }
    if rng.below(2) == 0 {
        if let Value::Object(meta) = value(rng, 1) {
            map.insert("meta".into(), Value::Object(meta));
        }
    }
    let candidate = Value::Object(map);
    // Random meta may hold characters the server refuses; keep what it accepts.
    Action::from_value(candidate.clone())
        .ok()
        .map(|_| candidate)
}

#[test]
fn random_corpus_is_self_consistent() {
    // The endless runner (scripts/soak.sh) asks for a new corpus each pass.
    let seed = std::env::var("TWOF_SOAK_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let mut rng = Rng(seed.unwrap_or(0x2f2f_2f2f_2f2f_2f2f) | 1);
    let mut values = Vec::new();
    while values.len() < 3000 {
        let v = value(&mut rng, 0);
        let canonical = to_canonical(&v).unwrap();
        // Canonical text is valid JSON for the same value, and a fixed point.
        let back = parse_strict(&canonical).unwrap();
        assert_eq!(back, v);
        assert_eq!(to_canonical(&back).unwrap(), canonical);
        // Parsing ordinary JSON text of it gives the same canonical form.
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        assert_eq!(
            to_canonical(&parse_strict(&pretty).unwrap()).unwrap(),
            canonical
        );
        values.push(json!({ "value": v, "canonical": canonical }));
    }
    let mut actions = Vec::new();
    while actions.len() < 1500 {
        let Some(candidate) = action(&mut rng) else {
            continue;
        };
        let parsed = Action::from_value(candidate.clone()).unwrap();
        let hash = parsed.hash_hex().unwrap();
        let binding = Binding::new(
            "pj_x",
            &format!("ch_{:032x}", rng.next()),
            &hash,
            rng.below(4_000_000_000),
        );
        actions.push(json!({
            "action": candidate,
            "canonical": parsed.canonical().unwrap(),
            "hash": hash,
            "binding": binding,
            "binding_hash": b64(&binding.hash()),
            "reject_hash": b64(&binding.reject_hash()),
        }));
    }
    assert!(actions.iter().any(|a| a["action"].get("meta").is_some()));
    if std::env::var("TWOF_WRITE_CORPUS").is_ok() {
        let text = serde_json::to_string(&json!({ "values": values, "actions": actions })).unwrap();
        std::fs::write(PATH, text).unwrap();
    }
}
