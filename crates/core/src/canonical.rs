//! Canonical JSON: RFC 8785 (JCS) restricted to values without floats.
//!
//! Floats are the one part of JCS where implementations disagree in practice,
//! and a disagreement here means two parties hashing "the same" action get
//! different hashes, or worse, different actions get the same one. So they are
//! rejected. Amounts travel as decimal strings.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Largest integer every JSON implementation represents exactly (2^53 - 1).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonError {
    #[error("floating point numbers are not allowed; send amounts as decimal strings")]
    Float,
    #[error("integer outside the safe range (+/- 2^53 - 1)")]
    Range,
    #[error("duplicate object key: {0}")]
    DuplicateKey(String),
    #[error("invalid JSON: {0}")]
    Parse(String),
}

/// Parses JSON rejecting duplicate keys (which `serde_json` would silently
/// resolve to "last wins", letting two parsers see two different documents).
pub fn parse_strict(input: &str) -> Result<Value, CanonError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let value = Strict.deserialize(&mut de).map_err(map_err)?;
    de.end().map_err(map_err)?;
    Ok(value)
}

const DUP_MARK: &str = "duplicate object key: ";

fn map_err(e: serde_json::Error) -> CanonError {
    let msg = e.to_string();
    match msg.find(DUP_MARK) {
        Some(i) => {
            let rest = &msg[i + DUP_MARK.len()..];
            let key = rest.split(" at line ").next().unwrap_or(rest);
            CanonError::DuplicateKey(key.to_string())
        }
        None => CanonError::Parse(msg),
    }
}

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        // Kept as a float so canonicalization rejects it with a clear error.
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Strict)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(serde::de::Error::custom(format!("{DUP_MARK}{key}")));
            }
            let v = map.next_value_seed(Strict)?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Serializes a value to its canonical form.
pub fn to_canonical(value: &Value) -> Result<String, CanonError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785 3.2.3: order by UTF-16 code units, not by bytes.
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &Number, out: &mut String) -> Result<(), CanonError> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(CanonError::Range);
        }
        out.push_str(&u.to_string());
    } else if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonError::Range);
        }
        out.push_str(&i.to_string());
    } else {
        return Err(CanonError::Float);
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn canon(s: &str) -> Result<String, CanonError> {
        to_canonical(&parse_strict(s)?)
    }

    #[test]
    fn rfc8785_key_sorting() {
        // RFC 8785 section 3.2.3.
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
            \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
            \"\u{1f600}\":\"Emoji: Grinning Face\",\
            \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canon(input).unwrap(), expected);
    }

    #[test]
    fn rfc8785_string_escaping() {
        // RFC 8785 section 3.2.2.2.
        let input = r#""\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/""#;
        let expected = "\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"";
        assert_eq!(canon(input).unwrap(), expected);
    }

    #[test]
    fn literals_arrays_and_nesting() {
        let input = r#"{ "b": [true, false, null, 3, -7], "a": { "z": "x", "y": [] } }"#;
        assert_eq!(
            canon(input).unwrap(),
            r#"{"a":{"y":[],"z":"x"},"b":[true,false,null,3,-7]}"#
        );
    }

    #[test]
    fn floats_are_rejected() {
        assert_eq!(canon("1.5"), Err(CanonError::Float));
        assert_eq!(canon("1.0"), Err(CanonError::Float));
        assert_eq!(canon("1e3"), Err(CanonError::Float));
        assert_eq!(canon(r#"{"amount": 0.1}"#), Err(CanonError::Float));
        // Too large for u64 becomes a float in the parser.
        assert_eq!(
            canon("123456789012345678901234567890"),
            Err(CanonError::Float)
        );
    }

    #[test]
    fn unsafe_integers_are_rejected() {
        assert_eq!(canon("9007199254740991").unwrap(), "9007199254740991");
        assert_eq!(canon("-9007199254740991").unwrap(), "-9007199254740991");
        assert_eq!(canon("9007199254740992"), Err(CanonError::Range));
        assert_eq!(canon("-9007199254740992"), Err(CanonError::Range));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert_eq!(
            canon(r#"{"to":"alice","to":"mallory"}"#),
            Err(CanonError::DuplicateKey("to".into()))
        );
        assert!(matches!(
            canon(r#"{"a":{"k":1,"k":2}}"#),
            Err(CanonError::DuplicateKey(_))
        ));
    }

    #[test]
    fn trailing_data_is_rejected() {
        assert!(matches!(canon("{} {}"), Err(CanonError::Parse(_))));
        assert!(matches!(canon(""), Err(CanonError::Parse(_))));
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            (-(MAX_SAFE_INTEGER as i64)..=MAX_SAFE_INTEGER as i64).prop_map(|n| json!(n)),
            any::<String>().prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map(any::<String>(), inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// Canonical output parses back to the same value and is a fixed point.
        #[test]
        fn canonical_is_stable(v in arb_value()) {
            let c1 = to_canonical(&v).unwrap();
            let back = parse_strict(&c1).unwrap();
            prop_assert_eq!(&back, &v);
            prop_assert_eq!(to_canonical(&back).unwrap(), c1);
        }

        /// Whitespace and key order in the input never change the output.
        #[test]
        fn formatting_is_irrelevant(v in arb_value()) {
            let pretty = serde_json::to_string_pretty(&v).unwrap();
            prop_assert_eq!(canon(&pretty).unwrap(), to_canonical(&v).unwrap());
        }

        /// The strict parser never panics on arbitrary input.
        #[test]
        fn parser_never_panics(s in ".*") {
            let _ = canon(&s);
        }
    }
}
