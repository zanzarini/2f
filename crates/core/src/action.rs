//! The action a client wants to execute, and the binding approvers sign.

use crate::canonical::{self, CanonError};
use crate::tagged_hash;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ACTION_TAG: &str = "2F-ACTION-v1";
pub const BINDING_TAG: &str = "2F-BINDING-v1";
pub const REJECT_TAG: &str = "2F-REJECT-v1";

const MAX_TYPE: usize = 64;
const MAX_ASSET: usize = 64;
const MAX_DESTINATION: usize = 256;
const MAX_AMOUNT: usize = 40;
const MAX_CANONICAL: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActionError {
    #[error("invalid action: {0}")]
    Invalid(String),
    #[error(transparent)]
    Canonical(#[from] CanonError),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ActionError> {
    Err(ActionError::Invalid(msg.into()))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
}

impl Action {
    /// Parses and validates an action from untrusted JSON text.
    pub fn parse(json: &str) -> Result<Self, ActionError> {
        Self::from_value(canonical::parse_strict(json)?)
    }

    /// Validates an action from an already parsed JSON value.
    pub fn from_value(value: Value) -> Result<Self, ActionError> {
        let action: Action =
            serde_json::from_value(value).map_err(|e| ActionError::Invalid(e.to_string()))?;
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> Result<(), ActionError> {
        check_text("type", &self.kind, MAX_TYPE)?;
        if let Some(asset) = &self.asset {
            check_text("asset", asset, MAX_ASSET)?;
        }
        if let Some(destination) = &self.destination {
            check_text("destination", destination, MAX_DESTINATION)?;
        }
        if self.amount.is_some() {
            self.amount_decimal()?;
        }
        if let Some(meta) = &self.meta {
            check_meta_map(meta)?;
        }
        if self.canonical()?.len() > MAX_CANONICAL {
            return invalid("action is too large");
        }
        Ok(())
    }

    /// The amount as a number. Only plain non negative decimals are accepted:
    /// no sign, no exponent, no separators.
    pub fn amount_decimal(&self) -> Result<Option<Decimal>, ActionError> {
        let Some(text) = &self.amount else {
            return Ok(None);
        };
        if text.is_empty() || text.len() > MAX_AMOUNT {
            return invalid("amount has an invalid length");
        }
        let (int, frac) = match text.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (text.as_str(), None),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(int) || frac.is_some_and(|f| !digits(f)) {
            return invalid("amount must be a plain decimal string such as \"1500.25\"");
        }
        // "0001000" reads as a thousand to a machine and as something else
        // to a person in a hurry.
        if int.len() > 1 && int.starts_with('0') {
            return invalid("amount cannot have leading zeros");
        }
        match Decimal::from_str_exact(text) {
            Ok(d) => Ok(Some(d)),
            Err(_) => invalid("amount is out of range"),
        }
    }

    pub fn canonical(&self) -> Result<String, ActionError> {
        let value = serde_json::to_value(self).map_err(|e| ActionError::Invalid(e.to_string()))?;
        Ok(canonical::to_canonical(&value)?)
    }

    pub fn hash(&self) -> Result<[u8; 32], ActionError> {
        Ok(tagged_hash(ACTION_TAG, self.canonical()?.as_bytes()))
    }

    pub fn hash_hex(&self) -> Result<String, ActionError> {
        Ok(hex::encode(self.hash()?))
    }
}

/// Characters that are invisible or reorder the text around them. In a
/// destination they would let the screen show something other than what is
/// signed (for example a right-to-left override reversing an address).
fn deceptive(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

fn bad_key(key: &str) -> bool {
    key.is_empty() || key.chars().any(|c| c.is_control() || deceptive(c))
}

fn check_text(field: &str, value: &str, max: usize) -> Result<(), ActionError> {
    if value.is_empty() || value.len() > max {
        return invalid(format!("{field} must have between 1 and {max} bytes"));
    }
    if value.chars().any(|c| c.is_control() || deceptive(c)) {
        return invalid(format!("{field} contains control or invisible characters"));
    }
    if value.trim() != value {
        return invalid(format!("{field} has leading or trailing whitespace"));
    }
    Ok(())
}

/// Meta is free form, but it is shown to approvers too.
fn check_meta(value: &Value) -> Result<(), ActionError> {
    match value {
        Value::String(s) if s.chars().any(deceptive) => {
            invalid("meta contains invisible or text reordering characters")
        }
        Value::Array(items) => items.iter().try_for_each(check_meta),
        Value::Object(map) => check_meta_map(map),
        _ => Ok(()),
    }
}

fn check_meta_map(map: &Map<String, Value>) -> Result<(), ActionError> {
    for (key, item) in map {
        if bad_key(key) {
            return invalid("meta keys cannot be empty or contain control or invisible characters");
        }
        check_meta(item)?;
    }
    Ok(())
}

/// What an approver signs: this exact action, for this challenge, until then.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub v: u8,
    pub project: String,
    pub challenge: String,
    pub action_hash: String,
    pub expires_at: u64,
}

impl Binding {
    pub fn new(project: &str, challenge: &str, action_hash: &str, expires_at: u64) -> Self {
        Binding {
            v: 1,
            project: project.to_owned(),
            challenge: challenge.to_owned(),
            action_hash: action_hash.to_owned(),
            expires_at,
        }
    }

    pub fn canonical(&self) -> String {
        let value = serde_json::to_value(self).expect("binding is plain data");
        canonical::to_canonical(&value).expect("binding has no floats")
    }

    pub fn hash(&self) -> [u8; 32] {
        tagged_hash(BINDING_TAG, self.canonical().as_bytes())
    }

    /// What an approver signs to refuse the action. Distinct from `hash`, so
    /// a refusal can never be replayed as an approval or the reverse.
    pub fn reject_hash(&self) -> [u8; 32] {
        tagged_hash(REJECT_TAG, self.canonical().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Action {
        Action::parse(
            r#"{"type":"withdraw","amount":"1500.25","asset":"USDT","destination":"0xabc","meta":{"order":"A-1"}}"#,
        )
        .unwrap()
    }

    #[test]
    fn hash_ignores_formatting_but_not_content() {
        let a = sample();
        let reordered = Action::parse(
            r#"{ "meta": {"order":"A-1"}, "destination":"0xabc", "asset":"USDT", "amount":"1500.25", "type":"withdraw" }"#,
        )
        .unwrap();
        assert_eq!(a.hash().unwrap(), reordered.hash().unwrap());

        for tampered in [
            r#"{"type":"withdraw","amount":"1500.26","asset":"USDT","destination":"0xabc","meta":{"order":"A-1"}}"#,
            r#"{"type":"withdraw","amount":"1500.25","asset":"USDT","destination":"0xabd","meta":{"order":"A-1"}}"#,
            r#"{"type":"withdraw","amount":"1500.25","asset":"USDC","destination":"0xabc","meta":{"order":"A-1"}}"#,
            r#"{"type":"transfer","amount":"1500.25","asset":"USDT","destination":"0xabc","meta":{"order":"A-1"}}"#,
            r#"{"type":"withdraw","amount":"1500.25","asset":"USDT","destination":"0xabc","meta":{"order":"A-2"}}"#,
            r#"{"type":"withdraw","amount":"1500.25","asset":"USDT","destination":"0xabc"}"#,
        ] {
            assert_ne!(
                a.hash().unwrap(),
                Action::parse(tampered).unwrap().hash().unwrap()
            );
        }
    }

    #[test]
    fn rejects_malformed_actions() {
        for bad in [
            r#"{}"#,
            r#"{"type":""}"#,
            r#"{"type":"x","unknown":1}"#,
            r#"{"type":"x","amount":100}"#,
            r#"{"type":"x","amount":"-1"}"#,
            r#"{"type":"x","amount":"+1"}"#,
            r#"{"type":"x","amount":"1e3"}"#,
            r#"{"type":"x","amount":"1,000"}"#,
            r#"{"type":"x","amount":".5"}"#,
            r#"{"type":"x","amount":"5."}"#,
            r#"{"type":"x","amount":"007"}"#,
            r#"{"type":"x","amount":"00.5"}"#,
            r#"{"type":"x","amount":" 5"}"#,
            r#"{"type":"x","amount":""}"#,
            r#"{"type":"x","destination":" 0xabc"}"#,
            r#"{"type":"x","destination":"0x\u0000abc"}"#,
            r#"{"type":"x","meta":{"rate":0.5}}"#,
            r#"{"type":"x","type":"y"}"#,
            // Right-to-left override: the screen would show the address reversed.
            "{\"type\":\"x\",\"destination\":\"0xabc\u{202e}def\"}",
            "{\"type\":\"x\",\"asset\":\"US\u{200b}DT\"}",
            "{\"type\":\"x\",\"meta\":{\"note\":\"a\u{202e}b\"}}",
            "{\"type\":\"x\",\"meta\":{\"deep\":[{\"k\u{2066}\":1}]}}",
            r#"{"type":"x","meta":{"":1}}"#,
        ] {
            assert!(Action::parse(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn amount_parses_exactly() {
        let a = Action::parse(r#"{"type":"x","amount":"0.000000000000000001"}"#).unwrap();
        assert_eq!(
            a.amount_decimal().unwrap().unwrap().to_string(),
            "0.000000000000000001"
        );
    }

    #[test]
    fn binding_hash_covers_every_field() {
        let base = Binding::new("p", "c", "aa", 100);
        let variants = [
            Binding::new("q", "c", "aa", 100),
            Binding::new("p", "d", "aa", 100),
            Binding::new("p", "c", "ab", 100),
            Binding::new("p", "c", "aa", 101),
        ];
        for v in variants {
            assert_ne!(base.hash(), v.hash());
        }
        // A binding is never confused with an action carrying the same bytes.
        assert_ne!(
            base.hash(),
            tagged_hash(ACTION_TAG, base.canonical().as_bytes())
        );
    }
}
