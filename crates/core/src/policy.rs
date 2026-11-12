//! The rules that decide whether an action passes alone, needs approval, or
//! is refused. First matching rule decides. No match means deny.

use crate::action::Action;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    /// Something an attacker can answer by stealing a secret or an account.
    Weak,
    /// A signature from a key that never leaves the approver.
    Strong,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ApproverKind {
    Ed25519,
    Passkey,
    Cosigner,
    Telegram,
    Totp,
}

impl ApproverKind {
    /// Strength is a property of the mechanism and cannot be configured up.
    pub fn strength(self) -> Strength {
        match self {
            ApproverKind::Ed25519 | ApproverKind::Passkey | ApproverKind::Cosigner => {
                Strength::Strong
            }
            ApproverKind::Telegram | ApproverKind::Totp => Strength::Weak,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ApproverKind::Ed25519 => "ed25519",
            ApproverKind::Passkey => "passkey",
            ApproverKind::Cosigner => "cosigner",
            ApproverKind::Telegram => "telegram",
            ApproverKind::Totp => "totp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ed25519" => ApproverKind::Ed25519,
            "passkey" => ApproverKind::Passkey,
            "cosigner" => ApproverKind::Cosigner,
            "telegram" => ApproverKind::Telegram,
            "totp" => ApproverKind::Totp,
            _ => return None,
        })
    }
}

// `deny_unknown_fields` everywhere: a misspelled condition that was silently
// ignored would make a rule match more than its author intended.

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub lists: BTreeMap<String, Vec<String>>,
    pub rules: Vec<Rule>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub when: Conditions,
    pub then: Outcome,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Conditions {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_min: Option<Decimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_max: Option<Decimal>,
    /// Names of entries in `Policy::lists`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velocity: Option<Velocity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours_utc: Option<Hours>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Velocity {
    pub window_secs: u64,
    pub max_total: Decimal,
}

/// Half open range of UTC hours `[from, to)`. `from > to` wraps past midnight.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hours {
    pub from: u8,
    pub to: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "decision", rename_all = "lowercase", deny_unknown_fields)]
pub enum Outcome {
    Allow,
    Deny,
    Require { requirements: Vec<Requirement> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub count: u32,
    #[serde(default = "strong")]
    pub min_strength: Strength,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<ApproverKind>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvers: Option<Vec<String>>,
}

fn strong() -> Strength {
    Strength::Strong
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid policy: {0}")]
pub struct PolicyError(pub String);

fn bad<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(msg.into()))
}

/// What the engine needs to know about the world.
pub trait PolicyContext {
    fn now_unix(&self) -> u64;
    /// Sum of amounts already authorized for this asset in the last
    /// `window_secs` seconds. `None` means unknown, which never matches.
    fn velocity_total(&self, asset: &str, window_secs: u64) -> Option<Decimal>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub outcome: Outcome,
    /// Name of the rule that decided. `None` when nothing matched.
    pub rule: Option<String>,
}

impl Policy {
    pub fn parse(json: &str) -> Result<Self, PolicyError> {
        let value = crate::canonical::parse_strict(json).map_err(|e| PolicyError(e.to_string()))?;
        let policy: Policy =
            serde_json::from_value(value).map_err(|e| PolicyError(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// A policy that refuses everything. The state of a project before its
    /// owner configures one.
    pub fn deny_all() -> Self {
        Policy {
            version: 1,
            lists: BTreeMap::new(),
            rules: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return bad("unsupported version");
        }
        let mut names = BTreeSet::new();
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                return bad("every rule needs a name");
            }
            if !names.insert(rule.name.as_str()) {
                return bad(format!("duplicate rule name: {}", rule.name));
            }
            let ctx = |msg: &str| PolicyError(format!("rule \"{}\": {msg}", rule.name));
            let when = &rule.when;
            for (field, values) in [("type", &when.kinds), ("asset", &when.asset)] {
                if values.as_ref().is_some_and(Vec::is_empty) {
                    return Err(ctx(&format!("{field} cannot be an empty list")));
                }
            }
            for amount in [&when.amount_min, &when.amount_max].into_iter().flatten() {
                if amount.is_sign_negative() {
                    return Err(ctx("amounts cannot be negative"));
                }
            }
            if let (Some(min), Some(max)) = (&when.amount_min, &when.amount_max) {
                if min > max {
                    return Err(ctx("amount_min is greater than amount_max"));
                }
            }
            if let Some(lists) = &when.destination_in {
                if lists.is_empty() {
                    return Err(ctx("destination_in cannot be an empty list"));
                }
                for name in lists {
                    if !self.lists.contains_key(name) {
                        return Err(ctx(&format!("unknown list \"{name}\"")));
                    }
                }
            }
            if let Some(v) = &when.velocity {
                if v.window_secs == 0 || v.max_total.is_sign_negative() {
                    return Err(ctx(
                        "velocity needs a positive window and a non negative total",
                    ));
                }
            }
            if let Some(h) = &when.hours_utc {
                if h.from > 23 || h.to > 24 || h.from == h.to {
                    return Err(ctx(
                        "hours_utc must satisfy from in 0..=23, to in 0..=24, from != to",
                    ));
                }
            }
            if let Outcome::Require { requirements } = &rule.then {
                if requirements.is_empty() {
                    return Err(ctx("require needs at least one requirement"));
                }
                for req in requirements {
                    if req.count == 0 {
                        return Err(ctx("requirement count must be at least 1"));
                    }
                    if req.kinds.as_ref().is_some_and(Vec::is_empty)
                        || req.approvers.as_ref().is_some_and(Vec::is_empty)
                    {
                        return Err(ctx("requirement filters cannot be empty lists"));
                    }
                    // A requirement no approver could ever satisfy is a typo.
                    if let Some(kinds) = &req.kinds {
                        if kinds.iter().all(|k| k.strength() < req.min_strength) {
                            return Err(ctx(
                                "requirement lists only weak kinds; set min_strength to \"weak\" explicitly",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn evaluate(&self, action: &Action, ctx: &dyn PolicyContext) -> Decision {
        for rule in &self.rules {
            if self.matches(&rule.when, action, ctx) {
                return Decision {
                    outcome: rule.then.clone(),
                    rule: Some(rule.name.clone()),
                };
            }
        }
        Decision {
            outcome: Outcome::Deny,
            rule: None,
        }
    }

    fn matches(&self, when: &Conditions, action: &Action, ctx: &dyn PolicyContext) -> bool {
        if let Some(kinds) = &when.kinds {
            if !kinds.contains(&action.kind) {
                return false;
            }
        }
        if let Some(assets) = &when.asset {
            match &action.asset {
                Some(asset) if assets.contains(asset) => {}
                _ => return false,
            }
        }
        // An unparseable amount cannot happen for a validated action, but if
        // it ever does it must not match anything that looks at amounts.
        let amount = action.amount_decimal().ok().flatten();
        if when.amount_min.is_some() || when.amount_max.is_some() {
            let Some(amount) = amount else { return false };
            if when.amount_min.is_some_and(|min| amount < min) {
                return false;
            }
            if when.amount_max.is_some_and(|max| amount > max) {
                return false;
            }
        }
        if let Some(list_names) = &when.destination_in {
            let Some(destination) = &action.destination else {
                return false;
            };
            let known = list_names
                .iter()
                .filter_map(|name| self.lists.get(name))
                .any(|list| list.contains(destination));
            if !known {
                return false;
            }
        }
        if let Some(velocity) = &when.velocity {
            let (Some(amount), Some(asset)) = (amount, &action.asset) else {
                return false;
            };
            let Some(spent) = ctx.velocity_total(asset, velocity.window_secs) else {
                return false;
            };
            match spent.checked_add(amount) {
                Some(total) if total <= velocity.max_total => {}
                _ => return false,
            }
        }
        if let Some(hours) = &when.hours_utc {
            let hour = ((ctx.now_unix() / 3600) % 24) as u8;
            let inside = if hours.from < hours.to {
                hour >= hours.from && hour < hours.to
            } else {
                hour >= hours.from || hour < hours.to
            };
            if !inside {
                return false;
            }
        }
        true
    }
}

/// One verified approval, as far as the policy engine cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalFact {
    pub approver: String,
    pub kind: ApproverKind,
}

impl Requirement {
    pub fn accepts(&self, fact: &ApprovalFact) -> bool {
        fact.kind.strength() >= self.min_strength
            && self
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&fact.kind))
            && self
                .approvers
                .as_ref()
                .is_none_or(|ids| ids.contains(&fact.approver))
    }

    /// Satisfied by `count` distinct approvers. One person approving twice, or
    /// through two channels, counts once.
    pub fn satisfied(&self, approvals: &[ApprovalFact]) -> bool {
        let distinct: BTreeSet<&str> = approvals
            .iter()
            .filter(|fact| self.accepts(fact))
            .map(|fact| fact.approver.as_str())
            .collect();
        distinct.len() as u64 >= u64::from(self.count)
    }
}

/// True when every requirement is satisfied. An empty list is never
/// satisfied: "require nothing" is not a way to spell allow.
pub fn all_satisfied(requirements: &[Requirement], approvals: &[ApprovalFact]) -> bool {
    !requirements.is_empty() && requirements.iter().all(|r| r.satisfied(approvals))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        now: u64,
        spent: Option<Decimal>,
    }
    impl PolicyContext for Ctx {
        fn now_unix(&self) -> u64 {
            self.now
        }
        fn velocity_total(&self, _asset: &str, _window: u64) -> Option<Decimal> {
            self.spent
        }
    }
    fn ctx(spent: &str) -> Ctx {
        Ctx {
            now: 12 * 3600,
            spent: Some(spent.parse().unwrap()),
        }
    }

    const POLICY: &str = r#"{
        "version": 1,
        "lists": { "treasury": ["0xaaa", "0xbbb"] },
        "rules": [
            { "name": "blocked asset", "when": { "asset": ["SCAM"] }, "then": { "decision": "deny" } },
            { "name": "small known",
              "when": { "type": ["withdraw"], "asset": ["USDT"], "amount_max": "100",
                        "destination_in": ["treasury"],
                        "velocity": { "window_secs": 86400, "max_total": "250" } },
              "then": { "decision": "allow" } },
            { "name": "withdrawals need a human",
              "when": { "type": ["withdraw"] },
              "then": { "decision": "require", "requirements": [ { "count": 1 } ] } }
        ]
    }"#;

    fn act(json: &str) -> Action {
        Action::parse(json).unwrap()
    }
    fn decide(json: &str, c: &Ctx) -> (Outcome, Option<String>) {
        let d = Policy::parse(POLICY).unwrap().evaluate(&act(json), c);
        (d.outcome, d.rule)
    }
    fn rule(json: &str, c: &Ctx) -> Option<String> {
        decide(json, c).1
    }

    #[test]
    fn first_match_decides() {
        let small = r#"{"type":"withdraw","amount":"100","asset":"USDT","destination":"0xaaa"}"#;
        assert_eq!(
            decide(small, &ctx("0")),
            (Outcome::Allow, Some("small known".into()))
        );
        let scam = r#"{"type":"withdraw","amount":"1","asset":"SCAM","destination":"0xaaa"}"#;
        assert_eq!(decide(scam, &ctx("0")).0, Outcome::Deny);
    }

    #[test]
    fn anything_outside_the_allow_rule_needs_a_human() {
        let human = Some("withdrawals need a human".to_string());
        // Over the limit by the smallest amount.
        let over =
            r#"{"type":"withdraw","amount":"100.000001","asset":"USDT","destination":"0xaaa"}"#;
        assert_eq!(rule(over, &ctx("0")), human);
        // Unknown destination.
        let unknown = r#"{"type":"withdraw","amount":"1","asset":"USDT","destination":"0xccc"}"#;
        assert_eq!(rule(unknown, &ctx("0")), human);
        // Destination differing only in case is a different destination.
        let case = r#"{"type":"withdraw","amount":"1","asset":"USDT","destination":"0xAAA"}"#;
        assert_eq!(rule(case, &ctx("0")), human);
        // Missing fields never match a condition on them.
        assert_eq!(
            rule(
                r#"{"type":"withdraw","asset":"USDT","destination":"0xaaa"}"#,
                &ctx("0")
            ),
            human
        );
        assert_eq!(
            rule(
                r#"{"type":"withdraw","amount":"1","asset":"USDT"}"#,
                &ctx("0")
            ),
            human
        );
        assert_eq!(
            rule(
                r#"{"type":"withdraw","amount":"1","destination":"0xaaa"}"#,
                &ctx("0")
            ),
            human
        );
    }

    #[test]
    fn velocity_caps_the_total() {
        let a = r#"{"type":"withdraw","amount":"100","asset":"USDT","destination":"0xaaa"}"#;
        assert_eq!(decide(a, &ctx("150")).0, Outcome::Allow);
        assert!(matches!(
            decide(a, &ctx("150.01")).0,
            Outcome::Require { .. }
        ));
        // Unknown history never matches.
        let unknown = Ctx {
            now: 0,
            spent: None,
        };
        assert!(matches!(decide(a, &unknown).0, Outcome::Require { .. }));
        // Overflow never matches.
        let huge = Ctx {
            now: 0,
            spent: Some(Decimal::MAX),
        };
        assert!(matches!(decide(a, &huge).0, Outcome::Require { .. }));
    }

    #[test]
    fn no_match_is_deny() {
        let d = Policy::parse(POLICY)
            .unwrap()
            .evaluate(&act(r#"{"type":"trade"}"#), &ctx("0"));
        assert_eq!(
            d,
            Decision {
                outcome: Outcome::Deny,
                rule: None
            }
        );
        let d = Policy::deny_all().evaluate(&act(r#"{"type":"withdraw"}"#), &ctx("0"));
        assert_eq!(d.outcome, Outcome::Deny);
    }

    #[test]
    fn hours_window() {
        let p = Policy::parse(
            r#"{"version":1,"rules":[
                {"name":"day","when":{"hours_utc":{"from":9,"to":18}},"then":{"decision":"allow"}},
                {"name":"night","when":{"hours_utc":{"from":22,"to":6}},"then":{"decision":"deny"}}]}"#,
        )
        .unwrap();
        let at = |h: u64| {
            p.evaluate(
                &act(r#"{"type":"x"}"#),
                &Ctx {
                    now: h * 3600,
                    spent: None,
                },
            )
            .rule
        };
        assert_eq!(at(9).as_deref(), Some("day"));
        assert_eq!(at(17).as_deref(), Some("day"));
        assert_eq!(at(18), None);
        assert_eq!(at(23).as_deref(), Some("night"));
        assert_eq!(at(5).as_deref(), Some("night"));
        assert_eq!(at(6), None);
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let wrap = |rule: &str| format!(r#"{{"version":1,"rules":[{rule}]}}"#);
        for bad in [
            r#"{"version":2,"rules":[]}"#.to_string(),
            // Typo in a condition name must not widen the rule.
            wrap(r#"{"name":"a","when":{"amount_mx":"1"},"then":{"decision":"allow"}}"#),
            wrap(r#"{"name":"a","when":{"destination_in":["nope"]},"then":{"decision":"allow"}}"#),
            wrap(r#"{"name":"a","when":{"type":[]},"then":{"decision":"allow"}}"#),
            wrap(r#"{"name":"a","when":{"amount_max":"-1"},"then":{"decision":"allow"}}"#),
            wrap(r#"{"name":"a","when":{"amount_max":5},"then":{"decision":"allow"}}"#),
            wrap(r#"{"name":"a","when":{},"then":{"decision":"require","requirements":[]}}"#),
            wrap(
                r#"{"name":"a","when":{},"then":{"decision":"require","requirements":[{"count":0}]}}"#,
            ),
            wrap(
                r#"{"name":"a","when":{},"then":{"decision":"require","requirements":[{"count":1,"kinds":["totp"]}]}}"#,
            ),
            wrap(r#"{"name":"a","when":{},"then":{"decision":"maybe"}}"#),
            wrap(
                r#"{"name":"a","when":{},"then":{"decision":"allow"}},{"name":"a","when":{},"then":{"decision":"deny"}}"#,
            ),
            wrap(
                r#"{"name":"a","when":{"hours_utc":{"from":24,"to":3}},"then":{"decision":"allow"}}"#,
            ),
        ] {
            assert!(Policy::parse(&bad).is_err(), "should reject {bad}");
        }
    }

    fn fact(approver: &str, kind: ApproverKind) -> ApprovalFact {
        ApprovalFact {
            approver: approver.into(),
            kind,
        }
    }
    fn req(json: &str) -> Requirement {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn requirements_count_distinct_people() {
        let two = req(r#"{"count":2}"#);
        let alice_twice = [
            fact("alice", ApproverKind::Passkey),
            fact("alice", ApproverKind::Ed25519),
        ];
        assert!(!two.satisfied(&alice_twice));
        let both = [
            fact("alice", ApproverKind::Passkey),
            fact("bob", ApproverKind::Ed25519),
        ];
        assert!(two.satisfied(&both));
    }

    #[test]
    fn weak_channels_do_not_satisfy_by_default() {
        let default = req(r#"{"count":1}"#);
        assert!(!default.satisfied(&[fact("alice", ApproverKind::Telegram)]));
        assert!(!default.satisfied(&[fact("alice", ApproverKind::Totp)]));
        let weak_ok = req(r#"{"count":1,"min_strength":"weak"}"#);
        assert!(weak_ok.satisfied(&[fact("alice", ApproverKind::Telegram)]));
    }

    #[test]
    fn requirement_filters() {
        let cosigner = req(r#"{"count":1,"kinds":["cosigner"]}"#);
        assert!(!cosigner.satisfied(&[fact("alice", ApproverKind::Passkey)]));
        assert!(cosigner.satisfied(&[fact("vault", ApproverKind::Cosigner)]));
        let named = req(r#"{"count":1,"approvers":["alice"]}"#);
        assert!(!named.satisfied(&[fact("bob", ApproverKind::Passkey)]));

        let reqs = [req(r#"{"count":1,"kinds":["passkey"]}"#), cosigner];
        assert!(!all_satisfied(
            &reqs,
            &[fact("alice", ApproverKind::Passkey)]
        ));
        assert!(all_satisfied(
            &reqs,
            &[
                fact("alice", ApproverKind::Passkey),
                fact("vault", ApproverKind::Cosigner)
            ]
        ));
        assert!(!all_satisfied(&[], &[fact("alice", ApproverKind::Passkey)]));
    }
}
