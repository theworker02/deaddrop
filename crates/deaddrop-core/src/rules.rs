//! Intentionally limited automation. Not a general-purpose language.

use crate::{DdError, ErrorCode, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub when: String,
    pub filters: Vec<(String, String)>,
    pub action: String,
}

pub fn parse_rules(src: &str) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    let mut cur: Option<Rule> = None;
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line == "}" {
            if line == "}"
                && let Some(r) = cur.take()
            {
                rules.push(r);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("rule ") {
            let name = rest.trim().trim_end_matches('{').trim().to_string();
            cur = Some(Rule {
                name,
                when: String::new(),
                filters: Vec::new(),
                action: String::new(),
            });
            continue;
        }
        let Some(rule) = cur.as_mut() else {
            return Err(DdError::protocol(
                ErrorCode::Ddp1001InvalidFrame,
                "rule statement outside block",
            ));
        };
        if let Some(w) = line.strip_prefix("when ") {
            rule.when = w.trim().to_string();
        } else if let Some(i) = line.strip_prefix("if ") {
            let i = i.trim();
            if let Some((k, v)) = i.split_once("==") {
                rule.filters
                    .push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
            }
        } else if let Some(t) = line.strip_prefix("then ") {
            rule.action = t.trim().to_string();
        }
    }
    if let Some(r) = cur.take() {
        rules.push(r);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_rule() {
        let src = r#"
rule auto-pin-releases {
    when drop.received
    if drop.channel == "software/releases"
    if drop.publisher.trust == "verified"
    then drop.pin
}
"#;
        let r = parse_rules(src).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "auto-pin-releases");
        assert_eq!(r[0].action, "drop.pin");
        assert_eq!(r[0].filters.len(), 2);
    }
}
