//! `${VAR}` substitution.
//!
//! Walks a [`serde_json::Value`] recursively, replacing `${VAR}` occurrences in
//! strings via a caller-provided lookup. Unknown variables produce an error.

use serde_json::Value;

const VAR_RE: &str = r"\$\{(\w+)\}";

/// Recursively replace `${VAR}` in every string of `value`, using `get_value`
/// to resolve a variable name. Returns the rebuilt value, or an error if a
/// variable is unknown.
pub fn replace_vars<F>(value: &Value, get_value: &F) -> crate::error::Result<Value>
where
    F: Fn(&str) -> Option<String>,
{
    Ok(match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| replace_vars(v, get_value))
                .collect::<crate::error::Result<Vec<_>>>()?,
        ),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), replace_vars(v, get_value)?);
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(substitute_string(s, get_value)?),
        other => other.clone(),
    })
}

/// Replace `${VAR}` occurrences in a single string.
pub fn substitute_string<F>(input: &str, get_value: &F) -> crate::error::Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    let re = regex::Regex::new(VAR_RE).unwrap();
    let mut last_end = 0;
    let mut out = String::new();
    for caps in re.captures_iter(input) {
        let m = caps.get(0).unwrap();
        out.push_str(&input[last_end..m.start()]);
        let name = &caps[1];
        match get_value(name) {
            Some(v) => out.push_str(&v),
            None => {
                return Err(crate::error::Error::msg(format!(
                    "Unknown variable: {name}"
                )));
            }
        }
        last_end = m.end();
    }
    out.push_str(&input[last_end..]);
    Ok(out)
}
