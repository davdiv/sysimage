//! JSON Schema generation for the config and manifest models, using schemars.
//!
//! The schemas describe the *input* documents that sysimage consumes: the
//! partial [`ConfigBuild`](crate::model::config::ConfigBuild) written by users
//! and the [`ManifestBuild`](crate::model::manifest::ManifestBuild) emitted by
//! the build step (and consumed by `install`).
//!
//! Schemars represents `#[serde(tag = "type")]` enums as a `oneOf` whose every
//! entry is `{$ref: <variant>, properties: {type: {const: ...}}, required: [type]}`.
//! The variant struct itself does **not** list the `type` field, so naively
//! setting `additionalProperties: false` on it would reject the legitimate
//! discriminator. To keep strict unknown-field rejection *and* allow the tag,
//! [`finalize_schema`] merges each variant's `properties`/`required` into its
//! `oneOf` entry and puts `additionalProperties: false` on the entry instead,
//! leaving the shared variant-body definitions open.

use std::collections::{HashMap, HashSet};

use schemars::schema_for;
use serde_json::{Map, Value};

use crate::model::config::ConfigBuild;
use crate::model::manifest::ManifestBuild;
use crate::model::qemu::QemuConfig;

/// File name of the generated config schema (referenced via `$schema`).
pub const CONFIG_SCHEMA_FILE: &str = "sysimage.config.schema.json";
/// File name of the generated manifest schema (referenced via `$schema`).
pub const MANIFEST_SCHEMA_FILE: &str = "sysimage.manifest.schema.json";
/// File name of the generated QEMU launch-config schema.
pub const QEMU_SCHEMA_FILE: &str = "sysimage.qemu.schema.json";

/// Generate the JSON Schema for the user-facing config document.
pub fn config_schema() -> Value {
    let mut schema = schema_for!(ConfigBuild).to_value();
    finalize_schema(&mut schema);
    schema
}

/// Generate the JSON Schema for the manifest document.
pub fn manifest_schema() -> Value {
    let mut schema = schema_for!(ManifestBuild).to_value();
    finalize_schema(&mut schema);
    schema
}

/// Generate the JSON Schema for the QEMU launch-config (`qemu.json`) document.
pub fn qemu_schema() -> Value {
    let mut schema = schema_for!(QemuConfig).to_value();
    finalize_schema(&mut schema);
    schema
}

/// Merge tagged-union `oneOf` entries, then set `additionalProperties: false`
/// on every remaining plain object schema so unknown/misspelled fields are
/// rejected at load time.
fn finalize_schema(schema: &mut Value) {
    let variant_bodies = merge_tagged_unions(schema);
    deny_unknown_fields(schema, &variant_bodies);
}

/// For every `oneOf` entry of the form `{$ref, properties.type}`, merge the
/// referenced variant-body definition's `properties` and `required` into the
/// entry and set `additionalProperties: false` on it. Returns the set of
/// variant-body definition names (which must stay open).
fn merge_tagged_unions(root: &mut Value) -> HashSet<String> {
    let mut variant_bodies: HashSet<String> = HashSet::new();
    let Some(defs) = root.get_mut("$defs").and_then(|v| v.as_object_mut()) else {
        return variant_bodies;
    };

    // Snapshot each definition's `properties` and `required` so we can merge
    // without aliasing mutable borrows.
    let snapshots: HashMap<String, (Map<String, Value>, Vec<Value>)> = defs
        .iter()
        .filter_map(|(name, def)| {
            let props = def.get("properties").and_then(|v| v.as_object())?.clone();
            let required = def
                .get("required")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            Some((name.clone(), (props, required)))
        })
        .collect();

    for def in defs.values_mut() {
        let Some(one_of) = def.get_mut("oneOf").and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for entry in one_of.iter_mut() {
            let Some(entry_obj) = entry.as_object_mut() else {
                continue;
            };
            let Some(reference) = entry_obj.get("$ref").and_then(|v| v.as_str()) else {
                continue;
            };
            if entry_obj
                .get("properties")
                .and_then(|p| p.get("type"))
                .is_none()
            {
                continue;
            }

            let target = reference
                .rsplit('/')
                .next()
                .unwrap_or(reference)
                .to_string();
            variant_bodies.insert(target.clone());

            let Some((tprops, treq)) = snapshots.get(&target) else {
                continue;
            };
            let entry_props = entry_obj
                .get_mut("properties")
                .and_then(|v| v.as_object_mut())
                .expect("entry has properties.type");
            for (k, v) in tprops {
                entry_props.entry(k.clone()).or_insert_with(|| v.clone());
            }
            if let Some(entry_req) = entry_obj.get_mut("required").and_then(|v| v.as_array_mut()) {
                for r in treq {
                    if !entry_req.contains(r) {
                        entry_req.push(r.clone());
                    }
                }
            }
            entry_obj.insert("additionalProperties".to_string(), Value::Bool(false));
        }
    }

    variant_bodies
}

/// Recursively set `additionalProperties: false` on every plain object schema
/// (one that declares `properties` and `type: object`) which does not already
/// constrain additional properties and is not a `$ref` / combinator schema.
///
/// `variant_bodies` names definitions that are tagged-union variant bodies;
/// they are left open (the discriminator is enforced on the `oneOf` entry
/// instead) but their children are still processed.
fn deny_unknown_fields(schema: &mut Value, variant_bodies: &HashSet<String>) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };

    // Process every named definition, passing whether it is a variant body.
    if let Some(Value::Object(defs)) = obj.get_mut("$defs") {
        for (name, def) in defs.iter_mut() {
            mark_object(def, variant_bodies.contains(name));
        }
    }

    // Process the root schema itself (not a variant body).
    mark_object(schema, false);
}

fn mark_object(schema: &mut Value, is_variant_body: bool) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };

    // Recurse into children that may contain nested object schemas.
    for key in [
        "properties",
        "items",
        "additionalProperties",
        "oneOf",
        "anyOf",
        "allOf",
    ] {
        if let Some(child) = obj.get_mut(key) {
            match child {
                Value::Object(_) => mark_object(child, false),
                Value::Array(arr) => {
                    for v in arr.iter_mut() {
                        mark_object(v, false);
                    }
                }
                _ => {}
            }
        }
    }

    if is_variant_body {
        return;
    }

    let type_object = obj.get("type").is_some_and(|t| match t {
        Value::String(s) => s == "object",
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some("object")),
        _ => false,
    });
    if type_object
        && obj.contains_key("properties")
        && !obj.contains_key("$ref")
        && !obj.contains_key("oneOf")
        && !obj.contains_key("anyOf")
        && !obj.contains_key("allOf")
        && !obj.contains_key("additionalProperties")
    {
        obj.insert("additionalProperties".to_string(), Value::Bool(false));
    }
}
