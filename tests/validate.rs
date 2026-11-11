//! Schema-generation + validation behaviour for config and manifest documents.

use serde_json::json;
use sysimage::model::schema::{config_schema, manifest_schema};
use sysimage::validate::validate;

fn assert_invalid(value: &serde_json::Value, schema: &serde_json::Value, needle: &str) {
    let err = validate(value, schema).expect_err("expected validation error");
    let msg = err.to_string();
    assert!(
        msg.contains(needle),
        "error {msg:?} does not mention {needle:?}"
    );
}

#[test]
fn valid_minimal_config_passes() {
    let cfg = json!({
        "name": "demo",
        "disk": {
            "d": {
                "type": "gpt",
                "partitions": [{
                    "name": "efi",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "content": { "type": "fat", "files": [] }
                }]
            }
        }
    });
    validate(&cfg, &config_schema()).expect("valid config should pass");
}

#[test]
fn config_rejects_unknown_top_level_field() {
    let cfg = json!({ "name": "demo", "bogus": 1 });
    assert_invalid(
        &cfg,
        &config_schema(),
        "Additional properties are not allowed",
    );
}

#[test]
fn config_rejects_unknown_block_type() {
    let cfg = json!({
        "disk": { "d": { "type": "gtp", "partitions": [] } }
    });
    assert_invalid(&cfg, &config_schema(), "oneOf");
}

#[test]
fn config_rejects_unknown_field_in_partition() {
    let cfg = json!({
        "disk": {
            "d": {
                "type": "gpt",
                "partitions": [{
                    "name": "efi",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "bogusField": true
                }]
            }
        }
    });
    assert_invalid(&cfg, &config_schema(), "bogusField");
}

#[test]
fn config_rejects_bad_size_type() {
    // `sizeMin` must be a number-or-string size, not a boolean.
    let cfg = json!({
        "disk": {
            "d": {
                "type": "lvm",
                "sizeMin": true,
                "vg": "system"
            }
        }
    });
    assert_invalid(&cfg, &config_schema(), "/disk/d/sizeMin");
}

#[test]
fn valid_minimal_manifest_passes() {
    let manifest = json!({
        "name": "demo",
        "version": "20260805",
        "arch": "x64",
        "file": {},
        "disk": {
            "d": {
                "type": "gpt",
                "sizeMin": 1048576,
                "partitions": [{
                    "name": "efi",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "sizeMin": 1048576,
                    "sizeWeight": 0.0
                }]
            }
        },
        "lvm": {}
    });
    validate(&manifest, &manifest_schema()).expect("valid manifest should pass");
}

#[test]
fn manifest_rejects_missing_required_field() {
    // The top-level manifest requires `disk`; omitting it must fail.
    let manifest = json!({
        "name": "demo",
        "version": "20260805",
        "arch": "x64",
        "file": {},
        "lvm": {}
    });
    assert_invalid(&manifest, &manifest_schema(), "is a required property");
}

#[test]
fn manifest_rejects_unknown_field() {
    let manifest = json!({
        "name": "demo",
        "version": "20260805",
        "arch": "x64",
        "file": {},
        "disk": {},
        "lvm": {},
        "bogus": 1
    });
    assert_invalid(
        &manifest,
        &manifest_schema(),
        "Additional properties are not allowed",
    );
}

#[test]
fn config_schema_sets_additional_properties_false() {
    let schema = config_schema();
    assert_eq!(
        schema.get("additionalProperties").and_then(|v| v.as_bool()),
        Some(false)
    );
    // A tagged-union variant body itself stays open...
    let gpt = schema["$defs"]["ConfigBlockGpt"].as_object().unwrap();
    assert!(!gpt.contains_key("additionalProperties"));
    // ...but its oneOf entry is closed and carries the discriminator + fields.
    let entry = &schema["$defs"]["ConfigBlock"]["oneOf"][0];
    assert_eq!(entry["additionalProperties"].as_bool(), Some(false));
    let props = entry["properties"].as_object().unwrap();
    assert!(props.contains_key("type"));
    assert!(props.contains_key("partitions"));
}

#[test]
fn valid_mbr_config_passes() {
    let cfg = json!({
        "name": "demo",
        "disk": {
            "d": {
                "type": "mbr",
                "partitions": [{
                    "type": "linux",
                    "content": { "type": "ext4", "emptySpace": "32M" }
                }, {
                    "type": "fat32",
                    "bootable": true,
                    "content": { "type": "fat", "files": [] }
                }]
            }
        }
    });
    validate(&cfg, &config_schema()).expect("valid MBR config should pass");
}

#[test]
fn valid_hybrid_config_passes() {
    let cfg = json!({
        "name": "demo",
        "disk": {
            "d": {
                "type": "gpt",
                "partitions": [{
                    "name": "esp",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "content": { "type": "fat", "files": [] }
                }],
                "mbr": {
                    "protectiveSlot": 0,
                    "mirrored": [{ "partition": "esp", "type": "efi", "bootable": true }]
                }
            }
        }
    });
    validate(&cfg, &config_schema()).expect("valid hybrid gpt config should pass");
}

#[test]
fn valid_hybrid_config_accepts_numeric_mirrored_type() {
    let cfg = json!({
        "name": "demo",
        "disk": {
            "d": {
                "type": "gpt",
                "partitions": [{
                    "name": "esp",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "content": { "type": "fat", "files": [] }
                }],
                "mbr": {
                    "protectiveSlot": 0,
                    "mirrored": [{ "partition": "esp", "type": 0xEF, "bootable": true }]
                }
            }
        }
    });
    validate(&cfg, &config_schema()).expect("numeric mirrored type should pass");
}

#[test]
fn config_rejects_unknown_mirrored_type_name() {
    let cfg = json!({
        "name": "demo",
        "disk": {
            "d": {
                "type": "gpt",
                "partitions": [{
                    "name": "esp",
                    "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                    "content": { "type": "fat", "files": [] }
                }],
                "mbr": {
                    "mirrored": [{ "partition": "esp", "type": "not-a-real-mbr-type" }]
                }
            }
        }
    });
    assert_invalid(&cfg, &config_schema(), "not-a-real-mbr-type");
}

#[test]
fn config_rejects_unknown_field_in_mbr_partition() {
    let cfg = json!({
        "disk": {
            "d": {
                "type": "mbr",
                "partitions": [{
                    "type": "linux",
                    "bogusField": true
                }]
            }
        }
    });
    assert_invalid(&cfg, &config_schema(), "bogusField");
}
