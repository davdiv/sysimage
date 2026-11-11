//! LVM2 text-format metadata serialization (export) and parsing (import).
//!
//! The on-disk metadata area stores a single text blob in LVM2's config
//! grammar. The blob is the VG section (no `contents`/`version` header —
//! those appear only in `vgcfgbackup` files and are optional in raw metadata).
//!
//! # Export format
//!
//! ```text
//! vgname {
//!     id = "XXXXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXXX"
//!     seqno = 1
//!     extent_size = 8192
//!     max_pv = 0
//!     max_lv = 0
//!     status = ["RESIZEABLE", "READ", "WRITE"]
//!     flags = []
//!
//!     physical_volumes {
//!         pv0 {
//!             id = "..."
//!             status = ["ALLOCATABLE"]
//!             flags = []
//!             dev_size = 65536
//!             pe_start = 2048
//!             pe_count = 3
//!             pe_alloc_count = 1
//!         }
//!     }
//!
//!     logical_volumes {
//!         lv0 {
//!             id = "..."
//!             status = ["VISIBLE", "READ", "WRITE"]
//!             flags = []
//!             segment_count = 1
//!             segment1 {
//!                 start_extent = 0
//!                 extent_count = 1
//!                 type = "striped"
//!                 stripe_count = 1
//!                 stripes = [
//!                     "pv0", 0
//!                 ]
//!             }
//!         }
//!     }
//! }
//! contents = "Text Format Volume Group"
//! version = 1
//!
//! description = ""
//! creation_host = "sysimage"
//! creation_time = 0
//! ```
//!
//! The parser is a recursive-descent parser for the subset of the LVM2 config
//! grammar used by VG metadata. It handles strings, integers, arrays, nested
//! sections, and `#` line comments.

use crate::error::{Error, Result};
use crate::lvm::layout::SECTOR_SIZE;
use crate::lvm::model::{LogicalVolume, LvSegment, PhysicalVolume, VolumeGroup};
use crate::lvm::uuid::{format_id, parse_id};

// ---------------------------------------------------------------------------
// Config tree (intermediate representation for parsing)
// ---------------------------------------------------------------------------

/// A parsed config value.
#[derive(Debug, Clone)]
enum ConfigValue {
    String(String),
    Int(i64),
    Array(Vec<ConfigValue>),
}

/// A parsed config node: either a key-value pair or a section.
#[derive(Debug, Clone)]
enum ConfigNode {
    Value {
        key: String,
        value: ConfigValue,
    },
    Section {
        key: String,
        children: Vec<ConfigNode>,
    },
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// Skip whitespace and `#` line comments.
    fn skip_ws(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
                    self.pos += 1;
                }
                Some(b'#') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /// Parse an identifier (section key or value key).
    fn parse_ident(&mut self) -> Result<String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' || c == b'+' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(Error::msg(format!(
                "Expected identifier at position {}",
                self.pos
            )));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.pos]).into_owned())
    }

    /// Parse a quoted string: `"..."` with `\\` and `\"` escapes.
    fn parse_string(&mut self) -> Result<String> {
        // Expect opening quote
        if self.peek() != Some(b'"') {
            return Err(Error::msg(format!(
                "Expected '\"' at position {}",
                self.pos
            )));
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.advance() {
                None => return Err(Error::msg("Unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => match self.advance() {
                    Some(b'\\') => out.push('\\'),
                    Some(b'"') => out.push('"'),
                    Some(c) => out.push(c as char),
                    None => return Err(Error::msg("Unterminated escape")),
                },
                Some(c) => out.push(c as char),
            }
        }
        Ok(out)
    }

    /// Parse a value: string, integer, or array.
    fn parse_value(&mut self) -> Result<ConfigValue> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => Ok(ConfigValue::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(c) if c.is_ascii_digit() || c == b'-' => self.parse_int(),
            _ => Err(Error::msg(format!(
                "Expected value at position {}",
                self.pos
            ))),
        }
    }

    fn parse_int(&mut self) -> Result<ConfigValue> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| Error::msg("Invalid integer"))?;
        let n: i64 = s
            .parse()
            .map_err(|_| Error::msg(format!("Invalid integer: {s}")))?;
        Ok(ConfigValue::Int(n))
    }

    fn parse_array(&mut self) -> Result<ConfigValue> {
        // Expect '['
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                break;
            }
            // Allow empty arrays: "[]"
            if items.is_empty() && self.peek() == Some(b']') {
                self.pos += 1;
                break;
            }
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(Error::msg(format!(
                        "Expected ',' or ']' at position {}",
                        self.pos
                    )));
                }
            }
        }
        Ok(ConfigValue::Array(items))
    }

    /// Parse a single config node (key = value, or key { ... }).
    fn parse_node(&mut self) -> Result<ConfigNode> {
        self.skip_ws();
        let key = self.parse_ident()?;
        self.skip_ws();
        match self.peek() {
            Some(b'=') => {
                self.pos += 1;
                let value = self.parse_value()?;
                Ok(ConfigNode::Value { key, value })
            }
            Some(b'{') => {
                self.pos += 1;
                let mut children = Vec::new();
                loop {
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        break;
                    }
                    if self.peek().is_none() {
                        return Err(Error::msg(format!(
                            "Unexpected end of input in section '{key}'"
                        )));
                    }
                    children.push(self.parse_node()?);
                }
                Ok(ConfigNode::Section { key, children })
            }
            _ => Err(Error::msg(format!(
                "Expected '=' or '{{' after '{key}' at position {}",
                self.pos
            ))),
        }
    }

    /// Parse the entire config text into a list of top-level nodes.
    fn parse(&mut self) -> Result<Vec<ConfigNode>> {
        let mut nodes = Vec::new();
        loop {
            self.skip_ws();
            if self.peek().is_none() {
                break;
            }
            nodes.push(self.parse_node()?);
        }
        Ok(nodes)
    }
}

// ---------------------------------------------------------------------------
// Import: parse text metadata → VolumeGroup
// ---------------------------------------------------------------------------

/// Parse LVM2 text-format VG metadata into a [`VolumeGroup`].
///
/// The input is the raw text from the metadata area (without the NUL
/// terminator). Top-level key-value pairs (e.g. `contents`, `version`,
/// `description` from backup files) are silently skipped; the first top-level
/// section is the VG.
pub fn parse_vg_metadata(text: &str) -> Result<VolumeGroup> {
    let mut parser = Parser::new(text);
    let nodes = parser.parse()?;

    // Find the first top-level section (the VG). Skip top-level key-value
    // pairs (the backup-file header: contents, version, description, etc.).
    let vg_node = nodes
        .into_iter()
        .find_map(|n| match n {
            ConfigNode::Section { key, children } => Some((key, children)),
            ConfigNode::Value { .. } => None,
        })
        .ok_or_else(|| Error::msg("No volume group section found in metadata"))?;

    import_vg(&vg_node.0, &vg_node.1)
}

fn import_vg(name: &str, children: &[ConfigNode]) -> Result<VolumeGroup> {
    let id = get_str(children, "id").ok_or_else(|| Error::msg("VG missing 'id'"))?;
    let id = parse_id(&id).map_err(Error::msg)?;
    let seqno = get_int(children, "seqno").ok_or_else(|| Error::msg("VG missing 'seqno'"))? as u32;
    let extent_size_sectors = get_int(children, "extent_size")
        .ok_or_else(|| Error::msg("VG missing 'extent_size'"))?
        as u64;
    let extent_size = extent_size_sectors * SECTOR_SIZE;

    let pv_section = find_section(children, "physical_volumes")
        .ok_or_else(|| Error::msg("VG missing 'physical_volumes' section"))?;
    let pvs = pv_section
        .iter()
        .map(|n| match n {
            ConfigNode::Section { key, children } => import_pv(key, children, extent_size),
            _ => Err(Error::msg("Unexpected non-section in physical_volumes")),
        })
        .collect::<Result<Vec<_>>>()?;

    let lvs = find_section(children, "logical_volumes")
        .map(|lv_section| {
            lv_section
                .iter()
                .map(|n| match n {
                    ConfigNode::Section { key, children } => import_lv(key, children),
                    _ => Err(Error::msg("Unexpected non-section in logical_volumes")),
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(VolumeGroup {
        name: name.to_string(),
        id,
        seqno,
        extent_size,
        pvs,
        lvs,
    })
}

fn import_pv(name: &str, children: &[ConfigNode], extent_size: u64) -> Result<PhysicalVolume> {
    let id =
        get_str(children, "id").ok_or_else(|| Error::msg(format!("PV '{name}' missing 'id'")))?;
    let id = parse_id(&id).map_err(Error::msg)?;
    let pe_start_sectors = get_int(children, "pe_start")
        .ok_or_else(|| Error::msg(format!("PV '{name}' missing 'pe_start'")))?
        as u64;
    let pe_count = get_int(children, "pe_count")
        .ok_or_else(|| Error::msg(format!("PV '{name}' missing 'pe_count'")))?
        as u64;
    let pe_alloc_count = get_int(children, "pe_alloc_count").unwrap_or(0) as u64;
    let dev_size_sectors = get_int(children, "dev_size").unwrap_or(0) as u64;

    let pe_start = pe_start_sectors * SECTOR_SIZE;
    let device_size = if dev_size_sectors > 0 {
        dev_size_sectors * SECTOR_SIZE
    } else {
        pe_start + pe_count * extent_size
    };

    // Compute MDA offset/size from defaults (not stored in text metadata).
    let mda_offset = crate::lvm::layout::DEFAULT_MDA_OFFSET;
    let mda_size = crate::lvm::layout::default_mda_size(pe_start, mda_offset);

    Ok(PhysicalVolume {
        name: name.to_string(),
        id,
        device_size,
        pe_start,
        mda_offset,
        mda_size,
        pe_count,
        pe_alloc_count,
    })
}

fn import_lv(name: &str, children: &[ConfigNode]) -> Result<LogicalVolume> {
    let id =
        get_str(children, "id").ok_or_else(|| Error::msg(format!("LV '{name}' missing 'id'")))?;
    let id = parse_id(&id).map_err(Error::msg)?;

    let mut segments = Vec::new();
    for node in children {
        if let ConfigNode::Section {
            key,
            children: seg_children,
        } = node
            && key.starts_with("segment")
        {
            segments.push(import_segment(seg_children)?);
        }
    }

    Ok(LogicalVolume {
        name: name.to_string(),
        id,
        segments,
    })
}

fn import_segment(children: &[ConfigNode]) -> Result<LvSegment> {
    let start_extent = get_int(children, "start_extent").unwrap_or(0) as u64;
    let extent_count = get_int(children, "extent_count")
        .ok_or_else(|| Error::msg("Segment missing 'extent_count'"))? as u64;

    // Parse stripes array: ["pv0", 0]
    let stripes =
        get_array(children, "stripes").ok_or_else(|| Error::msg("Segment missing 'stripes'"))?;
    if stripes.len() < 2 {
        return Err(Error::msg("Segment stripes array too short"));
    }
    let pv_name = match &stripes[0] {
        ConfigValue::String(s) => s.clone(),
        _ => return Err(Error::msg("First stripe entry must be a PV name string")),
    };
    let pv_start_extent = match &stripes[1] {
        ConfigValue::Int(n) => *n as u64,
        _ => return Err(Error::msg("Second stripe entry must be an extent number")),
    };

    Ok(LvSegment {
        start_extent,
        extent_count,
        pv_name,
        pv_start_extent,
    })
}

// ---------------------------------------------------------------------------
// Export: VolumeGroup → text metadata
// ---------------------------------------------------------------------------

/// Serialize a [`VolumeGroup`] to LVM2 text-format metadata.
///
/// The output is the raw metadata-area blob (the bytes covered by
/// `raw_locn.checksum`). It starts directly with the VG name section and ends
/// with a trailing newline. A NUL terminator is **not** included here —
/// [`crate::lvm::io::build_metadata_bytes`] appends it.
pub fn emit_vg_metadata(vg: &VolumeGroup) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} {{\n", vg.name));
    out.push_str(&format!("    id = \"{}\"\n", format_id(&vg.id)));
    out.push_str(&format!("    seqno = {}\n", vg.seqno));
    out.push_str(&format!(
        "    extent_size = {}\n",
        vg.extent_size / SECTOR_SIZE
    ));
    out.push_str("    max_pv = 0\n");
    out.push_str("    max_lv = 0\n");
    out.push_str("    status = [\"RESIZEABLE\", \"READ\", \"WRITE\"]\n");
    out.push_str("    flags = []\n");
    out.push('\n');
    out.push_str("    physical_volumes {\n");
    for pv in &vg.pvs {
        out.push_str(&format!("        {} {{\n", pv.name));
        out.push_str(&format!("            id = \"{}\"\n", format_id(&pv.id)));
        out.push_str("            status = [\"ALLOCATABLE\"]\n");
        out.push_str("            flags = []\n");
        out.push_str(&format!(
            "            dev_size = {}\n",
            pv.device_size / SECTOR_SIZE
        ));
        out.push_str(&format!(
            "            pe_start = {}\n",
            pv.pe_start / SECTOR_SIZE
        ));
        out.push_str(&format!("            pe_count = {}\n", pv.pe_count));
        out.push_str(&format!(
            "            pe_alloc_count = {}\n",
            pv.pe_alloc_count
        ));
        out.push_str("        }\n");
    }
    out.push_str("    }\n");
    if !vg.lvs.is_empty() {
        out.push('\n');
        out.push_str("    logical_volumes {\n");
        for lv in &vg.lvs {
            out.push_str(&format!("        {} {{\n", lv.name));
            out.push_str(&format!("            id = \"{}\"\n", format_id(&lv.id)));
            out.push_str("            status = [\"VISIBLE\", \"READ\", \"WRITE\"]\n");
            out.push_str("            flags = []\n");
            out.push_str(&format!(
                "            segment_count = {}\n",
                lv.segments.len()
            ));
            for (i, seg) in lv.segments.iter().enumerate() {
                emit_segment(&mut out, seg, i + 1);
            }
            out.push_str("        }\n");
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    // LVM2 raw MDA metadata trailer: the contents/version fields are required
    // by lvm2's metadata parser. With no header, the header fields are emitted
    // after the VG section.
    out.push_str("contents = \"Text Format Volume Group\"\n");
    out.push_str("version = 1\n");
    out.push('\n');
    out.push_str("description = \"\"\n");
    out.push_str("creation_host = \"sysimage\"\n");
    out.push_str("creation_time = 0\n");
    out
}

fn emit_segment(out: &mut String, seg: &LvSegment, index: usize) {
    out.push_str(&format!("            segment{} {{\n", index));
    out.push_str(&format!(
        "                start_extent = {}\n",
        seg.start_extent
    ));
    out.push_str(&format!(
        "                extent_count = {}\n",
        seg.extent_count
    ));
    out.push_str("                type = \"striped\"\n");
    out.push_str("                stripe_count = 1\n");
    out.push_str("                stripes = [\n");
    out.push_str(&format!(
        "                    \"{}\", {}\n",
        seg.pv_name, seg.pv_start_extent
    ));
    out.push_str("                ]\n");
    out.push_str("            }\n");
}

// ---------------------------------------------------------------------------
// Helper functions for navigating the config tree
// ---------------------------------------------------------------------------

fn find_section<'a>(nodes: &'a [ConfigNode], key: &str) -> Option<&'a [ConfigNode]> {
    nodes.iter().find_map(|n| match n {
        ConfigNode::Section { key: k, children } if k == key => Some(children.as_slice()),
        _ => None,
    })
}

fn get_str(nodes: &[ConfigNode], key: &str) -> Option<String> {
    nodes.iter().find_map(|n| match n {
        ConfigNode::Value {
            key: k,
            value: ConfigValue::String(s),
        } if k == key => Some(s.clone()),
        _ => None,
    })
}

fn get_int(nodes: &[ConfigNode], key: &str) -> Option<i64> {
    nodes.iter().find_map(|n| match n {
        ConfigNode::Value {
            key: k,
            value: ConfigValue::Int(n),
        } if k == key => Some(*n),
        _ => None,
    })
}

fn get_array<'a>(nodes: &'a [ConfigNode], key: &str) -> Option<&'a [ConfigValue]> {
    nodes.iter().find_map(|n| match n {
        ConfigNode::Value {
            key: k,
            value: ConfigValue::Array(items),
        } if k == key => Some(items.as_slice()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lvm::uuid::generate_id;

    fn make_vg() -> VolumeGroup {
        let pv = PhysicalVolume::new("pv0", generate_id(), 16 * 1024 * 1024);
        let mut vg = VolumeGroup::new("testvg", generate_id(), 4 * 1024 * 1024);
        vg.pvs = vec![pv];
        vg
    }

    #[test]
    fn round_trip_basic() {
        let mut vg = make_vg();
        vg.lvs.push(LogicalVolume {
            name: "lv0".into(),
            id: generate_id(),
            segments: vec![LvSegment {
                start_extent: 0,
                extent_count: 2,
                pv_name: "pv0".into(),
                pv_start_extent: 0,
            }],
        });
        vg.pvs[0].pe_alloc_count = 2;

        let text = emit_vg_metadata(&vg);
        let parsed = parse_vg_metadata(&text).unwrap();

        assert_eq!(parsed.name, "testvg");
        assert_eq!(parsed.id, vg.id);
        assert_eq!(parsed.seqno, 1);
        assert_eq!(parsed.extent_size, 4 * 1024 * 1024);
        assert_eq!(parsed.pvs.len(), 1);
        assert_eq!(parsed.pvs[0].name, "pv0");
        assert_eq!(parsed.pvs[0].id, vg.pvs[0].id);
        assert_eq!(parsed.pvs[0].pe_start, 1024 * 1024);
        assert_eq!(parsed.pvs[0].pe_count, 3);
        assert_eq!(parsed.pvs[0].pe_alloc_count, 2);
        assert_eq!(parsed.lvs.len(), 1);
        assert_eq!(parsed.lvs[0].name, "lv0");
        assert_eq!(parsed.lvs[0].id, vg.lvs[0].id);
        assert_eq!(parsed.lvs[0].segments.len(), 1);
        assert_eq!(parsed.lvs[0].segments[0].start_extent, 0);
        assert_eq!(parsed.lvs[0].segments[0].extent_count, 2);
        assert_eq!(parsed.lvs[0].segments[0].pv_name, "pv0");
        assert_eq!(parsed.lvs[0].segments[0].pv_start_extent, 0);
    }

    #[test]
    fn round_trip_multi_pv() {
        let pv0 = PhysicalVolume::new("pv0", generate_id(), 16 * 1024 * 1024);
        let pv1 = PhysicalVolume::new("pv1", generate_id(), 16 * 1024 * 1024);
        let mut vg = VolumeGroup::new("multivg", generate_id(), 4 * 1024 * 1024);
        vg.pvs = vec![pv0, pv1];
        vg.lvs.push(LogicalVolume {
            name: "lv0".into(),
            id: generate_id(),
            segments: vec![
                LvSegment {
                    start_extent: 0,
                    extent_count: 2,
                    pv_name: "pv0".into(),
                    pv_start_extent: 0,
                },
                LvSegment {
                    start_extent: 2,
                    extent_count: 1,
                    pv_name: "pv1".into(),
                    pv_start_extent: 0,
                },
            ],
        });
        vg.pvs[0].pe_alloc_count = 2;
        vg.pvs[1].pe_alloc_count = 1;

        let text = emit_vg_metadata(&vg);
        let parsed = parse_vg_metadata(&text).unwrap();

        assert_eq!(parsed.pvs.len(), 2);
        assert_eq!(parsed.lvs.len(), 1);
        assert_eq!(parsed.lvs[0].segments.len(), 2);
        assert_eq!(parsed.lvs[0].segments[0].pv_name, "pv0");
        assert_eq!(parsed.lvs[0].segments[1].pv_name, "pv1");
    }

    #[test]
    fn parse_without_indentation() {
        // LVM's raw formatter produces no indentation — make sure we can parse it.
        let text = "\
testvg {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
seqno = 1\n\
extent_size = 8192\n\
max_pv = 0\n\
max_lv = 0\n\
physical_volumes {\n\
pv0 {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
pe_start = 2048\n\
pe_count = 3\n\
pe_alloc_count = 0\n\
}\n\
}\n\
}\n";
        let vg = parse_vg_metadata(text).unwrap();
        assert_eq!(vg.name, "testvg");
        assert_eq!(vg.pvs[0].pe_count, 3);
    }

    #[test]
    fn parse_with_backup_header() {
        // Backup files have a header before the VG section — it should be skipped.
        let text = "\
# Generated by LVM2 version 2.03.41\n\
contents = \"Text Format Volume Group\"\n\
version = 1\n\
\ndescription = \"Created by sysimage\"\n\
creation_host = \"test\"\n\
creation_time = 1700000000\n\
\ntestvg {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
seqno = 1\n\
extent_size = 8192\n\
max_pv = 0\n\
max_lv = 0\n\
physical_volumes {\n\
pv0 {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
pe_start = 2048\n\
pe_count = 3\n\
pe_alloc_count = 0\n\
}\n\
}\n\
}\n";
        let vg = parse_vg_metadata(text).unwrap();
        assert_eq!(vg.name, "testvg");
    }

    #[test]
    fn parse_empty_vg() {
        let text = "\
emptyvg {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
seqno = 1\n\
extent_size = 8192\n\
max_pv = 0\n\
max_lv = 0\n\
physical_volumes {\n\
pv0 {\n\
id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\"\n\
pe_start = 2048\n\
pe_count = 3\n\
pe_alloc_count = 0\n\
}\n\
}\n\
}\n";
        let vg = parse_vg_metadata(text).unwrap();
        assert_eq!(vg.lvs.len(), 0);
    }

    #[test]
    fn pv_status_flags_compatible_with_lvm2() {
        // lvm2 only recognizes "ALLOCATABLE", "EXPORTED", and "MISSING" as PV
        // status flags.
        // "READ" and "WRITE" are NOT valid PV status flags — they cause
        // "Unknown status flag 'READ'." errors when lvm2 reads the metadata.
        let vg = make_vg();
        let text = emit_vg_metadata(&vg);

        // Find the PV status line (inside physical_volumes section).
        let pv_status = text.lines().find(|l| l.contains("ALLOCATABLE")).unwrap();
        assert!(
            pv_status.contains(r#"["ALLOCATABLE"]"#),
            "PV status should be only ALLOCATABLE, got: {pv_status}"
        );
        assert!(
            !pv_status.contains("READ"),
            "PV status must not contain READ"
        );
        assert!(
            !pv_status.contains("WRITE"),
            "PV status must not contain WRITE"
        );
    }
}
