//! LVM2 UUID generation, formatting, and parsing.
//!
//! Mirrors lvm2's UUID rules:
//!
//! - Generation maps 32 random bytes to characters from the alphabet
//!   `"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#"`.
//! - Formatting inserts dashes in groups of `[6, 4, 4, 4, 4, 4, 6]`.
//! - Parsing strips dashes and validates each character.

use rand::Rng;

/// Length of a raw LVM UUID (32 bytes, no dashes).
pub const ID_LEN: usize = 32;

/// Length of a formatted LVM UUID with dashes (32 + 6 = 38 chars).
pub const ID_STR_LEN: usize = 38;

/// The character set used by LVM2 UUIDs.
///
/// Note: this uses `!` and `#`, **not** `+` and `/` — a common mistake.
const ID_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#";

/// Group sizes for the dashed UUID format.
const ID_GROUPS: [usize; 7] = [6, 4, 4, 4, 4, 4, 6];

/// Generate a random 32-character LVM UUID (no dashes).
///
/// Matches lvm2: 32 random bytes, each mapped via
/// `byte % (alphabet_len - 2)` (the last 2 chars are skipped for LVM1
/// backwards compatibility).
pub fn generate_id() -> String {
    let mut bytes = [0u8; ID_LEN];
    rand::rng().fill_bytes(&mut bytes);
    // The modulus is 62, so generated IDs use `0-9a-zA-Z`; `!` (index 62) and
    // `#` (index 63) remain valid for parsing but are never generated
    // (matching LVM2's LVM1 backwards-compatibility behaviour).
    let modulus = (ID_ALPHABET.len() - 2) as u8; // 62
    let mut out = String::with_capacity(ID_LEN);
    for b in &bytes {
        out.push(ID_ALPHABET[(*b % modulus) as usize] as char);
    }
    out
}

/// Format a 32-char raw UUID with dashes: `XXXXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXXX`.
pub fn format_id(id: &str) -> String {
    assert_eq!(id.len(), ID_LEN, "LVM id must be {ID_LEN} chars");
    let mut out = String::with_capacity(ID_STR_LEN);
    let mut pos = 0;
    for (i, &len) in ID_GROUPS.iter().enumerate() {
        out.push_str(&id[pos..pos + len]);
        pos += len;
        if i < ID_GROUPS.len() - 1 {
            out.push('-');
        }
    }
    out
}

/// Parse a dashed UUID back to its 32-char raw form.
///
/// Strips dashes and validates each character is in the LVM alphabet.
pub fn parse_id(formatted: &str) -> Result<String, String> {
    let mut out = String::with_capacity(ID_LEN);
    for c in formatted.chars() {
        if c == '-' {
            continue;
        }
        if out.len() >= ID_LEN {
            return Err("Too many characters to be uuid".into());
        }
        if !is_valid_id_char(c as u8) {
            return Err(format!("UUID contains invalid character '{c}'"));
        }
        out.push(c);
    }
    if out.len() != ID_LEN {
        return Err(format!(
            "Couldn't read uuid: incorrect number of characters ({} != {ID_LEN})",
            out.len()
        ));
    }
    Ok(out)
}

/// Check whether a byte is a valid LVM UUID character.
fn is_valid_id_char(b: u8) -> bool {
    ID_ALPHABET.contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_round_trip() {
        let id = generate_id();
        assert_eq!(id.len(), ID_LEN);
        let formatted = format_id(&id);
        assert_eq!(formatted.len(), ID_STR_LEN);
        let parsed = parse_id(&formatted).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn format_id_known() {
        let id = "0123456789abcdefghijklmnopqrstuv";
        let formatted = format_id(id);
        assert_eq!(formatted, "012345-6789-abcd-efgh-ijkl-mnop-qrstuv");
    }

    #[test]
    fn parse_id_strips_dashes() {
        let formatted = "012345-6789-abcd-efgh-ijkl-mnop-qrstuv";
        let parsed = parse_id(formatted).unwrap();
        assert_eq!(parsed, "0123456789abcdefghijklmnopqrstuv");
    }

    #[test]
    fn generated_id_no_plus_slash() {
        // LVM uses ! and #, never + or /
        for _ in 0..1000 {
            let id = generate_id();
            assert!(!id.contains('+'));
            assert!(!id.contains('/'));
        }
    }
}
