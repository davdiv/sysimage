//! UUID formatting.

/// Format 16 raw bytes as a canonical UUID string
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lowercase hex).
pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let h = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Parse a canonical UUID string `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// (lowercase or uppercase hex, with or without dashes) into 16 raw bytes
/// (string order). Returns `None` when the string is not a valid UUID.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    let hex_only: String = s.chars().filter(|c| *c != '-').collect();
    if hex_only.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let b = u8::from_str_radix(&hex_only[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = b;
    }
    Some(out)
}
