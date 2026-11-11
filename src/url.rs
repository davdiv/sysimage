//! Small URL helpers shared by the URL-ish parsers.
//!
//! Both the `nbd+unix://…?socket=…` parser ([`crate::nbd`]) and the
//! `podman+build:…?...` build-argument parser ([`crate::input`]) accept values
//! that may need characters the URL grammar reserves (spaces, `&`, `#`, `=`).
//! [`percent_decode`] undoes the `%XX` escaping so callers see the raw value.

/// Minimal percent-decoding (`%XX` → byte).
///
/// Invalid escapes (a `%` not followed by two hex digits) are copied verbatim,
/// so a plain string round-trips unchanged. The decoded bytes are interpreted
/// as UTF-8 (lossily, so arbitrary bytes never panic).
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(a), Some(b)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((a << 4) | b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::percent_decode;

    #[test]
    fn decodes_escapes_and_keeps_plain_text() {
        assert_eq!(percent_decode("a%20b%26c%23d"), "a b&c#d");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%2Gb"), "a%2Gb"); // invalid escape kept
        assert_eq!(percent_decode("%"), "%");
    }
}
