//! Cleaning for text a device or operator supplies before anyone sees it.

/// True for characters that can hide, reorder, or restyle displayed text:
/// C0/C1 controls (ESC, BEL), bidi overrides and isolates, zero-width
/// characters, and the byte order mark.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

/// Drops hidden characters and keeps at most `max_chars` characters.
pub fn clean(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|c| !is_hidden(*c))
        .take(max_chars)
        .collect()
}
