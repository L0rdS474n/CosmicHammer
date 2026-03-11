/// Parse a report window string like "10s", "30m", "6h", "3d" into seconds.
/// Returns `None` on parse error.
pub fn parse_report_window(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }

    let s = s.trim();
    let (digits, suffix) = if s
        .as_bytes()
        .last()
        .is_some_and(|b| b.is_ascii_alphabetic())
    {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        (s, "")
    };

    let val: i64 = digits.parse().ok()?;
    if val <= 0 {
        return None;
    }

    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };

    Some(val * multiplier)
}

/// Format seconds as a human-readable duration string like "3d 14h 32m 5s".
/// Omits zero fields.
pub fn fmt_duration(secs: i64) -> String {
    let secs = secs.unsigned_abs();
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;

    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_report_window() {
        assert_eq!(parse_report_window("10s"), Some(10));
        assert_eq!(parse_report_window("10S"), Some(10));
        assert_eq!(parse_report_window("30m"), Some(1800));
        assert_eq!(parse_report_window("6h"), Some(21600));
        assert_eq!(parse_report_window("3d"), Some(259200));
        assert_eq!(parse_report_window("100"), Some(100));
        assert_eq!(parse_report_window(""), None);
        assert_eq!(parse_report_window("0s"), None);
        assert_eq!(parse_report_window("-5s"), None);
        assert_eq!(parse_report_window("abc"), None);
        assert_eq!(parse_report_window("10x"), None);
    }

    #[test]
    fn test_fmt_duration() {
        assert_eq!(fmt_duration(0), "0s");
        assert_eq!(fmt_duration(5), "5s");
        assert_eq!(fmt_duration(60), "1m");
        assert_eq!(fmt_duration(3661), "1h 1m 1s");
        assert_eq!(fmt_duration(86400), "1d");
        assert_eq!(fmt_duration(259200), "3d");
        assert_eq!(fmt_duration(90061), "1d 1h 1m 1s");
    }
}
