//! Device instance range parsing for Who-Is.

/// Parse a discover range string like "1000-2000" into (low, high).
pub(crate) fn parse_discover_range(
    range: Option<&str>,
) -> Result<(Option<u32>, Option<u32>), Box<dyn std::error::Error>> {
    if let Some(r) = range {
        if let Some((lo, hi)) = r.split_once('-') {
            let low = lo
                .parse::<u32>()
                .map_err(|_| format!("invalid range low: '{lo}'"))?;
            let high = hi
                .parse::<u32>()
                .map_err(|_| format!("invalid range high: '{hi}'"))?;
            if low > high {
                return Err(format!("invalid range: low ({low}) > high ({high})").into());
            }
            Ok((Some(low), Some(high)))
        } else {
            Err(format!("invalid range format: '{r}', expected 'low-high'").into())
        }
    } else {
        Ok((None, None))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_discover_range;

    #[test]
    fn parses_bounded_and_absent_ranges() {
        assert_eq!(
            parse_discover_range(Some("101-103")).unwrap(),
            (Some(101), Some(103))
        );
        assert_eq!(parse_discover_range(None).unwrap(), (None, None));
    }

    #[test]
    fn rejects_inverted_and_malformed_ranges() {
        let inverted = parse_discover_range(Some("5-1")).unwrap_err().to_string();
        assert!(inverted.contains("low (5) > high (1)"), "{inverted}");
        let malformed = parse_discover_range(Some("12")).unwrap_err().to_string();
        assert!(malformed.contains("expected 'low-high'"), "{malformed}");
    }
}
