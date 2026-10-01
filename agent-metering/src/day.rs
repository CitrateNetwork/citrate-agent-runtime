//! UTC day arithmetic (proleptic Gregorian, Howard Hinnant's civil-day algorithms). Kept local so
//! the crate needs no calendar dependency.

use crate::MeteringError;

const DAY_MS: u64 = 86_400_000;

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// `[start, end)` in Unix milliseconds for a `YYYY-MM-DD` UTC day on or after 1970-01-01.
pub fn utc_day_bounds_ms(day: &str) -> Result<(u64, u64), MeteringError> {
    let bad = || MeteringError::InvalidDay(day.to_string());
    let b = day.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(bad());
    }
    let digits = |s: &str| -> Option<u32> {
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let y = digits(&day[0..4]).ok_or_else(bad)?;
    let m = digits(&day[5..7]).ok_or_else(bad)?;
    let d = digits(&day[8..10]).ok_or_else(bad)?;
    let y = i64::from(y);
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return Err(bad());
    }
    let days = days_from_civil(y, m, d);
    let days = u64::try_from(days).map_err(|_| bad())?;
    let start = days.checked_mul(DAY_MS).ok_or_else(bad)?;
    Ok((start, start + DAY_MS))
}

/// The `YYYY-MM-DD` UTC day containing a Unix millisecond timestamp.
pub fn utc_day_of_ms(ms: u64) -> String {
    let days = i64::try_from(ms / DAY_MS).unwrap_or(i64::MAX / 2);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_day_for_a_few_centuries() {
        let mut ms = 0u64;
        for _ in 0..(366 * 300) {
            let day = utc_day_of_ms(ms);
            assert_eq!(utc_day_bounds_ms(&day).unwrap().0, ms, "{day}");
            ms += DAY_MS;
        }
    }

    #[test]
    fn century_leap_rules() {
        assert!(utc_day_bounds_ms("2000-02-29").is_ok());
        assert!(utc_day_bounds_ms("2100-02-29").is_err());
    }
}
