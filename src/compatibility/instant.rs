//! Java ISO_INSTANT parsing for representable coordinator timestamps.

use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or unsupported instant")]
pub struct InstantError;

pub fn parse(value: &str) -> Result<DateTime<Utc>, InstantError> {
    let split = value.find(['T', 't']).ok_or(InstantError)?;
    let (date, time) = (&value[..split], &value[split + 1..]);
    let mut date_fields = date.rsplitn(3, '-');
    let day = date_fields.next().ok_or(InstantError)?;
    let month = date_fields.next().ok_or(InstantError)?;
    let year = date_fields.next().ok_or(InstantError)?;
    let signed = year.starts_with(['+', '-']);
    let year_digits = if signed { &year[1..] } else { year };
    if day.len() != 2
        || month.len() != 2
        || !day.bytes().chain(month.bytes()).all(|c| c.is_ascii_digit())
        || !year_digits.bytes().all(|c| c.is_ascii_digit())
        || (!signed && year_digits.len() != 4)
        || (signed && year_digits.len() < 4)
        || (year.starts_with('+') && year_digits.len() == 4)
        || (year.starts_with('-') && year_digits.bytes().all(|c| c == b'0'))
    {
        return Err(InstantError);
    }
    let zone = time.find(['Z', 'z', '+', '-']).ok_or(InstantError)?;
    let (clock, offset) = time.split_at(zone);
    let mut parts = clock.split(':');
    let hour = parts.next().ok_or(InstantError)?;
    let minute = parts.next().ok_or(InstantError)?;
    let second = parts.next().ok_or(InstantError)?;
    if parts.next().is_some()
        || hour.len() != 2
        || minute.len() != 2
        || !hour
            .bytes()
            .chain(minute.bytes())
            .all(|c| c.is_ascii_digit())
    {
        return Err(InstantError);
    }
    let (second, fraction) = second.split_once('.').unwrap_or((second, ""));
    if second.len() != 2
        || !second.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(InstantError);
    }
    let hour: u32 = hour.parse().map_err(|_| InstantError)?;
    let minute: u32 = minute.parse().map_err(|_| InstantError)?;
    let mut second: u32 = second.parse().map_err(|_| InstantError)?;
    let nanos: u32 = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u32>().map_err(|_| InstantError)? * 10u32.pow(9 - fraction.len() as u32)
    };
    let offset_seconds: i64 = if offset.eq_ignore_ascii_case("z") {
        0
    } else {
        let sign = if offset.starts_with('+') { 1 } else { -1 };
        let components: Vec<_> = offset[1..].split(':').collect();
        if !(2..=3).contains(&components.len())
            || components
                .iter()
                .any(|v| v.len() != 2 || !v.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(InstantError);
        }
        let fields = components
            .iter()
            .map(|v| v.parse::<i64>().map_err(|_| InstantError))
            .collect::<Result<Vec<_>, _>>()?;
        let seconds = fields.get(2).copied().unwrap_or(0);
        if fields[0] > 18
            || fields[1] > 59
            || seconds > 59
            || (fields[0] == 18 && (fields[1] != 0 || seconds != 0))
        {
            return Err(InstantError);
        }
        sign * (fields[0] * 3600 + fields[1] * 60 + seconds)
    };
    if hour == 23 && minute == 59 && second == 60 {
        // ISO_INSTANT maps leap seconds to :59 rather than Chrono's extended
        // nanosecond representation. This is observable in stored deadlines.
        second = 59;
    }
    let next_day = hour == 24 && minute == 0 && second == 0 && nanos == 0;
    let hour = if next_day { 0 } else { hour };
    let date = NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| InstantError)?;
    let date = if next_day {
        date.succ_opt().ok_or(InstantError)?
    } else {
        date
    };
    let clock = NaiveTime::from_hms_nano_opt(hour, minute, second, nanos).ok_or(InstantError)?;
    let timestamp = NaiveDateTime::new(date, clock)
        .checked_sub_signed(Duration::seconds(offset_seconds))
        .ok_or(InstantError)?;
    Ok(Utc.from_utc_datetime(&timestamp))
}
