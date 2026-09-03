// SPDX-License-Identifier: GPL-2.0

pub mod devmem;
pub mod dispatch;
pub mod loader;
pub mod rest;

use std::ffi::OsString;
use std::io;

pub fn parse_u64(value: &OsString, name: &str) -> io::Result<u64> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {name}")))?;
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix) = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (digits, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u64::from_str_radix(digits, radix)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {name}")))
}

pub fn errno_result(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_c_style_unsigned_numbers() {
        assert_eq!(parse_u64(&OsString::from("42"), "value").unwrap(), 42);
        assert_eq!(parse_u64(&OsString::from("052"), "value").unwrap(), 42);
        assert_eq!(parse_u64(&OsString::from("0x2a"), "value").unwrap(), 42);
        assert_eq!(parse_u64(&OsString::from("+42"), "value").unwrap(), 42);
        assert!(parse_u64(&OsString::from("08"), "value").is_err());
        assert!(parse_u64(&OsString::from("-1"), "value").is_err());
    }
}
