//! Blocking WinHTTP for background transfers. TLS certificate checks stay enabled.
//! Update requests use the GitHub allowlist; user-supplied sources use HTTPS only.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinHttp::*;

struct Handle(*mut c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn success(result: i32) -> Result<()> {
    ensure!(
        result != 0,
        "HTTPS error: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn owned(handle: *mut c_void) -> Result<Handle> {
    ensure!(
        !handle.is_null(),
        "WinHTTP error: {}",
        std::io::Error::last_os_error()
    );
    Ok(Handle(handle))
}

pub fn get(
    url: &str,
    binary: bool,
    limit: u64,
    receive: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    request(url, Some(binary), &[], limit, receive)
}

pub fn get_https(url: &str, limit: u64, receive: impl FnMut(&[u8]) -> Result<()>) -> Result<u32> {
    request(url, None, &[], limit, receive)
}

pub fn get_https_with_headers(
    url: &str,
    headers: &[(&str, &str)],
    limit: u64,
    receive: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    request(url, None, headers, limit, receive)
}

fn extra_headers(headers: &[(&str, &str)]) -> Result<String> {
    ensure!(headers.len() <= 8, "Too many subscription request headers");
    let mut result = String::new();
    for (name, value) in headers {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && value.len() <= 256
                && value.bytes().all(|byte| (32..=126).contains(&byte)),
            "Invalid subscription request header"
        );
        result.push_str(name);
        result.push_str(": ");
        result.push_str(value);
        result.push_str("\r\n");
    }
    Ok(result)
}

fn checked_url(text: &str) -> Result<url::Url> {
    ensure!(
        text.len() <= 4096 && !text.chars().any(|c| c.is_control() || c == '\\'),
        "Invalid HTTPS source"
    );
    let url = url::Url::parse(text).map_err(|_| anyhow::anyhow!("Invalid HTTPS source"))?;
    ensure!(
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "The source must be an HTTPS URL without credentials or a fragment"
    );
    Ok(url)
}

fn request(
    url: &str,
    github: Option<bool>,
    custom_headers: &[(&str, &str)],
    limit: u64,
    mut receive: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    let started = Instant::now();
    let extra = extra_headers(custom_headers)?;
    let identity_origin = if custom_headers.is_empty() {
        None
    } else {
        Some(checked_url(url)?.origin())
    };
    // SAFETY: NUL-terminated inputs outlive calls; handles are owned and dropped
    // in request -> connection -> session order on every return path.
    let session = owned(unsafe {
        WinHttpOpen(
            wide(concat!("TrueProxy/", env!("CARGO_PKG_VERSION"))).as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        )
    })?;
    success(unsafe { WinHttpSetTimeouts(session.0, 8000, 8000, 10000, 10000) })?;
    let protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    success(unsafe {
        WinHttpSetOption(
            session.0,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            (&protocols as *const u32).cast(),
            4,
        )
    })?;
    let mut next = url.to_string();
    for _ in 0..5 {
        let source = if github.is_none() {
            Some(checked_url(&next)?)
        } else {
            None
        };
        if let Some(origin) = &identity_origin {
            ensure!(
                source
                    .as_ref()
                    .is_some_and(|source| source.origin() == *origin),
                "The device-bound subscription redirected to a different origin"
            );
        }
        let (host, path, port) = if let Some(source) = &source {
            (
                source.host_str().context("Missing HTTPS host")?,
                &source[url::Position::BeforePath..],
                source.port().unwrap_or(443),
            )
        } else {
            let (host, path) = crate::updates::split_https(&next)?;
            (host, path, 443)
        };
        let connection = owned(unsafe { WinHttpConnect(session.0, wide(host).as_ptr(), port, 0) })?;
        let request = owned(unsafe {
            WinHttpOpenRequest(
                connection.0,
                wide("GET").as_ptr(),
                wide(path).as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                WINHTTP_FLAG_SECURE,
            )
        })?;
        let mut disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
        if github.is_none() {
            disabled |= WINHTTP_DISABLE_AUTHENTICATION;
        }
        success(unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_DISABLE_FEATURE,
                (&disabled as *const u32).cast(),
                4,
            )
        })?;
        let mut header_text = match github {
            Some(true) => {
                "Accept: application/octet-stream\r\nX-GitHub-Api-Version: 2026-03-10\r\n"
            }
            Some(false) => {
                "Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2026-03-10\r\n"
            }
            None => "Accept: */*\r\n",
        }
        .to_owned();
        header_text.push_str(&extra);
        let headers = wide(&header_text);
        success(unsafe {
            WinHttpSendRequest(
                request.0,
                headers.as_ptr(),
                (headers.len() - 1) as u32,
                ptr::null(),
                0,
                0,
                0,
            )
        })?;
        success(unsafe { WinHttpReceiveResponse(request.0, ptr::null_mut()) })?;
        if github.is_none() {
            ensure!(
                !response_flag(request.0, "x-hwid-max-devices-reached")?
                    && !response_flag(request.0, "x-hwid-limit")?,
                "The subscription device limit has been reached. Remove an unused device in your provider account and retry."
            );
            ensure!(
                !response_flag(request.0, "x-hwid-not-supported")?,
                "This subscription requires a device identity (HWID). Import its original ShadowNet HTTPS link."
            );
        }
        let mut status = 0u32;
        let mut size = 4;
        success(unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                ptr::null(),
                (&mut status as *mut u32).cast(),
                &mut size,
                ptr::null_mut(),
            )
        })?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let mut length = 0;
            unsafe {
                WinHttpQueryHeaders(
                    request.0,
                    WINHTTP_QUERY_LOCATION,
                    ptr::null(),
                    ptr::null_mut(),
                    &mut length,
                    ptr::null_mut(),
                );
            }
            ensure!((2..=32768).contains(&length), "Invalid HTTPS redirect");
            let mut location = vec![0u16; (length as usize).div_ceil(2)];
            success(unsafe {
                WinHttpQueryHeaders(
                    request.0,
                    WINHTTP_QUERY_LOCATION,
                    ptr::null(),
                    location.as_mut_ptr().cast(),
                    &mut length,
                    ptr::null_mut(),
                )
            })?;
            let end = location
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(location.len());
            let location =
                String::from_utf16(&location[..end]).context("Invalid HTTPS redirect")?;
            next = if let Some(source) = source {
                source
                    .join(&location)
                    .map_err(|_| anyhow::anyhow!("Invalid HTTPS redirect"))?
                    .to_string()
            } else {
                crate::updates::split_https(&location)?;
                location
            };
            ensure!(
                started.elapsed() < Duration::from_secs(120),
                "The download timed out"
            );
            continue;
        }
        if status != 200 {
            return Ok(status);
        }
        let mut received = 0u64;
        let mut buffer = [0u8; 32768];
        loop {
            ensure!(
                started.elapsed() < Duration::from_secs(120),
                "The download timed out"
            );
            let mut read = 0;
            success(unsafe {
                WinHttpReadData(
                    request.0,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                )
            })?;
            if read == 0 {
                return Ok(status);
            }
            received += read as u64;
            ensure!(
                received <= limit,
                "The HTTPS response exceeded the size limit"
            );
            receive(&buffer[..read as usize])?;
        }
    }
    anyhow::bail!("Too many HTTPS redirects")
}

fn response_flag(request: *mut c_void, name: &str) -> Result<bool> {
    let mut value = [0u16; 32];
    let mut length = std::mem::size_of_val(&value) as u32;
    // SAFETY: both the header name and writable output buffer outlive this call.
    let found = unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_CUSTOM,
            wide(name).as_ptr(),
            value.as_mut_ptr().cast(),
            &mut length,
            ptr::null_mut(),
        )
    };
    if found == 0 {
        return Ok(false);
    }
    let end = value
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(value.len());
    Ok(String::from_utf16(&value[..end])?
        .trim()
        .eq_ignore_ascii_case("true"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_headers_cannot_inject_additional_headers() {
        assert_eq!(
            extra_headers(&[("X-HWID", "abc123456789")]).unwrap(),
            "X-HWID: abc123456789\r\n"
        );
        assert!(extra_headers(&[("X-HWID", "abc\r\nInjected: yes")]).is_err());
        assert!(extra_headers(&[("Bad: header", "abc")]).is_err());
    }
}
