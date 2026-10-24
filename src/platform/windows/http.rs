//! Blocking WinHTTP lives on the update thread. TLS certificate checks stay enabled;
//! redirects are followed explicitly, only to the GitHub HTTPS allowlist.
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
        "Ошибка HTTPS: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn owned(handle: *mut c_void) -> Result<Handle> {
    ensure!(
        !handle.is_null(),
        "Ошибка WinHTTP: {}",
        std::io::Error::last_os_error()
    );
    Ok(Handle(handle))
}

pub fn get(
    url: &str,
    binary: bool,
    limit: u64,
    mut receive: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    let started = Instant::now();
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
        let (host, path) = crate::updates::split_https(&next)?;
        let connection = owned(unsafe { WinHttpConnect(session.0, wide(host).as_ptr(), 443, 0) })?;
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
        let disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
        success(unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_DISABLE_FEATURE,
                (&disabled as *const u32).cast(),
                4,
            )
        })?;
        let headers = wide(if binary {
            "Accept: application/octet-stream\r\nX-GitHub-Api-Version: 2026-03-10\r\n"
        } else {
            "Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2026-03-10\r\n"
        });
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
            ensure!(
                (2..=32768).contains(&length),
                "Некорректное перенаправление GitHub"
            );
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
            next = String::from_utf16(&location[..end])
                .context("Некорректное перенаправление GitHub")?;
            crate::updates::split_https(&next)?;
            ensure!(
                started.elapsed() < Duration::from_secs(120),
                "Истёк срок загрузки обновления"
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
                "Истёк срок загрузки обновления"
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
            ensure!(received <= limit, "Ответ GitHub превысил допустимый размер");
            receive(&buffer[..read as usize])?;
        }
    }
    anyhow::bail!("Слишком много перенаправлений GitHub")
}
