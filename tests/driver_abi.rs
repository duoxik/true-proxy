//! Tests DLL helper functions only; never opens a WinDivert device or changes networking.
#![cfg(windows)]
use anyhow::Result;
use true_proxy::platform::windows::divert::Driver;

#[test]
#[ignore = "optional extended DLL ABI check; no elevation or interception"]
fn bundled_dll_exports_and_filters_are_compatible() -> Result<()> {
    let driver = Driver::load()?;
    driver.validate_filter("!impostor and !loopback and ((outbound and (tcp or udp)) or (inbound and (tcp.SrcPort == 53 or udp.SrcPort == 53)))",0)?;
    driver.validate_filter("event == CLOSE and protocol == 17", 3)?;
    assert!(
        driver
            .validate_filter("this is not a WinDivert filter", 0)
            .is_err()
    );
    Ok(())
}
