// Owned test payload: no UI/network. Confirm the same startup event as the app.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> *mut std::ffi::c_void;
    fn SetEvent(handle: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}
fn main() {
    let executable = std::env::current_exe().unwrap();
    assert_eq!(std::env::args().nth(1).as_deref(), Some("--update-health"));
    let name = std::env::args().nth(2).unwrap();
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let event = OpenEventW(2, 0, wide.as_ptr());
        assert!(!event.is_null());
        assert_ne!(SetEvent(event), 0);
        CloseHandle(event);
    }
    std::fs::write(executable.with_extension("updated"), b"new payload started").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
}
