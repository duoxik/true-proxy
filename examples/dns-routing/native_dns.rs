//! Apply and restore resolver settings in our owned test helper, never another process.
use anyhow::{Context, Result, ensure};
use libloading::Library;
use std::{net::Ipv4Addr, path::PathBuf, ptr};

#[repr(C)]
struct Server {
    kind: u32,
    flags: u64,
    template: *const u16,
    address: [u8; 32],
}
#[repr(C)]
struct Settings {
    version: u32,
    flags: u64,
}
type Get = unsafe extern "system" fn(*mut u32, *mut *mut Server, *mut Settings) -> u32;
type Set = unsafe extern "system" fn(u32, *const Server, *const Settings) -> u32;
type Free = unsafe extern "system" fn(*mut u32, *mut *mut Server);

pub struct Scope {
    _library: Library,
    set: Set,
    free: Free,
    count: u32,
    servers: *mut Server,
    settings: Settings,
    snapshot_ready: bool,
}
impl Scope {
    pub fn new(ip: Ipv4Addr) -> Result<Self> {
        ensure!(
            ip.is_loopback(),
            "Only a loopback test resolver is permitted"
        );
        let directory =
            PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot missing")?);
        ensure!(directory.is_absolute(), "SystemRoot must be absolute");
        // SAFETY: system DLL at an absolute path; ABI mirrors windns.h x64
        // DNS_CUSTOM_SERVER / DNS_APPLICATION_SETTINGS. No foreign process is accessed.
        let library = unsafe { Library::new(directory.join("System32/dnsapi.dll")) }?;
        let (get, set, free) = unsafe {
            (
                *library.get::<Get>(b"DnsGetApplicationSettings\0")?,
                *library.get::<Set>(b"DnsSetApplicationSettings\0")?,
                *library.get::<Free>(b"DnsFreeCustomServers\0")?,
            )
        };
        let mut scope = Self {
            _library: library,
            set,
            free,
            count: 0,
            servers: ptr::null_mut(),
            settings: Settings {
                version: 1,
                flags: 0,
            },
            snapshot_ready: false,
        };
        ensure!(
            unsafe { get(&mut scope.count, &mut scope.servers, &mut scope.settings) } == 0,
            "Cannot read this helper's DNS settings"
        );
        scope.snapshot_ready = true;
        let mut server = Server {
            kind: 1,
            flags: 0,
            template: ptr::null(),
            address: [0; 32],
        };
        server.address[..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        // Port must be zero in the API; Windows uses the DNS port 53.
        server.address[4..8].copy_from_slice(&ip.octets());
        let exclusive = Settings {
            version: 1,
            flags: 1,
        };
        let status = unsafe { set(1, &server, &exclusive) };
        ensure!(status == 0, "Cannot set this helper's DNS server: {status}");
        Ok(scope)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.snapshot_ready {
            return;
        }
        // SAFETY: Get allocated the saved snapshot. Restore before freeing its data;
        // the DLL remains loaded throughout Drop, including failure paths.
        unsafe {
            (self.set)(self.count, self.servers, &self.settings);
            (self.free)(&mut self.count, &mut self.servers);
        }
    }
}
