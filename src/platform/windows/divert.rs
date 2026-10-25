//! Minimal dynamically loaded WinDivert ABI. Loading the DLL never opens a device.
use super::bundle::{self, PreparedDriver};
use anyhow::{Context, Result, ensure};
use libloading::Library;
use std::{
    ffi::{CStr, CString, c_void},
    net::IpAddr,
    path::Path,
    ptr,
    sync::Arc,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}
impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}
impl Address {
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
    pub fn outbound(&self) -> bool {
        self.flags & (1 << 17) != 0
    }
    pub fn set_inbound(&mut self) {
        self.flags &= !(1 << 17);
    }
}
type Handle = *mut c_void;
type Open = unsafe extern "system" fn(*const i8, i32, i16, u64) -> Handle;
type Recv = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const Address) -> i32;
type Shutdown = unsafe extern "system" fn(Handle, i32) -> i32;
type Close = unsafe extern "system" fn(Handle) -> i32;
type Checksums = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;
type FormatAddress = unsafe extern "system" fn(*const u32, *mut i8, u32) -> i32;
type CompileFilter =
    unsafe extern "system" fn(*const i8, i32, *mut i8, u32, *mut *const i8, *mut u32) -> i32;

pub struct Driver {
    _library: Library,
    _bundle: PreparedDriver,
    open: Open,
    recv: Recv,
    send: Send,
    shutdown: Shutdown,
    close: Close,
    checksums: Checksums,
    format_address: FormatAddress,
    compile_filter: CompileFilter,
}
impl Driver {
    pub fn library_path(&self) -> &Path {
        &self._bundle.dll
    }
    pub fn load() -> Result<Arc<Self>> {
        let bundle = bundle::prepare()?;
        // SAFETY: an absolute application-owned path is used; symbols stay valid while Library lives.
        let library = unsafe { Library::new(&bundle.dll) }
            .with_context(|| format!("Не удалось загрузить {}", bundle.dll.display()))?;
        unsafe {
            Ok(Arc::new(Self {
                open: *library.get(b"WinDivertOpen\0")?,
                recv: *library.get(b"WinDivertRecv\0")?,
                send: *library.get(b"WinDivertSend\0")?,
                shutdown: *library.get(b"WinDivertShutdown\0")?,
                close: *library.get(b"WinDivertClose\0")?,
                checksums: *library.get(b"WinDivertHelperCalcChecksums\0")?,
                format_address: *library.get(b"WinDivertHelperFormatIPv6Address\0")?,
                compile_filter: *library.get(b"WinDivertHelperCompileFilter\0")?,
                _library: library,
                _bundle: bundle,
            }))
        }
    }
    pub fn open(self: &Arc<Self>) -> Result<Arc<Device>> {
        // Loopback remains local. Replies from reflected TCP sockets must be captured too.
        let filter = CString::new(
            "!impostor and !loopback and ((outbound and (tcp or udp)) or (inbound and (tcp.SrcPort == 53 or udp.SrcPort == 53)))",
        )?;
        let handle = unsafe { (self.open)(filter.as_ptr(), 0, 123, 0) };
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "Не удалось открыть WinDivert: {}. Требуются права администратора и подписанный драйвер.",
            std::io::Error::last_os_error()
        );
        Ok(Arc::new(Device {
            driver: self.clone(),
            handle,
        }))
    }

    pub fn validate_filter(&self, filter: &str, layer: i32) -> Result<()> {
        let filter = CString::new(filter)?;
        let mut error = ptr::null();
        let mut offset = 0;
        ensure!(
            unsafe {
                (self.compile_filter)(
                    filter.as_ptr(),
                    layer,
                    ptr::null_mut(),
                    0,
                    &mut error,
                    &mut offset,
                )
            } != 0,
            "Некорректный фильтр WinDivert на позиции {offset}"
        );
        Ok(())
    }

    pub fn open_monitor(self: &Arc<Self>) -> Result<Arc<Device>> {
        let filter = CString::new("event == CLOSE and (protocol == 6 or protocol == 17)")?;
        let handle = unsafe { (self.open)(filter.as_ptr(), 3, 0, 1 | 4) };
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "Не удалось запустить отслеживание сокетов: {}",
            std::io::Error::last_os_error()
        );
        Ok(Arc::new(Device {
            driver: self.clone(),
            handle,
        }))
    }
}

impl Driver {
    fn decode_socket_close(&self, address: &Address) -> Result<SocketClose> {
        let ip = self.socket_ip(address, 20)?;
        let remote = self.socket_ip(address, 36)?;
        Ok(SocketClose {
            pid: u32::from_ne_bytes(address.data[16..20].try_into().unwrap()),
            source: std::net::SocketAddr::new(
                ip,
                u16::from_ne_bytes([address.data[52], address.data[53]]),
            ),
            destination: std::net::SocketAddr::new(
                remote,
                u16::from_ne_bytes([address.data[54], address.data[55]]),
            ),
            tcp: address.data[56] == 6,
            stamp: address.timestamp,
        })
    }

    fn socket_ip(&self, address: &Address, offset: usize) -> Result<IpAddr> {
        debug_assert!(offset == 20 || offset == 36);
        let mut buffer = [0i8; 64];
        // SAFETY: the socket union contains aligned four-u32 addresses at offsets 20 and 36.
        ensure!(
            unsafe {
                (self.format_address)(
                    address.data.as_ptr().add(offset).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                )
            } != 0,
            "Некорректный адрес сокета"
        );
        let ip: IpAddr = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_str()?
            .parse()?;
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        Ok(ip)
    }
}
pub struct Device {
    driver: Arc<Driver>,
    handle: Handle,
}
pub struct SocketClose {
    pub pid: u32,
    pub source: std::net::SocketAddr,
    pub destination: std::net::SocketAddr,
    pub tcp: bool,
    pub stamp: i64,
}
// SAFETY: WinDivert explicitly permits concurrent receive/send/shutdown calls on a handle.
// The handle remains valid until the last Arc is released; shutdown does not free it.
unsafe impl std::marker::Send for Device {}
unsafe impl Sync for Device {}
impl Device {
    pub fn recv_socket_change(&self) -> Result<SocketClose> {
        let mut address = Address::default();
        ensure!(
            unsafe {
                (self.driver.recv)(
                    self.handle,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut address,
                )
            } != 0,
            "Монитор сокетов остановился: {}",
            std::io::Error::last_os_error()
        );
        self.driver.decode_socket_close(&address)
    }
    pub fn recv(&self, buffer: &mut [u8]) -> Result<(usize, Address)> {
        let mut len = 0;
        let mut addr = Address::default();
        ensure!(
            unsafe {
                (self.driver.recv)(
                    self.handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut len,
                    &mut addr,
                )
            } != 0,
            "Ошибка чтения WinDivert: {}",
            std::io::Error::last_os_error()
        );
        Ok((len as usize, addr))
    }
    pub fn send(&self, bytes: &[u8], address: &Address) -> Result<()> {
        ensure!(
            unsafe {
                (self.driver.send)(
                    self.handle,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    ptr::null_mut(),
                    address,
                )
            } != 0,
            "Ошибка отправки WinDivert: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    pub fn inject(&self, mut bytes: Vec<u8>, mut address: Address) -> Result<()> {
        address.set_inbound();
        ensure!(
            unsafe {
                (self.driver.checksums)(bytes.as_mut_ptr(), bytes.len() as u32, &mut address, 0)
            } != 0,
            "Ошибка контрольной суммы"
        );
        self.send(&bytes, &address)
    }
    pub fn reflect(&self, bytes: &mut [u8], address: &mut Address) -> Result<()> {
        address.set_inbound();
        ensure!(
            unsafe { (self.driver.checksums)(bytes.as_mut_ptr(), bytes.len() as u32, address, 0) }
                != 0,
            "Ошибка контрольной суммы"
        );
        self.send(bytes, address)
    }
    pub fn shutdown(&self) {
        unsafe { (self.driver.shutdown)(self.handle, 1) };
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        unsafe { (self.driver.close)(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socket_close_abi_preserves_pid_remote_address_protocol_ports_and_timestamp() {
        #[repr(C)]
        struct SocketData {
            endpoint: u64,
            parent: u64,
            pid: u32,
            local: [u32; 4],
            remote: [u32; 4],
            local_port: u16,
            remote_port: u16,
            protocol: u8,
            padding: [u8; 7],
        }
        assert_eq!(size_of::<SocketData>(), 64);
        let driver = Driver::load().unwrap();
        for protocol in [6, 17] {
            let data = SocketData {
                endpoint: 1,
                parent: 2,
                pid: 1234,
                local: [0xc0000201, 0xffff, 0, 0],
                remote: [1, 0, 0, 0x20010db8],
                local_port: 5000,
                remote_port: 443,
                protocol,
                padding: [0; 7],
            };
            let mut address = Address {
                timestamp: 123456,
                ..Default::default()
            };
            // A synthetic ABI payload; only DLL formatting helpers are called.
            unsafe {
                address
                    .data
                    .as_mut_ptr()
                    .cast::<SocketData>()
                    .write_unaligned(data);
            }
            let event = driver.decode_socket_close(&address).unwrap();
            assert_eq!(event.pid, 1234);
            assert_eq!(event.stamp, 123456);
            assert_eq!(event.source, "192.0.2.1:5000".parse().unwrap());
            assert_eq!(event.destination, "[2001:db8::1]:443".parse().unwrap());
            assert_eq!(event.tcp, protocol == 6);
        }
    }
    #[test]
    fn abi_size() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert_eq!(std::mem::align_of::<Address>(), 8);
    }
}
