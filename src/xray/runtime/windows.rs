//! Windows process ownership and contained launch for the Xray runtime.

use super::{Activity, read_output};
use crate::{updates, xray::assets::Installed};
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::AF_INET,
    Security::{
        CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, GetTokenInformation,
        SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SetTokenInformation,
        TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevation, TokenIntegrityLevel,
        WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinMediumLabelSid,
    },
    Storage::FileSystem::FILE_SHARE_READ,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
            DETACHED_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

const SID_WORDS: usize = SECURITY_MAX_SID_SIZE as usize / size_of::<u32>();
const MAX_TABLE_BYTES: u32 = 16 * 1024 * 1024;

pub(super) struct Identity {
    process: OwnedHandle,
    pid: u32,
}

impl Identity {
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn alive(&self) -> bool {
        // SAFETY: the process handle stays owned for the duration of this call.
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) == WAIT_TIMEOUT }
    }

    fn exit_code(&self) -> Option<u32> {
        let mut code = 0;
        // SAFETY: the process handle is owned, and the output storage is writable.
        unsafe {
            (WaitForSingleObject(self.process.as_raw_handle(), 0) == WAIT_OBJECT_0
                && GetExitCodeProcess(self.process.as_raw_handle(), &mut code) != 0)
                .then_some(code)
        }
    }
}

pub(super) fn check_socks_port(port: u16) -> Result<()> {
    ensure!(port != 0, "Choose a SOCKS port between 1 and 65535");
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let _tcp = TcpListener::bind(endpoint)
        .map_err(|error| anyhow::anyhow!("Xray SOCKS TCP port {port} is unavailable: {error}"))?;
    let _udp = UdpSocket::bind(endpoint)
        .map_err(|error| anyhow::anyhow!("Xray SOCKS UDP port {port} is unavailable: {error}"))?;
    Ok(())
}

pub(super) struct Child {
    identity: Arc<Identity>,
    thread: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
    input: Option<File>,
    reader: Option<JoinHandle<()>>,
}

impl Child {
    pub(super) fn spawn(
        installed: &Installed,
        geo_directory: &Path,
        activity: &Arc<Activity>,
        secrets: Vec<String>,
    ) -> Result<Self> {
        let geo_directory = geo_directory.canonicalize()?;
        let (mut child, output) = Self::spawn_piped(
            &installed.executable,
            &installed.sha256,
            "xray.exe run -format json -config stdin:",
            Some(&geo_directory),
        )
        .context("Could not launch Xray")?;
        activity.new_session();
        let activity = activity.clone();
        child.reader = Some(
            thread::Builder::new()
                .name("xray-logs".into())
                .spawn(move || {
                    let _ = read_output(BufReader::new(output), &activity, &secrets);
                })?,
        );
        Ok(child)
    }

    fn spawn_piped(
        binary: &Path,
        sha256: &str,
        command: &str,
        geo_directory: Option<&Path>,
    ) -> Result<(Self, File)> {
        let binary = binary.canonicalize()?;
        let workdir = binary.parent().context("Missing executable directory")?;
        // Hold a read-only sharing handle across verification and process creation.
        // Windows denies a conflicting writer or renamer until this handle closes.
        let _locked = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&binary)
            .context("Could not lock the executable for launch")?;
        updates::verify_file(&binary, sha256)?;

        let job = make_job()?;
        let (read_config, write_config) = pipe()?;
        let (read_logs, write_logs) = pipe()?;
        without_inheritance(&write_config)?;
        without_inheritance(&read_logs)?;
        let inherited = [read_config.as_raw_handle(), write_logs.as_raw_handle()];
        let attributes = HandleList::new(&inherited)?;
        let token = restricted_token()?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0];
        startup.StartupInfo.hStdOutput = inherited[1];
        startup.StartupInfo.hStdError = inherited[1];
        startup.lpAttributeList = attributes.raw();
        // The GUI parent has no console. Keep the child detached so Windows does
        // not have to initialize a hidden console under the restricted token.
        let flags = CREATE_SUSPENDED
            | DETACHED_PROCESS
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT;
        let application = wide(binary.as_os_str());
        let directory = wide(workdir.as_os_str());
        let environment = environment(geo_directory);
        let mut command = wide(OsStr::new(command));
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: all paths and the command are NUL-terminated, the environment
        // is a double-NUL-terminated UTF-16 block, and the inheritable handles
        // named in the attribute list remain open until creation returns.
        let created = unsafe {
            if let Some(token) = token {
                CreateProcessAsUserW(
                    token.as_raw_handle(),
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    flags,
                    environment.as_ptr().cast(),
                    directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut process,
                )
            } else {
                CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    flags,
                    environment.as_ptr().cast(),
                    directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut process,
                )
            }
        };
        last_error(
            created != 0,
            "Could not launch the process with restricted privileges",
        )?;
        // SAFETY: a successful create returns unique process and thread handles.
        let identity = Arc::new(Identity {
            process: unsafe { OwnedHandle::from_raw_handle(process.hProcess) },
            pid: process.dwProcessId,
        });
        let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
        let child = Self {
            identity,
            thread: Some(thread),
            job: Some(job),
            input: Some(File::from(write_config)),
            reader: None,
        };
        // SAFETY: both owned handles are valid; the primary thread is suspended.
        let assigned = unsafe {
            AssignProcessToJobObject(
                child.job.as_ref().unwrap().as_raw_handle(),
                child.identity.process.as_raw_handle(),
            )
        };
        last_error(
            assigned != 0,
            "Could not contain the process in a Windows job",
        )?;
        drop(read_config);
        drop(write_logs);
        Ok((child, File::from(read_logs)))
    }

    pub(super) fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    pub(super) fn start(&mut self, config: Vec<u8>) -> Result<()> {
        let mut input = self.input.take().context("Xray was already started")?;
        // Write on a separate thread so a stalled child can be stopped by the
        // readiness deadline instead of holding the controller on a full pipe.
        thread::Builder::new()
            .name("xray-config".into())
            .spawn(move || {
                let _ = input.write_all(&config);
            })?;
        self.resume()
    }

    fn resume(&mut self) -> Result<()> {
        let primary = self.thread.take().context("No suspended process thread")?;
        // SAFETY: the primary thread handle belongs to the newly launched child.
        let resumed = unsafe { ResumeThread(primary.as_raw_handle()) };
        last_error(resumed != u32::MAX, "Could not resume the process")
    }

    pub(super) fn wait_socks(&self, port: u16, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        while start.elapsed() < timeout {
            if !self.identity.alive() {
                if let Some(code) = self.identity.exit_code() {
                    bail!(
                        "Xray exited before its local SOCKS port was ready (Windows exit code 0x{code:08X})"
                    );
                }
                bail!("Xray exited before its local SOCKS port was ready");
            }
            if owns_loopback_listener(self.identity.pid, port)
                && socks_ready(endpoint)
                && owns_loopback_listener(self.identity.pid, port)
                && self.identity.alive()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(40));
        }
        bail!("Xray did not open its SOCKS listener on 127.0.0.1:{port}");
    }

    pub(super) fn stop(&mut self) {
        if let Some(job) = self.job.take() {
            drop(job);
            // SAFETY: the owned process handle remains valid. Explicitly terminate
            // as well if creation succeeded but job assignment failed.
            if self.identity.alive() {
                unsafe { TerminateProcess(self.identity.process.as_raw_handle(), 1) };
            }
            // SAFETY: the process handle remains owned while waiting.
            unsafe { WaitForSingleObject(self.identity.process.as_raw_handle(), 2000) };
        }
        if let Some(reader) = self.reader.take()
            && !self.identity.alive()
        {
            let _ = reader.join();
        }
    }
}

pub(in crate::xray) fn run_link_decoder(
    binary: &Path,
    sha256: &str,
    command: &str,
) -> Result<Vec<u8>> {
    let (mut child, output) = Child::spawn_piped(binary, sha256, command, None)?;
    drop(child.input.take());
    let reader = thread::Builder::new()
        .name("hpwnr-output".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            output.take(32 * 1024 + 1).read_to_end(&mut bytes)?;
            Ok::<_, io::Error>(bytes)
        })?;
    child.resume()?;
    // SAFETY: the owned process handle remains live throughout the bounded wait.
    let wait = unsafe { WaitForSingleObject(child.identity.process.as_raw_handle(), 5000) };
    ensure!(
        wait == WAIT_OBJECT_0,
        "hpwnr did not finish within five seconds"
    );
    ensure!(
        child.identity.exit_code() == Some(0),
        "hpwnr could not decrypt this link"
    );
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("Could not read hpwnr output"))??;
    ensure!(bytes.len() <= 32 * 1024, "hpwnr returned too much data");
    Ok(bytes)
}

impl Drop for Child {
    fn drop(&mut self) {
        self.stop();
    }
}

fn last_error(success: bool, message: &str) -> Result<()> {
    if success {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context(message.to_owned())
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn environment(geo_directory: Option<&Path>) -> Vec<u16> {
    let mut root = OsString::from("SystemRoot=");
    root.push(std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows")));
    let mut env = wide(&root);
    if let Some(geo_directory) = geo_directory {
        let mut asset = OsString::from("XRAY_LOCATION_ASSET=");
        asset.push(geo_directory);
        env.extend(wide(&asset));
    }
    env.push(0);
    env
}

fn make_job() -> Result<OwnedHandle> {
    // SAFETY: no security attributes or name are needed for a private job.
    let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    last_error(!handle.is_null(), "Could not create the Xray process job")?;
    // SAFETY: CreateJobObjectW returned an owned handle.
    let job = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    // SAFETY: `limits` has the required type and remains live for this call.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    };
    last_error(ok != 0, "Could not set Xray process job limits")?;
    Ok(job)
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: both output pointers and attributes remain live until the call returns.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) };
    last_error(ok != 0, "Could not create the Xray I/O pipe")?;
    // SAFETY: success returns ownership of both ends.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

fn without_inheritance(handle: &OwnedHandle) -> Result<()> {
    // SAFETY: the owned handle is valid.
    let ok = unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
    last_error(ok != 0, "Could not isolate the Xray pipe")
}

struct HandleList<'a> {
    buffer: Vec<usize>,
    _inherited: &'a [HANDLE],
}

impl<'a> HandleList<'a> {
    fn new(inherited: &'a [HANDLE]) -> Result<Self> {
        let mut size = 0;
        // SAFETY: a null list requests only the size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        ensure!(size > 0, "Windows returned an empty process attribute list");
        let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
        // SAFETY: buffer is aligned and has at least the requested number of bytes.
        let ok = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut size)
        };
        last_error(ok != 0, "Could not initialize Xray handle isolation")?;
        let list = Self {
            buffer,
            _inherited: inherited,
        };
        // SAFETY: initialized list and inherited handles remain alive through creation.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_ptr().cast(),
                size_of_val(inherited),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        last_error(ok != 0, "Could not set the Xray inherited handle list")?;
        Ok(list)
    }

    fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_ptr().cast_mut().cast()
    }
}

impl Drop for HandleList<'_> {
    fn drop(&mut self) {
        // SAFETY: the attribute list was initialized and its storage is still owned.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

fn restricted_token() -> Result<Option<OwnedHandle>> {
    let mut raw = ptr::null_mut();
    // SAFETY: current-process pseudo-handle and output pointer are valid.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut raw,
        )
    };
    last_error(ok != 0, "Could not query the True Proxy token")?;
    // SAFETY: OpenProcessToken succeeded and returned an owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevated = TOKEN_ELEVATION::default();
    let mut size = 0;
    // SAFETY: valid token and correctly sized output buffer.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevated as *mut TOKEN_ELEVATION).cast(),
            size_of_val(&elevated) as u32,
            &mut size,
        )
    };
    last_error(ok != 0, "Could not check process elevation")?;
    if elevated.TokenIsElevated == 0 {
        return Ok(None);
    }
    let mut administrators = [0u32; SID_WORDS];
    well_known_sid(WinBuiltinAdministratorsSid, &mut administrators)?;
    let disabled = SID_AND_ATTRIBUTES {
        Sid: administrators.as_mut_ptr().cast(),
        Attributes: 0,
    };
    // SAFETY: source token and disabled SID are valid for the whole call.
    let ok = unsafe {
        CreateRestrictedToken(
            token.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &disabled,
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut raw,
        )
    };
    last_error(ok != 0, "Could not drop Xray administrative privileges")?;
    // SAFETY: CreateRestrictedToken returned a distinct owned handle.
    let reduced = unsafe { OwnedHandle::from_raw_handle(raw) };
    #[repr(C)]
    struct IntegrityLabel {
        label: TOKEN_MANDATORY_LABEL,
        sid: [u32; SID_WORDS],
    }
    let mut integrity = IntegrityLabel {
        label: TOKEN_MANDATORY_LABEL::default(),
        sid: [0; SID_WORDS],
    };
    let sid_length = well_known_sid(WinMediumLabelSid, &mut integrity.sid)?;
    const SE_GROUP_INTEGRITY: u32 = 0x20;
    integrity.label.Label = SID_AND_ATTRIBUTES {
        Sid: integrity.sid.as_mut_ptr().cast(),
        Attributes: SE_GROUP_INTEGRITY,
    };
    // SAFETY: the valid medium-integrity SID resides inside the sized buffer.
    let ok = unsafe {
        SetTokenInformation(
            reduced.as_raw_handle(),
            TokenIntegrityLevel,
            (&integrity as *const IntegrityLabel).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_length,
        )
    };
    last_error(ok != 0, "Could not set Xray's integrity level")?;
    Ok(Some(reduced))
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE, buffer: &mut [u32; SID_WORDS]) -> Result<u32> {
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: a maximum-sized, aligned writable SID buffer is supplied.
    let ok = unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    last_error(ok != 0, "Could not create the Windows SID for Xray")?;
    Ok(length)
}

fn owns_loopback_listener(pid: u32, port: u16) -> bool {
    let mut size = 0;
    // SAFETY: the first call only queries the required table size.
    let status = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER || !(4..=MAX_TABLE_BYTES).contains(&size) {
        return false;
    }
    let mut storage = vec![0u32; (size as usize).div_ceil(size_of::<u32>())];
    // SAFETY: the aligned output buffer has at least `size` bytes.
    let status = unsafe {
        GetExtendedTcpTable(
            storage.as_mut_ptr().cast(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    let count = storage[0] as usize;
    if status != 0
        || count > (storage.len() * size_of::<u32>() - 4) / size_of::<MIB_TCPROW_OWNER_PID>()
    {
        return false;
    }
    // SAFETY: the table layout is a count followed by aligned owner rows,
    // and the checked count stays inside the initialized output buffer.
    let rows = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().add(1).cast::<MIB_TCPROW_OWNER_PID>(),
            count,
        )
    };
    rows.iter().any(|row| {
        row.dwOwningPid == pid
            && row.dwLocalAddr.to_ne_bytes() == Ipv4Addr::LOCALHOST.octets()
            && u16::from_be(row.dwLocalPort as u16) == port
    })
}

fn socks_ready(endpoint: SocketAddr) -> bool {
    let timeout = Duration::from_millis(120);
    let Ok(mut stream) = TcpStream::connect_timeout(&endpoint, timeout) else {
        return false;
    };
    let mut method = [0; 2];
    let mut reply = [0; 10];
    stream.set_read_timeout(Some(timeout)).is_ok()
        && stream.set_write_timeout(Some(timeout)).is_ok()
        && stream.write_all(&[5, 1, 0]).is_ok()
        && stream.read_exact(&mut method).is_ok()
        && method == [5, 0]
        // Check that the owned SOCKS endpoint can also allocate a loopback
        // UDP relay. No datagram is sent and the control socket closes here.
        && stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).is_ok()
        && stream.read_exact(&mut reply).is_ok()
        && reply[..8] == [5, 0, 0, 1, 127, 0, 0, 1]
        && reply[8..] != [0, 0]
}
