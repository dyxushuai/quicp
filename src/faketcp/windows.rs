//! Windows Tier 0 `FakeTCP` adapter backed by the signed WinDivert WFP driver.
//!
//! Winsock raw TCP cannot inject TCP packets on supported Windows client versions. WinDivert
//! supplies the packet-divert and reinjection boundary; this module owns only the adapter and
//! keeps the QUICP/FakeTCP codec in the parent module. The caller must ship a matching, signed
//! WinDivert distribution and run with administrator privileges.

use super::{
    Arc, CarrierDirection, CarrierError, FakeTcpCarrier, FourTuple, IPV4_HEADER_BYTES,
    MAX_PACKET_BYTES, MAX_TCP_OPTIONS_BYTES, SocketAddr, SynDataMode, TCP_HEADER_BYTES, Vec,
};
use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use std::ffi::{CString, c_char, c_void};
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::task::{Context, Poll, Waker};
use std::thread;

const MAX_DECODE_REJECTS_PER_POLL: usize = 64;
const CHANNEL_CAPACITY: usize = 256;

// WINDIVERT_ADDRESS flags are a UINT64 bitfield in the upstream C ABI.
const ADDRESS_OUTBOUND: u64 = 1 << 17;
const ADDRESS_IMPOSTOR: u64 = 1 << 19;
const ADDRESS_IP_CHECKSUM: u64 = 1 << 21;
const ADDRESS_TCP_CHECKSUM: u64 = 1 << 22;
const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_SHUTDOWN_BOTH: u32 = 3;
const INVALID_HANDLE_VALUE: isize = -1;

#[repr(C)]
#[derive(Clone, Copy)]
struct WinDivertAddress {
    timestamp: i64,
    flags: u64,
    data: [u8; 64],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            data: [0; 64],
        }
    }
}

const _: () = assert!(core::mem::size_of::<WinDivertAddress>() == 80);
const _: () = assert!(core::mem::align_of::<WinDivertAddress>() == 8);

#[allow(unsafe_code)]
mod ffi {
    use super::{WinDivertAddress, c_char, c_void, io};
    use crate::config::{TrustedFileMode, verify_owner_and_acl};
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::iter::once;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Path, PathBuf};
    use std::ptr::{addr_of_mut, null_mut};
    use windows_sys::Win32::Security::WinTrust::{
        DRIVER_ACTION_VERIFY, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ, FileIdInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx,
    };

    type Open = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> isize;
    type Receive =
        unsafe extern "system" fn(isize, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
    type Send = unsafe extern "system" fn(
        isize,
        *const c_void,
        u32,
        *mut u32,
        *const WinDivertAddress,
    ) -> i32;
    type Shutdown = unsafe extern "system" fn(isize, u32) -> i32;
    type Close = unsafe extern "system" fn(isize) -> i32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    }

    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    const WINDIVERT_DLL_SHA256: [u8; 32] = [
        0xc1, 0xe0, 0x60, 0xee, 0x19, 0x44, 0x4a, 0x25, 0x9b, 0x21, 0x62, 0xf8, 0xaf, 0x0f, 0x3f,
        0xe8, 0xc4, 0x42, 0x8a, 0x1c, 0x6f, 0x69, 0x4d, 0xce, 0x20, 0xde, 0x19, 0x4a, 0xc8, 0xd7,
        0xd9, 0xa2,
    ];
    const WINDIVERT_DRIVER_SHA256: [u8; 32] = [
        0x8d, 0xa0, 0x85, 0x33, 0x27, 0x82, 0x70, 0x8d, 0x87, 0x67, 0xbc, 0xac, 0xe5, 0x32, 0x7a,
        0x6e, 0xc7, 0x28, 0x3c, 0x17, 0xcf, 0xb8, 0x5e, 0x40, 0xb0, 0x3c, 0xd2, 0x32, 0x3a, 0x90,
        0xdd, 0xc2,
    ];

    pub(super) fn application_library_path(file_name: &OsStr) -> io::Result<PathBuf> {
        let mut components = Path::new(file_name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "library name must be one path component",
            ));
        }

        let executable = std::env::current_exe()?.canonicalize()?;
        let application_dir = executable.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "current executable has no application directory",
            )
        })?;
        let library = application_dir.join(file_name).canonicalize()?;
        if !library.is_absolute() || library.parent() != Some(application_dir) || !library.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "library must resolve to an application-directory file",
            ));
        }
        Ok(library)
    }

    fn open_trusted_path(path: &Path, directory: bool) -> io::Result<File> {
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(flags)
            .open(path)?;
        let metadata = file.metadata()?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted WinDivert path has the wrong file type",
            ));
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe {
            GetFileInformationByHandle(file.as_raw_handle().cast(), addr_of_mut!(information))
        } == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted WinDivert path must not be a reparse point",
            ));
        }
        verify_owner_and_acl(path, &file, TrustedFileMode::SystemOwned)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
        Ok(file)
    }

    pub(super) fn verify_sha256(
        file: &mut File,
        expected: &[u8; 32],
        name: &str,
    ) -> io::Result<()> {
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        if digest.finish().as_ref() == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsupported {name} binary hash"),
            ))
        }
    }

    #[allow(unsafe_code)]
    fn verify_driver_authenticode(path: &Path, file: &File) -> io::Result<()> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<_>>();
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).expect("structure fits u32"),
            pcwszFilePath: wide.as_ptr(),
            hFile: file.as_raw_handle().cast(),
            pgKnownSubject: null_mut(),
        };
        let mut trust = WINTRUST_DATA {
            cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).expect("structure fits u32"),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                pFile: addr_of_mut!(file_info),
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4,
            ..WINTRUST_DATA::default()
        };
        let mut action = DRIVER_ACTION_VERIFY;
        let status =
            unsafe { WinVerifyTrust(null_mut(), addr_of_mut!(action), addr_of_mut!(trust).cast()) };
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            let _ = WinVerifyTrust(null_mut(), addr_of_mut!(action), addr_of_mut!(trust).cast());
        }
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WinDivert driver Authenticode verification failed: 0x{status:08x}"),
            ))
        }
    }

    fn file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
        let mut information = FILE_ID_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FileIdInfo,
                addr_of_mut!(information).cast(),
                u32::try_from(size_of::<FILE_ID_INFO>()).expect("file identity structure fits u32"),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        ))
    }

    #[allow(unsafe_code)]
    fn verify_loaded_path(module: *mut c_void, expected: &Path, held: &File) -> io::Result<()> {
        let mut wide = vec![0u16; 32_768];
        let length = unsafe {
            GetModuleFileNameW(
                module,
                wide.as_mut_ptr(),
                u32::try_from(wide.len()).expect("Windows path buffer fits u32"),
            )
        };
        if length == 0 || usize::try_from(length).ok() == Some(wide.len()) {
            return Err(io::Error::last_os_error());
        }
        let loaded = PathBuf::from(OsString::from_wide(
            &wide[..usize::try_from(length).expect("module path length fits usize")],
        ))
        .canonicalize()?;
        let loaded_file = open_trusted_path(&loaded, false)?;
        if loaded == expected && file_identity(&loaded_file)? == file_identity(held)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "loaded WinDivert module does not match the verified file",
            ))
        }
    }

    #[derive(Debug)]
    struct TrustedWinDivertDistribution {
        _application_dir: File,
        dll: File,
        _driver: File,
    }

    impl TrustedWinDivertDistribution {
        fn open() -> io::Result<(Self, PathBuf)> {
            #[cfg(not(target_pointer_width = "64"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "QUICP supports only the x64 WinDivert distribution",
            ));

            #[cfg(target_pointer_width = "64")]
            {
                let library = application_library_path(OsStr::new("WinDivert.dll"))?;
                let driver = application_library_path(OsStr::new("WinDivert64.sys"))?;
                let application_dir = library.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WinDivert has no parent directory",
                    )
                })?;
                if driver.parent() != Some(application_dir) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "WinDivert files must share one application directory",
                    ));
                }
                let application_dir_file = open_trusted_path(application_dir, true)?;
                let mut dll = open_trusted_path(&library, false)?;
                let mut driver_file = open_trusted_path(&driver, false)?;
                verify_sha256(&mut dll, &WINDIVERT_DLL_SHA256, "WinDivert.dll")?;
                verify_sha256(
                    &mut driver_file,
                    &WINDIVERT_DRIVER_SHA256,
                    "WinDivert64.sys",
                )?;
                verify_driver_authenticode(&driver, &driver_file)?;
                Ok((
                    Self {
                        _application_dir: application_dir_file,
                        dll,
                        _driver: driver_file,
                    },
                    library,
                ))
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct Api {
        module: usize,
        _distribution: TrustedWinDivertDistribution,
        pub(super) open: Open,
        pub(super) receive: Receive,
        pub(super) send: Send,
        pub(super) shutdown: Shutdown,
        pub(super) close: Close,
    }

    impl Api {
        #[allow(unsafe_code)]
        pub(super) fn load() -> io::Result<Self> {
            let (distribution, library) = TrustedWinDivertDistribution::open()?;
            let wide = library
                .as_os_str()
                .encode_wide()
                .chain(once(0))
                .collect::<Vec<_>>();
            let module = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    core::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }
            let result = (|| unsafe {
                verify_loaded_path(module, &library, &distribution.dll)?;
                Ok(Self {
                    module: module as usize,
                    _distribution: distribution,
                    open: load_symbol(module, c"WinDivertOpen".as_ptr())?,
                    receive: load_symbol(module, c"WinDivertRecv".as_ptr())?,
                    send: load_symbol(module, c"WinDivertSend".as_ptr())?,
                    shutdown: load_symbol(module, c"WinDivertShutdown".as_ptr())?,
                    close: load_symbol(module, c"WinDivertClose".as_ptr())?,
                })
            })();
            if result.is_err() {
                unsafe {
                    let _ = FreeLibrary(module);
                }
            }
            result
        }
    }

    #[allow(unsafe_code)]
    unsafe fn load_symbol<T: Copy>(module: *mut c_void, name: *const c_char) -> io::Result<T> {
        let symbol = unsafe { GetProcAddress(module, name.cast()) };
        if symbol.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { core::mem::transmute_copy(&symbol) })
    }

    #[allow(unsafe_code)]
    impl Drop for Api {
        fn drop(&mut self) {
            unsafe {
                let _ = FreeLibrary(self.module as *mut c_void);
            }
        }
    }
}

#[allow(unsafe_code)]
#[derive(Debug)]
struct WinDivertState {
    api: Arc<ffi::Api>,
    handle: isize,
    stopped: AtomicBool,
}

#[allow(unsafe_code)]
impl WinDivertState {
    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            unsafe {
                let _ = (self.api.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
            }
        }
    }

    fn receive(&self, packet: &mut [u8], address: &mut WinDivertAddress) -> io::Result<usize> {
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WinDivert packet buffer is too large",
            )
        })?;
        let mut received = 0u32;
        let ok = unsafe {
            (self.api.receive)(
                self.handle,
                packet.as_mut_ptr().cast(),
                packet_len,
                &mut received,
                address,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(received as usize)
        }
    }

    fn send(&self, packet: &[u8], address: &WinDivertAddress) -> io::Result<()> {
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "WinDivert packet is too large")
        })?;
        let mut sent = 0u32;
        let ok = unsafe {
            (self.api.send)(
                self.handle,
                packet.as_ptr().cast(),
                packet_len,
                &mut sent,
                address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if sent != packet_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "WinDivert injected only part of a packet",
            ));
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
impl Drop for WinDivertState {
    fn drop(&mut self) {
        self.stop();
        unsafe {
            let _ = (self.api.close)(self.handle);
        }
    }
}

fn carrier_io_error(error: CarrierError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn build_filter(tuple: FourTuple) -> io::Result<CString> {
    let source = tuple.source.ip();
    let destination = tuple.destination.ip();
    if !source.is_ipv4() || !destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows WinDivert carrier currently supports IPv4 only",
        ));
    }
    let filter = format!(
        "ip and tcp and !impostor and ((outbound and ip.SrcAddr == {source} and ip.DstAddr == {destination} and tcp.SrcPort == {} and tcp.DstPort == {}) or (inbound and ip.SrcAddr == {destination} and ip.DstAddr == {source} and tcp.SrcPort == {} and tcp.DstPort == {}))",
        tuple.source.port(),
        tuple.destination.port(),
        tuple.destination.port(),
        tuple.source.port(),
    );
    CString::new(filter)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "WinDivert filter contains NUL"))
}

fn wake(waker: &Mutex<Option<Waker>>) {
    if let Ok(mut guard) = waker.lock() {
        if let Some(waker) = guard.take() {
            waker.wake();
        }
    }
}

fn spawn_receiver(
    state: Arc<WinDivertState>,
    sender: SyncSender<io::Result<Vec<u8>>>,
    waker: Arc<Mutex<Option<Waker>>>,
) -> io::Result<()> {
    thread::Builder::new()
        .name("quicp-windivert-recv".to_owned())
        .spawn(move || {
            let mut packet = vec![0; MAX_PACKET_BYTES];
            loop {
                if state.stopped.load(Ordering::Acquire) {
                    break;
                }
                let mut address = WinDivertAddress::default();
                match state.receive(&mut packet, &mut address) {
                    Ok(length) if length > 0 && length <= packet.len() => {
                        if sender.send(Ok(packet[..length].to_vec())).is_err() {
                            break;
                        }
                        wake(&waker);
                    }
                    Ok(_) => {}
                    Err(_error) if state.stopped.load(Ordering::Acquire) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        wake(&waker);
                        break;
                    }
                }
            }
        })
        .map(|_| ())
}

/// One Windows WinDivert-backed `FakeTCP` path.
#[derive(Debug)]
pub struct FakeTcpSocket {
    state: Arc<WinDivertState>,
    tuple: FourTuple,
    inbound: FakeTcpCarrier,
    outbound: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    receiver: Mutex<Receiver<io::Result<Vec<u8>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    decode_rejects: u64,
}

impl FakeTcpSocket {
    /// Binds a Windows Tier 0 carrier through the signed WinDivert WFP driver.
    ///
    /// The caller must install the pinned WinDivert 2.2.2-A x64 DLL and its matching signed driver
    /// in a protected application directory, and the process must have administrator privileges.
    /// The tuple is reserved exclusively by this handle; malformed packets and kernel-generated
    /// RSTs are diverted and dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when WinDivert is unavailable, the tuple is invalid, or the driver denies
    /// the requested packet filter.
    #[allow(unsafe_code)]
    pub fn bind(
        tuple: FourTuple,
        outbound_direction: CarrierDirection,
        syn_data: SynDataMode,
        syn_mss: u16,
        outer_mtu: u16,
        _packet_socket: bool,
    ) -> io::Result<Self> {
        tuple.validate().map_err(carrier_io_error)?;
        let filter = build_filter(tuple)?;
        let (inbound, outbound) =
            FakeTcpCarrier::pair_with_mtu(tuple, outbound_direction, syn_data, syn_mss, outer_mtu)
                .map_err(carrier_io_error)?;
        let api = Arc::new(ffi::Api::load()?);
        let handle = unsafe { (api.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(io::Error::last_os_error());
        }
        let state = Arc::new(WinDivertState {
            api,
            handle,
            stopped: AtomicBool::new(false),
        });
        let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
        let waker = Arc::new(Mutex::new(None));
        if let Err(error) = spawn_receiver(Arc::clone(&state), sender, Arc::clone(&waker)) {
            state.stop();
            return Err(error);
        }
        Ok(Self {
            state,
            tuple,
            inbound,
            outbound: Arc::new(Mutex::new(outbound)),
            server_side: outbound_direction == CarrierDirection::ServerToClient,
            receiver: Mutex::new(receiver),
            waker,
            decode_rejects: 0,
        })
    }

    fn next_packet(&mut self, cx: &Context<'_>) -> Option<io::Result<Vec<u8>>> {
        let receiver = match self.receiver.lock() {
            Ok(receiver) => receiver,
            Err(_) => return Some(Err(io::Error::other("WinDivert receiver poisoned"))),
        };
        match receiver.try_recv() {
            Ok(packet) => Some(packet),
            Err(TryRecvError::Disconnected) => Some(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert receiver stopped",
            ))),
            Err(TryRecvError::Empty) => {
                let Ok(mut guard) = self.waker.lock() else {
                    return Some(Err(io::Error::other("WinDivert waker poisoned")));
                };
                *guard = Some(cx.waker().clone());
                match receiver.try_recv() {
                    Ok(packet) => Some(packet),
                    Err(TryRecvError::Disconnected) => Some(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WinDivert receiver stopped",
                    ))),
                    Err(TryRecvError::Empty) => None,
                }
            }
        }
    }
}

impl Drop for FakeTcpSocket {
    fn drop(&mut self) {
        self.state.stop();
    }
}

impl AsyncUdpSocket for FakeTcpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(FakeTcpSender {
            state: Arc::clone(&self.state),
            tuple: self.tuple,
            carrier: Arc::clone(&self.outbound),
            server_side: self.server_side,
            pending: vec![0; MAX_PACKET_BYTES],
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no receive buffer",
            )));
        }
        let mut rejects = 0;
        loop {
            let Some(packet) = self.next_packet(cx) else {
                return Poll::Pending;
            };
            let packet = match packet {
                Ok(packet) => packet,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let decoded = match self.inbound.decode_datagram_borrowed(&packet) {
                Ok(decoded) => decoded,
                Err(_) => {
                    self.decode_rejects = self.decode_rejects.saturating_add(1);
                    rejects += 1;
                    if rejects >= MAX_DECODE_REJECTS_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    continue;
                }
            };
            let payload = decoded.payload();
            if payload.len() > bufs[0].len() {
                self.decode_rejects = self.decode_rejects.saturating_add(1);
                rejects += 1;
                if rejects >= MAX_DECODE_REJECTS_PER_POLL {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }
            bufs[0][..payload.len()].copy_from_slice(payload);
            let mut received = RecvMeta::default();
            received.addr = self.tuple.destination;
            received.len = payload.len();
            received.stride = payload.len();
            received.dst_ip = Some(self.tuple.source.ip());
            meta[0] = received;
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.tuple.source)
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(1).expect("one receive segment")
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct FakeTcpSender {
    state: Arc<WinDivertState>,
    tuple: FourTuple,
    carrier: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    pending: Vec<u8>,
}

impl UdpSender for FakeTcpSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if transmit.destination != this.tuple.destination {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender destination does not match its path",
            )));
        }
        if transmit
            .src_ip
            .is_some_and(|source| source != this.tuple.source.ip())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender source does not match its path",
            )));
        }
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 || transmit.contents.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender received invalid segmentation metadata",
            )));
        }
        let segment_count = transmit.contents.len().div_ceil(segment_size);
        let packet_capacity = segment_size
            .checked_add(IPV4_HEADER_BYTES + TCP_HEADER_BYTES + MAX_TCP_OPTIONS_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "FakeTCP packet capacity overflow",
                )
            });
        let packet_capacity = match packet_capacity {
            Ok(capacity) => capacity,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if this.pending.len() < packet_capacity {
            this.pending.resize(packet_capacity, 0);
        }
        let mut carrier = match this.carrier.lock() {
            Ok(carrier) => carrier,
            Err(_) => return Poll::Ready(Err(io::Error::other("FakeTCP send state poisoned"))),
        };
        let address = WinDivertAddress {
            flags: ADDRESS_OUTBOUND | ADDRESS_IMPOSTOR | ADDRESS_IP_CHECKSUM | ADDRESS_TCP_CHECKSUM,
            ..WinDivertAddress::default()
        };
        for segment in 0..segment_count {
            let start = segment * segment_size;
            let end = (start + segment_size).min(transmit.contents.len());
            let length = if carrier.sent_syn {
                carrier.encode_datagram_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            } else if this.server_side {
                carrier.encode_syn_ack_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            } else {
                carrier.encode_syn_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            };
            let length = match length.map_err(carrier_io_error) {
                Ok(length) => length,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if let Err(error) = this.state.send(&this.pending[..length], &address) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(1).expect("one transmit segment")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::io::{Seek, Write};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn windivert_library_path_is_application_local_and_fail_closed() {
        let executable = std::env::current_exe()
            .expect("current executable")
            .canonicalize()
            .expect("resolved current executable");
        assert_eq!(
            ffi::application_library_path(executable.file_name().expect("executable file name"))
                .expect("the test executable is application-local"),
            executable
        );
        assert_eq!(
            ffi::application_library_path(OsStr::new("../WinDivert.dll"))
                .expect_err("parent traversal must be rejected")
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let missing = OsString::from(format!(
            "quicp-missing-{}-WinDivert.dll",
            std::process::id()
        ));
        assert_eq!(
            ffi::application_library_path(&missing)
                .expect_err("missing application-local DLL must fail")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn windivert_hash_check_accepts_only_the_expected_bytes() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"abc").unwrap();
        file.rewind().unwrap();
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        ffi::verify_sha256(&mut file, &expected, "test").unwrap();
        file.rewind().unwrap();
        assert_eq!(
            ffi::verify_sha256(&mut file, &[0; 32], "test")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn filter_covers_both_directions_of_one_tuple() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 44_443)),
        );
        let filter = build_filter(tuple)
            .expect("valid IPv4 tuple")
            .into_string()
            .expect("filter is UTF-8");
        assert!(filter.contains("outbound"));
        assert!(filter.contains("inbound"));
        assert!(filter.contains("192.0.2.1"));
        assert!(filter.contains("198.51.100.1"));
        assert!(filter.contains("40000"));
        assert!(filter.contains("44443"));
    }

    #[test]
    fn filter_rejects_ipv6_until_the_adapter_supports_it() {
        let tuple = FourTuple::new(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 40_000)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 2], 44_443)),
        );
        assert_eq!(
            build_filter(tuple)
                .expect_err("IPv6 is not admitted by the Windows adapter")
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    #[ignore = "requires the signed WinDivert driver and Administrator privileges"]
    fn windivert_carrier_binds_a_filtered_tuple() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 44_443)),
        );
        let socket = FakeTcpSocket::bind(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
            1460,
            1500,
            false,
        )
        .expect("WinDivert should open the filtered tuple");
        assert_eq!(socket.local_addr().expect("local address"), tuple.source);
    }
}
