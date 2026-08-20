use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use fs4::{FileExt, TryLockError};
use thiserror::Error;

use crate::config::Ipv4Pool;
use crate::wire::CanonicalHost;

const HEADER: &[u8; 8] = b"QUICPJ\x01\0";
const HOST_CAPACITY: usize = 253;
const RECORD_BODY_LEN: usize = 4 + 1 + HOST_CAPACITY;
const RECORD_LEN: usize = RECORD_BODY_LEN + 4;

pub struct FakeIpDirectory {
    file: File,
    pool: Ipv4Pool,
    endpoint: Ipv4Addr,
    by_host: HashMap<CanonicalHost, Ipv4Addr>,
    by_address: HashMap<Ipv4Addr, CanonicalHost>,
    next_address: Option<u32>,
}

impl FakeIpDirectory {
    /// Opens, exclusively locks, and recovers a journal.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal is locked, insecure, corrupt, or inaccessible.
    pub fn open(path: &Path, pool: Ipv4Pool, endpoint: Ipv4Addr) -> Result<Self, DirectoryError> {
        if !pool.contains(endpoint) {
            return Err(DirectoryError::AddressOutsidePool(endpoint));
        }
        if !pool.is_usable(endpoint) {
            return Err(DirectoryError::UnusableEndpoint(endpoint));
        }

        let (mut file, created) = open_file(path)?;
        match FileExt::try_lock(&file) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(DirectoryError::Locked),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        verify_permissions(&file)?;

        if created {
            file.write_all(HEADER)?;
            file.sync_data()?;
            sync_parent(path)?;
        }

        let length = file.metadata()?.len();
        if length < HEADER.len() as u64 {
            return Err(DirectoryError::BadHeader);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0; HEADER.len()];
        file.read_exact(&mut header)?;
        if &header != HEADER {
            return Err(DirectoryError::BadHeader);
        }

        let payload_len = length - HEADER.len() as u64;
        let complete_len = payload_len / RECORD_LEN as u64 * RECORD_LEN as u64;
        if complete_len != payload_len {
            file.set_len(HEADER.len() as u64 + complete_len)?;
            file.sync_data()?;
        }

        file.seek(SeekFrom::Start(HEADER.len() as u64))?;
        let mut reader = BufReader::new(&mut file);
        let mut by_host = HashMap::new();
        let mut by_address = HashMap::new();
        let record_count = complete_len / RECORD_LEN as u64;
        for index in 0..record_count {
            let mut record = [0; RECORD_LEN];
            reader.read_exact(&mut record)?;
            let (address, host) = decode_record(&record, index, pool, endpoint)?;
            if by_host.insert(host.clone(), address).is_some()
                || by_address.insert(address, host).is_some()
            {
                return Err(DirectoryError::ConflictingMapping { index });
            }
        }
        drop(reader);
        file.seek(SeekFrom::End(0))?;
        let next_address = next_free_from(
            pool,
            endpoint,
            &by_address,
            u32::from(pool.network()).saturating_add(1),
        );

        Ok(Self {
            file,
            pool,
            endpoint,
            by_host,
            by_address,
            next_address,
        })
    }

    #[must_use]
    pub fn lookup_address(&self, host: &CanonicalHost) -> Option<Ipv4Addr> {
        self.by_host.get(host).copied()
    }

    #[must_use]
    pub fn lookup_host(&self, address: Ipv4Addr) -> Option<&CanonicalHost> {
        self.by_address.get(&address)
    }

    /// Returns a stable mapping, durably appending a new one when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool is exhausted or persistence fails.
    pub fn lookup_or_allocate(&mut self, host: CanonicalHost) -> Result<Ipv4Addr, DirectoryError> {
        if let Some(address) = self.lookup_address(&host) {
            return Ok(address);
        }

        let address = Ipv4Addr::from(self.next_address.ok_or(DirectoryError::Exhausted)?);
        let record = encode_record(address, &host);
        let old_len = self.file.metadata()?.len();
        if let Err(original) = self
            .file
            .write_all(&record)
            .and_then(|()| self.file.sync_data())
        {
            if let Err(rollback) = self
                .file
                .set_len(old_len)
                .and_then(|()| self.file.sync_data())
                .and_then(|()| self.file.seek(SeekFrom::Start(old_len)).map(|_| ()))
            {
                return Err(DirectoryError::RollbackFailed(rollback));
            }
            return Err(original.into());
        }

        self.by_host.insert(host.clone(), address);
        self.by_address.insert(address, host);
        self.next_address = next_free_from(
            self.pool,
            self.endpoint,
            &self.by_address,
            u32::from(address).saturating_add(1),
        );
        Ok(address)
    }
}

fn next_free_from(
    pool: Ipv4Pool,
    endpoint: Ipv4Addr,
    used: &HashMap<Ipv4Addr, CanonicalHost>,
    start: u32,
) -> Option<u32> {
    (start..u32::from(pool.broadcast())).find(|candidate| {
        let address = Ipv4Addr::from(*candidate);
        address != endpoint && !used.contains_key(&address)
    })
}

fn open_file(path: &Path) -> Result<(File, bool), DirectoryError> {
    #[cfg(unix)]
    return match secure_open(path, true) {
        Ok(file) => Ok((file, true)),
        Err(rustix::io::Errno::EXIST) => Ok((secure_open(path, false)?, false)),
        Err(error) => Err(error.into()),
    };

    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;

        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => Ok((file, true)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = OpenOptions::new().read(true).write(true).open(path)?;
                Ok((file, false))
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(target_os = "linux")]
fn secure_open(path: &Path, create: bool) -> Result<File, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        flags,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn secure_open(path: &Path, create: bool) -> Result<File, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags};

    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR).map(File::from)
}

#[cfg(unix)]
fn verify_permissions(file: &File) -> Result<(), DirectoryError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(DirectoryError::NotRegularFile);
    }
    let owner = metadata.uid();
    let current = rustix::process::geteuid().as_raw();
    if owner != 0 && owner != current {
        return Err(DirectoryError::WrongOwner(owner));
    }
    if metadata.nlink() != 1 {
        return Err(DirectoryError::MultipleLinks(metadata.nlink()));
    }
    let mode = metadata.mode();
    if mode & 0o077 != 0 {
        return Err(DirectoryError::InsecurePermissions(mode & 0o777));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_permissions(_file: &File) -> Result<(), DirectoryError> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), DirectoryError> {
    let parent = path.parent().ok_or(DirectoryError::MissingParent)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn encode_record(address: Ipv4Addr, host: &CanonicalHost) -> [u8; RECORD_LEN] {
    let mut record = [0; RECORD_LEN];
    record[..4].copy_from_slice(&u32::from(address).to_be_bytes());
    let host = host.as_str().as_bytes();
    record[4] = u8::try_from(host.len()).expect("canonical host length fits in u8");
    record[5..5 + host.len()].copy_from_slice(host);
    let checksum = crc32c::crc32c(&record[..RECORD_BODY_LEN]);
    record[RECORD_BODY_LEN..].copy_from_slice(&checksum.to_be_bytes());
    record
}

fn decode_record(
    record: &[u8; RECORD_LEN],
    index: u64,
    pool: Ipv4Pool,
    endpoint: Ipv4Addr,
) -> Result<(Ipv4Addr, CanonicalHost), DirectoryError> {
    let expected = u32::from_be_bytes(
        record[RECORD_BODY_LEN..]
            .try_into()
            .expect("fixed checksum slice"),
    );
    if crc32c::crc32c(&record[..RECORD_BODY_LEN]) != expected {
        return Err(DirectoryError::CorruptRecord { index });
    }

    let host_len = usize::from(record[4]);
    if host_len == 0
        || host_len > HOST_CAPACITY
        || record[5 + host_len..RECORD_BODY_LEN]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(DirectoryError::CorruptRecord { index });
    }
    let host = std::str::from_utf8(&record[5..5 + host_len])
        .ok()
        .and_then(|host| CanonicalHost::parse(host).ok())
        .ok_or(DirectoryError::CorruptRecord { index })?;
    let address = Ipv4Addr::from(u32::from_be_bytes(
        record[..4].try_into().expect("fixed address slice"),
    ));
    if !pool.contains(address)
        || address == pool.network()
        || address == pool.broadcast()
        || address == endpoint
    {
        return Err(DirectoryError::CorruptRecord { index });
    }
    Ok((address, host))
}

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    #[cfg(unix)]
    #[error("secure journal open failed: {0}")]
    SecureOpen(#[from] rustix::io::Errno),
    #[error("journal is locked by another writer")]
    Locked,
    #[error("journal header is invalid")]
    BadHeader,
    #[error("journal record {index} is corrupt")]
    CorruptRecord { index: u64 },
    #[error("journal record {index} conflicts with an earlier mapping")]
    ConflictingMapping { index: u64 },
    #[error("FakeIP pool is exhausted")]
    Exhausted,
    #[error("reserved address {0} is outside the FakeIP pool")]
    AddressOutsidePool(Ipv4Addr),
    #[error("reserved address {0} is a network or broadcast address")]
    UnusableEndpoint(Ipv4Addr),
    #[error("journal permissions {0:#o} allow group or other access")]
    InsecurePermissions(u32),
    #[error("journal is not a regular file")]
    NotRegularFile,
    #[error("journal owner {0} is neither root nor the daemon user")]
    WrongOwner(u32),
    #[error("journal has {0} hard links")]
    MultipleLinks(u64),
    #[error("journal path has no parent directory")]
    MissingParent,
    #[error("journal rollback failed; serving must stop: {0}")]
    RollbackFailed(io::Error),
}
