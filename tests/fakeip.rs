use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

use quicp::config::Ipv4Pool;
use quicp::fakeip::{DirectoryError, FakeIpDirectory};
use quicp::wire::CanonicalHost;

#[test]
fn mapping_survives_restart_and_unknown_addresses_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("fakeip.journal");
    let pool = "198.18.0.0/24".parse::<Ipv4Pool>().expect("pool");
    let endpoint = "198.18.0.1".parse().expect("endpoint");
    let host = CanonicalHost::parse("www.example.com").expect("host");

    let address = {
        let mut directory = FakeIpDirectory::open(&path, pool, endpoint).expect("directory");
        let address = directory.lookup_or_allocate(host.clone()).expect("mapping");
        assert_eq!(directory.lookup_host(address), Some(&host));
        assert_eq!(
            directory.lookup_host("198.18.0.254".parse().expect("address")),
            None
        );
        address
    };

    let reopened = FakeIpDirectory::open(&path, pool, endpoint).expect("reopened directory");
    assert_eq!(reopened.lookup_address(&host), Some(address));
    assert_eq!(reopened.lookup_host(address), Some(&host));
}

#[test]
fn torn_tail_is_truncated_but_complete_corruption_is_rejected() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("fakeip.journal");
    let pool = "198.18.0.0/24".parse::<Ipv4Pool>().expect("pool");
    let endpoint = "198.18.0.1".parse().expect("endpoint");

    {
        let mut directory = FakeIpDirectory::open(&path, pool, endpoint).expect("directory");
        directory
            .lookup_or_allocate(CanonicalHost::parse("one.example").expect("host"))
            .expect("mapping");
    }
    let complete_len = std::fs::metadata(&path).expect("metadata").len();

    OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("journal")
        .write_all(&[1, 2, 3])
        .expect("torn tail");
    drop(FakeIpDirectory::open(&path, pool, endpoint).expect("recover torn tail"));
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        complete_len
    );

    let mut journal = OpenOptions::new().write(true).open(&path).expect("journal");
    journal.seek(SeekFrom::Start(8)).expect("record start");
    journal.write_all(&[0xff]).expect("corruption");
    journal.sync_data().expect("sync corruption");

    assert!(matches!(
        FakeIpDirectory::open(&path, pool, endpoint),
        Err(DirectoryError::CorruptRecord { index: 0 })
    ));
}

#[test]
fn pool_exhaustion_does_not_reassign_an_address() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("fakeip.journal");
    let pool = "198.18.0.0/30".parse::<Ipv4Pool>().expect("pool");
    let endpoint = "198.18.0.1".parse().expect("endpoint");
    let mut directory = FakeIpDirectory::open(&path, pool, endpoint).expect("directory");

    directory
        .lookup_or_allocate(CanonicalHost::parse("one.example").expect("host"))
        .expect("last mapping");
    assert!(matches!(
        directory.lookup_or_allocate(CanonicalHost::parse("two.example").expect("host")),
        Err(DirectoryError::Exhausted)
    ));
}

#[test]
fn journal_has_a_single_writer() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("fakeip.journal");
    let pool = "198.18.0.0/24".parse::<Ipv4Pool>().expect("pool");
    let endpoint = "198.18.0.1".parse().expect("endpoint");

    let first = FakeIpDirectory::open(&path, pool, endpoint).expect("first writer");
    assert!(matches!(
        FakeIpDirectory::open(&path, pool, endpoint),
        Err(DirectoryError::Locked)
    ));
    drop(first);
    FakeIpDirectory::open(&path, pool, endpoint).expect("lock released");
}

#[cfg(unix)]
#[test]
fn journal_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let target = temporary.path().join("target.journal");
    let link = temporary.path().join("link.journal");
    let pool = "198.18.0.0/24".parse::<Ipv4Pool>().expect("pool");
    let endpoint = "198.18.0.1".parse().expect("endpoint");

    drop(FakeIpDirectory::open(&target, pool, endpoint).expect("target"));
    symlink(&target, &link).expect("symlink");
    assert!(matches!(
        FakeIpDirectory::open(&link, pool, endpoint),
        Err(DirectoryError::SecureOpen(_))
    ));
}
