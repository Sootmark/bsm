//! Tokens plaso's samples don't have, written here as OpenBSM's
//! `bsm_token.c` writes them: file tokens around the records, `_ex` and
//! 64-bit headers, program arguments and environment, file attributes,
//! groups, socket addresses, exit; and a damaged record skipped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bsm::{read, Role, TokenData};
use proptest::prelude::*;

/// A record: `header` token type, the tokens, a trailer.
fn record(header: u8, event_type: u16, host: Option<&[u8]>, tokens: &[u8]) -> Vec<u8> {
    let wide = matches!(header, 0x74 | 0x79);
    let host_size = host.map_or(0, |h| 4 + h.len());
    let size = 1 + 4 + 1 + 2 + 2 + host_size + if wide { 16 } else { 8 } + tokens.len() + 7;
    let mut out = vec![header];
    out.extend((size as u32).to_be_bytes());
    out.push(11);
    out.extend(event_type.to_be_bytes());
    out.extend(0u16.to_be_bytes());
    if let Some(host) = host {
        out.extend((host.len() as u32).to_be_bytes());
        out.extend(host);
    }
    if wide {
        out.extend(1_700_000_000u64.to_be_bytes());
        out.extend(250u64.to_be_bytes());
    } else {
        out.extend(1_700_000_000u32.to_be_bytes());
        out.extend(250u32.to_be_bytes());
    }
    out.extend(tokens);
    out.push(0x13);
    out.extend(0xb105u16.to_be_bytes());
    out.extend((size as u32).to_be_bytes());
    out
}

fn file_token(name: &str) -> Vec<u8> {
    let mut out = vec![0x11];
    out.extend(1_700_000_000u32.to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend((name.len() as u16 + 1).to_be_bytes());
    out.extend(name.as_bytes());
    out.push(0);
    out
}

fn subject64_ex() -> Vec<u8> {
    let mut out = vec![0x7C];
    for id in [501u32, 0, 0, 501, 20, 4242, 100_007] {
        out.extend(id.to_be_bytes());
    }
    out.extend(0x1234_u64.to_be_bytes());
    out.extend(4u32.to_be_bytes());
    out.extend([203, 0, 113, 9]);
    out
}

fn exec(kind: u8, strings: &[&str]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend((strings.len() as u32).to_be_bytes());
    for s in strings {
        out.extend(s.as_bytes());
        out.push(0);
    }
    out
}

#[test]
fn every_token_written() {
    let mut tokens = subject64_ex();
    tokens.extend(exec(0x3C, &["/usr/bin/curl", "-o", "/tmp/x"]));
    tokens.extend(exec(0x3D, &["HOME=/Users/a"]));
    // attr32: pad, mode, uid, gid, fsid, node, device.
    tokens.push(0x3E);
    tokens.extend(0u16.to_be_bytes());
    tokens.extend(0o100_755u16.to_be_bytes());
    tokens.extend(501u32.to_be_bytes());
    tokens.extend(20u32.to_be_bytes());
    tokens.extend(16_777_220u32.to_be_bytes());
    tokens.extend(987_654u64.to_be_bytes());
    tokens.extend(7u32.to_be_bytes());
    // newgroups: a 16-bit count.
    tokens.push(0x3B);
    tokens.extend(2u16.to_be_bytes());
    tokens.extend(20u32.to_be_bytes());
    tokens.extend(80u32.to_be_bytes());
    // sockinet128, sockunix.
    tokens.push(0x81);
    tokens.extend(30u16.to_be_bytes());
    tokens.extend(443u16.to_be_bytes());
    tokens.extend(Ipv6Addr::LOCALHOST.octets());
    tokens.push(0x82);
    tokens.extend(1u16.to_be_bytes());
    tokens.extend(b"/var/run/sock\0");
    // exit, return64.
    tokens.push(0x52);
    tokens.extend(0u32.to_be_bytes());
    tokens.extend(3u32.to_be_bytes());
    tokens.push(0x72);
    tokens.push(13);
    tokens.extend(u64::MAX.to_be_bytes());

    let mut data = file_token("20231114221320.not_terminated");
    data.extend(record(0x79, 23, Some(&[10, 0, 0, 1]), &tokens));
    data.extend(b"\x14\0\0\0\xffdamaged");
    data.extend(record(
        0x14,
        45028,
        None,
        &[0x28, 0, 5, b's', b'u', b'd', b'o', 0],
    ));
    data.extend(file_token(""));

    assert!(bsm::detect(&data));
    assert!(!bsm::detect(&file_token("only a file token")));
    let trail = read(&data);
    assert_eq!(trail.files.len(), 2);
    assert_eq!(trail.files[0].name, "20231114221320.not_terminated");
    assert_eq!(trail.problems.len(), 1, "{:?}", trail.problems);
    assert_eq!(trail.records.len(), 2);

    let exec = &trail.records[0];
    assert_eq!(exec.event_name(), Some("execve(2)"));
    assert_eq!(exec.host, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(exec.time.unwrap().ticks(), Some(1_700_000_000_250 * 10_000));
    let subject = exec.subject().unwrap();
    assert_eq!(subject.role, Role::Subject);
    assert_eq!(
        (subject.audit_uid, subject.pid, subject.session),
        (501, 4242, 100_007)
    );
    assert_eq!(
        subject.terminal_address,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
    );
    assert_eq!(exec.exec_args().unwrap(), ["/usr/bin/curl", "-o", "/tmp/x"]);
    let outcome = exec.outcome().unwrap();
    assert_eq!((outcome.status, outcome.value), (13, -1));
    assert_eq!(bsm::error_name(outcome.status), Some("Permission denied"));
    let names: Vec<&str> = exec.tokens.iter().map(bsm::Token::name).collect();
    assert_eq!(
        names,
        [
            "AUT_SUBJECT64_EX",
            "AUT_EXEC_ARGS",
            "AUT_EXEC_ENV",
            "AUT_ATTR32",
            "AUT_NEWGROUPS",
            "AUT_SOCKINET128",
            "AUT_SOCKUNIX",
            "AUT_EXIT",
            "AUT_RETURN64",
        ]
    );
    assert!(exec.tokens.iter().any(|t| matches!(
        &t.data,
        TokenData::Attributes(a) if a.mode == 0o100_755 && a.node == 987_654 && a.device == 7
    )));
    assert!(exec
        .tokens
        .iter()
        .any(|t| t.data == TokenData::Groups(vec![20, 80])));
    assert!(exec.tokens.iter().any(|t| t.data
        == TokenData::UnixSocket {
            family: 1,
            path: "/var/run/sock".to_owned()
        }));

    let sudo = &trail.records[1];
    assert_eq!(sudo.event_name(), Some("sudo(1)"));
    assert_eq!(sudo.texts().collect::<Vec<_>>(), ["sudo"]);
}

proptest! {
    #[test]
    fn any_bytes_read_without_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = bsm::detect(&data);
        let _ = read(&data);
    }

    #[test]
    fn damaged_records_read_without_panic(
        cut in 0usize..200,
        flip in 0usize..200,
        byte in any::<u8>(),
    ) {
        let mut data = record(0x79, 23, Some(&[10, 0, 0, 1]), &subject64_ex());
        data.extend(record(0x74, 1, None, &exec(0x3C, &["a", "b"])));
        let at = flip % data.len();
        data[at] = byte;
        data.truncate(cut.min(data.len()));
        let _ = read(&data);
    }
}
