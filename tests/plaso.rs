//! plaso's audit trails (Apache-2.0, `tests/fixtures/plaso/`): a macOS
//! trail and OpenBSM's test trail of one record per token type. Every
//! record plaso's `bsm_log` parser reads, read the same
//! (`tests/oracle/plaso-bsm.tsv.gz`, written by `tests/oracle/gen.py`
//! from plaso's output: file, offset, size, event type, seconds, the
//! sub-second field, and every token's values).

use std::fmt::Write;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use bsm::{read, Record, Role, TokenData};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plaso")
            .join(name),
    )
    .unwrap()
}

/// An address as plaso writes it: IPv6 as eight groups of four digits.
fn address(ip: Option<IpAddr>) -> String {
    match ip {
        None => "0.0.0.0".to_owned(),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => v6
            .segments()
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A token's values with plaso's keys.
fn values(data: &TokenData) -> Vec<(&'static str, String)> {
    match data {
        TokenData::Subject(s) => vec![
            ("aid", s.audit_uid.to_string()),
            ("euid", s.euid.to_string()),
            ("egid", s.egid.to_string()),
            ("uid", s.ruid.to_string()),
            ("gid", s.rgid.to_string()),
            ("pid", s.pid.to_string()),
            ("session_id", s.session.to_string()),
            ("terminal_port", s.terminal_port.to_string()),
            ("terminal_ip", address(s.terminal_address)),
        ],
        TokenData::Return(r) => vec![
            (
                "error",
                bsm::error_name(r.status).unwrap_or("UNKNOWN").to_owned(),
            ),
            ("token_status", r.status.to_string()),
            ("call_status", r.value.to_string()),
        ],
        TokenData::Text(t) => vec![("text", t.clone())],
        TokenData::Path(p) => vec![("path", p.clone())],
        TokenData::Zone(z) => vec![("name", z.clone())],
        TokenData::Argument { index, value, name } => vec![
            ("string", name.clone()),
            ("num_arg", index.to_string()),
            ("is", value.to_string()),
        ],
        TokenData::Data { format, bytes } => {
            assert_eq!(*format, 4);
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            vec![
                ("format", "String".to_owned()),
                ("data", String::from_utf8(bytes[..end].to_vec()).unwrap()),
            ]
        }
        TokenData::Ipc { kind, id } => vec![
            ("object_type", kind.to_string()),
            ("object_id", id.to_string()),
        ],
        TokenData::Address(ip) => vec![("ip", address(Some(*ip)))],
        TokenData::IpHeader(bytes) => vec![("IPv4_Header", hex(bytes))],
        TokenData::Port(port) => vec![("port_number", port.to_string())],
        TokenData::Opaque(bytes) => vec![("data", hex(bytes))],
        TokenData::Sequence(n) => vec![("sequence_number", n.to_string())],
        TokenData::File(file) => {
            let millis = file.time.unwrap().ticks().unwrap() / 10_000;
            vec![
                ("string", file.name.clone()),
                ("timestamp", format!("{}.{}", millis / 1000, millis % 1000)),
            ]
        }
        TokenData::Socket(s) => vec![
            ("from", address(Some(s.local.0))),
            ("from_port", s.local.1.to_string()),
            ("to", address(Some(s.remote.0))),
            ("to_port", s.remote.1.to_string()),
        ],
        other => panic!("not in plaso's samples: {other:?}"),
    }
}

fn line(file: &str, record: &Record) -> String {
    let millis = record.time.unwrap().ticks().unwrap() / 10_000;
    let tokens: Vec<String> = record
        .tokens
        .iter()
        .map(|token| {
            let mut pairs = values(&token.data);
            pairs.sort();
            let pairs: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{} {}", token.name(), pairs.join(" "))
        })
        .collect();
    [
        file.to_owned(),
        record.offset.to_string(),
        record.size.to_string(),
        record.event_type.to_string(),
        (millis / 1000).to_string(),
        (millis % 1000).to_string(),
        tokens.join(" | "),
    ]
    .join("\t")
}

#[test]
fn every_record_as_plaso_reads_it() {
    let mut got = Vec::new();
    for file in ["apple.bsm", "openbsm.bsm"] {
        let data = fixture(file);
        assert!(bsm::detect(&data), "{file}");
        let trail = read(&data);
        assert_eq!(trail.problems, Vec::<String>::new(), "{file}");
        assert!(trail.files.is_empty());
        got.extend(trail.records.iter().map(|r| line(file, r)));
    }
    got.sort();
    let mut oracle = String::new();
    common::gzip::Decoder::new(&include_bytes!("oracle/plaso-bsm.tsv.gz")[..])
        .read_to_string(&mut oracle)
        .unwrap();
    let expected: Vec<&str> = oracle.lines().collect();
    assert_eq!(got.len(), expected.len());
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
}

#[test]
fn what_a_macos_trail_says() {
    let trail = read(&fixture("apple.bsm"));
    let login = trail
        .records
        .iter()
        .find(|r| r.event_type == 45021)
        .unwrap();
    assert_eq!(login.event_name(), Some("loginwindow login"));
    let subject = login.subject().unwrap();
    assert_eq!(
        (subject.audit_uid, subject.ruid, subject.pid),
        (501, 501, 67)
    );
    assert_eq!(subject.role, Role::Subject);
    assert!(login.outcome().unwrap().succeeded());
    let first = &trail.records[0];
    assert_eq!(first.event_name(), Some("audit crash recovery"));
    assert_eq!(
        first.paths().collect::<Vec<_>>(),
        ["/var/audit/20131104171720.crash_recovery"]
    );
    assert_eq!(
        first.texts().collect::<Vec<_>>(),
        ["launchctl::Audit recovery"]
    );
}
