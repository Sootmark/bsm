//! Basic Security Module audit trails (`/var/audit/*` on macOS before 14
//! and FreeBSD, written by OpenBSM): every audited event, with who did it
//! (the subject: audit user, effective and real user and group, process,
//! session, terminal), what it touched (paths, arguments, sockets, file
//! attributes, program arguments) and how it ended (the return token).
//!
//! A trail is big-endian records, each a header token (its size, the
//! format version, the event type and modifier, the time in seconds and
//! milliseconds; the `_ex` headers add the host's address), tokens, and a
//! trailer token (`0xb105` and the size again). File tokens sit between
//! records where a trail starts and ends.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let trail = bsm::read(&std::fs::read("/var/audit/20240101000000.crash_recovery")?);
//! for record in &trail.records {
//!     let who = record.subject().map(|s| s.audit_uid);
//!     println!("{:?} {:?} {:?}", record.time, record.event_name(), who);
//! }
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::time::Ts;

mod errors;
mod events;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The trailer token's signature.
const TRAILER_MAGIC: u16 = 0xb105;
/// The smallest record: a 32-bit header (18 bytes) and a trailer (7).
const MIN_RECORD: usize = 25;

/// A token's type.
mod code {
    pub const OTHER_FILE32: u8 = 0x11;
    pub const TRAILER: u8 = 0x13;
    pub const HEADER32: u8 = 0x14;
    pub const HEADER32_EX: u8 = 0x15;
    pub const DATA: u8 = 0x21;
    pub const IPC: u8 = 0x22;
    pub const PATH: u8 = 0x23;
    pub const SUBJECT32: u8 = 0x24;
    pub const PROCESS32: u8 = 0x26;
    pub const RETURN32: u8 = 0x27;
    pub const TEXT: u8 = 0x28;
    pub const OPAQUE: u8 = 0x29;
    pub const IN_ADDR: u8 = 0x2A;
    pub const IP: u8 = 0x2B;
    pub const IPORT: u8 = 0x2C;
    pub const ARG32: u8 = 0x2D;
    pub const SEQ: u8 = 0x2F;
    pub const IPC_PERM: u8 = 0x32;
    pub const NEWGROUPS: u8 = 0x3B;
    pub const EXEC_ARGS: u8 = 0x3C;
    pub const EXEC_ENV: u8 = 0x3D;
    pub const ATTR32: u8 = 0x3E;
    pub const EXIT: u8 = 0x52;
    pub const ZONENAME: u8 = 0x60;
    pub const ARG64: u8 = 0x71;
    pub const RETURN64: u8 = 0x72;
    pub const ATTR64: u8 = 0x73;
    pub const HEADER64: u8 = 0x74;
    pub const SUBJECT64: u8 = 0x75;
    pub const PROCESS64: u8 = 0x77;
    pub const HEADER64_EX: u8 = 0x79;
    pub const SUBJECT32_EX: u8 = 0x7A;
    pub const PROCESS32_EX: u8 = 0x7B;
    pub const SUBJECT64_EX: u8 = 0x7C;
    pub const PROCESS64_EX: u8 = 0x7D;
    pub const IN_ADDR_EX: u8 = 0x7E;
    pub const SOCKET_EX: u8 = 0x7F;
    pub const SOCKINET32: u8 = 0x80;
    pub const SOCKINET128: u8 = 0x81;
    pub const SOCKUNIX: u8 = 0x82;
}

/// An audit trail's records and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trail {
    /// The records, in file order.
    pub records: Vec<Record>,
    /// The file tokens between records (where a trail starts and ends).
    pub files: Vec<FileToken>,
    /// Damage met; reading goes on at the next record found.
    pub problems: Vec<String>,
}

/// A record: one audited event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// Its offset in the file.
    pub offset: u64,
    /// Its size, header to trailer.
    pub size: u32,
    /// The format version (11 for OpenBSM).
    pub version: u8,
    /// The event type (`AUE_*`; see [`Record::event_name`]).
    pub event_type: u16,
    /// The event modifier.
    pub modifier: u16,
    /// When (UTC, to the millisecond).
    pub time: Option<Ts>,
    /// The host's address (`_ex` headers only).
    pub host: Option<IpAddr>,
    /// The tokens between header and trailer, in order.
    pub tokens: Vec<Token>,
}

impl Record {
    /// What the event type is (`execve(2)`, `OpenSSH login`, `sudo(1)`).
    #[must_use]
    pub fn event_name(&self) -> Option<&'static str> {
        event_name(self.event_type)
    }

    /// The first subject token: who did it.
    #[must_use]
    pub fn subject(&self) -> Option<&Subject> {
        self.tokens.iter().find_map(|t| match &t.data {
            TokenData::Subject(s) if s.role == Role::Subject => Some(s),
            _ => None,
        })
    }

    /// The return token: how it ended.
    #[must_use]
    pub fn outcome(&self) -> Option<Return> {
        self.tokens.iter().find_map(|t| match &t.data {
            TokenData::Return(r) => Some(*r),
            _ => None,
        })
    }

    /// The path tokens' paths.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().filter_map(|t| match &t.data {
            TokenData::Path(p) => Some(p.as_str()),
            _ => None,
        })
    }

    /// The text tokens' texts.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().filter_map(|t| match &t.data {
            TokenData::Text(p) => Some(p.as_str()),
            _ => None,
        })
    }

    /// The program arguments (`exec_args`), when recorded.
    #[must_use]
    pub fn exec_args(&self) -> Option<&[String]> {
        self.tokens.iter().find_map(|t| match &t.data {
            TokenData::ExecArgs(a) => Some(a.as_slice()),
            _ => None,
        })
    }
}

/// What an event type is (`execve(2)`, `OpenSSH login`), from the
/// OpenBSM table with Apple's additions.
#[must_use]
pub fn event_name(event_type: u16) -> Option<&'static str> {
    events::EVENTS
        .binary_search_by_key(&event_type, |&(t, _)| t)
        .ok()
        .map(|at| events::EVENTS[at].1)
}

/// A file token: a trail's start or end, or a file a record names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileToken {
    /// Its offset in the file.
    pub offset: u64,
    /// The time it holds (UTC, to the millisecond).
    pub time: Option<Ts>,
    /// The file name it holds.
    pub name: String,
}

/// Whose a subject token is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Role {
    /// The process that did it (`AUT_SUBJECT*`).
    #[default]
    Subject,
    /// A process acted on (`AUT_PROCESS*`: signalled, traced).
    Process,
}

/// A subject or process token: a process and who it runs as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Subject {
    /// The subject or the process acted on.
    pub role: Role,
    /// The audit user (who logged in, kept across `su` and `sudo`).
    pub audit_uid: i32,
    /// The effective user.
    pub euid: i32,
    /// The effective group.
    pub egid: i32,
    /// The real user.
    pub ruid: i32,
    /// The real group.
    pub rgid: i32,
    /// The process.
    pub pid: u32,
    /// The audit session.
    pub session: u32,
    /// The terminal's port (device, or remote port).
    pub terminal_port: u64,
    /// The terminal's address (where a remote session came from).
    pub terminal_address: Option<IpAddr>,
}

/// A return or exit token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Return {
    /// The error (0 success; see [`error_name`]); an exit token's status.
    pub status: u32,
    /// The value returned; an exit token's return.
    pub value: i64,
}

impl Return {
    /// Whether it succeeded.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == 0
    }
}

/// A file's attributes (`AUT_ATTR32`, `AUT_ATTR64`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Attributes {
    /// The mode (type and permissions).
    pub mode: u16,
    /// The owner.
    pub uid: i32,
    /// The group.
    pub gid: i32,
    /// The file system.
    pub file_system: u32,
    /// The file (inode).
    pub node: u64,
    /// The device.
    pub device: u64,
}

/// A socket's ends (`AUT_SOCKET_EX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socket {
    /// The domain (2 IPv4, 26 or 30 IPv6, as the system numbers them).
    pub domain: u16,
    /// The type (1 stream, 2 datagram).
    pub kind: u16,
    /// The local address and port.
    pub local: (IpAddr, u16),
    /// The remote address and port.
    pub remote: (IpAddr, u16),
}

/// IPC permissions (`AUT_IPC_PERM`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcPermissions {
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The creator.
    pub creator_uid: u32,
    /// The creator's group.
    pub creator_gid: u32,
    /// The access mode.
    pub mode: u16,
    /// The slot sequence number.
    pub sequence: u16,
    /// The key.
    pub key: u32,
}

/// A token between a record's header and trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Its type (`0x24` a 32-bit subject; see [`token_name`]).
    pub kind: u8,
    /// What it holds.
    pub data: TokenData,
}

impl Token {
    /// Its name as `praudit` and plaso give it (`AUT_SUBJECT32`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        token_name(self.kind)
    }
}

/// What a token holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenData {
    /// A subject or process (`AUT_SUBJECT*`, `AUT_PROCESS*`).
    Subject(Subject),
    /// How the call ended (`AUT_RETURN32`, `AUT_RETURN64`).
    Return(Return),
    /// A process's exit (`AUT_EXIT`).
    Exit(Return),
    /// Text (`AUT_TEXT`).
    Text(String),
    /// A path (`AUT_PATH`).
    Path(String),
    /// A system call argument (`AUT_ARG32`, `AUT_ARG64`).
    Argument {
        /// Which argument (1 the first).
        index: u8,
        /// Its value.
        value: u64,
        /// What it is (`sflags`, `fd`).
        name: String,
    },
    /// A file's attributes.
    Attributes(Attributes),
    /// Program arguments (`AUT_EXEC_ARGS`).
    ExecArgs(Vec<String>),
    /// Program environment (`AUT_EXEC_ENV`).
    ExecEnv(Vec<String>),
    /// Groups (`AUT_NEWGROUPS`).
    Groups(Vec<u32>),
    /// Data (`AUT_DATA`): how to show it (4 a string) and the bytes.
    Data {
        /// How to show it (0 binary, 1 octal, 2 decimal, 3 hex, 4 string).
        format: u8,
        /// Its bytes.
        bytes: Vec<u8>,
    },
    /// An IPC object (`AUT_IPC`).
    Ipc {
        /// Its type (1 message queue, 2 semaphore, 3 shared memory).
        kind: u8,
        /// Its id.
        id: u32,
    },
    /// IPC permissions.
    IpcPermissions(IpcPermissions),
    /// An address (`AUT_IN_ADDR`, `AUT_IN_ADDR_EX`).
    Address(IpAddr),
    /// An IP header (`AUT_IP`, 20 bytes).
    IpHeader(Vec<u8>),
    /// A port (`AUT_IPORT`).
    Port(u16),
    /// Opaque bytes (`AUT_OPAQUE`).
    Opaque(Vec<u8>),
    /// A sequence number (`AUT_SEQ`).
    Sequence(u32),
    /// A file (`AUT_OTHER_FILE32`).
    File(FileToken),
    /// A socket's ends (`AUT_SOCKET_EX`).
    Socket(Socket),
    /// An Internet socket address (`AUT_SOCKINET32`, `AUT_SOCKINET128`).
    SocketAddress {
        /// The family.
        family: u16,
        /// The port.
        port: u16,
        /// The address.
        address: IpAddr,
    },
    /// A Unix socket (`AUT_SOCKUNIX`).
    UnixSocket {
        /// The family.
        family: u16,
        /// Its path.
        path: String,
    },
    /// A Solaris zone (`AUT_ZONENAME`).
    Zone(String),
}

/// A token type's name (`AUT_SUBJECT32`), `AUT_UNKNOWN` if none.
#[must_use]
pub fn token_name(code: u8) -> &'static str {
    match code {
        code::OTHER_FILE32 => "AUT_OTHER_FILE32",
        code::TRAILER => "AUT_TRAILER",
        code::HEADER32 => "AUT_HEADER32",
        code::HEADER32_EX => "AUT_HEADER32_EX",
        code::DATA => "AUT_DATA",
        code::IPC => "AUT_IPC",
        code::PATH => "AUT_PATH",
        code::SUBJECT32 => "AUT_SUBJECT32",
        code::PROCESS32 => "AUT_PROCESS32",
        code::RETURN32 => "AUT_RETURN32",
        code::TEXT => "AUT_TEXT",
        code::OPAQUE => "AUT_OPAQUE",
        code::IN_ADDR => "AUT_IN_ADDR",
        code::IP => "AUT_IP",
        code::IPORT => "AUT_IPORT",
        code::ARG32 => "AUT_ARG32",
        code::SEQ => "AUT_SEQ",
        code::IPC_PERM => "AUT_IPC_PERM",
        code::NEWGROUPS => "AUT_NEWGROUPS",
        code::EXEC_ARGS => "AUT_EXEC_ARGS",
        code::EXEC_ENV => "AUT_EXEC_ENV",
        code::ATTR32 => "AUT_ATTR32",
        code::EXIT => "AUT_EXIT",
        code::ZONENAME => "AUT_ZONENAME",
        code::ARG64 => "AUT_ARG64",
        code::RETURN64 => "AUT_RETURN64",
        code::ATTR64 => "AUT_ATTR64",
        code::HEADER64 => "AUT_HEADER64",
        code::SUBJECT64 => "AUT_SUBJECT64",
        code::PROCESS64 => "AUT_PROCESS64",
        code::HEADER64_EX => "AUT_HEADER64_EX",
        code::SUBJECT32_EX => "AUT_SUBJECT32_EX",
        code::PROCESS32_EX => "AUT_PROCESS32_EX",
        code::SUBJECT64_EX => "AUT_SUBJECT64_EX",
        code::PROCESS64_EX => "AUT_PROCESS64_EX",
        code::IN_ADDR_EX => "AUT_IN_ADDR_EX",
        code::SOCKET_EX => "AUT_SOCKET_EX",
        code::SOCKINET32 => "AUT_SOCKINET32",
        code::SOCKINET128 => "AUT_SOCKINET128",
        code::SOCKUNIX => "AUT_SOCKUNIX",
        _ => "AUT_UNKNOWN",
    }
}

/// What a return token's error is (`Permission denied`): BSM numbers
/// errors its own way (OpenBSM's `audit_errno.h`), the same whichever
/// system wrote the trail.
#[must_use]
pub fn error_name(status: u32) -> Option<&'static str> {
    errors::ERRORS
        .binary_search_by_key(&status, |&(n, _)| n)
        .ok()
        .map(|at| errors::ERRORS[at].1)
}

/// Whether `head` starts like an audit trail: a record header of a known
/// version, or a file token followed by one.
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    let start = if head.first() == Some(&code::OTHER_FILE32) {
        let mut c = Cursor::new(head, 1);
        if other_file(&mut c, 0).is_none() {
            return false;
        }
        c.at
    } else {
        0
    };
    header(head, start).is_ok_and(|(h, _)| h.version == 11 || h.version == 2)
}

/// Read an audit trail.
#[must_use]
pub fn read(data: &[u8]) -> Trail {
    let mut trail = Trail::default();
    let mut at = 0;
    while at < data.len() {
        if data[at] == code::OTHER_FILE32 {
            let mut cursor = Cursor::new(data, at + 1);
            let Some(file) = other_file(&mut cursor, at) else {
                trail
                    .problems
                    .push(format!("offset {at:#x}: a file token cut short"));
                break;
            };
            trail.files.push(file);
            at = cursor.at;
            continue;
        }
        match record(data, at) {
            Ok(record) => {
                at += record.size as usize;
                trail.records.push(record);
            }
            Err(why) => {
                trail.problems.push(format!("offset {at:#x}: {why}"));
                match resync(data, at + 1) {
                    Some(next) => at = next,
                    None => break,
                }
            }
        }
    }
    trail
}

/// The next offset from `from` where a whole record (header, and a trailer
/// of the same size) starts.
fn resync(data: &[u8], from: usize) -> Option<usize> {
    (from..data.len().saturating_sub(MIN_RECORD - 1)).find(|&at| {
        header(data, at).is_ok_and(|(h, _)| {
            let size = h.size as usize;
            at.checked_add(size)
                .and_then(|end| data.get(end.checked_sub(7)?..end))
                .is_some_and(|t| trailer(t) == Some(h.size))
        })
    })
}

/// A trailer token's size, if it is one.
fn trailer(token: &[u8]) -> Option<u32> {
    let mut c = Cursor::new(token, 0);
    (c.u8()? == code::TRAILER && c.u16()? == TRAILER_MAGIC).then_some(())?;
    c.u32()
}

/// A record's header fields.
struct Header {
    size: u32,
    version: u8,
    event_type: u16,
    modifier: u16,
    time: Option<Ts>,
    host: Option<IpAddr>,
}

/// The header token at `at` and where its tokens start.
fn header(data: &[u8], at: usize) -> Result<(Header, usize), String> {
    let mut c = Cursor::new(data, at);
    let kind = c.u8().ok_or("cut short")?;
    let wide = match kind {
        code::HEADER32 | code::HEADER32_EX => false,
        code::HEADER64 | code::HEADER64_EX => true,
        other => return Err(format!("{} where a header was expected", token_name(other))),
    };
    let short = || "a header cut short".to_owned();
    let size = c.u32().ok_or_else(short)?;
    let version = c.u8().ok_or_else(short)?;
    let event_type = c.u16().ok_or_else(short)?;
    let modifier = c.u16().ok_or_else(short)?;
    let host = if matches!(kind, code::HEADER32_EX | code::HEADER64_EX) {
        let kind = c.u32().ok_or_else(short)?;
        Some(
            c.address(kind as usize)
                .ok_or("a header with a bad address type")?,
        )
    } else {
        None
    };
    let (seconds, millis) = if wide {
        (c.u64().ok_or_else(short)?, c.u64().ok_or_else(short)?)
    } else {
        (
            u64::from(c.u32().ok_or_else(short)?),
            u64::from(c.u32().ok_or_else(short)?),
        )
    };
    if (size as usize) < MIN_RECORD {
        return Err(format!("a record of {size} bytes"));
    }
    let header = Header {
        size,
        version,
        event_type,
        modifier,
        time: unix_millis(seconds, millis),
        host,
    };
    Ok((header, c.at))
}

/// Seconds and milliseconds as a time; none when zero or out of range.
fn unix_millis(seconds: u64, millis: u64) -> Option<Ts> {
    let millis = i64::try_from(seconds)
        .ok()?
        .checked_mul(1000)?
        .checked_add(i64::try_from(millis).ok()?)?;
    (millis > 0).then(|| Ts::from_unix_millis(millis))
}

/// The record at `at`.
fn record(data: &[u8], at: usize) -> Result<Record, String> {
    let (header, start) = header(data, at)?;
    let end = at
        .checked_add(header.size as usize)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| format!("a record of {} bytes past the end", header.size))?;
    let close = trailer(&data[end - 7..end]);
    if close != Some(header.size) {
        return Err(format!(
            "no trailer of {} bytes where the record ends",
            header.size
        ));
    }
    let body = &data[..end - 7];
    let mut c = Cursor::new(body, start);
    let mut tokens = Vec::new();
    while c.at < body.len() {
        let token_at = c.at;
        let kind = c.u8().ok_or("cut short")?;
        let data = token(kind, &mut c, token_at)
            .ok_or_else(|| format!("{} at {token_at:#x} unreadable", token_name(kind)))?;
        tokens.push(Token { kind, data });
    }
    Ok(Record {
        offset: at as u64,
        size: header.size,
        version: header.version,
        event_type: header.event_type,
        modifier: header.modifier,
        time: header.time,
        host: header.host,
        tokens,
    })
}

/// A token of type `kind` (already read) at the cursor.
fn token(kind: u8, c: &mut Cursor<'_>, at: usize) -> Option<TokenData> {
    Some(match kind {
        code::SUBJECT32 | code::PROCESS32 | code::SUBJECT64 | code::PROCESS64 => {
            TokenData::Subject(subject(kind, c, false)?)
        }
        code::SUBJECT32_EX | code::PROCESS32_EX | code::SUBJECT64_EX | code::PROCESS64_EX => {
            TokenData::Subject(subject(kind, c, true)?)
        }
        code::RETURN32 | code::RETURN64 | code::EXIT => ending(kind, c)?,
        code::TEXT => TokenData::Text(c.counted_text()?),
        code::PATH => TokenData::Path(c.counted_text()?),
        code::ZONENAME => TokenData::Zone(c.counted_text()?),
        code::ARG32 | code::ARG64 => TokenData::Argument {
            index: c.u8()?,
            value: c.word(kind == code::ARG64)?,
            name: c.counted_text()?,
        },
        code::ATTR32 | code::ATTR64 => TokenData::Attributes(attributes(kind, c)?),
        code::EXEC_ARGS => TokenData::ExecArgs(c.c_strings()?),
        code::EXEC_ENV => TokenData::ExecEnv(c.c_strings()?),
        code::NEWGROUPS => {
            let count = c.u16()?;
            TokenData::Groups((0..count).map(|_| c.u32()).collect::<Option<_>>()?)
        }
        code::DATA => data(c)?,
        code::IPC => TokenData::Ipc {
            kind: c.u8()?,
            id: c.u32()?,
        },
        code::IPC_PERM => TokenData::IpcPermissions(IpcPermissions {
            uid: c.u32()?,
            gid: c.u32()?,
            creator_uid: c.u32()?,
            creator_gid: c.u32()?,
            mode: c.skip(2).and_then(|()| c.u16())?,
            sequence: c.skip(2).and_then(|()| c.u16())?,
            key: c.u32()?,
        }),
        code::OPAQUE => {
            let size = usize::from(c.u16()?);
            TokenData::Opaque(c.bytes(size)?.to_vec())
        }
        code::SEQ => TokenData::Sequence(c.u32()?),
        code::OTHER_FILE32 => TokenData::File(other_file(c, at)?),
        _ => network(kind, c)?,
    })
}

/// A return or exit token.
fn ending(kind: u8, c: &mut Cursor<'_>) -> Option<TokenData> {
    Some(match kind {
        code::EXIT => TokenData::Exit(Return {
            status: c.u32()?,
            value: i64::from(c.u32()? as i32),
        }),
        code::RETURN32 => TokenData::Return(Return {
            status: u32::from(c.u8()?),
            value: i64::from(c.u32()? as i32),
        }),
        _ => TokenData::Return(Return {
            status: u32::from(c.u8()?),
            value: c.u64()? as i64,
        }),
    })
}

/// A file attributes token: a pad, then the fields; the device is 64-bit
/// in `AUT_ATTR64`.
fn attributes(kind: u8, c: &mut Cursor<'_>) -> Option<Attributes> {
    c.skip(2)?;
    Some(Attributes {
        mode: c.u16()?,
        uid: c.u32()? as i32,
        gid: c.u32()? as i32,
        file_system: c.u32()?,
        node: c.u64()?,
        device: c.word(kind == code::ATTR64)?,
    })
}

/// A data token: how to show it, the unit (1, 2, 4 or 8 bytes) and the
/// number of units.
fn data(c: &mut Cursor<'_>) -> Option<TokenData> {
    let format = c.u8()?;
    let unit = match c.u8()? {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return None,
    };
    let count = usize::from(c.u8()?);
    Some(TokenData::Data {
        format,
        bytes: c.bytes(count * unit)?.to_vec(),
    })
}

/// An address, IP header, port or socket token; none for other types.
fn network(kind: u8, c: &mut Cursor<'_>) -> Option<TokenData> {
    Some(match kind {
        code::IN_ADDR => TokenData::Address(c.address(4)?),
        code::IN_ADDR_EX => {
            let size = c.u32()? as usize;
            let bytes = c.bytes(16)?;
            TokenData::Address(Cursor::new(bytes, 0).address(size)?)
        }
        code::IP => TokenData::IpHeader(c.bytes(20)?.to_vec()),
        code::IPORT => TokenData::Port(c.u16()?),
        code::SOCKET_EX => {
            let (domain, kind) = (c.u16()?, c.u16()?);
            let size = usize::from(c.u16()?);
            let local_port = c.u16()?;
            let local = (c.address(size)?, local_port);
            let remote_port = c.u16()?;
            let remote = (c.address(size)?, remote_port);
            TokenData::Socket(Socket {
                domain,
                kind,
                local,
                remote,
            })
        }
        code::SOCKINET32 | code::SOCKINET128 => TokenData::SocketAddress {
            family: c.u16()?,
            port: c.u16()?,
            address: c.address(if kind == code::SOCKINET32 { 4 } else { 16 })?,
        },
        code::SOCKUNIX => TokenData::UnixSocket {
            family: c.u16()?,
            path: c.c_string()?,
        },
        _ => return None,
    })
}

/// A subject or process token's fields; `extended`: with an address type.
fn subject(kind: u8, c: &mut Cursor<'_>, extended: bool) -> Option<Subject> {
    let wide = matches!(
        kind,
        code::SUBJECT64 | code::PROCESS64 | code::SUBJECT64_EX | code::PROCESS64_EX
    );
    let role = if matches!(
        kind,
        code::PROCESS32 | code::PROCESS64 | code::PROCESS32_EX | code::PROCESS64_EX
    ) {
        Role::Process
    } else {
        Role::Subject
    };
    let mut ids = [0i32; 5];
    for id in &mut ids {
        *id = c.u32()? as i32;
    }
    let (pid, session) = (c.u32()?, c.u32()?);
    let terminal_port = if wide { c.u64()? } else { u64::from(c.u32()?) };
    let size = if extended { c.u32()? as usize } else { 4 };
    let address = c.address(size)?;
    Some(Subject {
        role,
        audit_uid: ids[0],
        euid: ids[1],
        egid: ids[2],
        ruid: ids[3],
        rgid: ids[4],
        pid,
        session,
        terminal_port,
        terminal_address: (!address.is_unspecified()).then_some(address),
    })
}

/// A file token's fields (its type already read).
fn other_file(c: &mut Cursor<'_>, at: usize) -> Option<FileToken> {
    let (seconds, millis) = (c.u32()?, c.u32()?);
    Some(FileToken {
        offset: at as u64,
        time: unix_millis(u64::from(seconds), u64::from(millis)),
        name: c.counted_text()?,
    })
}

/// A big-endian reader over a slice.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], at: usize) -> Self {
        Self { data, at }
    }

    fn bytes(&mut self, size: usize) -> Option<&'a [u8]> {
        let bytes = self.data.get(self.at..self.at.checked_add(size)?)?;
        self.at += size;
        Some(bytes)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }

    /// A 64-bit value if `wide`, else a 32-bit one.
    fn word(&mut self, wide: bool) -> Option<u64> {
        if wide {
            self.u64()
        } else {
            self.u32().map(u64::from)
        }
    }

    fn skip(&mut self, size: usize) -> Option<()> {
        self.bytes(size).map(|_| ())
    }

    /// An IPv4 (4 bytes) or IPv6 (16 bytes) address.
    fn address(&mut self, size: usize) -> Option<IpAddr> {
        match size {
            4 => Some(IpAddr::V4(Ipv4Addr::from(self.array::<4>()?))),
            16 => Some(IpAddr::V6(Ipv6Addr::from(self.array::<16>()?))),
            _ => None,
        }
    }

    /// Text after its 16-bit size, without the NUL it ends with.
    fn counted_text(&mut self) -> Option<String> {
        let size = usize::from(self.u16()?);
        Some(text(self.bytes(size)?))
    }

    /// A 32-bit count of NUL-terminated strings.
    fn c_strings(&mut self) -> Option<Vec<String>> {
        let count = self.u32()?;
        (0..count).map(|_| self.c_string()).collect()
    }

    /// Text up to and past a NUL.
    fn c_string(&mut self) -> Option<String> {
        let rest = self.data.get(self.at..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        self.at += end + 1;
        Some(text(&rest[..end]))
    }
}

fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names() {
        assert_eq!(event_name(0), Some("indir system call"));
        assert_eq!(event_name(45029), Some("audit crash recovery"));
        assert_eq!(event_name(65535), None);
        assert!(events::EVENTS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn other_files() {
        assert!(!detect(b"not a trail"));
        assert!(!detect(b""));
        let trail = read(b"\x14\0\0\0\x05garbage");
        assert!(trail.records.is_empty());
        assert!(!trail.problems.is_empty());
    }
}
