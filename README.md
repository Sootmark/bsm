# bsm

macOS and FreeBSD audit trails (Basic Security Module, as OpenBSM writes them: `/var/audit/*` on macOS before 14, still where auditing was kept on, and on FreeBSD): every audited event with who did it, what it touched and how it ended. One dependency, its sibling `sootmark-common` (times); no libbsm.

```toml
[dependencies]
sootmark-bsm = "0.1"
```

```rust
let trail = bsm::read(&std::fs::read("/var/audit/20240101000000.crash_recovery")?);
for record in &trail.records {
    let who = record.subject().map(|s| (s.audit_uid, s.ruid, s.pid));
    let ok = record.outcome().map(|r| r.succeeded());
    println!("{:?} {:?} {:?} {:?}", record.time, record.event_name(), who, ok);
}
```

## What you get

- `read(bytes)`: every record in file order, and the file tokens where a trail starts and ends.
- `Record`: offset and size, event type and its name (`execve(2)`, `OpenSSH login`, `loginwindow login`, `sudo(1)`: OpenBSM's table with Apple's additions), modifier, time (UTC, to the millisecond), the host's address (`_ex` headers), and its tokens.
- Tokens: subjects and processes (audit user, effective and real user and group, process, session, terminal port and address; 32- and 64-bit, IPv4 and IPv6), return and exit (with the error's name), text, paths, system call arguments, program arguments and environment, file attributes, groups, data, IPC objects and permissions, addresses, IP headers, ports, opaque data, sequence numbers, file tokens, sockets (`socket_ex`, `sockinet32`, `sockinet128`, `sockunix`), zones. `subject()`, `outcome()`, `paths()`, `texts()` and `exec_args()` give the usual questions' answers.
- Damage is reported, never a panic: a record whose header, tokens or trailer don't read is listed in `problems`, and reading goes on at the next whole record (a header with a trailer of the same size where it ends).

## Tested against

- plaso's two test trails (a macOS one and OpenBSM's one-record-per-token sample): all 104 records, every token's every value, as plaso reads them.
- Trails written in the tests as OpenBSM writes them, for the tokens those samples lack, and arbitrary and damaged bytes.

## License

MIT or Apache-2.0, at your option. The event names come from plaso's BSM formatter (Apache-2.0), itself from OpenBSM's `audit_event`.
