//! Discovery through the system Bonjour service's `dns_sd` C API (R76).
//!
//! One session thread owns one shared `dns_sd` connection and every operation
//! started on it. Each operation's `DNSServiceRef` is owned by an [`Op`] that
//! deallocates it, the connection is owned by [`Connection`] and deallocated
//! after every operation, and both are created, polled and deallocated only on
//! that thread. Callbacks run only inside `DNSServiceProcessResult` on the same
//! thread, copy what they are handed and record it, and the thread acts on the
//! records after the call returns.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use connetto_peer::{DNS_SD_SERVICE, DnsSd, DnsSdEvent, DnsSdSession, DnsSdSink};

/// The opaque `DNSServiceRef` handle the system library allocates and frees.
type ServiceRef = *mut c_void;
type Flags = u32;
type ErrorCode = i32;

const FLAGS_ADD: Flags = 0x2;
const FLAGS_SHARE_CONNECTION: Flags = 0x4000;
const NO_ERROR: ErrorCode = 0;
const ERR_SERVICE_NOT_RUNNING: ErrorCode = -65563;
const ERR_POLICY_DENIED: ErrorCode = -65570;
const ERR_NO_SUCH_RECORD: ErrorCode = -65554;
/// `kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6`.
const PROTOCOL_BOTH: u32 = 0x3;
/// Every interface, as `kDNSServiceInterfaceIndexAny`.
const ANY_INTERFACE: u32 = 0;
/// How long the thread waits on its socket before it reads its commands.
const POLL_MS: c_int = 250;
/// How long a denied local network permission waits before a fresh session asks again.
const DENIED_WAIT: Duration = Duration::from_secs(5);

type RegisterReply = extern "C" fn(
    ServiceRef,
    Flags,
    ErrorCode,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type BrowseReply = extern "C" fn(
    ServiceRef,
    Flags,
    u32,
    ErrorCode,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type ResolveReply = extern "C" fn(
    ServiceRef,
    Flags,
    u32,
    ErrorCode,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
type AddressReply = extern "C" fn(
    ServiceRef,
    Flags,
    u32,
    ErrorCode,
    *const c_char,
    *const libc::sockaddr,
    u32,
    *mut c_void,
);

// SAFETY: these are the functions libSystem exports from `<dns_sd.h>` with
// their documented signatures. Every string argument is read during the call
// only, every `ServiceRef` out-parameter is written only on success, and every
// callback context is handed back unchanged.
unsafe extern "C" {
    fn DNSServiceCreateConnection(service: *mut ServiceRef) -> ErrorCode;
    fn DNSServiceRefSockFD(service: ServiceRef) -> c_int;
    fn DNSServiceProcessResult(service: ServiceRef) -> ErrorCode;
    fn DNSServiceRefDeallocate(service: ServiceRef);
    fn DNSServiceRegister(
        service: *mut ServiceRef,
        flags: Flags,
        interface: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port: u16,
        txt_len: u16,
        txt: *const c_void,
        reply: RegisterReply,
        context: *mut c_void,
    ) -> ErrorCode;
    fn DNSServiceBrowse(
        service: *mut ServiceRef,
        flags: Flags,
        interface: u32,
        regtype: *const c_char,
        domain: *const c_char,
        reply: BrowseReply,
        context: *mut c_void,
    ) -> ErrorCode;
    fn DNSServiceResolve(
        service: *mut ServiceRef,
        flags: Flags,
        interface: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        reply: ResolveReply,
        context: *mut c_void,
    ) -> ErrorCode;
    fn DNSServiceGetAddrInfo(
        service: *mut ServiceRef,
        flags: Flags,
        interface: u32,
        protocol: u32,
        hostname: *const c_char,
        reply: AddressReply,
        context: *mut c_void,
    ) -> ErrorCode;
}

/// The system Bonjour service as the peer link's DNS-SD service.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bonjour;

impl DnsSd for Bonjour {
    fn open(&self, events: DnsSdSink) -> io::Result<Box<dyn DnsSdSession>> {
        let (commands_tx, commands) = mpsc::channel();
        let (started_tx, started) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("connetto-bonjour".to_owned())
            .spawn(move || serve(&commands, &started_tx, events))?;
        match started.recv_timeout(crate::HOP_WITHIN) {
            Ok(Ok(())) => Ok(Box::new(BonjourSession {
                commands: commands_tx,
            })),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the Bonjour session did not start",
            )),
        }
    }
}

/// A command the session hands its thread.
enum Command {
    Register {
        name: CString,
        port: u16,
        txt: Vec<u8>,
    },
    Unregister {
        name: CString,
    },
}

/// The async side of one session, whose drop ends the thread.
struct BonjourSession {
    commands: mpsc::Sender<Command>,
}

impl DnsSdSession for BonjourSession {
    fn register(&mut self, name: &str, port: u16, txt: &[(&str, &str)]) -> io::Result<()> {
        let name = CString::new(name).map_err(io::Error::other)?;
        let txt = txt_record(txt)?;
        self.commands
            .send(Command::Register { name, port, txt })
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))
    }

    fn unregister(&mut self, name: &str) {
        if let Ok(name) = CString::new(name) {
            let _ = self.commands.send(Command::Unregister { name });
        }
    }
}

/// The TXT record's wire form, each `key=value` behind its one-byte length.
fn txt_record(pairs: &[(&str, &str)]) -> io::Result<Vec<u8>> {
    let mut record = Vec::new();
    for (key, value) in pairs {
        let entry = format!("{key}={value}");
        let len = u8::try_from(entry.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a TXT entry passes 255 bytes")
        })?;
        record.push(len);
        record.extend_from_slice(entry.as_bytes());
    }
    u16::try_from(record.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the TXT record passes 65535 bytes",
        )
    })?;
    Ok(record)
}

/// A TXT record's pairs, a key without `=` carrying no value.
type Txt = Vec<(String, Option<Vec<u8>>)>;

/// The pairs a TXT record's wire form carries.
fn txt_pairs(record: &[u8]) -> Txt {
    let mut pairs = Vec::new();
    let mut rest = record;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len).min(tail.len());
        let (entry, next) = tail.split_at(len);
        rest = next;
        let (key, value) = match entry.iter().position(|byte| *byte == b'=') {
            Some(at) => (&entry[..at], Some(entry[at + 1..].to_vec())),
            None => (entry, None),
        };
        if let Ok(key) = std::str::from_utf8(key)
            && !key.is_empty()
        {
            pairs.push((key.to_owned(), value));
        }
    }
    pairs
}

/// What a callback recorded, copied out of the library's buffers.
enum Record {
    Failed {
        op: &'static str,
        code: ErrorCode,
    },
    Browse {
        add: bool,
        interface: u32,
        name: CString,
        domain: CString,
    },
    Resolve {
        id: u64,
        host: CString,
        port: u16,
        txt: Txt,
    },
    Address {
        id: u64,
        add: bool,
        address: SocketAddr,
    },
}

/// The context one operation hands its callbacks.
///
/// The library keeps a pointer to it until the operation is deallocated, so
/// the owning [`Op`] holds it boxed and deallocates the operation first.
struct Tag {
    records: Rc<RefCell<Vec<Record>>>,
    id: u64,
}

impl Tag {
    fn push(&self, record: Record) {
        self.records.borrow_mut().push(record);
    }
}

/// The shared connection, deallocated after every operation started on it.
struct Connection(ServiceRef);

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the connection was created by `DNSServiceCreateConnection`,
        // is deallocated once here on the thread that created it, and every
        // operation on it was deallocated first by `Worker`'s field order.
        unsafe { DNSServiceRefDeallocate(self.0) };
    }
}

/// One operation on the shared connection and the context its callbacks read.
struct Op {
    service: ServiceRef,
    _tag: Box<Tag>,
}

impl Drop for Op {
    fn drop(&mut self) {
        // SAFETY: the operation was started on the worker's connection, which
        // outlives it, and is deallocated once here on the session thread,
        // after which the library no longer reads the boxed tag.
        unsafe { DNSServiceRefDeallocate(self.service) };
    }
}

/// One instance seen on one interface.
struct Pair {
    id: u64,
    interface: u32,
    _resolve: Op,
    host: Option<CString>,
    lookup: Option<Op>,
    port: u16,
    txt: Option<Txt>,
    addresses: BTreeSet<SocketAddr>,
}

/// What a drain of the records leaves the thread to do.
enum Standing {
    Running,
    Lost,
    Denied(&'static str),
}

/// The session thread's state, every operation declared before the connection
/// it was started on, so the operations deallocate first.
struct Worker {
    events: DnsSdSink,
    records: Rc<RefCell<Vec<Record>>>,
    regtype: CString,
    registrations: HashMap<CString, Op>,
    pairs: HashMap<(CString, u32), Pair>,
    ids: HashMap<u64, (CString, u32)>,
    reported: HashMap<String, (Txt, BTreeSet<SocketAddr>)>,
    next_id: u64,
    browse: Option<Op>,
    connection: Connection,
}

/// The session thread, until the session drops or the connection is lost.
fn serve(
    commands: &mpsc::Receiver<Command>,
    started: &mpsc::SyncSender<io::Result<()>>,
    events: DnsSdSink,
) {
    let mut worker = match Worker::open(events) {
        Ok(worker) => {
            let _ = started.send(Ok(()));
            worker
        }
        Err(err) => {
            let _ = started.send(Err(err));
            return;
        }
    };
    // SAFETY: the connection is live for the worker's lifetime.
    let fd = unsafe { DNSServiceRefSockFD(worker.connection.0) };
    let mut denied_at: Option<Instant> = None;
    loop {
        loop {
            match commands.try_recv() {
                Ok(Command::Register { name, port, txt }) => worker.register(name, port, &txt),
                Ok(Command::Unregister { name }) => {
                    worker.registrations.remove(&name);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        if denied_at.is_some_and(|at| at.elapsed() >= DENIED_WAIT) {
            (worker.events)(DnsSdEvent::Restart);
            return;
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` is one initialized `pollfd` the call writes only for
        // its duration.
        let ready = unsafe { libc::poll(&raw mut poll, 1, POLL_MS) };
        if ready <= 0 {
            continue;
        }
        // SAFETY: the connection is live, and its callbacks read tags the
        // worker's operations own.
        let code = unsafe { DNSServiceProcessResult(worker.connection.0) };
        if code != NO_ERROR {
            (worker.events)(DnsSdEvent::Fault(format!(
                "the Bonjour connection failed with {code}"
            )));
            (worker.events)(DnsSdEvent::Restart);
            return;
        }
        match worker.drain() {
            Standing::Running => {}
            Standing::Lost => {
                (worker.events)(DnsSdEvent::Restart);
                return;
            }
            Standing::Denied(op) => {
                if denied_at.is_none() {
                    denied_at = Some(Instant::now());
                    (worker.events)(DnsSdEvent::Fault(format!(
                        "the local network permission refused the Bonjour {op}"
                    )));
                }
            }
        }
    }
}

impl Worker {
    fn open(events: DnsSdSink) -> io::Result<Self> {
        let mut service: ServiceRef = std::ptr::null_mut();
        // SAFETY: `service` is a writable out-parameter the call fills on success.
        let code = unsafe { DNSServiceCreateConnection(&raw mut service) };
        if code != NO_ERROR {
            return Err(io::Error::other(format!(
                "the Bonjour connection failed with {code}"
            )));
        }
        let mut worker = Self {
            events,
            records: Rc::new(RefCell::new(Vec::new())),
            regtype: CString::new(DNS_SD_SERVICE).map_err(io::Error::other)?,
            registrations: HashMap::new(),
            pairs: HashMap::new(),
            ids: HashMap::new(),
            reported: HashMap::new(),
            next_id: 0,
            browse: None,
            connection: Connection(service),
        };
        let regtype = worker.regtype.clone();
        let browse = worker
            .start(0, |service, context| {
                // SAFETY: `service` holds the shared connection as the flag
                // requires, the strings outlive the call, and `context` is the
                // boxed tag the returned operation keeps.
                unsafe {
                    DNSServiceBrowse(
                        service,
                        FLAGS_SHARE_CONNECTION,
                        ANY_INTERFACE,
                        regtype.as_ptr(),
                        c"local.".as_ptr(),
                        on_browse,
                        context,
                    )
                }
            })
            .map_err(|code| io::Error::other(format!("the Bonjour browse failed with {code}")))?;
        worker.browse = Some(browse);
        Ok(worker)
    }

    /// Start one operation on the shared connection with a fresh tag.
    fn start(
        &self,
        id: u64,
        call: impl FnOnce(*mut ServiceRef, *mut c_void) -> ErrorCode,
    ) -> Result<Op, ErrorCode> {
        let tag = Box::new(Tag {
            records: Rc::clone(&self.records),
            id,
        });
        let mut service = self.connection.0;
        let context = std::ptr::from_ref::<Tag>(&*tag).cast_mut().cast::<c_void>();
        match call(&raw mut service, context) {
            NO_ERROR => Ok(Op { service, _tag: tag }),
            code => Err(code),
        }
    }

    fn register(&mut self, name: CString, port: u16, txt: &[u8]) {
        let regtype = self.regtype.clone();
        let Ok(txt_len) = u16::try_from(txt.len()) else {
            return;
        };
        let started = self.start(0, |service, context| {
            // SAFETY: `service` holds the shared connection as the flag
            // requires, the name, type and TXT bytes outlive the call, the
            // port is in network byte order, and `context` is the boxed tag
            // the returned operation keeps.
            unsafe {
                DNSServiceRegister(
                    service,
                    FLAGS_SHARE_CONNECTION,
                    ANY_INTERFACE,
                    name.as_ptr(),
                    regtype.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    port.to_be(),
                    txt_len,
                    txt.as_ptr().cast::<c_void>(),
                    on_register,
                    context,
                )
            }
        });
        match started {
            Ok(op) => {
                self.registrations.insert(name, op);
            }
            Err(code) => (self.events)(DnsSdEvent::Fault(format!(
                "the Bonjour advertisement failed with {code}"
            ))),
        }
    }

    /// Act on what the callbacks recorded.
    fn drain(&mut self) -> Standing {
        let records = std::mem::take(&mut *self.records.borrow_mut());
        let mut standing = Standing::Running;
        for record in records {
            match record {
                Record::Failed {
                    code: ERR_SERVICE_NOT_RUNNING,
                    ..
                } => return Standing::Lost,
                Record::Failed {
                    op,
                    code: ERR_POLICY_DENIED,
                } => standing = Standing::Denied(op),
                Record::Failed {
                    code: ERR_NO_SUCH_RECORD,
                    ..
                } => {}
                Record::Failed { op, code } => (self.events)(DnsSdEvent::Fault(format!(
                    "the Bonjour {op} failed with {code}"
                ))),
                Record::Browse {
                    add,
                    interface,
                    name,
                    domain,
                } => {
                    if add {
                        self.resolve(name, interface, &domain);
                    } else if let Some(pair) = self.pairs.remove(&(name.clone(), interface)) {
                        self.ids.remove(&pair.id);
                        self.report(&name);
                    }
                }
                Record::Resolve {
                    id,
                    host,
                    port,
                    txt,
                } => self.resolved(id, host, port, txt),
                Record::Address { id, add, address } => {
                    let Some(key) = self.ids.get(&id).cloned() else {
                        continue;
                    };
                    if let Some(pair) = self.pairs.get_mut(&key) {
                        if add {
                            pair.addresses.insert(address);
                        } else {
                            pair.addresses.remove(&address);
                        }
                    }
                    self.report(&key.0);
                }
            }
        }
        standing
    }

    /// Start resolving the instance `name` seen on `interface`.
    fn resolve(&mut self, name: CString, interface: u32, domain: &CStr) {
        let key = (name, interface);
        if self.pairs.contains_key(&key) {
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        let regtype = self.regtype.clone();
        let started = self.start(id, |service, context| {
            // SAFETY: `service` holds the shared connection as the flag
            // requires, the strings outlive the call, and `context` is the
            // boxed tag the returned operation keeps.
            unsafe {
                DNSServiceResolve(
                    service,
                    FLAGS_SHARE_CONNECTION,
                    interface,
                    key.0.as_ptr(),
                    regtype.as_ptr(),
                    domain.as_ptr(),
                    on_resolve,
                    context,
                )
            }
        });
        match started {
            Ok(op) => {
                self.ids.insert(id, key.clone());
                self.pairs.insert(
                    key,
                    Pair {
                        id,
                        interface,
                        _resolve: op,
                        host: None,
                        lookup: None,
                        port: 0,
                        txt: None,
                        addresses: BTreeSet::new(),
                    },
                );
            }
            Err(code) => (self.events)(DnsSdEvent::Fault(format!(
                "the Bonjour resolve failed with {code}"
            ))),
        }
    }

    /// The resolve answered, so the instance's host is looked up when it moved.
    fn resolved(&mut self, id: u64, host: CString, port: u16, txt: Txt) {
        let Some(key) = self.ids.get(&id).cloned() else {
            return;
        };
        let Some(pair) = self.pairs.get(&key) else {
            return;
        };
        let interface = pair.interface;
        let lookup = if pair.host.as_ref() == Some(&host) {
            None
        } else {
            let started = self.start(id, |service, context| {
                // SAFETY: `service` holds the shared connection as the flag
                // requires, the host name outlives the call, and `context` is
                // the boxed tag the returned operation keeps.
                unsafe {
                    DNSServiceGetAddrInfo(
                        service,
                        FLAGS_SHARE_CONNECTION,
                        interface,
                        PROTOCOL_BOTH,
                        host.as_ptr(),
                        on_address,
                        context,
                    )
                }
            });
            match started {
                Ok(op) => Some(op),
                Err(code) => {
                    (self.events)(DnsSdEvent::Fault(format!(
                        "the Bonjour address lookup failed with {code}"
                    )));
                    return;
                }
            }
        };
        if let Some(pair) = self.pairs.get_mut(&key) {
            if let Some(lookup) = lookup {
                pair.lookup = Some(lookup);
                pair.host = Some(host);
                pair.addresses.clear();
            }
            pair.port = port;
            pair.txt = Some(txt);
        }
        self.report(&key.0);
    }

    /// Report the instance's TXT and every address its interfaces answered,
    /// or its removal once no interface sees it.
    fn report(&mut self, name: &CStr) {
        let Ok(label) = name.to_str() else {
            return;
        };
        let mut seen = false;
        let mut found_txt = None;
        let mut addresses = BTreeSet::new();
        for ((pair_name, _), pair) in &self.pairs {
            if pair_name.as_c_str() != name {
                continue;
            }
            seen = true;
            if found_txt.is_none() {
                found_txt.clone_from(&pair.txt);
            }
            addresses.extend(pair.addresses.iter().map(|address| {
                let mut address = *address;
                address.set_port(pair.port);
                address
            }));
        }
        if !seen {
            if self.reported.remove(label).is_some() {
                (self.events)(DnsSdEvent::Removed {
                    name: label.to_owned(),
                });
            }
            return;
        }
        let Some(txt) = found_txt else {
            return;
        };
        if addresses.is_empty() {
            return;
        }
        let current = (txt, addresses);
        if self.reported.get(label) == Some(&current) {
            return;
        }
        self.reported.insert(label.to_owned(), current.clone());
        (self.events)(DnsSdEvent::Resolved {
            name: label.to_owned(),
            txt: current.0,
            addresses: current.1.into_iter().collect(),
        });
    }
}

/// The tag a callback's context points to.
///
/// # Safety
///
/// `context` must be the pointer [`Worker::start`] handed the library, whose
/// owning [`Op`] is alive, which holds for every callback since callbacks run
/// only inside `DNSServiceProcessResult` before the operation is deallocated.
unsafe fn tag_of<'a>(context: *mut c_void) -> &'a Tag {
    // SAFETY: the caller's contract above.
    unsafe { &*context.cast::<Tag>() }
}

/// A copy of a string the library hands a callback, or `None` for a null.
///
/// # Safety
///
/// `text` must be null or a NUL-terminated string the library keeps valid and
/// unchanged for the callback's duration, which `<dns_sd.h>` documents.
unsafe fn copied(text: *const c_char) -> Option<CString> {
    if text.is_null() {
        return None;
    }
    // SAFETY: non-null and NUL-terminated for the callback's duration, per the
    // caller's contract, and copied before the callback returns.
    Some(unsafe { CStr::from_ptr(text) }.to_owned())
}

extern "C" fn on_register(
    _service: ServiceRef,
    _flags: Flags,
    code: ErrorCode,
    _name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: the context is the registration's live tag.
    let tag = unsafe { tag_of(context) };
    if code != NO_ERROR {
        tag.push(Record::Failed {
            op: "advertisement",
            code,
        });
    }
}

extern "C" fn on_browse(
    _service: ServiceRef,
    flags: Flags,
    interface: u32,
    code: ErrorCode,
    name: *const c_char,
    _regtype: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: the context is the browse's live tag.
    let tag = unsafe { tag_of(context) };
    if code != NO_ERROR {
        tag.push(Record::Failed { op: "browse", code });
        return;
    }
    // SAFETY: the library's instance name for this callback.
    let name = unsafe { copied(name) };
    // SAFETY: the library's reply domain for this callback.
    let domain = unsafe { copied(domain) };
    if let (Some(name), Some(domain)) = (name, domain) {
        tag.push(Record::Browse {
            add: flags & FLAGS_ADD != 0,
            interface,
            name,
            domain,
        });
    }
}

extern "C" fn on_resolve(
    _service: ServiceRef,
    _flags: Flags,
    _interface: u32,
    code: ErrorCode,
    _fullname: *const c_char,
    host: *const c_char,
    port: u16,
    txt_len: u16,
    txt: *const u8,
    context: *mut c_void,
) {
    // SAFETY: the context is the resolve's live tag.
    let tag = unsafe { tag_of(context) };
    if code != NO_ERROR {
        tag.push(Record::Failed {
            op: "resolve",
            code,
        });
        return;
    }
    // SAFETY: the library's host target for this callback.
    let Some(host) = (unsafe { copied(host) }) else {
        return;
    };
    let record = if txt.is_null() || txt_len == 0 {
        Vec::new()
    } else {
        // SAFETY: the library hands `txt_len` initialized bytes at `txt`,
        // valid for the callback's duration and copied before it returns.
        unsafe { std::slice::from_raw_parts(txt, usize::from(txt_len)) }.to_vec()
    };
    tag.push(Record::Resolve {
        id: tag.id,
        host,
        port: u16::from_be(port),
        txt: txt_pairs(&record),
    });
}

extern "C" fn on_address(
    _service: ServiceRef,
    flags: Flags,
    interface: u32,
    code: ErrorCode,
    _host: *const c_char,
    address: *const libc::sockaddr,
    _ttl: u32,
    context: *mut c_void,
) {
    // SAFETY: the context is the lookup's live tag.
    let tag = unsafe { tag_of(context) };
    if code != NO_ERROR {
        tag.push(Record::Failed {
            op: "address lookup",
            code,
        });
        return;
    }
    // SAFETY: the library's address for this callback, null or a socket
    // address of the family its header names.
    let Some(address) = (unsafe { socket_address(address, interface) }) else {
        return;
    };
    tag.push(Record::Address {
        id: tag.id,
        add: flags & FLAGS_ADD != 0,
        address,
    });
}

/// A copy of the library's socket address with port 0, or `None` for another family.
///
/// # Safety
///
/// `address` must be null or point to a socket address the library keeps valid
/// for the callback's duration, sized for the family its header names.
unsafe fn socket_address(address: *const libc::sockaddr, interface: u32) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: non-null and valid for the callback, per the caller's contract.
    let family = c_int::from(unsafe { (*address).sa_family });
    if family == libc::AF_INET {
        // SAFETY: an `AF_INET` address is a `sockaddr_in`.
        let v4 = unsafe { &*address.cast::<libc::sockaddr_in>() };
        let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
        Some(SocketAddr::V4(SocketAddrV4::new(ip, 0)))
    } else if family == libc::AF_INET6 {
        // SAFETY: an `AF_INET6` address is a `sockaddr_in6`.
        let v6 = unsafe { &*address.cast::<libc::sockaddr_in6>() };
        let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
        let scope = if v6.sin6_scope_id == 0 {
            interface
        } else {
            v6.sin6_scope_id
        };
        Some(SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, scope)))
    } else {
        None
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use connetto_peer::{DnsSd, DnsSdEvent};

    use super::Bonjour;

    const WAIT: Duration = Duration::from_secs(30);

    fn open(
        port: u16,
        name: &str,
        fingerprint: &str,
    ) -> (
        Box<dyn connetto_peer::DnsSdSession>,
        mpsc::Receiver<DnsSdEvent>,
    ) {
        let (tx, rx) = mpsc::channel();
        let mut session = Bonjour
            .open(Box::new(move |event| {
                let _ = tx.send(event);
            }))
            .expect("the Bonjour session opens");
        session
            .register(name, port, &[("v", "1"), ("fp", fingerprint)])
            .expect("the advertisement registers");
        (session, rx)
    }

    /// Wait until `rx` reports `wanted`, failing at the bound.
    fn await_event(rx: &mpsc::Receiver<DnsSdEvent>, wanted: impl Fn(&DnsSdEvent) -> bool) {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let event = rx
                .recv_timeout(left)
                .expect("the event arrives within the bound");
            if wanted(&event) {
                return;
            }
        }
    }

    fn resolved(name: &str, port: u16, fingerprint: &str) -> impl Fn(&DnsSdEvent) -> bool {
        let name = name.to_owned();
        let fingerprint = fingerprint.as_bytes().to_vec();
        move |event| match event {
            DnsSdEvent::Resolved {
                name: found,
                txt,
                addresses,
            } => {
                *found == name
                    && txt.iter().any(|(key, value)| {
                        key == "fp" && value.as_deref() == Some(&fingerprint[..])
                    })
                    && !addresses.is_empty()
                    && addresses.iter().all(|address| address.port() == port)
            }
            _ => false,
        }
    }

    /// Two sessions resolve each other's advertisement and see its removal.
    #[test]
    fn two_sessions_resolve_each_other_and_see_the_removal() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock stands after the epoch")
            .as_nanos();
        let a_name = format!("a{stamp:x}");
        let b_name = format!("b{stamp:x}");
        let a_fp = "a".repeat(64);
        let b_fp = "b".repeat(64);
        let (_a, a_rx) = open(41_001, &a_name, &a_fp);
        let (mut b, b_rx) = open(41_002, &b_name, &b_fp);

        await_event(&a_rx, resolved(&b_name, 41_002, &b_fp));
        await_event(&b_rx, resolved(&a_name, 41_001, &a_fp));

        b.unregister(&b_name);
        await_event(
            &a_rx,
            |event| matches!(event, DnsSdEvent::Removed { name } if *name == b_name),
        );
    }
}
