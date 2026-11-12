//! The peer-to-peer transport (docs/NETWORK.md), on threads of its own: transactions, blocks
//! and votes.
//!
//! A node's Python spent most of its time on its peers' traffic, on its one thread: HTTP,
//! JSON, a signed request a batch, a signature a transaction (docs/PERFORMANCE.md). Here,
//! peers keep a connection open (session.rs: authenticated by their node keys, encrypted with a
//! post-quantum session key) and the work runs on a tokio runtime and rayon's threads:
//!
//! * reading and checking a peer's transactions: parsing, the signed bytes and hash (tx.rs),
//!   setting duplicates aside, the signature;
//! * gossip: a transaction a wallet sent this node goes whole to every peer; one a peer sent is
//!   announced by hash to the others, which ask for what they lack;
//! * a pool of the transactions seen lately, to answer those requests, and a block's
//!   operations asked of the peer that sent it;
//! * blocks and votes: each set aside if seen before, and handed to Python, which checks it as
//!   it checks one that came over HTTP and relays it (`send_block`, `send_votes`) only once it
//!   has taken it.
//!
//! Python is handed what is new, in batches, through `drain` (an event descriptor wakes its
//! event loop), and does what needs the chain's state: nonces, balances, the mempool
//! (qrdx/node/netd.py). Only what Python admits is relayed (`relay`).
//!
//! Who may connect is Python's to say (`allow`: the peers the node admitted, by node id).

mod proto;
mod session;

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use rayon::prelude::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::AbortHandle;

use crate::tx;
use proto::Message;
use session::{Chain, Established, Identity};

/// Transactions kept to answer peers' requests, and hashes remembered as handled.
const POOL_CAPACITY: usize = 262_144;
const SEEN_CAPACITY: usize = 1_048_576;
/// Messages queued to one peer before more are dropped (a peer that does not read).
const PEER_QUEUE: usize = 4096;
/// How long a transaction asked of one peer is not asked of another.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Handshakes in progress at once (each costs a signature and a KEM).
const MAX_HANDSHAKES: usize = 16;
/// Invalid transactions a peer may send before it is disconnected.
const STRIKES: u32 = 3;
/// What one push may carry.
const PUSH_BYTES: usize = 8 * 1024 * 1024;
/// Blocks and votes remembered as handled.
const BLOCKS_SEEN: usize = 4096;
const VOTES_SEEN: usize = 262_144;
/// How long an answer to a request for a block's operations is waited for.
const ASK_TIMEOUT: Duration = Duration::from_secs(10);
/// What one peer may send a second, beyond a burst of twice that: blocks, votes, and a block's
/// operations asked of this node. More is dropped (``dropped_in``), never queued: a node relays
/// a block of each slot once, and a vote of each validator a slot.
const BLOCKS_PER_SECOND: f64 = 32.0;
const VOTES_PER_SECOND: f64 = 16_384.0;
const ASKED_PER_SECOND: f64 = 32_768.0;

struct Bounded<K: Eq + Hash + Copy, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    cap: usize,
}

impl<K: Eq + Hash + Copy, V> Bounded<K, V> {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    fn insert(&mut self, k: K, v: V) -> bool {
        if self.map.insert(k, v).is_some() {
            return false;
        }
        self.order.push_back(k);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        true
    }

    fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k)
    }

    fn contains(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }
}

struct PeerHandle {
    conn: u64,
    tx: mpsc::Sender<Vec<u8>>,
    addr: SocketAddr,
    inbound: bool,
    since: Instant,
    tasks: Vec<AbortHandle>,
    budget: Budget,
}

/// What a peer may still send, per kind (a token bucket each).
struct Budget {
    tokens: [f64; 3],
    at: Instant,
}

#[derive(Clone, Copy)]
enum Kind {
    Blocks = 0,
    Votes = 1,
    Asked = 2,
}

const RATES: [f64; 3] = [BLOCKS_PER_SECOND, VOTES_PER_SECOND, ASKED_PER_SECOND];

impl Budget {
    fn new() -> Self {
        Self {
            tokens: RATES.map(|r| 2.0 * r),
            at: Instant::now(),
        }
    }

    fn take(&mut self, kind: Kind, n: usize) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.at).as_secs_f64();
        self.at = now;
        for (t, r) in self.tokens.iter_mut().zip(RATES) {
            *t = (*t + dt * r).min(2.0 * r);
        }
        let t = &mut self.tokens[kind as usize];
        if *t < n as f64 {
            return false;
        }
        *t -= n as f64;
        true
    }
}

/// A transaction from a peer, read here: for Python.
struct Incoming {
    raw: Arc<Vec<u8>>,
    checked: Option<(String, Vec<u8>, Option<bool>)>, // (hash, signed bytes, verdict)
    reason: Option<&'static str>,                     // why Python reads it itself
}

enum Event {
    Txs { from: String, txs: Vec<Incoming> },
    Block { from: String, raw: Vec<u8> },
    Votes { from: String, votes: Vec<Vec<u8>> },
    BlockTxs { from: String, id: u64, txs: Vec<Option<Vec<u8>>> },
    Up { node: String, addr: String, inbound: bool },
    Down { node: String },
}

#[derive(Default)]
struct Stats {
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    txs_in: AtomicU64,
    txs_new: AtomicU64,
    txs_invalid: AtomicU64,
    dropped_out: AtomicU64,
    dropped_in: AtomicU64,
    handshakes_failed: AtomicU64,
    blocks_in: AtomicU64,
    blocks_new: AtomicU64,
    votes_in: AtomicU64,
    votes_new: AtomicU64,
}

/// What the transport remembers of transactions: those it holds to answer peers' requests, the
/// hashes it has handled, and those it asked a peer for. One lock, so no order to get wrong.
struct Memory {
    pool: Bounded<[u8; 32], Arc<Vec<u8>>>,
    seen: Bounded<[u8; 32], ()>,
    requested: HashMap<[u8; 32], Instant>,
    pruned: Instant,
    blocks: Bounded<[u8; 32], ()>, // (by the hash of the bytes as they travelled)
    votes: Bounded<[u8; 32], ()>,
    /// Requests for blocks' operations this node made: id → (the peer asked, how many, when).
    asked: HashMap<u64, (String, usize, Instant)>,
}

impl Memory {
    /// Forget requests that went unanswered, at most once a second.
    fn prune_requests(&mut self, now: Instant) {
        if now.duration_since(self.pruned) >= Duration::from_secs(1) {
            self.requested
                .retain(|_, at| now.duration_since(*at) < REQUEST_TIMEOUT);
            self.asked
                .retain(|_, (_, _, at)| now.duration_since(*at) < ASK_TIMEOUT);
            self.pruned = now;
        }
    }
}

struct Shared {
    me: Identity,
    chain: Chain,
    node_id: String,
    max_peers: usize,
    peers: Mutex<HashMap<String, PeerHandle>>,
    allowed: RwLock<Option<HashSet<String>>>,
    memory: Mutex<Memory>,
    inbox: Mutex<VecDeque<Event>>,
    wake: Mutex<UnixStream>,
    handshakes: Semaphore,
    next_conn: AtomicU64,
    stats: Stats,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Shared {
    fn push_event(&self, event: Event) {
        self.inbox.lock().unwrap().push_back(event);
        // One byte wakes Python's event loop; a full pipe means a wake-up is already pending.
        let _ = self.wake.lock().unwrap().write(&[1]);
    }

    fn allowed(&self, node: &str) -> bool {
        match &*self.allowed.read().unwrap() {
            None => true,
            Some(set) => set.contains(node),
        }
    }

    fn send_to(&self, node: &str, message: Vec<u8>) {
        if let Some(p) = self.peers.lock().unwrap().get(node) {
            if p.tx.try_send(message).is_err() {
                self.stats.dropped_out.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// To every peer but ``except``; the peers it was queued to.
    fn send_all(&self, message: &[u8], except: Option<&str>) -> Vec<String> {
        let mut sent = Vec::new();
        for (node, p) in self.peers.lock().unwrap().iter() {
            if Some(node.as_str()) == except {
                continue;
            }
            if p.tx.try_send(message.to_vec()).is_err() {
                self.stats.dropped_out.fetch_add(1, Ordering::Relaxed);
            } else {
                sent.push(node.clone());
            }
        }
        sent
    }

    /// Whether ``node`` may send ``n`` more of ``kind`` now (taking them if so).
    fn within_budget(&self, node: &str, kind: Kind, n: usize) -> bool {
        let ok = self
            .peers
            .lock()
            .unwrap()
            .get_mut(node)
            .is_some_and(|p| p.budget.take(kind, n));
        if !ok {
            self.stats.dropped_in.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Read a peer's (or a wallet's) transactions: the new ones, with their verdicts; how many
    /// had invalid signatures. Duplicates are set aside before any signature is checked.
    fn read_new(&self, raws: Vec<Vec<u8>>) -> (Vec<Incoming>, u32) {
        let parsed: Vec<(Arc<Vec<u8>>, tx::Read)> = raws
            .into_par_iter()
            .map(|raw| {
                let read = tx::read(&raw);
                (Arc::new(raw), read)
            })
            .collect();
        let mut fresh: Vec<(Arc<Vec<u8>>, tx::Read)> = Vec::with_capacity(parsed.len());
        {
            let mut memory = self.memory.lock().unwrap();
            for (raw, read) in parsed {
                match &read {
                    tx::Read::Checked(c) => {
                        if memory.seen.insert(c.hash, ()) {
                            fresh.push((raw, read));
                        }
                    }
                    tx::Read::Python(_) => fresh.push((raw, read)),
                    tx::Read::Malformed(_) => {}
                }
            }
        }
        let checked: Vec<Incoming> = fresh
            .into_par_iter()
            .map(|(raw, read)| match read {
                tx::Read::Checked(c) => {
                    let verdict = c.verdict();
                    Incoming {
                        raw,
                        checked: Some((hex(&c.hash), c.signed, verdict)),
                        reason: None,
                    }
                }
                tx::Read::Python(why) => Incoming {
                    raw,
                    checked: None,
                    reason: Some(why),
                },
                tx::Read::Malformed(why) => Incoming {
                    raw,
                    checked: None,
                    reason: Some(why),
                },
            })
            .collect();
        let mut invalid = 0u32;
        let mut keep = Vec::with_capacity(checked.len());
        {
            let mut memory = self.memory.lock().unwrap();
            for item in checked {
                if let Some((h, _, verdict)) = &item.checked {
                    if *verdict == Some(false) {
                        invalid += 1;
                        continue;
                    }
                    let key = unhex32(h).expect("a hash this module wrote");
                    memory.requested.remove(&key);
                    memory.pool.insert(key, item.raw.clone());
                }
                keep.push(item);
            }
        }
        (keep, invalid)
    }

    fn handle(self: &Arc<Self>, from: &str, message: Message) -> Result<(), &'static str> {
        match message {
            Message::Push(raws) => {
                self.stats
                    .txs_in
                    .fetch_add(raws.len() as u64, Ordering::Relaxed);
                let shared = self.clone();
                let from = from.to_string();
                // (off the runtime's threads: parsing and signatures are CPU work)
                tokio::task::spawn_blocking(move || {
                    let (txs, invalid) = shared.read_new(raws);
                    if invalid > 0 {
                        shared
                            .stats
                            .txs_invalid
                            .fetch_add(invalid as u64, Ordering::Relaxed);
                        shared.strike(&from, invalid);
                    }
                    if !txs.is_empty() {
                        shared
                            .stats
                            .txs_new
                            .fetch_add(txs.len() as u64, Ordering::Relaxed);
                        shared.push_event(Event::Txs { from, txs });
                    }
                });
            }
            Message::Announce(hashes) => {
                let now = Instant::now();
                let wanted: Vec<[u8; 32]> = {
                    let mut memory = self.memory.lock().unwrap();
                    memory.prune_requests(now);
                    let m = &mut *memory;
                    hashes
                        .into_iter()
                        .filter(|h| {
                            if m.seen.contains(h)
                                || m.pool.contains(h)
                                || m.requested.contains_key(h)
                            {
                                return false;
                            }
                            m.requested.insert(*h, now);
                            true
                        })
                        .collect()
                };
                if !wanted.is_empty() {
                    self.send_to(from, proto::encode_hashes(proto::TX_GET, &wanted));
                }
            }
            Message::Get(hashes) => {
                let found: Vec<Arc<Vec<u8>>> = {
                    let memory = self.memory.lock().unwrap();
                    hashes
                        .iter()
                        .filter_map(|h| memory.pool.get(h).cloned())
                        .collect()
                };
                for message in pushes(&found) {
                    self.send_to(from, message);
                }
            }
            Message::Block(raw) => {
                self.stats.blocks_in.fetch_add(1, Ordering::Relaxed);
                if !self.within_budget(from, Kind::Blocks, 1) {
                    return Ok(());
                }
                let key = *blake3::hash(&raw).as_bytes();
                if self.memory.lock().unwrap().blocks.insert(key, ()) {
                    self.stats.blocks_new.fetch_add(1, Ordering::Relaxed);
                    self.push_event(Event::Block {
                        from: from.to_string(),
                        raw,
                    });
                }
            }
            Message::Votes(raws) => {
                self.stats
                    .votes_in
                    .fetch_add(raws.len() as u64, Ordering::Relaxed);
                if !self.within_budget(from, Kind::Votes, raws.len()) {
                    return Ok(());
                }
                let fresh: Vec<Vec<u8>> = {
                    let mut memory = self.memory.lock().unwrap();
                    raws.into_iter()
                        .filter(|v| memory.votes.insert(*blake3::hash(v).as_bytes(), ()))
                        .collect()
                };
                if !fresh.is_empty() {
                    self.stats
                        .votes_new
                        .fetch_add(fresh.len() as u64, Ordering::Relaxed);
                    self.push_event(Event::Votes {
                        from: from.to_string(),
                        votes: fresh,
                    });
                }
            }
            Message::BlockTxsGet(id, hashes) => {
                if !self.within_budget(from, Kind::Asked, hashes.len().max(1)) {
                    return Ok(());
                }
                // From the pool, up to what one push may carry; the rest as not held (the
                // asker fetches those another way).
                let found: Vec<Option<Arc<Vec<u8>>>> = {
                    let memory = self.memory.lock().unwrap();
                    let mut size = 0usize;
                    hashes
                        .iter()
                        .map(|h| {
                            let raw = memory.pool.get(h)?;
                            size += raw.len() + 4;
                            (size <= PUSH_BYTES).then(|| raw.clone())
                        })
                        .collect()
                };
                let refs: Vec<Option<&[u8]>> =
                    found.iter().map(|t| t.as_deref().map(Vec::as_slice)).collect();
                self.send_to(from, proto::encode_block_txs(id, &refs));
            }
            Message::BlockTxs(id, txs) => {
                let mut memory = self.memory.lock().unwrap();
                match memory.asked.get(&id) {
                    None => return Ok(()), // (late: given up on)
                    Some((node, n, _)) if node != from || *n != txs.len() => {
                        return Err("an answer to a request it was not asked");
                    }
                    Some(_) => {}
                }
                memory.asked.remove(&id);
                drop(memory);
                self.push_event(Event::BlockTxs {
                    from: from.to_string(),
                    id,
                    txs,
                });
            }
            Message::Ping(v) => self.send_to(from, proto::encode_ping(proto::PONG, v)),
            Message::Pong => {}
        }
        Ok(())
    }

    fn strike(&self, node: &str, count: u32) {
        // Peers relay only what they admitted, so an invalid signature is the sender's doing.
        if count >= STRIKES {
            self.disconnect(node);
        }
    }

    fn disconnect(&self, node: &str) {
        let removed = self.peers.lock().unwrap().remove(node);
        if let Some(p) = removed {
            for t in p.tasks {
                t.abort();
            }
            drop(p.tx);
            self.push_event(Event::Down {
                node: node.to_string(),
            });
        }
    }
}

/// Transactions cut into pushes no larger than a frame should be.
fn pushes(txs: &[Arc<Vec<u8>>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut part: Vec<&[u8]> = Vec::new();
    let mut size = 0usize;
    for t in txs {
        if !part.is_empty() && (part.len() >= proto::MAX_PUSH || size + t.len() > PUSH_BYTES) {
            out.push(proto::encode_push(&part));
            part.clear();
            size = 0;
        }
        part.push(t.as_slice());
        size += t.len() + 4;
    }
    if !part.is_empty() {
        out.push(proto::encode_push(&part));
    }
    out
}

async fn run(shared: Arc<Shared>, est: Established, addr: SocketAddr, inbound: bool) {
    let node = est.peer_node_id.clone();
    if !shared.allowed(&node) {
        return;
    }
    let conn = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE);
    // One connection a pair of nodes. Both may dial at once; each side keeps the connection the
    // node with the lower id began, so both keep the same one.
    let preferred = (node.as_str() < shared.node_id.as_str()) == inbound;
    {
        let mut peers = shared.peers.lock().unwrap();
        if let Some(existing) = peers.get(&node) {
            let existing_preferred =
                (node.as_str() < shared.node_id.as_str()) == existing.inbound;
            if existing_preferred || !preferred {
                return;
            }
            let old = peers.remove(&node).expect("present");
            for t in old.tasks {
                t.abort();
            }
        }
        if peers.len() >= shared.max_peers {
            return;
        }
        peers.insert(
            node.clone(),
            PeerHandle {
                conn,
                tx,
                addr,
                inbound,
                since: Instant::now(),
                tasks: Vec::new(),
                budget: Budget::new(),
            },
        );
    }
    shared.push_event(Event::Up {
        node: node.clone(),
        addr: addr.to_string(),
        inbound,
    });

    let mut sender = est.sender;
    let mut receiver = est.receiver;
    let writer_shared = shared.clone();
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let len = message.len() as u64;
            if sender.send(&message).await.is_err() {
                break;
            }
            writer_shared
                .stats
                .frames_out
                .fetch_add(1, Ordering::Relaxed);
            writer_shared
                .stats
                .bytes_out
                .fetch_add(len, Ordering::Relaxed);
        }
    });
    let reader_shared = shared.clone();
    let reader_node = node.clone();
    let reader = tokio::spawn(async move {
        loop {
            let frame = match receiver.recv().await {
                Ok(f) => f,
                Err(_) => break,
            };
            reader_shared
                .stats
                .frames_in
                .fetch_add(1, Ordering::Relaxed);
            reader_shared
                .stats
                .bytes_in
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
            let Some(message) = proto::decode(&frame) else {
                break; // (a malformed message: the peer is misbehaving)
            };
            if reader_shared.handle(&reader_node, message).is_err() {
                break;
            }
        }
    });
    if let Some(p) = shared.peers.lock().unwrap().get_mut(&node) {
        if p.conn == conn {
            p.tasks = vec![writer.abort_handle(), reader.abort_handle()];
        }
    }
    let _ = reader.await;
    writer.abort();
    let mut peers = shared.peers.lock().unwrap();
    if peers.get(&node).map(|p| p.conn) == Some(conn) {
        peers.remove(&node);
        drop(peers);
        shared.push_event(Event::Down { node });
    }
}

async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = shared.handshakes.try_acquire() else {
            continue; // (too many handshakes at once: refused, the dialer retries)
        };
        permit.forget();
        let s = shared.clone();
        tokio::spawn(async move {
            let result = session::respond(stream, &s.me, &s.chain, |n| s.allowed(n)).await;
            s.handshakes.add_permits(1);
            match result {
                Ok(est) => run(s, est, addr, true).await,
                Err(_) => {
                    s.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

async fn dial(shared: Arc<Shared>, addr: SocketAddr, expect: Option<String>) {
    let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await
    else {
        return;
    };
    let _permit = match shared.handshakes.acquire().await {
        Ok(p) => p,
        Err(_) => return,
    };
    match session::initiate(stream, &shared.me, &shared.chain).await {
        Ok(est) => {
            drop(_permit);
            if expect.as_ref().is_some_and(|e| *e != est.peer_node_id) {
                return; // (not the node we meant to reach)
            }
            run(shared, est, addr, false).await;
        }
        Err(_) => {
            shared
                .stats
                .handshakes_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The transport, as Python holds it (qrdx/node/netd.py).
#[pyclass(frozen, module = "qrdx_native._native")]
pub struct NetService {
    shared: Arc<Shared>,
    runtime: Arc<Runtime>,
    read_end: Mutex<Option<UnixStream>>,
    local: Mutex<Option<SocketAddr>>,
    listen: String,
}

/// A ``bytes`` (or ``bytearray``) argument's contents, copied once: PyO3 reads a ``Vec<u8>``
/// argument an element at a time (a transaction's 5 KB, a block's megabytes; docs/NATIVE.md).
fn bytes_of(v: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(b) = v.downcast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(b) = v.downcast::<pyo3::types::PyByteArray>() {
        return Ok(b.to_vec());
    }
    v.extract::<Vec<u8>>()
}

#[pymethods]
impl NetService {
    #[new]
    #[pyo3(signature = (listen, secret_key, public_key, chain_id, genesis_hash, max_peers=64, threads=4))]
    fn new(
        listen: String,
        secret_key: &[u8],
        public_key: &[u8],
        chain_id: u64,
        genesis_hash: &str,
        max_peers: usize,
        threads: usize,
    ) -> PyResult<Self> {
        let genesis = unhex32(genesis_hash.trim_start_matches("0x"))
            .ok_or_else(|| PyValueError::new_err("genesis_hash is 64 hex characters"))?;
        if secret_key.len() != crate::oqs::DSA_SECRET_KEY_LEN
            || public_key.len() != crate::oqs::DSA_PUBLIC_KEY_LEN
        {
            return Err(PyValueError::new_err("an ML-DSA-65 node key pair is required"));
        }
        // The key pair must be a pair: a signature made with it must verify under it.
        let probe = crate::oqs::dsa_sign(secret_key, b"qrdx-p2p-v1/self-check")
            .ok_or_else(|| PyValueError::new_err("the node key does not sign"))?;
        if !crate::oqs::dsa_verify(public_key, b"qrdx-p2p-v1/self-check", &probe) {
            return Err(PyValueError::new_err("the node keys are not a pair"));
        }
        let (read_end, write_end) = UnixStream::pair()
            .map_err(|e| PyRuntimeError::new_err(format!("event pipe: {e}")))?;
        read_end
            .set_nonblocking(true)
            .and_then(|_| write_end.set_nonblocking(true))
            .map_err(|e| PyRuntimeError::new_err(format!("event pipe: {e}")))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads.max(1))
            .thread_name("qrdx-net")
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("runtime: {e}")))?;
        let shared = Arc::new(Shared {
            node_id: session::node_id(public_key),
            me: Identity {
                public_key: public_key.to_vec(),
                secret_key: secret_key.to_vec(),
            },
            chain: Chain { chain_id, genesis },
            max_peers,
            peers: Mutex::new(HashMap::new()),
            allowed: RwLock::new(None),
            memory: Mutex::new(Memory {
                pool: Bounded::new(POOL_CAPACITY),
                seen: Bounded::new(SEEN_CAPACITY),
                requested: HashMap::new(),
                pruned: Instant::now(),
                blocks: Bounded::new(BLOCKS_SEEN),
                votes: Bounded::new(VOTES_SEEN),
                asked: HashMap::new(),
            }),
            inbox: Mutex::new(VecDeque::new()),
            wake: Mutex::new(write_end),
            handshakes: Semaphore::new(MAX_HANDSHAKES),
            next_conn: AtomicU64::new(1),
            stats: Stats::default(),
        });
        Ok(Self {
            shared,
            runtime: Arc::new(runtime),
            read_end: Mutex::new(Some(read_end)),
            local: Mutex::new(None),
            listen,
        })
    }

    /// Listen for peers. Returns the address bound (a port of 0 picks one).
    fn start(&self) -> PyResult<String> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| PyValueError::new_err("listen is host:port"))?;
        let listener = self
            .runtime
            .block_on(TcpListener::bind(addr))
            .map_err(|e| PyRuntimeError::new_err(format!("listen on {addr}: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        *self.local.lock().unwrap() = Some(local);
        self.runtime
            .spawn(accept_loop(self.shared.clone(), listener));
        Ok(local.to_string())
    }

    #[getter]
    fn node_id(&self) -> String {
        self.shared.node_id.clone()
    }

    /// Dial a peer (in the background). With `expect`, a peer with another node id is dropped.
    #[pyo3(signature = (addr, expect=None))]
    fn connect(&self, addr: &str, expect: Option<String>) -> PyResult<()> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| PyValueError::new_err("addr is ip:port"))?;
        if let Some(e) = &expect {
            if self.shared.peers.lock().unwrap().contains_key(e) {
                return Ok(());
            }
        }
        self.runtime.spawn(dial(self.shared.clone(), addr, expect));
        Ok(())
    }

    /// Who may stay connected, by node id (None: anyone on this chain). Peers not in it are
    /// disconnected.
    #[pyo3(signature = (node_ids=None))]
    fn allow(&self, node_ids: Option<Vec<String>>) {
        let set = node_ids.map(|ids| ids.into_iter().collect::<HashSet<_>>());
        let gone: Vec<String> = match &set {
            None => Vec::new(),
            Some(s) => self
                .shared
                .peers
                .lock()
                .unwrap()
                .keys()
                .filter(|k| !s.contains(*k))
                .cloned()
                .collect(),
        };
        *self.shared.allowed.write().unwrap() = set;
        for node in gone {
            self.shared.disconnect(&node);
        }
    }

    /// The connected peers: (node id, address, inbound, seconds connected).
    fn peers(&self) -> Vec<(String, String, bool, f64)> {
        self.shared
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(k, p)| {
                (
                    k.clone(),
                    p.addr.to_string(),
                    p.inbound,
                    p.since.elapsed().as_secs_f64(),
                )
            })
            .collect()
    }

    /// The descriptor that becomes readable when `drain` has something.
    fn event_fd(&self) -> PyResult<i32> {
        self.read_end
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.as_raw_fd())
            .ok_or_else(|| PyRuntimeError::new_err("closed"))
    }

    /// What arrived since the last call:
    /// ("txs", from, [(raw, hash | None, signed | None, verdict | None, reason | None)]),
    /// ("block", from, raw), ("votes", from, [raw]), ("block_txs", from, request id,
    /// [raw | None]), ("up", node, addr, inbound), ("down", node).
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        if let Some(r) = self.read_end.lock().unwrap().as_ref() {
            let mut buf = [0u8; 4096];
            let mut r = r;
            while let Ok(n) = std::io::Read::read(&mut r, &mut buf) {
                if n == 0 {
                    break;
                }
            }
        }
        let events: Vec<Event> = self.shared.inbox.lock().unwrap().drain(..).collect();
        let out = PyList::empty_bound(py);
        for event in events {
            match event {
                Event::Txs { from, txs } => {
                    let items = PyList::empty_bound(py);
                    for t in txs {
                        let raw = PyBytes::new_bound(py, &t.raw);
                        let (hash, signed, verdict) = match t.checked {
                            Some((h, s, v)) => (
                                Some(h),
                                Some(PyBytes::new_bound(py, &s).into_any()),
                                v,
                            ),
                            None => (None, None, None),
                        };
                        items.append((raw, hash, signed, verdict, t.reason))?;
                    }
                    out.append(("txs", from, items))?;
                }
                Event::Block { from, raw } => {
                    out.append(("block", from, PyBytes::new_bound(py, &raw)))?
                }
                Event::Votes { from, votes } => {
                    let items = PyList::empty_bound(py);
                    for v in votes {
                        items.append(PyBytes::new_bound(py, &v))?;
                    }
                    out.append(("votes", from, items))?;
                }
                Event::BlockTxs { from, id, txs } => {
                    let items = PyList::empty_bound(py);
                    for t in txs {
                        match t {
                            Some(raw) => items.append(PyBytes::new_bound(py, &raw))?,
                            None => items.append(py.None())?,
                        }
                    }
                    out.append(("block_txs", from, id, items))?;
                }
                Event::Up {
                    node,
                    addr,
                    inbound,
                } => out.append(("up", node, addr, inbound))?,
                Event::Down { node } => out.append(("down", node))?,
            }
        }
        Ok(out)
    }

    /// Read and check transactions a wallet sent this node (the same as a peer's): for each,
    /// (hash | None, signed | None, verdict | None, reason | None). Duplicates come back with
    /// the reason "seen".
    fn check<'py>(
        &self,
        py: Python<'py>,
        raws: Vec<Vec<u8>>,
    ) -> PyResult<Vec<(Option<String>, Option<PyObject>, Option<bool>, Option<String>)>> {
        let shared = self.shared.clone();
        let results: Vec<(Option<([u8; 32], Vec<u8>, Option<bool>)>, Option<&'static str>)> = py
            .allow_threads(move || {
                raws.into_par_iter()
                    .map(|raw| match tx::read(&raw) {
                        tx::Read::Checked(c) => {
                            let verdict = c.verdict();
                            if verdict != Some(false) {
                                let raw = Arc::new(raw);
                                let mut memory = shared.memory.lock().unwrap();
                                memory.seen.insert(c.hash, ());
                                memory.pool.insert(c.hash, raw);
                            }
                            (Some((c.hash, c.signed, verdict)), None)
                        }
                        tx::Read::Python(why) => (None, Some(why)),
                        tx::Read::Malformed(why) => (None, Some(why)),
                    })
                    .collect()
            });
        Ok(results
            .into_iter()
            .map(|(checked, reason)| match checked {
                Some((h, s, v)) => (
                    Some(hex(&h)),
                    Some(PyBytes::new_bound(py, &s).into_any().unbind()),
                    v,
                    None,
                ),
                None => (None, None, None, reason.map(str::to_string)),
            })
            .collect())
    }

    /// Relay what Python admitted: (hash, raw | None, local, from | None). What a wallet sent
    /// this node (`local`) goes whole to every peer; what a peer sent is announced to the
    /// others. A raw not in the pool must be given.
    fn relay(&self, py: Python<'_>, items: &Bound<'_, PyList>) -> PyResult<()> {
        let mut keyed = Vec::with_capacity(items.len());
        for item in items.iter() {
            let (hash, raw, local, from): (String, Option<Bound<'_, PyAny>>, bool, Option<String>) =
                item.extract()?;
            let Some(key) = unhex32(&hash) else {
                return Err(PyValueError::new_err("a hash is 64 hex characters"));
            };
            let raw = raw.map(|r| bytes_of(&r)).transpose()?;
            keyed.push((key, raw, local, from));
        }
        let shared = self.shared.clone();
        py.allow_threads(move || {
            let mut whole: Vec<Arc<Vec<u8>>> = Vec::new();
            let mut announce: HashMap<Option<String>, Vec<[u8; 32]>> = HashMap::new();
            {
                let mut memory = shared.memory.lock().unwrap();
                for (key, raw, local, from) in keyed {
                    memory.seen.insert(key, ());
                    if let Some(raw) = raw {
                        memory.pool.insert(key, Arc::new(raw));
                    }
                    if local {
                        if let Some(raw) = memory.pool.get(&key) {
                            whole.push(raw.clone());
                        }
                    } else {
                        announce.entry(from).or_default().push(key);
                    }
                }
            }
            for message in pushes(&whole) {
                shared.send_all(&message, None);
            }
            for (from, hashes) in announce {
                for chunk in hashes.chunks(proto::MAX_HASHES) {
                    let message = proto::encode_hashes(proto::TX_ANNOUNCE, chunk);
                    let _ = shared.send_all(&message, from.as_deref());
                }
            }
        });
        Ok(())
    }

    /// The transactions the transport holds, by hash (None for one it does not): what a block
    /// rebuilt from its hashes reads before asking its sender for the rest. They may not be
    /// admitted yet; the block's import checks them as it checks any.
    fn lookup<'py>(&self, py: Python<'py>, hashes: Vec<String>) -> Vec<Option<Bound<'py, PyBytes>>> {
        let memory = self.shared.memory.lock().unwrap();
        hashes
            .iter()
            .map(|h| {
                let key = unhex32(h)?;
                memory.pool.get(&key).map(|raw| PyBytes::new_bound(py, raw))
            })
            .collect()
    }

    /// Send a block Python took (or proposed) to every peer but ``except``: the peers it was
    /// queued to (the rest are sent it over HTTP). Its copies coming back are set aside.
    #[pyo3(signature = (raw, except=None))]
    fn send_block(&self, raw: &Bound<'_, PyAny>, except: Option<String>) -> PyResult<Vec<String>> {
        let raw = bytes_of(raw)?;
        if raw.is_empty() || raw.len() > proto::MAX_BLOCK_BYTES {
            return Err(PyValueError::new_err("a block is 1 byte to 15 MiB"));
        }
        let key = *blake3::hash(&raw).as_bytes();
        self.shared.memory.lock().unwrap().blocks.insert(key, ());
        Ok(self
            .shared
            .send_all(&proto::encode_block(&raw), except.as_deref()))
    }

    /// Send votes Python took (or made) to every peer but ``except``: the peers they were
    /// queued to. Copies coming back are set aside.
    #[pyo3(signature = (raws, except=None))]
    fn send_votes(&self, raws: &Bound<'_, PyList>, except: Option<String>) -> PyResult<Vec<String>> {
        let raws: Vec<Vec<u8>> = raws.iter().map(|r| bytes_of(&r)).collect::<PyResult<_>>()?;
        if raws
            .iter()
            .any(|v| v.is_empty() || v.len() > proto::MAX_VOTE_BYTES)
        {
            return Err(PyValueError::new_err("a vote is 1 byte to 16 KiB"));
        }
        {
            let mut memory = self.shared.memory.lock().unwrap();
            for v in &raws {
                memory.votes.insert(*blake3::hash(v).as_bytes(), ());
            }
        }
        let mut sent = HashSet::new();
        for chunk in raws.chunks(proto::MAX_VOTES) {
            let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
            sent.extend(
                self.shared
                    .send_all(&proto::encode_votes(&refs), except.as_deref()),
            );
        }
        Ok(sent.into_iter().collect())
    }

    /// Ask ``node`` for operations of a block it sent, by hash (at most 1,024): the request's
    /// id, whose answer comes as a "block_txs" event — or None if the node is not connected.
    fn ask_block_txs(&self, node: &str, hashes: Vec<String>) -> PyResult<Option<u64>> {
        if hashes.is_empty() || hashes.len() > proto::MAX_BLOCK_TXS {
            return Err(PyValueError::new_err("1 to 1,024 hashes"));
        }
        let keys = hashes
            .iter()
            .map(|h| unhex32(h))
            .collect::<Option<Vec<[u8; 32]>>>()
            .ok_or_else(|| PyValueError::new_err("a hash is 64 hex characters"))?;
        if !self.shared.peers.lock().unwrap().contains_key(node) {
            return Ok(None);
        }
        let id = self.shared.next_conn.fetch_add(1, Ordering::Relaxed);
        {
            let mut memory = self.shared.memory.lock().unwrap();
            memory.prune_requests(Instant::now());
            memory
                .asked
                .insert(id, (node.to_string(), keys.len(), Instant::now()));
        }
        self.shared
            .send_to(node, proto::encode_block_txs_get(id, &keys));
        Ok(Some(id))
    }

    /// Hold operations to answer peers' requests for a block's (those of a block this node
    /// sends that its pool does not hold): (hash, raw).
    fn hold(&self, items: &Bound<'_, PyList>) -> PyResult<()> {
        let items: Vec<(String, Vec<u8>)> = items
            .iter()
            .map(|item| {
                let (hash, raw): (String, Bound<'_, PyAny>) = item.extract()?;
                Ok((hash, bytes_of(&raw)?))
            })
            .collect::<PyResult<_>>()?;
        let mut memory = self.shared.memory.lock().unwrap();
        for (hash, raw) in items {
            let key = unhex32(&hash).ok_or_else(|| PyValueError::new_err("a hash is 64 hex"))?;
            if !raw.is_empty() && raw.len() <= tx::MAX_TX_BYTES {
                memory.pool.insert(key, Arc::new(raw));
            }
        }
        Ok(())
    }

    /// Which of ``hashes`` the pool does not hold.
    fn missing(&self, hashes: Vec<String>) -> Vec<String> {
        let memory = self.shared.memory.lock().unwrap();
        hashes
            .into_iter()
            .filter(|h| unhex32(h).is_none_or(|k| !memory.pool.contains(&k)))
            .collect()
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = &self.shared.stats;
        let d = PyDict::new_bound(py);
        for (k, v) in [
            ("frames_in", &s.frames_in),
            ("frames_out", &s.frames_out),
            ("bytes_in", &s.bytes_in),
            ("bytes_out", &s.bytes_out),
            ("txs_in", &s.txs_in),
            ("txs_new", &s.txs_new),
            ("txs_invalid", &s.txs_invalid),
            ("dropped_out", &s.dropped_out),
            ("dropped_in", &s.dropped_in),
            ("handshakes_failed", &s.handshakes_failed),
            ("blocks_in", &s.blocks_in),
            ("blocks_new", &s.blocks_new),
            ("votes_in", &s.votes_in),
            ("votes_new", &s.votes_new),
        ] {
            d.set_item(k, v.load(Ordering::Relaxed))?;
        }
        d.set_item("peers", self.shared.peers.lock().unwrap().len())?;
        d.set_item("pool", self.shared.memory.lock().unwrap().pool.map.len())?;
        Ok(d)
    }

    /// Close every connection and stop listening.
    fn stop(&self) {
        let nodes: Vec<String> = self.shared.peers.lock().unwrap().keys().cloned().collect();
        for n in nodes {
            self.shared.disconnect(&n);
        }
        // (the runtime's tasks end when the service is dropped)
    }
}
