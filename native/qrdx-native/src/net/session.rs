//! A peer connection's handshake and its encrypted frames (docs/NETWORK.md).
//!
//! The handshake authenticates both nodes by their node keys (ML-DSA-65, the keys their node
//! ids derive from) and agrees a session key by ML-KEM-768, over everything both sides sent:
//!
//! ```text
//! initiator → responder   M1 = magic, chain id, genesis, node key, KEM key, nonce
//! responder → initiator   M2 = magic, chain id, genesis, node key, KEM ciphertext, nonce,
//!                              signature over ("responder", M1, M2 so far)
//! initiator → responder   M3 = signature over ("initiator", M1, M2)
//! ```
//!
//! Both sides refuse another chain (chain id and genesis), and the keys come from
//! HKDF-SHA256(KEM secret, salt = SHA-256(M1 ‖ M2)), one a direction. A KEM key is made for each
//! connection, so a key later stolen does not open recorded sessions.
//!
//! Each frame after it is `length ‖ ChaCha20-Poly1305(counter, message)`, the counter one a
//! frame and a direction: a frame changed, replayed, dropped or reordered fails to open, and
//! the connection closes.

use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::oqs;

const MAGIC: &[u8; 8] = b"QRDXP2P1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKE_MESSAGE: usize = 16 * 1024;
/// The largest frame either side sends or accepts (a compact block is far smaller; a push of
/// transactions is cut below it).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub struct Identity {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Clone)]
pub struct Chain {
    pub chain_id: u64,
    pub genesis: [u8; 32],
}

pub fn node_id(public_key: &[u8]) -> String {
    let h = blake3::hash(public_key);
    let mut out = String::from("qx");
    for b in &h.as_bytes()[..20] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub struct Sender {
    half: OwnedWriteHalf,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

pub struct Receiver {
    half: OwnedReadHalf,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

pub struct Established {
    pub peer_node_id: String,
    pub sender: Sender,
    pub receiver: Receiver,
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

impl Sender {
    pub async fn send(&mut self, message: &[u8]) -> std::io::Result<()> {
        let sealed = self
            .cipher
            .encrypt(&nonce(self.counter), message)
            .map_err(|_| std::io::Error::other("seal failed"))?;
        if sealed.len() > MAX_FRAME {
            return Err(std::io::Error::other("frame too large"));
        }
        self.counter += 1;
        self.half.write_u32(sealed.len() as u32).await?;
        self.half.write_all(&sealed).await?;
        Ok(())
    }
}

impl Receiver {
    pub async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.half.read_u32().await? as usize;
        if len > MAX_FRAME || len < 16 {
            return Err(std::io::Error::other("bad frame length"));
        }
        let mut sealed = vec![0u8; len];
        self.half.read_exact(&mut sealed).await?;
        let opened = self
            .cipher
            .decrypt(&nonce(self.counter), sealed.as_slice())
            .map_err(|_| std::io::Error::other("frame failed to open"))?;
        self.counter += 1;
        Ok(opened)
    }
}

async fn write_msg(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    stream.write_u32(msg.len() as u32).await?;
    stream.write_all(msg).await
}

async fn read_msg(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    if len > MAX_HANDSHAKE_MESSAGE {
        return Err(std::io::Error::other("handshake message too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the OS random source");
    b
}

fn transcript(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qrdx-p2p-v1/");
    h.update(label);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn keys(shared: &[u8], m1: &[u8], m2: &[u8]) -> ([u8; 32], [u8; 32]) {
    let salt = transcript(b"keys", &[m1, m2]);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut i2r = [0u8; 32];
    let mut r2i = [0u8; 32];
    hk.expand(b"qrdx-p2p-v1 initiator to responder", &mut i2r)
        .expect("32 bytes is a valid HKDF length");
    hk.expand(b"qrdx-p2p-v1 responder to initiator", &mut r2i)
        .expect("32 bytes is a valid HKDF length");
    (i2r, r2i)
}

struct Header<'a> {
    node_key: &'a [u8],
    rest: &'a [u8],
}

fn check_header<'a>(msg: &'a [u8], chain: &Chain) -> std::io::Result<Header<'a>> {
    let head = 8 + 8 + 32 + oqs::DSA_PUBLIC_KEY_LEN;
    if msg.len() < head || &msg[..8] != MAGIC {
        return Err(std::io::Error::other("not a QRDX peer"));
    }
    let chain_id = u64::from_be_bytes(msg[8..16].try_into().expect("8 bytes"));
    if chain_id != chain.chain_id || msg[16..48] != chain.genesis {
        return Err(std::io::Error::other("another chain"));
    }
    Ok(Header {
        node_key: &msg[48..head],
        rest: &msg[head..],
    })
}

fn header(chain: &Chain, me: &Identity) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 8 + 32 + oqs::DSA_PUBLIC_KEY_LEN + 4096);
    m.extend_from_slice(MAGIC);
    m.extend_from_slice(&chain.chain_id.to_be_bytes());
    m.extend_from_slice(&chain.genesis);
    m.extend_from_slice(&me.public_key);
    m
}

fn split(stream: TcpStream, peer_key: &[u8], send_key: [u8; 32], recv_key: [u8; 32]) -> Established {
    let (r, w) = stream.into_split();
    Established {
        peer_node_id: node_id(peer_key),
        sender: Sender {
            half: w,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&send_key)),
            counter: 0,
        },
        receiver: Receiver {
            half: r,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&recv_key)),
            counter: 0,
        },
    }
}

/// Dial side.
pub async fn initiate(
    mut stream: TcpStream,
    me: &Identity,
    chain: &Chain,
) -> std::io::Result<Established> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        stream.set_nodelay(true)?;
        let (kem_pk, kem_sk) = oqs::kem_keypair().ok_or_else(|| std::io::Error::other("KEM"))?;
        let mut m1 = header(chain, me);
        m1.extend_from_slice(&kem_pk);
        m1.extend_from_slice(&random32());
        write_msg(&mut stream, &m1).await?;

        let m2 = read_msg(&mut stream).await?;
        let h = check_header(&m2, chain)?;
        let body = oqs::KEM_CIPHERTEXT_LEN + 32 + oqs::DSA_SIGNATURE_LEN;
        if h.rest.len() != body {
            return Err(std::io::Error::other("malformed handshake"));
        }
        let ct = &h.rest[..oqs::KEM_CIPHERTEXT_LEN];
        let unsigned = &m2[..m2.len() - oqs::DSA_SIGNATURE_LEN];
        let sig = &m2[m2.len() - oqs::DSA_SIGNATURE_LEN..];
        if h.node_key == me.public_key.as_slice() {
            return Err(std::io::Error::other("a connection to itself"));
        }
        if !oqs::dsa_verify(h.node_key, &transcript(b"responder", &[&m1, unsigned]), sig) {
            return Err(std::io::Error::other("the responder's proof does not verify"));
        }
        let shared = oqs::kem_decaps(&kem_sk, ct).ok_or_else(|| std::io::Error::other("KEM"))?;
        let proof = oqs::dsa_sign(&me.secret_key, &transcript(b"initiator", &[&m1, &m2]))
            .ok_or_else(|| std::io::Error::other("signing failed"))?;
        write_msg(&mut stream, &proof).await?;
        let (i2r, r2i) = keys(&shared, &m1, &m2);
        let peer_key = h.node_key.to_vec();
        Ok(split(stream, &peer_key, i2r, r2i))
    })
    .await
    .map_err(|_| std::io::Error::other("handshake timed out"))?
}

/// Accept side. `admit` is asked about the node the dialer claims to be before any work is done
/// for it (a signature, a KEM): a node this one did not admit costs it one read.
pub async fn respond(
    mut stream: TcpStream,
    me: &Identity,
    chain: &Chain,
    admit: impl Fn(&str) -> bool,
) -> std::io::Result<Established> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        stream.set_nodelay(true)?;
        let m1 = read_msg(&mut stream).await?;
        let h = check_header(&m1, chain)?;
        if h.rest.len() != oqs::KEM_PUBLIC_KEY_LEN + 32 {
            return Err(std::io::Error::other("malformed handshake"));
        }
        if h.node_key == me.public_key.as_slice() {
            return Err(std::io::Error::other("a connection to itself"));
        }
        if !admit(&node_id(h.node_key)) {
            return Err(std::io::Error::other("a node this one did not admit"));
        }
        let peer_key = h.node_key.to_vec();
        let kem_pk = &h.rest[..oqs::KEM_PUBLIC_KEY_LEN];
        let (ct, shared) = oqs::kem_encaps(kem_pk).ok_or_else(|| std::io::Error::other("KEM"))?;
        let mut m2 = header(chain, me);
        m2.extend_from_slice(&ct);
        m2.extend_from_slice(&random32());
        let proof = oqs::dsa_sign(&me.secret_key, &transcript(b"responder", &[&m1, &m2]))
            .ok_or_else(|| std::io::Error::other("signing failed"))?;
        m2.extend_from_slice(&proof);
        write_msg(&mut stream, &m2).await?;

        let m3 = read_msg(&mut stream).await?;
        if m3.len() != oqs::DSA_SIGNATURE_LEN
            || !oqs::dsa_verify(&peer_key, &transcript(b"initiator", &[&m1, &m2]), &m3)
        {
            return Err(std::io::Error::other("the initiator's proof does not verify"));
        }
        let (i2r, r2i) = keys(&shared, &m1, &m2);
        Ok(split(stream, &peer_key, r2i, i2r))
    })
    .await
    .map_err(|_| std::io::Error::other("handshake timed out"))?
}
