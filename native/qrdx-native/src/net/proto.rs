//! What peers send each other inside a session's frames: a type byte, then its fields, every
//! count and length bounded before anything is allocated.

use crate::tx::MAX_TX_BYTES;

pub const TX_PUSH: u8 = 1;
pub const TX_ANNOUNCE: u8 = 2;
pub const TX_GET: u8 = 3;
pub const BLOCK: u8 = 4;
pub const VOTES: u8 = 5;
pub const BLOCK_TXS_GET: u8 = 6;
pub const BLOCK_TXS: u8 = 7;
pub const PING: u8 = 16;
pub const PONG: u8 = 17;

/// The most transactions one push carries, and hashes one announcement or request.
pub const MAX_PUSH: usize = 4096;
pub const MAX_HASHES: usize = 16384;
/// A block as it travels (compact: its exchange operations named by hash; whole only to a peer
/// that could not rebuild it): within a frame.
pub const MAX_BLOCK_BYTES: usize = 15 * 1024 * 1024;
/// Votes (attestations, each a signature and its fields) a message carries, and one's size.
pub const MAX_VOTES: usize = 1024;
pub const MAX_VOTE_BYTES: usize = 16 * 1024;
/// Transactions one request for a block's operations names.
pub const MAX_BLOCK_TXS: usize = 1024;

pub enum Message {
    Push(Vec<Vec<u8>>),
    Announce(Vec<[u8; 32]>),
    Get(Vec<[u8; 32]>),
    Block(Vec<u8>),
    Votes(Vec<Vec<u8>>),
    /// (request id, hashes): a block's operations, asked of the peer that sent the block.
    BlockTxsGet(u64, Vec<[u8; 32]>),
    /// (request id, each operation or None where the peer does not hold it).
    BlockTxs(u64, Vec<Option<Vec<u8>>>),
    Ping(u64),
    Pong,
}

pub fn encode_push(txs: &[&[u8]]) -> Vec<u8> {
    let size: usize = txs.iter().map(|t| 4 + t.len()).sum();
    let mut m = Vec::with_capacity(5 + size);
    m.push(TX_PUSH);
    m.extend_from_slice(&(txs.len() as u32).to_be_bytes());
    for t in txs {
        m.extend_from_slice(&(t.len() as u32).to_be_bytes());
        m.extend_from_slice(t);
    }
    m
}

pub fn encode_hashes(kind: u8, hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut m = Vec::with_capacity(5 + 32 * hashes.len());
    m.push(kind);
    m.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    for h in hashes {
        m.extend_from_slice(h);
    }
    m
}

/// A list of byte strings: a count, then (length, bytes) each.
fn put_list(m: &mut Vec<u8>, items: &[&[u8]]) {
    m.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for t in items {
        m.extend_from_slice(&(t.len() as u32).to_be_bytes());
        m.extend_from_slice(t);
    }
}

pub fn encode_block(block: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(5 + block.len());
    m.push(BLOCK);
    m.extend_from_slice(&(block.len() as u32).to_be_bytes());
    m.extend_from_slice(block);
    m
}

pub fn encode_votes(votes: &[&[u8]]) -> Vec<u8> {
    let mut m = Vec::with_capacity(5 + votes.iter().map(|v| 4 + v.len()).sum::<usize>());
    m.push(VOTES);
    put_list(&mut m, votes);
    m
}

pub fn encode_block_txs_get(id: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut m = Vec::with_capacity(13 + 32 * hashes.len());
    m.push(BLOCK_TXS_GET);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    for h in hashes {
        m.extend_from_slice(h);
    }
    m
}

/// An answer: each operation, or an empty string for one not held (no operation is empty).
pub fn encode_block_txs(id: u64, txs: &[Option<&[u8]>]) -> Vec<u8> {
    let items: Vec<&[u8]> = txs.iter().map(|t| t.unwrap_or(&[])).collect();
    let mut m = Vec::with_capacity(13 + items.iter().map(|t| 4 + t.len()).sum::<usize>());
    m.push(BLOCK_TXS);
    m.extend_from_slice(&id.to_be_bytes());
    put_list(&mut m, &items);
    m
}

pub fn encode_ping(kind: u8, value: u64) -> Vec<u8> {
    let mut m = vec![kind];
    m.extend_from_slice(&value.to_be_bytes());
    m
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.buf.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    fn done(&self) -> bool {
        self.at == self.buf.len()
    }
}

/// The message in a frame, or None if it is malformed (the sender is misbehaving).
pub fn decode(frame: &[u8]) -> Option<Message> {
    let (&kind, rest) = frame.split_first()?;
    let mut c = Cursor { buf: rest, at: 0 };
    let message = match kind {
        TX_PUSH => {
            let n = c.u32()?;
            if n > MAX_PUSH {
                return None;
            }
            let mut txs = Vec::with_capacity(n.min(c.remaining() / 4));
            for _ in 0..n {
                let len = c.u32()?;
                if len > MAX_TX_BYTES {
                    return None;
                }
                txs.push(c.take(len)?.to_vec());
            }
            Message::Push(txs)
        }
        TX_ANNOUNCE | TX_GET => {
            let n = c.u32()?;
            if n > MAX_HASHES {
                return None;
            }
            let mut hashes = Vec::with_capacity(n.min(c.remaining() / 32));
            for _ in 0..n {
                hashes.push(c.take(32)?.try_into().ok()?);
            }
            if kind == TX_ANNOUNCE {
                Message::Announce(hashes)
            } else {
                Message::Get(hashes)
            }
        }
        BLOCK => {
            let len = c.u32()?;
            if len == 0 || len > MAX_BLOCK_BYTES {
                return None;
            }
            Message::Block(c.take(len)?.to_vec())
        }
        VOTES => {
            let n = c.u32()?;
            if n == 0 || n > MAX_VOTES {
                return None;
            }
            let mut votes = Vec::with_capacity(n.min(c.remaining() / 4));
            for _ in 0..n {
                let len = c.u32()?;
                if len == 0 || len > MAX_VOTE_BYTES {
                    return None;
                }
                votes.push(c.take(len)?.to_vec());
            }
            Message::Votes(votes)
        }
        BLOCK_TXS_GET => {
            let id = c.u64()?;
            let n = c.u32()?;
            if n > MAX_BLOCK_TXS {
                return None;
            }
            let mut hashes = Vec::with_capacity(n.min(c.remaining() / 32));
            for _ in 0..n {
                hashes.push(c.take(32)?.try_into().ok()?);
            }
            Message::BlockTxsGet(id, hashes)
        }
        BLOCK_TXS => {
            let id = c.u64()?;
            let n = c.u32()?;
            if n > MAX_BLOCK_TXS {
                return None;
            }
            let mut txs = Vec::with_capacity(n.min(c.remaining() / 4));
            for _ in 0..n {
                let len = c.u32()?;
                if len > MAX_TX_BYTES {
                    return None;
                }
                txs.push(if len == 0 { None } else { Some(c.take(len)?.to_vec()) });
            }
            Message::BlockTxs(id, txs)
        }
        PING => Message::Ping(c.u64()?),
        PONG => {
            c.u64()?;
            Message::Pong
        }
        _ => return None,
    };
    c.done().then_some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_votes_and_block_txs_round_trip() {
        match decode(&encode_block(b"{\"id\":1}")) {
            Some(Message::Block(b)) => assert_eq!(b, b"{\"id\":1}"),
            _ => panic!("a block"),
        }
        match decode(&encode_votes(&[b"a", b"bc"])) {
            Some(Message::Votes(v)) => assert_eq!(v, vec![b"a".to_vec(), b"bc".to_vec()]),
            _ => panic!("votes"),
        }
        let h = [[7u8; 32], [9u8; 32]];
        match decode(&encode_block_txs_get(42, &h)) {
            Some(Message::BlockTxsGet(42, got)) => assert_eq!(got, h.to_vec()),
            _ => panic!("a request"),
        }
        match decode(&encode_block_txs(42, &[Some(b"tx"), None])) {
            Some(Message::BlockTxs(42, got)) => assert_eq!(got, vec![Some(b"tx".to_vec()), None]),
            _ => panic!("an answer"),
        }
    }

    #[test]
    fn what_is_out_of_bounds_or_short_is_malformed() {
        assert!(decode(&encode_block(b"")).is_none()); // (an empty block)
        assert!(decode(&encode_votes(&[])).is_none()); // (no votes)
        assert!(decode(&encode_votes(&[b""])).is_none()); // (an empty vote)
        let big = vec![b'x'; MAX_VOTE_BYTES + 1];
        assert!(decode(&encode_votes(&[&big])).is_none());
        let many: Vec<[u8; 32]> = vec![[1u8; 32]; MAX_BLOCK_TXS + 1];
        assert!(decode(&encode_block_txs_get(1, &many)).is_none());
        let mut short = encode_block(b"abcdef");
        short.truncate(short.len() - 1);
        assert!(decode(&short).is_none());
        let mut extra = encode_block_txs(1, &[Some(b"tx")]);
        extra.push(0);
        assert!(decode(&extra).is_none());
        let mut lying = vec![BLOCK];
        lying.extend_from_slice(&((MAX_BLOCK_BYTES + 1) as u32).to_be_bytes());
        assert!(decode(&lying).is_none());
    }
}
