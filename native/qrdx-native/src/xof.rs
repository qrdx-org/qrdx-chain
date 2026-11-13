//! BLAKE3's extendable output for LtHash entries, eight output blocks at a time (src/lthash.rs).
//!
//! An LtHash entry is 4,096 bytes of BLAKE3 output over a short input (a tag, a length, a digest
//! or a row: one chunk). The ``blake3`` crate writes long outputs several blocks at a time only
//! with AVX-512; elsewhere each 64-byte block is one compression after another — 64 of them an
//! entry, about 3.3 µs, which was most of every commitment's cost (the exchange's collections,
//! the store's domains). Each output block is the same compression of the input's root node
//! with its own counter, so eight of them are eight lanes of one AVX2 computation.
//!
//! ``fill4096`` returns exactly what ``blake3::Hasher::finalize_xof().fill`` returns for the same
//! input (tests below, and tests/test_native.py through the accumulators): the root node by a
//! portable compression, the output by AVX2 where the CPU has it; an input past one chunk (1,024
//! bytes), or a CPU without AVX2, goes to the crate. The compression follows the BLAKE3
//! specification; the vector form follows the crate's ``rust_avx2.rs`` (CC0 / Apache-2.0).

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const ROOT: u32 = 8;
const BLOCK: usize = 64;
const CHUNK: usize = 1024;
pub const OUT: usize = 4096;

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// The compression function: the state after seven rounds (before the output's xors).
fn rounds(cv: &[u32; 8], m: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    let mut v = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3],
        counter as u32, (counter >> 32) as u32, block_len, flags,
    ];
    for s in MSG_SCHEDULE.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    v
}

fn words(block: &[u8; BLOCK]) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    m
}

/// The root node of a one-chunk input: (its chaining value, its last block's words, the block's
/// length, its flags).
fn root_node(input: &[u8]) -> ([u32; 8], [u32; 16], u32, u32) {
    let blocks = input.len().div_ceil(BLOCK).max(1);
    let mut cv = IV;
    for i in 0..blocks - 1 {
        let block: &[u8; BLOCK] = input[i * BLOCK..(i + 1) * BLOCK].try_into().expect("a block");
        let flags = if i == 0 { CHUNK_START } else { 0 };
        let v = rounds(&cv, &words(block), 0, BLOCK as u32, flags);
        for j in 0..8 {
            cv[j] = v[j] ^ v[j + 8];
        }
    }
    let last = &input[(blocks - 1) * BLOCK..];
    let mut block = [0u8; BLOCK];
    block[..last.len()].copy_from_slice(last);
    let flags = CHUNK_END | ROOT | if blocks == 1 { CHUNK_START } else { 0 };
    (cv, words(&block), last.len() as u32, flags)
}

/// Output block ``t`` of the root node, portably.
fn output_block(node: &([u32; 8], [u32; 16], u32, u32), t: u64, out: &mut [u8]) {
    let (cv, m, len, flags) = node;
    let v = rounds(cv, m, t, *len, *flags);
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&(v[i] ^ v[i + 8]).to_le_bytes());
        out[32 + 4 * i..32 + 4 * i + 4].copy_from_slice(&(v[i + 8] ^ cv[i]).to_le_bytes());
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use std::arch::x86_64::*;

    use super::{IV, MSG_SCHEDULE};

    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        _mm256_add_epi32(a, b)
    }
    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        _mm256_xor_si256(a, b)
    }
    #[inline(always)]
    unsafe fn set1(x: u32) -> __m256i {
        _mm256_set1_epi32(x as i32)
    }
    #[inline(always)]
    unsafe fn rot<const R: i32, const L: i32>(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x))
    }
    #[inline(always)]
    unsafe fn g(v: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize, x: __m256i, y: __m256i) {
        v[a] = add(add(v[a], v[b]), x);
        v[d] = rot::<16, 16>(xor(v[d], v[a]));
        v[c] = add(v[c], v[d]);
        v[b] = rot::<12, 20>(xor(v[b], v[c]));
        v[a] = add(add(v[a], v[b]), y);
        v[d] = rot::<8, 24>(xor(v[d], v[a]));
        v[c] = add(v[c], v[d]);
        v[b] = rot::<7, 25>(xor(v[b], v[c]));
    }

    #[inline(always)]
    unsafe fn transpose(vecs: &mut [__m256i; 8]) {
        let ab_0145 = _mm256_unpacklo_epi32(vecs[0], vecs[1]);
        let ab_2367 = _mm256_unpackhi_epi32(vecs[0], vecs[1]);
        let cd_0145 = _mm256_unpacklo_epi32(vecs[2], vecs[3]);
        let cd_2367 = _mm256_unpackhi_epi32(vecs[2], vecs[3]);
        let ef_0145 = _mm256_unpacklo_epi32(vecs[4], vecs[5]);
        let ef_2367 = _mm256_unpackhi_epi32(vecs[4], vecs[5]);
        let gh_0145 = _mm256_unpacklo_epi32(vecs[6], vecs[7]);
        let gh_2367 = _mm256_unpackhi_epi32(vecs[6], vecs[7]);
        let abcd_04 = _mm256_unpacklo_epi64(ab_0145, cd_0145);
        let abcd_15 = _mm256_unpackhi_epi64(ab_0145, cd_0145);
        let abcd_26 = _mm256_unpacklo_epi64(ab_2367, cd_2367);
        let abcd_37 = _mm256_unpackhi_epi64(ab_2367, cd_2367);
        let efgh_04 = _mm256_unpacklo_epi64(ef_0145, gh_0145);
        let efgh_15 = _mm256_unpackhi_epi64(ef_0145, gh_0145);
        let efgh_26 = _mm256_unpacklo_epi64(ef_2367, gh_2367);
        let efgh_37 = _mm256_unpackhi_epi64(ef_2367, gh_2367);
        vecs[0] = _mm256_permute2x128_si256::<0x20>(abcd_04, efgh_04);
        vecs[4] = _mm256_permute2x128_si256::<0x31>(abcd_04, efgh_04);
        vecs[1] = _mm256_permute2x128_si256::<0x20>(abcd_15, efgh_15);
        vecs[5] = _mm256_permute2x128_si256::<0x31>(abcd_15, efgh_15);
        vecs[2] = _mm256_permute2x128_si256::<0x20>(abcd_26, efgh_26);
        vecs[6] = _mm256_permute2x128_si256::<0x31>(abcd_26, efgh_26);
        vecs[3] = _mm256_permute2x128_si256::<0x20>(abcd_37, efgh_37);
        vecs[7] = _mm256_permute2x128_si256::<0x31>(abcd_37, efgh_37);
    }

    /// Output blocks ``t .. t + 8`` of the root node, into ``out`` (512 bytes).
    #[target_feature(enable = "avx2")]
    pub unsafe fn output8(cv: &[u32; 8], m: &[u32; 16], len: u32, flags: u32, t: u64, out: &mut [u8]) {
        debug_assert!(out.len() >= 512);
        let mut msg = [set1(0); 16];
        for (i, w) in msg.iter_mut().enumerate() {
            *w = set1(m[i]);
        }
        let lo = |k: u64| (t + k) as u32;
        let hi = |k: u64| ((t + k) >> 32) as u32;
        let mut v = [
            set1(cv[0]), set1(cv[1]), set1(cv[2]), set1(cv[3]),
            set1(cv[4]), set1(cv[5]), set1(cv[6]), set1(cv[7]),
            set1(IV[0]), set1(IV[1]), set1(IV[2]), set1(IV[3]),
            _mm256_setr_epi32(lo(0) as i32, lo(1) as i32, lo(2) as i32, lo(3) as i32,
                              lo(4) as i32, lo(5) as i32, lo(6) as i32, lo(7) as i32),
            _mm256_setr_epi32(hi(0) as i32, hi(1) as i32, hi(2) as i32, hi(3) as i32,
                              hi(4) as i32, hi(5) as i32, hi(6) as i32, hi(7) as i32),
            set1(len), set1(flags),
        ];
        for s in MSG_SCHEDULE.iter() {
            g(&mut v, 0, 4, 8, 12, msg[s[0]], msg[s[1]]);
            g(&mut v, 1, 5, 9, 13, msg[s[2]], msg[s[3]]);
            g(&mut v, 2, 6, 10, 14, msg[s[4]], msg[s[5]]);
            g(&mut v, 3, 7, 11, 15, msg[s[6]], msg[s[7]]);
            g(&mut v, 0, 5, 10, 15, msg[s[8]], msg[s[9]]);
            g(&mut v, 1, 6, 11, 12, msg[s[10]], msg[s[11]]);
            g(&mut v, 2, 7, 8, 13, msg[s[12]], msg[s[13]]);
            g(&mut v, 3, 4, 9, 14, msg[s[14]], msg[s[15]]);
        }
        let mut first = [set1(0); 8];
        let mut second = [set1(0); 8];
        for i in 0..8 {
            first[i] = xor(v[i], v[i + 8]);
            second[i] = xor(v[i + 8], set1(cv[i]));
        }
        transpose(&mut first);
        transpose(&mut second);
        let p = out.as_mut_ptr();
        for j in 0..8 {
            _mm256_storeu_si256(p.add(64 * j) as *mut __m256i, first[j]);
            _mm256_storeu_si256(p.add(64 * j + 32) as *mut __m256i, second[j]);
        }
    }

    /// ``output8``, each output word's low 16 bits added into ``total`` (wrapping) at its own
    /// position — LtHash's entry — instead of written out: ``total`` holds the 16 lanes of
    /// each of the blocks ``t .. t + 8`` from ``16·t``.
    #[target_feature(enable = "avx2")]
    pub unsafe fn add8(cv: &[u32; 8], m: &[u32; 16], len: u32, flags: u32, t: u64, total: &mut [u16]) {
        debug_assert!(total.len() >= 16 * (t as usize + 8));
        let mut words = [0u8; 512];
        output8(cv, m, len, flags, t, &mut words);
        let low = _mm256_set1_epi32(0xFFFF);
        let p = words.as_ptr();
        let q = total.as_mut_ptr().add(16 * t as usize);
        for j in 0..8 {
            let a = _mm256_and_si256(_mm256_loadu_si256(p.add(64 * j) as *const __m256i), low);
            let b = _mm256_and_si256(_mm256_loadu_si256(p.add(64 * j + 32) as *const __m256i), low);
            // (packed per 128-bit half: a0-3 b0-3 | a4-7 b4-7, put back in order)
            let packed = _mm256_permute4x64_epi64::<0b11_01_10_00>(_mm256_packus_epi32(a, b));
            let at = q.add(16 * j) as *mut __m256i;
            _mm256_storeu_si256(at, _mm256_add_epi16(_mm256_loadu_si256(at), packed));
        }
    }
}

fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::sync::OnceLock;
        static AVX2: OnceLock<bool> = OnceLock::new();
        *AVX2.get_or_init(|| std::is_x86_feature_detected!("avx2"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// 4,096 bytes of BLAKE3 output over ``parts`` concatenated, as ``blake3`` writes them.
pub fn fill4096(parts: &[&[u8]], out: &mut [u8; OUT]) {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total > CHUNK || !has_avx2() {
        let mut h = blake3::Hasher::new();
        for p in parts {
            h.update(p);
        }
        h.finalize_xof().fill(out);
        return;
    }
    let mut input = [0u8; CHUNK];
    let mut at = 0;
    for p in parts {
        input[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    let node = root_node(&input[..at]);
    #[cfg(target_arch = "x86_64")]
    {
        let (cv, m, len, flags) = &node;
        for t in (0..(OUT / BLOCK) as u64).step_by(8) {
            // SAFETY: AVX2 is present (checked above); ``out`` holds 512 bytes from 64·t.
            unsafe { avx2::output8(cv, m, *len, *flags, t, &mut out[64 * t as usize..]) };
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    for t in 0..(OUT / BLOCK) as u64 {
        output_block(&node, t, &mut out[64 * t as usize..64 * (t as usize + 1)]);
    }
}

/// LtHash's entry of ``parts`` concatenated: the low 16 bits of each little-endian u32 of
/// ``fill4096``'s output, added into ``total`` lane by lane (wrapping).
pub fn add4096(parts: &[&[u8]], total: &mut [u16; OUT / 4]) {
    let size: usize = parts.iter().map(|p| p.len()).sum();
    #[cfg(target_arch = "x86_64")]
    if size <= CHUNK && has_avx2() {
        let mut input = [0u8; CHUNK];
        let mut at = 0;
        for p in parts {
            input[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        let (cv, m, len, flags) = root_node(&input[..at]);
        for t in (0..(OUT / BLOCK) as u64).step_by(8) {
            // SAFETY: AVX2 is present; ``total`` holds 16 lanes for each of the 64 blocks.
            unsafe { avx2::add8(&cv, &m, len, flags, t, &mut total[..]) };
        }
        return;
    }
    let _ = size;
    let mut out = [0u8; OUT];
    fill4096(parts, &mut out);
    for (t, word) in total.iter_mut().zip(out.chunks_exact(4)) {
        *t = t.wrapping_add(u16::from_le_bytes([word[0], word[1]]));
    }
}

/// ``fill4096`` with every block computed portably (the tests' second reference).
#[allow(dead_code)]
pub fn fill4096_portable(input: &[u8], out: &mut [u8; OUT]) {
    let node = root_node(input);
    for t in 0..(OUT / BLOCK) as u64 {
        output_block(&node, t, &mut out[64 * t as usize..64 * (t as usize + 1)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_xof(input: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; OUT];
        let mut h = blake3::Hasher::new();
        h.update(input);
        h.finalize_xof().fill(&mut out);
        out
    }

    #[test]
    fn an_entry_added_is_its_output_words_low_halves() {
        let data: Vec<u8> = (0..1100u32).map(|i| (i * 17 + 3) as u8).collect();
        for len in [0, 1, 36, 63, 64, 65, 100, 1024, 1025, 1100] {
            let mut total = [0u16; OUT / 4];
            for (i, t) in total.iter_mut().enumerate() {
                *t = (i as u16).wrapping_mul(40503);
            }
            let mut want = total;
            let out = crate_xof(&data[..len]);
            for (t, word) in want.iter_mut().zip(out.chunks_exact(4)) {
                *t = t.wrapping_add(u16::from_le_bytes([word[0], word[1]]));
            }
            add4096(&[&data[..len]], &mut total);
            assert_eq!(total, want, "length {len}");
        }
    }

    #[test]
    fn every_length_of_a_chunk_is_blake3s() {
        let data: Vec<u8> = (0..1100u32).map(|i| (i * 31 + 7) as u8).collect();
        for len in (0..=1100).filter(|n| *n <= 200 || n % 37 == 0 || *n >= 1020) {
            let want = crate_xof(&data[..len]);
            let mut got = [0u8; OUT];
            fill4096(&[&data[..len / 3], &data[len / 3..len]], &mut got);
            assert_eq!(&got[..], &want[..], "length {len}");
            if len <= CHUNK {
                let mut portable = [0u8; OUT];
                fill4096_portable(&data[..len], &mut portable);
                assert_eq!(&portable[..], &want[..], "length {len} (portable)");
            }
        }
    }
}
