//! liboqs, linked from the system library the Python node uses (build.rs): ML-DSA-65 for
//! signatures, ML-KEM-768 for the peer transport's session keys.

use std::os::raw::c_int;
use std::sync::Once;

pub const DSA_PUBLIC_KEY_LEN: usize = 1952;
pub const DSA_SECRET_KEY_LEN: usize = 4032;
pub const DSA_SIGNATURE_LEN: usize = 3309;
pub const KEM_PUBLIC_KEY_LEN: usize = 1184;
pub const KEM_SECRET_KEY_LEN: usize = 2400;
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
pub const KEM_SHARED_SECRET_LEN: usize = 32;

extern "C" {
    fn OQS_init();
    fn OQS_SIG_ml_dsa_65_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> c_int;
    fn OQS_SIG_ml_dsa_65_sign(
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> c_int;
    fn OQS_SIG_ml_dsa_65_keypair(public_key: *mut u8, secret_key: *mut u8) -> c_int;
    fn OQS_KEM_ml_kem_768_keypair(public_key: *mut u8, secret_key: *mut u8) -> c_int;
    fn OQS_KEM_ml_kem_768_encaps(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> c_int;
    fn OQS_KEM_ml_kem_768_decaps(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> c_int;
}

static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| unsafe { OQS_init() });
}

/// Whether `signature` is a valid ML-DSA-65 signature of `message` under `public_key`.
pub fn dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    init();
    // liboqs reads a public key of its fixed length from the pointer it is given.
    if public_key.len() != DSA_PUBLIC_KEY_LEN || signature.len() != DSA_SIGNATURE_LEN {
        return false;
    }
    // SAFETY: the lengths are checked above; liboqs reads only within them.
    unsafe {
        OQS_SIG_ml_dsa_65_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
        ) == 0
    }
}

pub fn dsa_sign(secret_key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    init();
    if secret_key.len() != DSA_SECRET_KEY_LEN {
        return None;
    }
    let mut signature = vec![0u8; DSA_SIGNATURE_LEN];
    let mut len = 0usize;
    // SAFETY: the buffers have the lengths liboqs writes and reads.
    let status = unsafe {
        OQS_SIG_ml_dsa_65_sign(
            signature.as_mut_ptr(),
            &mut len,
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
        )
    };
    if status != 0 || len != DSA_SIGNATURE_LEN {
        return None;
    }
    Some(signature)
}

pub fn dsa_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
    init();
    let mut pk = vec![0u8; DSA_PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; DSA_SECRET_KEY_LEN];
    // SAFETY: the buffers have the lengths liboqs writes.
    let status = unsafe { OQS_SIG_ml_dsa_65_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    (status == 0).then_some((pk, sk))
}

pub fn kem_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
    init();
    let mut pk = vec![0u8; KEM_PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; KEM_SECRET_KEY_LEN];
    // SAFETY: the buffers have the lengths liboqs writes.
    let status = unsafe { OQS_KEM_ml_kem_768_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    (status == 0).then_some((pk, sk))
}

/// (ciphertext, shared secret) for `public_key`.
pub fn kem_encaps(public_key: &[u8]) -> Option<(Vec<u8>, [u8; KEM_SHARED_SECRET_LEN])> {
    init();
    if public_key.len() != KEM_PUBLIC_KEY_LEN {
        return None;
    }
    let mut ct = vec![0u8; KEM_CIPHERTEXT_LEN];
    let mut ss = [0u8; KEM_SHARED_SECRET_LEN];
    // SAFETY: the lengths are checked and the buffers sized as liboqs requires.
    let status =
        unsafe { OQS_KEM_ml_kem_768_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), public_key.as_ptr()) };
    (status == 0).then_some((ct, ss))
}

pub fn kem_decaps(secret_key: &[u8], ciphertext: &[u8]) -> Option<[u8; KEM_SHARED_SECRET_LEN]> {
    init();
    if secret_key.len() != KEM_SECRET_KEY_LEN || ciphertext.len() != KEM_CIPHERTEXT_LEN {
        return None;
    }
    let mut ss = [0u8; KEM_SHARED_SECRET_LEN];
    // SAFETY: the lengths are checked and the buffers sized as liboqs requires.
    let status = unsafe {
        OQS_KEM_ml_kem_768_decaps(ss.as_mut_ptr(), ciphertext.as_ptr(), secret_key.as_ptr())
    };
    (status == 0).then_some(ss)
}
