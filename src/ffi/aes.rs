use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use sha2::{Digest, Sha256};
use std::slice;

#[no_mangle]
pub extern "C" fn sha256_digest(data_ptr: *const u8, data_len: usize, hash_ptr: *mut u8) {
    // Ensure the data_ptr and hash_ptr are valid pointers from the caller
    if data_ptr.is_null() || hash_ptr.is_null() {
        return;
    }

    // Convert the raw pointers into Rust slices for safety
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let hash_slice = unsafe { slice::from_raw_parts_mut(hash_ptr, 32) };

    // Create a SHA-256 hasher instance and hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Copy the result into the provided hash_ptr buffer
    hash_slice.copy_from_slice(&result);
}

#[no_mangle]
pub extern "C" fn aes256gcm_encrypt(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ciphertext_ptr: *mut u8,
    ciphertext_len: usize,
) {
    assert!(key_len == 32);
    let key: &[u8] = unsafe {
        slice::from_raw_parts(key_ptr, key_len)
    };
    assert!(nonce_len == 12);
    let nonce: &[u8] = unsafe {
        slice::from_raw_parts(nonce_ptr, nonce_len)
    };

    // Check CT size (we pre-allocate it to avoid heap-allocations cross FFI)
    assert!(ciphertext_len == plaintext_len + nonce_len + 16);
    let plaintext: &[u8] = unsafe {
        slice::from_raw_parts(plaintext_ptr, plaintext_len)
    };
    let ciphertext: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(ciphertext_ptr, ciphertext_len)
    };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher.encrypt(nonce.into(), plaintext).unwrap();
    assert!(ct.len() == ciphertext_len - 12);

    // Copy into out buffer
    ciphertext[..12].copy_from_slice(nonce);
    ciphertext[12..12 + ct.len()].copy_from_slice(&ct);
}

#[no_mangle]
pub extern "C" fn aes256gcm_decrypt(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    plaintext_ptr: *mut u8,
    plaintext_len: usize,
) {
    assert!(key_len == 32);
    let key: &[u8] = unsafe {
        slice::from_raw_parts(key_ptr, key_len)
    };
    assert!(nonce_len == 12);
    let nonce: &[u8] = unsafe {
        slice::from_raw_parts(nonce_ptr, nonce_len)
    };

    // Check CT size (we pre-allocate it to avoid heap-allocations cross FFI,
    // but we already separate CT and Nonce in the caller)
    assert!(ciphertext_len == plaintext_len + 16);
    let ciphertext: &[u8] = unsafe {
        slice::from_raw_parts(ciphertext_ptr, ciphertext_len)
    };
    let plaintext: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(plaintext_ptr, plaintext_len)
    };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let pt = cipher.decrypt(nonce.into(), ciphertext).unwrap();
    assert!(pt.len() == plaintext_len);

    // Copy into out buffer
    plaintext[..pt.len()].copy_from_slice(&pt);
}
