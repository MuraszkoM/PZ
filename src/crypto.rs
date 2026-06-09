// Moduł kryptograficzny vaulta
// Autor: P
// Implementuje: Argon2id, HKDF, HMAC-SHA256, ChaCha20-Poly1305

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

// Stała kontekstowa do domain separation w HKDF
pub const CONTEXT: &[u8] = b"vault-v1";

// Parametry Argon2id zapisywane w nagłówku pliku
#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    // Domyślne parametry zgodne z OWASP: m=64MiB, t=3, p=1
    fn default() -> Self {
        Self {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

// Błędy kryptograficzne - celowo ogólne, żeby nie dawać atakującemu wskazówek
#[derive(Debug, PartialEq)]
pub enum CryptoError {
    Argon2Error,
    AeadError,
    HmacError,
    HkdfError,
}

// Wyprowadza master_key z hasła przez Argon2id
// Celowo wolny i pamięciożerny - utrudnia brute force
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<[u8; 32], CryptoError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::Argon2Error)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut master_key)
        .map_err(|_| CryptoError::Argon2Error)?;

    Ok(master_key)
}

// Wyprowadza wrap_key z master_key przez HKDF
// wrap_key służy tylko do opakowania DEK
pub fn derive_wrap_key(master_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut info = CONTEXT.to_vec();
    info.extend_from_slice(b"wrap-dek-key");
    hkdf_expand(master_key, &info)
}

// Wyprowadza header_mac_key z master_key przez HKDF
// header_mac_key służy tylko do obliczenia HMAC nagłówka
pub fn derive_header_mac_key(master_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut info = CONTEXT.to_vec();
    info.extend_from_slice(b"header-mac");
    hkdf_expand(master_key, &info)
}

fn hkdf_expand(ikm: &[u8; 32], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::HkdfError)?;
    Ok(okm)
}

// Oblicza HMAC-SHA256 - chroni nagłówek przed modyfikacją
pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC akceptuje klucze dowolnej długości");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// Weryfikuje HMAC w czasie stałym - zapobiega timing oracle
pub fn verify_hmac_sha256(key: &[u8; 32], data: &[u8], expected: &[u8; 32]) -> bool {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC akceptuje klucze dowolnej długości");
    mac.update(data);
    mac.verify_slice(expected.as_ref()).is_ok()
}

// Szyfruje dane - nonce musi być zawsze unikalny!
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadError)
}

// Deszyfruje i weryfikuje dane - błąd jeśli cokolwiek zostało zmienione
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: ciphertext, aad };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadError)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Testy Argon2id
    #[test]
    fn test_argon2id_deterministic() {
        let password = b"correct horse battery staple";
        let salt = [0u8; 16];
        let params = Argon2Params { memory_kib: 64, iterations: 1, parallelism: 1 };

        let key1 = derive_master_key(password, &salt, &params).unwrap();
        let key2 = derive_master_key(password, &salt, &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_passwords() {
        let salt = [0u8; 16];
        let params = Argon2Params { memory_kib: 64, iterations: 1, parallelism: 1 };

        let key1 = derive_master_key(b"password1", &salt, &params).unwrap();
        let key2 = derive_master_key(b"password2", &salt, &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_salts() {
        let params = Argon2Params { memory_kib: 64, iterations: 1, parallelism: 1 };
        let key1 = derive_master_key(b"password", &[0u8; 16], &params).unwrap();
        let key2 = derive_master_key(b"password", &[1u8; 16], &params).unwrap();
        assert_ne!(key1, key2);
    }

    // Wektor z RFC 5869 Appendix A.1
    #[test]
    fn test_hkdf_rfc5869_appendix_a1() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let ikm = [0x0bu8; 22];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).unwrap();

        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        ];
        assert_eq!(okm, expected);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let master_key = [0x42u8; 32];
        let wrap_key = derive_wrap_key(&master_key).unwrap();
        let mac_key = derive_header_mac_key(&master_key).unwrap();
        assert_ne!(wrap_key, mac_key);
    }

    // Wektor z RFC 4231 Test Case 1
    #[test]
    fn test_hmac_sha256_rfc4231_tc1() {
        let key_bytes = [0x0bu8; 20];
        let data = b"Hi There";

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key_bytes).unwrap();
        mac.update(data);
        let result: [u8; 32] = mac.finalize().into_bytes().into();

        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_verify_correct() {
        let key = [0x42u8; 32];
        let data = b"test header data";
        let mac = hmac_sha256(&key, data);
        assert!(verify_hmac_sha256(&key, data, &mac));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let mac = hmac_sha256(&[0x42u8; 32], b"data");
        assert!(!verify_hmac_sha256(&[0x43u8; 32], b"data", &mac));
    }

    #[test]
    fn test_hmac_verify_tampered_data() {
        let key = [0x42u8; 32];
        let mac = hmac_sha256(&key, b"original header");
        assert!(!verify_hmac_sha256(&key, b"tampered header", &mac));
    }

    // Wektor z RFC 8439 §2.8.2
    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
                          If I could offer you only one tip for the future, \
                          sunscreen would be it.";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, &aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = aead_decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aead_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let ciphertext = aead_encrypt(&key, &nonce, b"secret", b"correct aad").unwrap();
        let result = aead_decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert_eq!(result, Err(CryptoError::AeadError));
    }

    #[test]
    fn test_aead_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let mut ciphertext = aead_encrypt(&key, &nonce, b"secret data", b"aad").unwrap();
        ciphertext[0] ^= 0x01;
        let result = aead_decrypt(&key, &nonce, &ciphertext, b"aad");
        assert_eq!(result, Err(CryptoError::AeadError));
    }

    #[test]
    fn test_aead_truncated_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let ciphertext = aead_encrypt(&key, &nonce, b"secret data", b"aad").unwrap();
        let truncated = &ciphertext[..ciphertext.len() / 2];
        let result = aead_decrypt(&key, &nonce, truncated, b"aad");
        assert_eq!(result, Err(CryptoError::AeadError));
    }

    #[test]
    fn test_zeroize_works() {
        let mut master_key = [0xffu8; 32];
        master_key.zeroize();
        assert_eq!(master_key, [0u8; 32]);
    }
}