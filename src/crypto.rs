// crypto.rs — moduł kryptograficzny vault v1
//
// Implementuje całą hierarchię kluczy i operacje kryptograficzne zgodnie ze SPEC.md:
//   - Argon2id (KDF z hasła, §4)
//   - HKDF-SHA256 (wyprowadzenie wrap_key i header_mac_key, §4)
//   - HMAC-SHA256 (integralność nagłówka, §6)
//   - ChaCha20-Poly1305 (szyfrowanie AEAD: wrapped DEK §7, body §8)
//   - Zeroizacja kluczy po użyciu (NF-11)
//
// Stała kontekstowa (SPEC §3):
//   CONTEXT = "vault-v1"
//
// Hierarchia kluczy (SPEC §4):
//   master_key     = Argon2id(password, kdf_salt, params)
//   wrap_key       = HKDF(master_key, info = "vault-v1" || "wrap-dek-key")
//   header_mac_key = HKDF(master_key, info = "vault-v1" || "header-mac")
//
// Autor: Bartosz Palicki (crypto core)

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Stałe ───────────────────────────────────────────────────────────────────

/// Stała kontekstowa (SPEC §3)
const CONTEXT: &[u8] = b"vault-v1";

/// Rozmiar master_key, wrap_key, header_mac_key i DEK — zawsze 32 bajty
pub const KEY_LEN: usize = 32;

/// Rozmiar nonce dla ChaCha20-Poly1305 — 12 bajtów
pub const NONCE_LEN: usize = 12;

/// Rozmiar tagu AEAD (Poly1305) — 16 bajtów
pub const AEAD_TAG_LEN: usize = 16;

/// Rozmiar wrapped DEK: 32 B DEK + 16 B tag = 48 B (SPEC §7)
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + AEAD_TAG_LEN;

/// Rozmiar HMAC-SHA256 — 32 bajty
pub const HMAC_LEN: usize = 32;

/// Domyślne parametry Argon2id (SPEC §3, NF-02)
pub const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;

// ─── Typy kluczy z zeroizacją ────────────────────────────────────────────────

/// Klucz główny wyprowadzony z hasła przez Argon2id.
/// Zeroizowany automatycznie przy Drop (NF-11).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Klucz do opakowania DEK (wrap_key).
/// Zeroizowany automatycznie przy Drop (NF-11).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrapKey([u8; KEY_LEN]);

/// Klucz do HMAC nagłówka (header_mac_key).
/// Zeroizowany automatycznie przy Drop (NF-11).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HeaderMacKey([u8; KEY_LEN]);

/// DEK (Data Encryption Key) — losowy klucz szyfrowania body.
/// Zeroizowany automatycznie przy Drop (NF-11).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; KEY_LEN]);

impl Dek {
    /// Tworzy DEK z surowych bajtów (np. po rozpakowaniu z pliku).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Dek(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Błędy operacji kryptograficznych.
#[derive(Debug)]
pub enum CryptoError {
    /// Argon2id nie mógł wyprowadzić klucza (nieprawidłowe parametry)
    Argon2Error,
    /// Szyfrowanie AEAD się nie powiodło
    AeadEncryptError,
    /// Deszyfrowanie AEAD się nie powiodło — złe hasło lub uszkodzony plik
    AeadDecryptError,
    /// HMAC nie zgadza się — nagłówek zmieniony lub złe hasło
    HmacMismatch,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Argon2Error => write!(f, "błąd wyprowadzenia klucza Argon2id"),
            CryptoError::AeadEncryptError => write!(f, "błąd szyfrowania AEAD"),
            CryptoError::AeadDecryptError => write!(f, "ERR_BAD_PASSWORD_OR_CORRUPTED"),
            CryptoError::HmacMismatch => write!(f, "ERR_BAD_PASSWORD_OR_CORRUPTED"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ─── 1. KDF z hasła — Argon2id ───────────────────────────────────────────────

/// Wyprowadza master_key z hasła i soli przez Argon2id (SPEC §4).
///
/// Parametry zgodne z SPEC §3 i NF-02:
///   m = 65536 KiB (64 MiB), t = 3, p = 1
///
/// # Błędy
/// Zwraca `CryptoError::Argon2Error` jeśli parametry są nieprawidłowe
/// (w praktyce nie powinno się zdarzyć przy stałych parametrach).
pub fn derive_master_key(
    password: &[u8],
    kdf_salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<MasterKey, CryptoError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))
        .map_err(|_| CryptoError::Argon2Error)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, kdf_salt, &mut key)
        .map_err(|_| CryptoError::Argon2Error)?;

    Ok(MasterKey(key))
}

// ─── 2. Wyprowadzenie kluczy pochodnych — HKDF-SHA256 ────────────────────────

/// Struktura przechowująca klucze pochodne wyprowadzone z master_key.
/// Zeroizowane automatycznie przy Drop.
pub struct DerivedKeys {
    pub wrap_key: WrapKey,
    pub header_mac_key: HeaderMacKey,
}

impl Zeroize for DerivedKeys {
    fn zeroize(&mut self) {
        self.wrap_key.zeroize();
        self.header_mac_key.zeroize();
    }
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Wyprowadza wrap_key i header_mac_key z master_key przez HKDF-SHA256 (SPEC §4).
///
/// info dla kluczy:
///   wrap_key:       CONTEXT || "wrap-dek-key"
///   header_mac_key: CONTEXT || "header-mac"
pub fn derive_keys(master_key: &MasterKey) -> Result<DerivedKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key.as_bytes());

    // wrap_key = HKDF(master_key, info = "vault-v1wrap-dek-key")
    let mut wrap_key_bytes = [0u8; KEY_LEN];
    let wrap_info: Vec<u8> = [CONTEXT, b"wrap-dek-key"].concat();
    hkdf.expand(&wrap_info, &mut wrap_key_bytes)
        .map_err(|_| CryptoError::Argon2Error)?;

    // header_mac_key = HKDF(master_key, info = "vault-v1header-mac")
    let mut header_mac_key_bytes = [0u8; KEY_LEN];
    let mac_info: Vec<u8> = [CONTEXT, b"header-mac"].concat();
    hkdf.expand(&mac_info, &mut header_mac_key_bytes)
        .map_err(|_| CryptoError::Argon2Error)?;

    Ok(DerivedKeys {
        wrap_key: WrapKey(wrap_key_bytes),
        header_mac_key: HeaderMacKey(header_mac_key_bytes),
    })
}

// ─── 3. HMAC nagłówka ────────────────────────────────────────────────────────

/// Oblicza HMAC-SHA256 canonical headera (bajty 0..100) (SPEC §6).
///
/// canonical_header to pierwsze 100 bajtów pliku (bez header_mac).
pub fn compute_header_mac(
    header_mac_key: &HeaderMacKey,
    canonical_header: &[u8],
) -> [u8; HMAC_LEN] {
    let mut mac =
<Hmac<Sha256> as KeyInit>::new_from_slice(&header_mac_key.0)
            .expect("HMAC akceptuje każdy rozmiar klucza");
    mac.update(canonical_header);    let result = mac.finalize().into_bytes();
    result.into()
}

/// Weryfikuje HMAC nagłówka w czasie stałym (SPEC §6, S-2).
///
/// Zwraca `CryptoError::HmacMismatch` jeśli MAC się nie zgadza.
/// Używa stałoczasowego porównania żeby nie tworzyć timing oracle.
pub fn verify_header_mac(
    header_mac_key: &HeaderMacKey,
    canonical_header: &[u8],
    expected_mac: &[u8],
) -> Result<(), CryptoError> {
    let mut mac =
<Hmac<Sha256> as KeyInit>::new_from_slice(&header_mac_key.0)
            .expect("HMAC akceptuje każdy rozmiar klucza");    mac.update(canonical_header);
    mac.verify_slice(expected_mac)
        .map_err(|_| CryptoError::HmacMismatch)
}

// ─── 4. Opakowanie DEK (wrap/unwrap) ─────────────────────────────────────────

/// Opakowuje DEK przez ChaCha20-Poly1305 (SPEC §7).
///
/// wrapped_dek = AEAD.encrypt(
///     key   = wrap_key,
///     nonce = nonce_dek,
///     plaintext = DEK,
///     aad   = CONTEXT || "wrap-dek"
/// )
///
/// Wynik: 48 bajtów (32 B ciphertext + 16 B tag).
pub fn wrap_dek(
    wrap_key: &WrapKey,
    nonce_dek: &[u8; NONCE_LEN],
    dek: &Dek,
) -> Result<[u8; WRAPPED_DEK_LEN], CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&wrap_key.0)
        .map_err(|_| CryptoError::AeadEncryptError)?;

    let nonce = Nonce::from_slice(nonce_dek);
    let aad: Vec<u8> = [CONTEXT, b"wrap-dek"].concat();

    let payload = Payload {
        msg: dek.as_bytes(),
        aad: &aad,
    };

    let ct = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadEncryptError)?;

    // ct ma dokładnie 48 bajtów (32 + 16)
    let mut result = [0u8; WRAPPED_DEK_LEN];
    result.copy_from_slice(&ct);
    Ok(result)
}

/// Rozpakowuje DEK z wrapped_dek (SPEC §7).
///
/// Zwraca `CryptoError::AeadDecryptError` jeśli tag nie pasuje
/// (złe hasło lub uszkodzony plik) — komunikat ERR_BAD_PASSWORD_OR_CORRUPTED.
pub fn unwrap_dek(
    wrap_key: &WrapKey,
    nonce_dek: &[u8; NONCE_LEN],
    wrapped_dek: &[u8; WRAPPED_DEK_LEN],
) -> Result<Dek, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&wrap_key.0)
        .map_err(|_| CryptoError::AeadDecryptError)?;

    let nonce = Nonce::from_slice(nonce_dek);
    let aad: Vec<u8> = [CONTEXT, b"wrap-dek"].concat();

    let payload = Payload {
        msg: wrapped_dek.as_slice(),
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadDecryptError)?;

    let mut dek_bytes = [0u8; KEY_LEN];
    dek_bytes.copy_from_slice(&plaintext);
    Ok(Dek::from_bytes(dek_bytes))
}

// ─── 5. Szyfrowanie body ─────────────────────────────────────────────────────

/// Szyfruje body CBOR przez ChaCha20-Poly1305 (SPEC §8).
///
/// aad = canonical_header || header_mac (pierwsze 132 bajty pliku)
///
/// ct_body = AEAD.encrypt(
///     key   = DEK,
///     nonce = nonce_body,
///     plaintext = body_cbor,
///     aad   = aad_body
/// )
pub fn encrypt_body(
    dek: &Dek,
    nonce_body: &[u8; NONCE_LEN],
    body_cbor: &[u8],
    aad_body: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes())
        .map_err(|_| CryptoError::AeadEncryptError)?;

    let nonce = Nonce::from_slice(nonce_body);

    let payload = Payload {
        msg: body_cbor,
        aad: aad_body,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadEncryptError)
}

/// Deszyfruje ct_body przez ChaCha20-Poly1305 (SPEC §8).
///
/// Zwraca `CryptoError::AeadDecryptError` jeśli tag nie pasuje.
pub fn decrypt_body(
    dek: &Dek,
    nonce_body: &[u8; NONCE_LEN],
    ct_body: &[u8],
    aad_body: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes())
        .map_err(|_| CryptoError::AeadDecryptError)?;

    let nonce = Nonce::from_slice(nonce_body);

    let payload = Payload {
        msg: ct_body,
        aad: aad_body,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadDecryptError)
}

// ─── Testy jednostkowe ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Pomocnicze dane testowe — używamy zerowych soli/nonce żeby testy były deterministyczne
    fn test_password() -> &'static [u8] {
        b"correct horse battery staple"
    }

    fn test_salt() -> [u8; 16] {
        [0u8; 16]
    }

    fn test_nonce() -> [u8; NONCE_LEN] {
        [0u8; NONCE_LEN]
    }

    // ── Argon2id ──────────────────────────────────────────────────────────────

    #[test]
    fn derive_master_key_returns_32_bytes() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_eq!(mk.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_master_key_is_deterministic() {
        let mk1 = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let mk2 = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn derive_master_key_different_password_gives_different_key() {
        let mk1 = derive_master_key(
            b"haslo1",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let mk2 = derive_master_key(
            b"haslo2",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn derive_master_key_different_salt_gives_different_key() {
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];
        let mk1 = derive_master_key(
            test_password(),
            &salt1,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let mk2 = derive_master_key(
            test_password(),
            &salt2,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    // ── HKDF ─────────────────────────────────────────────────────────────────

    #[test]
    fn derive_keys_produces_different_wrap_and_mac_keys() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        // wrap_key i header_mac_key muszą być różne (różne info)
        assert_ne!(keys.wrap_key.0, keys.header_mac_key.0);
    }

    #[test]
    fn derive_keys_is_deterministic() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys1 = derive_keys(&mk).unwrap();
        let keys2 = derive_keys(&mk).unwrap();
        assert_eq!(keys1.wrap_key.0, keys2.wrap_key.0);
        assert_eq!(keys1.header_mac_key.0, keys2.header_mac_key.0);
    }

    // ── HMAC ─────────────────────────────────────────────────────────────────

    #[test]
    fn hmac_verify_correct_mac_passes() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let canonical = vec![0u8; 100];
        let mac = compute_header_mac(&keys.header_mac_key, &canonical);
        assert!(verify_header_mac(&keys.header_mac_key, &canonical, &mac).is_ok());
    }

    #[test]
    fn hmac_verify_tampered_header_fails() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let canonical = vec![0u8; 100];
        let mac = compute_header_mac(&keys.header_mac_key, &canonical);

        // Zmieniamy jeden bajt nagłówka — MAC powinien nie pasować
        let mut tampered = canonical.clone();
        tampered[0] ^= 0xFF;
        assert!(verify_header_mac(&keys.header_mac_key, &tampered, &mac).is_err());
    }

    #[test]
    fn hmac_verify_wrong_key_fails() {
        let mk1 = derive_master_key(
            b"haslo1",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let mk2 = derive_master_key(
            b"haslo2",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys1 = derive_keys(&mk1).unwrap();
        let keys2 = derive_keys(&mk2).unwrap();
        let canonical = vec![0u8; 100];
        let mac = compute_header_mac(&keys1.header_mac_key, &canonical);
        // Weryfikacja innym kluczem musi się nie udać
        assert!(verify_header_mac(&keys2.header_mac_key, &canonical, &mac).is_err());
    }

    // ── Wrap / Unwrap DEK ────────────────────────────────────────────────────

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let dek = Dek::from_bytes([42u8; KEY_LEN]);
        let nonce = test_nonce();

        let wrapped = wrap_dek(&keys.wrap_key, &nonce, &dek).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_DEK_LEN);

        let unwrapped = unwrap_dek(&keys.wrap_key, &nonce, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn unwrap_dek_wrong_key_fails() {
        let mk1 = derive_master_key(
            b"haslo1",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let mk2 = derive_master_key(
            b"haslo2",
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys1 = derive_keys(&mk1).unwrap();
        let keys2 = derive_keys(&mk2).unwrap();
        let dek = Dek::from_bytes([99u8; KEY_LEN]);
        let nonce = test_nonce();

        let wrapped = wrap_dek(&keys1.wrap_key, &nonce, &dek).unwrap();
        // Próba rozpakowania złym kluczem musi się nie udać (S-1)
        assert!(unwrap_dek(&keys2.wrap_key, &nonce, &wrapped).is_err());
    }

    #[test]
    fn unwrap_dek_tampered_ciphertext_fails() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let dek = Dek::from_bytes([7u8; KEY_LEN]);
        let nonce = test_nonce();

        let mut wrapped = wrap_dek(&keys.wrap_key, &nonce, &dek).unwrap();
        // Modyfikacja jednego bajtu ciphertextu — tag nie może pasować (A1)
        wrapped[0] ^= 0xFF;
        assert!(unwrap_dek(&keys.wrap_key, &nonce, &wrapped).is_err());
    }

    // ── Szyfrowanie/deszyfrowanie body ────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_body_roundtrip() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let dek_raw = Dek::from_bytes([11u8; KEY_LEN]);

        // Najpierw wrapujemy DEK żeby mieć prawdziwy DEK do body
        let nonce_dek = test_nonce();
        let wrapped = wrap_dek(&keys.wrap_key, &nonce_dek, &dek_raw).unwrap();
        let dek = unwrap_dek(&keys.wrap_key, &nonce_dek, &wrapped).unwrap();

        let body = b"test body CBOR data";
        let aad = vec![0u8; 132]; // canonical_header || header_mac
        let nonce_body = [1u8; NONCE_LEN];

        let ct = encrypt_body(&dek, &nonce_body, body, &aad).unwrap();
        let pt = decrypt_body(&dek, &nonce_body, &ct, &aad).unwrap();
        assert_eq!(pt, body);
    }

    #[test]
    fn decrypt_body_tampered_ciphertext_fails() {
        let dek = Dek::from_bytes([55u8; KEY_LEN]);
        let body = b"tajne dane";
        let aad = vec![0u8; 132];
        let nonce = [2u8; NONCE_LEN];

        let mut ct = encrypt_body(&dek, &nonce, body, &aad).unwrap();
        ct[0] ^= 0xFF; // Modyfikacja ciphertextu (A1)
        assert!(decrypt_body(&dek, &nonce, &ct, &aad).is_err());
    }

    #[test]
    fn decrypt_body_wrong_aad_fails() {
        let dek = Dek::from_bytes([33u8; KEY_LEN]);
        let body = b"tajne dane body";
        let aad_ok = vec![0u8; 132];
        let aad_bad = vec![1u8; 132]; // Zmieniony nagłówek (A2, A3 — downgrade resistance)
        let nonce = [3u8; NONCE_LEN];

        let ct = encrypt_body(&dek, &nonce, body, &aad_ok).unwrap();
        // Zmiana AAD (nagłówka) musi spowodować błąd deszyfrowania (S-3)
        assert!(decrypt_body(&dek, &nonce, &ct, &aad_bad).is_err());
    }

    #[test]
    fn decrypt_body_truncated_ciphertext_fails() {
        let dek = Dek::from_bytes([77u8; KEY_LEN]);
        let body = b"dane do uciecia";
        let aad = vec![0u8; 132];
        let nonce = [4u8; NONCE_LEN];

        let ct = encrypt_body(&dek, &nonce, body, &aad).unwrap();
        // Ucięcie ciphertextu (A7)
        let truncated = &ct[..ct.len() / 2];
        assert!(decrypt_body(&dek, &nonce, truncated, &aad).is_err());
    }

    #[test]
    fn wrapped_dek_has_correct_length() {
        let mk = derive_master_key(
            test_password(),
            &test_salt(),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let dek = Dek::from_bytes([0u8; KEY_LEN]);
        let nonce = test_nonce();
        let wrapped = wrap_dek(&keys.wrap_key, &nonce, &dek).unwrap();
        // SPEC §7: wrapped_dek = 32 B DEK + 16 B tag = 48 B
        assert_eq!(wrapped.len(), WRAPPED_DEK_LEN);
        assert_eq!(WRAPPED_DEK_LEN, 48);
    }
}