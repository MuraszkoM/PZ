// Testy adwersarialne – scenariusze z modelu zagrożeń (§9.4)
// Każdy test generuje zmodyfikowany plik vault i sprawdza że vault open zwraca błąd.

#[cfg(test)]
mod adversarial {
    use vault::crypto::{
        compute_header_mac, decrypt_body, derive_keys, derive_master_key, encrypt_body, unwrap_dek,
        wrap_dek, Dek, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, KEY_LEN,
        NONCE_LEN,
    };
    use vault::format::{
        KdfParams, VaultHeader, AEAD_ID_CHACHA20_POLY1305, HEADER_MAC_LEN, KDF_ID_ARGON2ID,
        KDF_SALT_LEN, NONCE_BODY_LEN, NONCE_DEK_LEN, VERSION, WRAPPED_DEK_LEN,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SALT: [u8; KDF_SALT_LEN] = [0u8; KDF_SALT_LEN];
    const NONCE_DEK: [u8; NONCE_DEK_LEN] = [1u8; NONCE_DEK_LEN];
    const NONCE_BODY: [u8; NONCE_BODY_LEN] = [2u8; NONCE_BODY_LEN];

    // Tworzy poprawny zaszyfrowany plik vault w pamięci
    fn make_vault_bytes() -> Vec<u8> {
        let mk = derive_master_key(
            PASSWORD,
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let dek = Dek::from_bytes([42u8; KEY_LEN]);
        let wrapped_dek = wrap_dek(&keys.wrap_key, &NONCE_DEK, &dek).unwrap();

        let mut header = VaultHeader {
            version: VERSION,
            flags: 0,
            kdf_id: KDF_ID_ARGON2ID,
            kdf_params: KdfParams::default_v1(),
            kdf_salt: SALT,
            aead_id: AEAD_ID_CHACHA20_POLY1305,
            nonce_dek: NONCE_DEK,
            wrapped_dek,
            header_mac: [0u8; HEADER_MAC_LEN],
            nonce_body: NONCE_BODY,
        };

        let canonical = header.serialize_canonical();
        let mac = compute_header_mac(&keys.header_mac_key, &canonical);
        header.header_mac = mac;

        let full_header = header.serialize_full();
        let aad = full_header.clone();
        let body_cbor = b"test body";
        let ct_body = encrypt_body(&dek, &NONCE_BODY, body_cbor, &aad).unwrap();

        let mut file = full_header;
        file.extend_from_slice(&ct_body);
        file
    }

    // A1 — Modyfikacja bajtu w body
    #[test]
    fn a1_modified_body_byte() {
        let mut file = make_vault_bytes();
        // ct_body zaczyna się po 144 bajtach nagłówka
        file[144] ^= 0xFF;
        let ct_body = &file[144..];
        let aad = &file[..144];
        let dek = Dek::from_bytes([42u8; KEY_LEN]);
        let result = decrypt_body(&dek, &NONCE_BODY, ct_body, aad);
        assert!(result.is_err(), "A1: zmodyfikowane body powinno dać błąd");
    }

    // A2 — Modyfikacja parametrów KDF (kdf_iterations na offset 13)
    #[test]
    fn a2_modified_kdf_iterations() {
        let mut file = make_vault_bytes();
        // kdf_iterations jest na offsetach 13-16 (big-endian u32)
        file[13] ^= 0xFF;
        let mk = derive_master_key(
            PASSWORD,
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let canonical = &file[..100];
        let stored_mac = &file[100..132];
        let result = vault::crypto::verify_header_mac(&keys.header_mac_key, canonical, stored_mac);
        assert!(
            result.is_err(),
            "A2: zmieniony nagłówek powinien dać błąd HMAC"
        );
    }

    // A3 — Podmiana aead_id (offset 35)
    #[test]
    fn a3_modified_aead_id() {
        let mut file = make_vault_bytes();
        file[35] = 0x63; // zmiana aead_id na 99
        let mk = derive_master_key(
            PASSWORD,
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let canonical = &file[..100];
        let stored_mac = &file[100..132];
        let result = vault::crypto::verify_header_mac(&keys.header_mac_key, canonical, stored_mac);
        assert!(
            result.is_err(),
            "A3: zmieniony aead_id powinien dać błąd HMAC"
        );
    }

    // A4 — Podmiana wrapped DEK (offsety 52-99)
    #[test]
    fn a4_replaced_wrapped_dek() {
        let mut file = make_vault_bytes();
        for b in &mut file[52..100] {
            *b = 0xAB;
        }
        let mk = derive_master_key(
            PASSWORD,
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys = derive_keys(&mk).unwrap();
        let canonical = &file[..100];
        let stored_mac = &file[100..132];
        let result = vault::crypto::verify_header_mac(&keys.header_mac_key, canonical, stored_mac);
        assert!(
            result.is_err(),
            "A4: podmieniony wrapped_dek powinien dać błąd HMAC"
        );
    }

    // A5 — Brute force cost
    #[test]
    fn a5_brute_force_cost() {
        let start = std::time::Instant::now();
        derive_master_key(
            b"password123",
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() >= 100,
            "A5: Argon2id powinien trwać >= 100ms, było {}ms",
            elapsed.as_millis()
        );
        println!(
            "A5: Argon2id zajął {}ms — ~{:.2} prób/s",
            elapsed.as_millis(),
            1000.0 / elapsed.as_millis() as f64
        );
    }

    // A6 — Stare hasło po changepass (symulacja przez inne hasło)
    #[test]
    fn a6_old_password_after_changepass() {
        let file = make_vault_bytes();
        // Próba otwarcia z innym hasłem — inny master_key → inny wrap_key → błąd
        let mk_wrong = derive_master_key(
            b"stare_haslo",
            &SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        let keys_wrong = derive_keys(&mk_wrong).unwrap();
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = file[52..100].try_into().unwrap();
        let result = unwrap_dek(&keys_wrong.wrap_key, &NONCE_DEK, &wrapped_dek);
        assert!(
            result.is_err(),
            "A6: stare hasło nie powinno otworzyć vault po changepass"
        );
    }

    // A7 — Truncation pliku
    #[test]
    fn a7_truncated_file() {
        let file = make_vault_bytes();
        let truncated = &file[..file.len() / 2];
        let ct_body = &truncated[144.min(truncated.len())..];
        let aad = &file[..144];
        let dek = Dek::from_bytes([42u8; KEY_LEN]);
        let result = decrypt_body(&dek, &NONCE_BODY, ct_body, aad);
        assert!(result.is_err(), "A7: ucięty plik powinien dać błąd");
    }

    // A8 — Plik pusty / błędny magic
    #[test]
    fn a8_empty_file() {
        let result = vault::format::parse_header(&[]);
        assert!(result.is_err(), "A8: pusty plik powinien dać błąd");
    }

    #[test]
    fn a8_wrong_magic() {
        let mut file = make_vault_bytes();
        file[0] = b'X';
        let result = vault::format::parse_header(&file);
        assert!(result.is_err(), "A8: błędny magic powinien dać błąd");
    }
}
