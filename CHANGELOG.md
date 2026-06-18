# CHANGELOG

W tym pliku zapisujemy ważniejsze zmiany w projekcie.

## Dodane

- Implementacja Crypto Core: Argon2id, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, zeroizacja kluczy (src/crypto.rs)
- Implementacja Format: parser i serializator nagłówka binarnego, CBOR body (src/format.rs)
- Implementacja Storage: atomowy zapis pliku, advisory lock (src/storage.rs)
- Implementacja CLI: parsowanie argumentów, komendy init/open/list/get/add/verify (src/cli.rs)
- Implementacja Record: schemat rekordów login/note/apikey/totp/sshkey (src/record.rs)
- Implementacja View: formatowanie listy i szczegółów rekordów (src/view.rs)
- Implementacja Clip: kopiowanie do schowka z auto-czyszczeniem po 30s (src/clip.rs)
- Implementacja Prompt: bezpieczne wczytywanie haseł bez echa (src/prompt.rs)
- Testy adwersarialne A1-A8 zgodnie z §9.4 specyfikacji (tests/adversarial_tests.rs)
- Szkielet testów integracyjnych E2E-1 do E2E-4 (tests/integration/)
- Wektory testowe v1 (testvectors/v1.json)
- Cele fuzzingu: header_parser, body_parser (fuzz/)
- Dokumentacja: SPEC.md, ARCHITECTURE.md, THREAT_MODEL.md, SECURITY.md
- ADR-001 do ADR-007: decyzje technologiczne
- Konfiguracja CI/CD (GitHub Actions)
- Implementacja vault init i vault open
- Testy integracyjne E2E
