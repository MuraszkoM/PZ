# Vault — bezpieczny menedżer sekretów

Projekt zespołowy — Kierunek: Kryptologia i Cyberbezpieczeństwo, Edycja 2025/26.

Celem projektu jest implementacja narzędzia CLI `vault` służącego do przechowywania sekretów użytkownika w jednym pliku zaszyfrowanym hasłem głównym.

## Jak zbudować

Wymagania:
- Rust 1.75+ (https://rustup.rs)
- Windows x86_64 / Linux x86_64 / macOS arm64

    git clone https://github.com/MuraszkoM/PZ.git
    cd PZ
    cargo build --release

Binarka zostanie zbudowana w `target/release/vault.exe` (Windows) lub `target/release/vault` (Linux/macOS).

## Jak uruchomić

    vault init moje_sekrety.vlt
    vault add login
    vault list
    vault get <id|nazwa>
    vault verify moje_sekrety.vlt
    vault verify moje_sekrety.vlt --with-password
    vault changepass

## Zakres MVP

- `vault init <plik>` — tworzy nowy vault
- `vault open <plik>` — otwiera vault
- `vault add login` — dodaje rekord login
- `vault list` — wyświetla listę rekordów
- `vault get <id|nazwa>` — pokazuje rekord
- `vault changepass` — zmienia hasło główne
- `vault verify <plik> [--with-password]` — weryfikuje plik
- Format pliku vault (SPEC.md)
- Argon2id, ChaCha20-Poly1305, HMAC-SHA256
- Key wrapping (dwuwarstwowa hierarchia kluczy)
- Atomowy zapis pliku
- Testy adwersarialne A1-A8
- CI/CD

## Technologia

Język implementacji: Rust.

Główne biblioteki:
- `argon2` — KDF z hasła
- `chacha20poly1305` — szyfrowanie AEAD
- `hmac`, `sha2`, `hkdf` — integralność i wyprowadzanie kluczy
- `zeroize` — zerowanie kluczy w pamięci
- `ciborium` — serializacja CBOR
- `clap` — parser argumentów CLI
- `uuid` — identyfikatory rekordów
- `rpassword` — bezpieczne wczytywanie haseł

## Struktura repozytorium

    src/                        kod główny
    tests/adversarial_tests.rs  testy bezpieczeństwa (A1-A8)
    tests/integration/          testy integracyjne E2E
    tests/regressions/          testy regresyjne
    fuzz/                       cele fuzzingu
    testvectors/                wektory testowe
    docs/                       dokumentacja techniczna i ADR
    .github/workflows/          konfiguracja CI

## Dokumentacja

- [Specyfikacja formatu](docs/SPEC.md)
- [Architektura](docs/ARCHITECTURE.md)
- [Model zagrożeń](THREAT_MODEL.md)
- [Bezpieczeństwo](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Zespół

| Imię | GitHub | Rola |
|------|--------|------|
| Bartosz Palicki | Paliciak | Crypto Core Engineer |
| Michał Muraszko | MuraszkoM | Security Champion |
| Jakub Halejcio | byalixon | Format & Storage Engineer |
| Bartosz Kroczak | Charn00h | Application Engineer |
| Łukasz Krawiec | Lukas0327 | Quality & Process Lead |
