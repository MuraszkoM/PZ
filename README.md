# Vault — bezpieczny menager sekretów

Projekt zespołowy

Celem projektu jest implementacja narzędzia CLI `vault` służącego do przechowywania sekretów użytkownika w jednym pliku zaszyfrowanym hasłem głównym.


## Zakres MVP
MVP obejmuje:

- `vault init <plik>`
- `vault open <plik>`
- `vault add login`
- `vault list`
- `vault get <id|nazwa>`
- `vault changepass`
- `vault verify <plik> --with-password`
- format pliku vault
- Argon2id
- ChaCha20-Poly1305
- key wrapping
- atomowy zapis pliku
- podstawowe testy integracyjne i adwersarialne
- CI/CD


## Technologia
Planowany język implementacji: Rust.

Główne biblioteki:

- `argon2`
- `chacha20poly1305`
- `hmac`
- `sha2`
- `hkdf`
- `zeroize`
- `rand`
- `ciborium`
- `clap`
- `uuid`


## Struktura repozytorium

```text
src/                  kod główny
tests/integration/    testy integracyjne
tests/adversarial/    testy bezpieczeństwa
tests/regressions/    testy regresyjne
fuzz/                 cele fuzzingu
testvectors/          wektory testowe
docs/                 dokumentacja techniczna i ADR
.github/workflows/    konfiguracja CI
