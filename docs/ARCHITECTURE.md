# ARCHITECTURE

Opis architektury projektu vault.

Planowany podział modułów:

- Crypto Core
- Format
- Storage
- Vault Service
- CLI

## Crypto Core
Moduł odpowiedzialny za Argon2id, HKDF, AEAD, HMAC, key wrapping i zeroizację.


## Format
Moduł odpowiedzialny za parser i serializer formatu pliku vault.


## Storage
Moduł odpowiedzialny za odczyt, zapis atomowy i obsługę pliku vault.


## Vault Service
Warstwa łącząca kryptografię, format danych i operacje na rekordach.


## CLI
Warstwa komend użytkownika.
