ADR-001 — Wybór języka implementacji

Status: Zaakceptowany
Data: 26.05.2026
Autorzy: Cały zespół
 
Kontekst
Zespół musi wybrać język implementacji dla narzędzia CLI vault. Specyfikacja projektu dopuszcza dwa języki: Rust oraz Go. Wybór języka determinuje dostępne biblioteki kryptograficzne, infrastrukturę testowania i fuzzingu, sposób zarządzania pamięcią oraz ergonomię implementacji wymagań bezpieczeństwa (zeroizacja kluczy, obsługa błędów).

Rozważane opcje:
•	Rust — rekomendacja prowadzącego jako opcja domyślna
•	Go — alternatywa z łagodniejszą krzywą uczenia
 
Decyzja
Wybieramy Rust.
 
Uzasadnienie
1. Zeroizacja pamięci
Wymaganie F-16 i NF-11 nakładają obowiązek aktywnego zerowania kluczy (KEK, DEK, master_key) po użyciu. Rust oferuje crate zeroize (biała lista §10.2), który integruje się z systemem typów i gwarantuje, że kompilator nie usunie zerowania jako „martwego kodu" (co jest realnym problemem w C i Go przy optymalizacjach). W Go explicit_bzero wymaga wywołań unsafe, co jest trudniejsze do poprawnego użycia i weryfikacji w code review.
2. Fuzzing
Wymaganie NF-06 i M8 wymagają minimum 24 h CPU fuzzingu parserów. Rust ma cargo-fuzz oparty na libFuzzer z natywnym wsparciem dla coverage-guided fuzzing i sanitizerów (AddressSanitizer, MemorySanitizer). W Go infrastruktura fuzzingu jest słabsza — go-fuzz jest mniej zintegrowany z ekosystemem.
3. Biblioteki kryptograficzne
Specyfikacja §10.2 dostarcza gotową białą listę bibliotek Rust (argon2, chacha20poly1305, hmac, sha2, hkdf, zeroize, rand, ciborium, clap, uuid). Wszystkie są aktywnie utrzymywane, audytowane przez społeczność RustCrypto i przypięte do konkretnych wersji. Odpowiedniki w Go wymagałyby dodatkowej analizy i zatwierdzeń prowadzącego.
4. System typów i obsługa błędów
Rust wymusza obsługę błędów na poziomie systemu typów (Result<T, E>). Trudno przypadkowo zignorować błąd deszyfrowania czy parsowania — co jest krytyczne dla wymagań bezpieczeństwa (F-17: jeden komunikat błędu, brak oracle'i). Kompilator wymusza też poprawne zarządzanie czasem życia danych wrażliwych.
5. Audyt zależności
cargo audit i cargo deny (biała lista §10.3) są pierwszorzędnymi narzędziami w ekosystemie Rust do weryfikacji CVE i licencji zależności, wymaganymi przez NF-10.
 
Konsekwencje

Pozytywne:
•	Silne gwarancje bezpieczeństwa pamięci bez garbage collectora
•	Natywna integracja z libFuzzer przez cargo-fuzz
•	Gotowa biała lista bibliotek bez konieczności dodatkowych zatwierdzeń
•	cargo fmt i cargo clippy ujednolicają styl i wymuszają jakość (NF-04, NF-07)

Negatywne / ryzyka:
•	Wyższa krzywa uczenia dla osób bez doświadczenia z Rustem (borrow checker)
•	Dłuższy czas kompilacji niż Go
•	Mitygacja: na początku projektu zespół poświęca czas na zapoznanie się z podstawami Rusta; trudniejsze fragmenty (Crypto Core) bierze osoba z największym doświadczeniem (P)
 
Alternatywy odrzucone
Go: odrzucony z powodu słabszej infrastruktury fuzzingu, trudniejszej zeroizacji pamięci i braku gotowej białej listy bibliotek w specyfikacji projektu.
