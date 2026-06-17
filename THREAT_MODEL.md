Threat Model – Model Zagrożeń

   Projekt: Bezpieczny menedżer sekretów (Vault)
   Wersja: 0.2
   Data: 14.06.2026
   Autorzy: Bartosz Palicki, Łukasz Krawiec
   Status: W trakcie przeglądu


1. Aktorzy

1) User (właściciel vaulta)
   - Zna hasło główne
   - Korzysta z CLI na zaufanej maszynie

2) Adversary (atakujący próbujący uzyskać dostęp do sekretów lub naruszyć ich integralność)


2. Założenia

   - Implementacja Argon2id, ChaCha20-Poly1305 i HMAC-SHA256 z zatwierdzonej biblioteki jest poprawna i odporna na typowe side-channel.
   - OS dostarcza CSPRNG o właściwej entropii.
   - Maszyna użytkownika podczas operowania na vaulcie nie ma aktywnego malware (otherwise out of scope).


3. Cele bezpieczeństwa i argumenty

S-1   Poufność
      Wymóg: Bez znajomości hasła głównego atakujący nie odzyska zawartości rekordów.
      Argument: Body vaulta jest szyfrowane przez ChaCha20-Poly1305 kluczem DEK. DEK jest owinięty
      przez wrap_key (AEAD), a wrap_key pochodzi z master_key przez HKDF. master_key pochodzi z hasła
      przez Argon2id (m=64MiB, t=3, p=1). Bez hasła atakujący nie może wyprowadzić master_key →
      wrap_key → DEK → odszyfrować body.

S-2   Integralność
      Wymóg: Każda modyfikacja pliku (nagłówka lub body) musi być wykryta przez open albo
      verify --with-password. verify bez hasła wykrywa tylko błędy strukturalne.
      Argument: Nagłówek jest chroniony przez HMAC-SHA256(header_mac_key, canonical(H)). Każda zmiana
      nagłówka powoduje niezgodność MAC-a. Body jest chronione przez tag AEAD (Poly1305). canonical(H)
      jest użyty jako AAD przy szyfrowaniu body — zmiana nagłówka powoduje błąd przy deszyfrowaniu body.

S-3   Downgrade resistance
      Wymóg: Atakujący nie może osłabić parametrów KDF ani algorytmu AEAD niezauważalnie dla użytkownika.
      Argument: Parametry KDF (kdf_iterations, kdf_memory_kib, kdf_parallelism, aead_id) są częścią
      nagłówka objętego HMAC-SHA256. Zmiana jakiegokolwiek parametru zmienia canonical(H), co powoduje
      niezgodność HMAC — open zwraca błąd. Dodatkowo canonical(H) jest AAD dla AEAD body.

S-4   Brute-force resistance
      Wymóg: Argon2id z parametrami z §5 czyni próbę off-line brute force kosztowną.
      Argument: Argon2id z m=64MiB, t=3, p=1 wymaga minimum 64 MiB pamięci i 3 iteracji na każdą
      próbę hasła. Na typowym laptopie daje to ~1 próbę/sekundę. Atak słownikowy jest kosztowny
      czasowo i sprzętowo.

S-5   Odporność bieżącego pliku na stare hasło
      Wymóg: Po changepass stare hasło nie wystarcza do otwarcia bieżącej wersji pliku.
      Argument: changepass generuje nowy salt_a2, oblicza nowy master_key z nowym hasłem, ponownie
      owija DEK nowym wrap_key i aktualizuje nagłówek wraz z header_mac. Stare hasło daje inny
      master_key → inny wrap_key → nie może rozpakować nowego wrapped_DEK.
      Ograniczenie: Jeśli atakujący posiada starą kopię pliku i zna stare hasło, może odczytać
      tę starą kopię. changepass nie chroni historycznych backupów.


4. Klasy zagrożeń, które będą jawnie testowane

1)  A1 — Modyfikacja bajtu w body. Atakujący zmienia jeden bajt szyfrogramu body.
    Oczekiwane: tag AEAD nie pasuje, open zwraca błąd.
2)  A2 — Modyfikacja parametrów KDF. Atakujący zmienia kdf_iterations z 3 na 1.
    Oczekiwane: HMAC nagłówka nie pasuje, open zwraca błąd.
3)  A3 — Podmiana algorytmu AEAD. Atakujący zmienia aead_id.
    Oczekiwane: HMAC nagłówka nie pasuje.
4)  A4 — Podmiana wrapped DEK. Atakujący zastępuje wrapped_dek swoim.
    Oczekiwane: HMAC nie pasuje (jest częścią canonical header).
5)  A5 — Brute force słabego hasła. Hasło "password123" + Argon2id wciąż wymaga kosztu.
    Test: zmierz ile prób/sekundę osiąga się na typowej maszynie; raport ma to udokumentować.
6)  A6 — Reuse hasła po changepass. Atakujący zna stare hasło i próbuje otworzyć aktualną
    wersję pliku po zmianie hasła. Oczekiwane: błąd.
7)  A7 — Truncation pliku. Plik ucięty w środku body.
    Oczekiwane: tag AEAD nie pasuje, błąd.
8)  A8 — Plik pusty / o niewłaściwym magic.
    Oczekiwane: kontrolowany błąd, nie crash.


5. Poza zakresem zagrożeń

   - Side-channel timing/cache na samym Argon2id — ufamy implementacji biblioteki.
   - Phishing hasła głównego od użytkownika.
   - Złośliwa modyfikacja binarki vaulta (supply-chain attack).
   - Atakujący z dostępem do RAM podczas otwartej sesji.
   - Ochrona starych kopii pliku vault po changepass.


Załącznik nr 1 — Wymagania niefunkcjonalne

ID      Wymaganie                                                                    Uzasadnienie
NF-01   Otwarcie vaulta z 100 rekordami trwa ≤ 2 s na typowym laptopie             Komfort UX
NF-02   Argon2id z parametrami minimum: m = 64 MiB, t = 3, p = 1 (domyślnie)      Wytyczne OWASP
NF-03   Maksymalny rozmiar vaulta: 100 MiB                                          Praktyczny limit dla in-memory
NF-04   Kod zgodny z konwencjami stylu języka (rustfmt)                             Jakość
NF-05   Pokrycie testami jednostkowymi ≥ 70% (mierzone narzędziem CI)              Jakość testów
NF-06   Fuzzing parsera nagłówka: minimum 24 h CPU bez crasha (po triage)          Robustność
NF-07   Każdy commit przechodzi pipeline CI: build + test + lint + audit            Proces
NF-08   Każdy PR ma minimum 1 review innego członka zespołu                         Proces
NF-09   Brak hard-coded sekretów w kodzie i testach                                 Bezpieczeństwo
NF-10   Wszystkie zewnętrzne zależności na białej liście i przypięte do wersji     Audytowalność
NF-11   Zerowanie kluczy w pamięci za pomocą zeroize (Rust)                        Bezpieczeństwo
NF-12   Dokumentacja użytkownika i operatora w języku polskim, konsekwentnie       Czytelność

Wyniki testów adwersarialnych (M8)

Wszystkie 9 testów adwersarialnych przechodzi zielono w CI.

ID   Wynik   Plik testu
A1   PASS    tests/adversarial_tests.rs::adversarial::a1_modified_body_byte
A2   PASS    tests/adversarial_tests.rs::adversarial::a2_modified_kdf_iterations
A3   PASS    tests/adversarial_tests.rs::adversarial::a3_modified_aead_id
A4   PASS    tests/adversarial_tests.rs::adversarial::a4_replaced_wrapped_dek
A5   PASS    tests/adversarial_tests.rs::adversarial::a5_brute_force_cost
A6   PASS    tests/adversarial_tests.rs::adversarial::a6_old_password_after_changepass
A7   PASS    tests/adversarial_tests.rs::adversarial::a7_truncated_file
A8   PASS    tests/adversarial_tests.rs::adversarial::a8_empty_file
A8   PASS    tests/adversarial_tests.rs::adversarial::a8_wrong_magic