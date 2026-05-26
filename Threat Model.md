Threat Model – Model Zagrożeń

•	Projekt: Bezpieczny menedżer sekretów (Vault)
•	Wersja: 0.1 (szkic)
•	Data: 26.05.2026
•	Autor: Bartosz Palicki
•	Status: Szkic do review

1.	Aktorzy

1)	User (właściciel vaulta)

•	Zna hasło główne
•	Korzysta z CLI na zaufanej maszynie

2)	Adversary (atakujący próbujący uzyskać dostęp do sekretów lub naruszyć ich integralność)

2.	Założenia:

•	Implementacja Argon2id, ChaCha20-Poly1305 i HMAC-SHA256 z zatwierdzonej biblioteki jest poprawna i odporna na typowe side-channel.
•	OS dostarcza CSPRNG o właściwej entropii.
•	Maszyna użytkownika podczas operowania na vaulcie nie ma aktywnego malware (otherwise out of scope)

3.	Cele bezpieczeństwa:

ID	  Własność	              Wymóg
S-1	  Poufnośc	              Bez znajomości hasla głownego, atakujący nie odzyska zawartości rekordów.
S-2	  Integralność	          Każda modyfikacja pliku (nagłówka lub body) musi być wykryta przez open albo verify—with—password. Verify bez hasła wykrywa tylko błędy strukturalne.
S-3	  Downgrade resistance	  Atakujący nie może osłabić parametrów KDF ani algorytmu AEAD niezauważalnie dla użytkownika.
S-4	  Brute-force resistance	Argon2id z parametrami z załącznika nr 1 czyni próbę off-line brute force kosztowną.
S-5	  Odporność bieżącego     Po changepass stare hasło nie wystarcza do otwarcia bieżącej wersji pliku. Nie chroni to starych kopii vaulta posiadanych przez atakującego.
      pliku na stare hasło	

4.	Klasy zagrożeń, które będą jawnie testowane:

1)	A1 — Modyfikacja bajtu w body. Atakujący zmienia jeden bajt szyfrogramu body. Oczekiwane: tag AEAD nie pasuje, open zwraca błąd. 
2)	A2 — Modyfikacja parametrów KDF. Atakujący zmienia kdf_iterations z 3 na 1. Oczekiwane: HMAC nagłówka nie pasuje, open zwraca błąd. 
3)	A3 — Podmiana algorytmu AEAD. Atakujący zmienia aead_id. Oczekiwane: HMAC nagłówka nie pasuje. 
4)	A4 — Podmiana wrapped DEK. Atakujący zastępuje wrapped_dek swoim. Oczekiwane: HMAC nie pasuje (jest częścią canonical header). 
5)	A5 — Brute force słabego hasła. Hasło “password123” + Argon2id wciąż wymaga kosztu. Test: zmierz, ile prób/sekundę osiąga się na typowej maszynie; raport ma to udokumentować. 
6)	A6 — Reuse hasła po changepass. Atakujący zna stare hasło i próbuje otworzyć aktualną wersję pliku po zmianie hasła. Oczekiwane: błąd. Uwaga: jeśli atakujący ma starą kopię pliku i stare hasło, odczyt starej kopii pozostaje poza ochroną changepass. 
7)	A7 — Truncation pliku. Plik ucięty w środku body. Oczekiwane: tag AEAD nie pasuje, błąd. 
8)	A8 — Plik pusty / o niewłaściwym magic. Oczekiwane: kontrolowany błąd, nie crash. 



Załącznik nr 1

ID 	Wymaganie 	Uzasadnienie
 
NF-01	Otwarcie vaulta z 100 rekordami trwa ≤ 2 s na typowym laptopie	Komfort UX
NF-02	Argon2id z parametrami minimum: m = 64 MiB, t = 3, p = 1 (domyślnie)	Wytyczne OWASP
NF-03	Maksymalny rozmiar vaulta: 100 MiB	Praktyczny limit dla in-memory
NF-04	Kod zgodny z konwencjami stylu języka (rustfmt / gofmt / black)	Jakość
NF-05	Pokrycie 	testami 	jednostkowymi 	≥ 	70% 	(mierzone narzędziem CI)	Jakość testów
NF-06	Fuzzing parsera nagłówka: minimum 24 h CPU bez crasha (po triage)	Robustność
NF-07	Każdy commit przechodzi pipeline CI: build + test + lint + audit zależności	Proces
NF-08	Każdy PR ma minimum 1 review innego członka zespołu	Proces
NF-09	Brak hard-coded sekretów w kodzie i testach (sekrety testowe z .env.example)	Bezpieczeństwo
NF-10	Wszystkie zewnętrzne zależności na białej liście (zob. §10) i przypięte do wersji	Audytowalność
NF-11	Zerowanie kluczy w pamięci za pomocą zeroize (Rust) / Bezpieczeństwo unsafe.Slice z explicit_bzero (Go)
NF-12	Dokumentacja 	użytkownika 	(README) 	i 	operatora 	Czytelność
(THREAT_MODEL.md, SECURITY.md) — w języku polskim lub angielskim, konsekwentnie

