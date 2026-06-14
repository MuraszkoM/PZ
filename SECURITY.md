# SECURITY

Ten plik opisuje, jak podchodzimy do kwestii bezpieczeństwa w projekcie.


## Zgłaszanie problemów

Jeśli ktoś znajdzie błąd bezpieczeństwa albo podejrzane zachowanie aplikacji,
nie powinien od razu opisywać szczegółów w publicznym issue.

Najpierw zgłaszamy to prywatnie do dowolnego członka zespołu projektowego.
Dopiero po analizie i przygotowaniu poprawki można opisać problem szerzej.

Oczekiwany czas odpowiedzi: do 48 godzin.


## Co projekt ma chronić

Projekt ma chronić sekrety zapisane w pliku vault, np.:

- loginy i hasła
- klucze API
- notatki
- sekrety TOTP
- klucze SSH
- małe załączniki

Zakładamy, że atakujący może mieć dostęp do pliku vault, ale nie zna hasła głównego.


## Czego projekt nie chroni

Projekt nie chroni przed wszystkim. Poza zakresem są między innymi:

- malware działające na komputerze użytkownika
- atakujący mający dostęp do pamięci RAM podczas otwartej sesji
- phishing hasła głównego
- podmiana samego programu vault
- stare kopie pliku vault sprzed zmiany hasła


## Zasady bezpieczeństwa w kodzie

W projekcie pilnujemy, żeby:

- hasło główne nie było zapisywane na dysk ani logowane
- sekrety nie były przekazywane jako argumenty komendy
- pliki .env nie trafiały do repozytorium
- błędy typu "złe hasło" i "uszkodzony plik" nie były łatwe do odróżnienia
- repozytorium było sprawdzane pod kątem przypadkowo dodanych sekretów
- klucze były zerowane w pamięci po użyciu (zeroize)


## Postępowanie po znalezieniu luki (Runbook)

1. Zgłoś problem prywatnie do dowolnego członka zespołu.
2. Quality & Process Lead tworzy prywatne issue w repo z etykietą "security".
3. Zespół analizuje problem i ocenia jego wpływ (do 48h).
4. Odpowiedni członek zespołu przygotowuje poprawkę na osobnym branchu.
5. Poprawka przechodzi code review przez minimum 2 osoby.
6. Po merge QPL aktualizuje CHANGELOG.md z opisem luki (bez szczegółów exploita).
7. Jeśli luka dotyczy użytkowników zewnętrznych — QPL przygotowuje publiczne ogłoszenie.


## Kontakt

Za kontakt w sprawach bezpieczeństwa odpowiada zespół projektowy:

   Łukasz Krawiec (Quality & Process Lead) — GitHub: Lukas0327
   Bartosz Palicki (Crypto Core Engineer) — GitHub: Paliciak
   Michał Muraszko (Security Champion) — GitHub: MuraszkoM
   Jakub Halejcio (Format & Storage Engineer) — GitHub: byalixon
   Bartosz Kroczak (Application Engineer) — GitHub: Charn00h