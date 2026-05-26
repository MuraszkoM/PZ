# SECURITY

Ten plik opisuje, jak podchodzimy do kwestii bezpieczeństwa w projekcie.


## Zgłaszanie problemów
Jeśli ktoś znajdzie błąd bezpieczeństwa albo podejrzane zachowanie aplikacji, nie powinien od razu opisywać szczegółów w publicznym issue

Najpierw zgłaszamy to prywatnie w zespole albo osobie odpowiedzialnej za bezpieczeństwo projektu. Dopiero po analizie i przygotowaniu poprawki można opisać problem szerzej


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
- podmiana samego programu `vault`
- stare kopie pliku vault sprzed zmiany hasła


## Zasady bezpieczeństwa w kodzie
W projekcie pilnujemy, żeby:

- hasło główne nie było zapisywane na dysk
- hasło główne nie było logowane
- sekrety nie były przekazywane jako argumenty komendy
- pliki `.env` nie trafiały do repozytorium
- błędy typu „złe hasło” i „uszkodzony plik” nie były łatwe do odróżnienia
- repozytorium było sprawdzane pod kątem przypadkowo dodanych sekretów


## Kontakt
Za kontakt w sprawach bezpieczeństwa odpowiada zespół projektowy

Dane kontaktowe zostaną uzupełnione po ustaleniu ról w zespole.
