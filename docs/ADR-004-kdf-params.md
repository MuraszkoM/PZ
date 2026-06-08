# ADR-004: Parametry Argon2id

## Status
Accepted

## Kontekst
Vault wyprowadza klucze z hasła głównego użytkownika. 
KDF musi utrudniać offline brute force w sytuacji, gdy atakujący posiada plik vault, ale nie zna hasła.

## Decyzja
Domyślne parametry Argon2id dla formatu v1:

- memory: 65536 KiB
- iterations: 3
- parallelism: 1
- salt length: 16 B
- output length: 32 B

## Uzasadnienie
Parametry są zgodne z wymaganiami projektu. 
Dają sensowny koszt obliczeniowy przy zachowaniu akceptowalnego czasu otwierania vaulta na typowym laptopie.

## Konsekwencje
Otwarcie vaulta nie powinno być natychmiastowe. Parametry KDF są zapisane w nagłówku pliku, 
a zmiana parametrów wymaga aktualizacji MAC nagłówka i ponownego szyfrowania body z nowym AAD.
