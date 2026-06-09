# ADR-005: Obsługa błędów kryptograficznych

## Status
Accepted

## Kontekst
Vault nie powinien ułatwiać atakującemu odróżnienia błędnego hasła od uszkodzonego pliku. 
Różne komunikaty mogłyby działać jak oracle.

## Decyzja
Dla błędów po podaniu hasła używamy jednego ogólnego błędu:

```
ERR_BAD_PASSWORD_OR_CORRUPTED
```
