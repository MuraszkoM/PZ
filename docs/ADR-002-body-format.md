# ADR-002: Wybór formatu body

## Status
Proposed


## Kontekst
Body vaulta musi przechowywać rekordy różnych typów i obsługiwać dane tekstowe oraz binarne.


## Decyzja
Planoany format body: CBOR.


## Uzasadnienie
CBOR jest formatem binarnym, obsługuje bajty i lepiej pasuje do canonical encoding niż zwykły JSON.


## Konsekwencje
Musimy dokładnie opisać canonical encoding w SPEC.md i pilnować zgodności parsera oraz serializera.
