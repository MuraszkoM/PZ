# ADR-002: Wybór formatu body

## Status
Accepted

## Kontekst
Body vaulta przechowuje rekordy użytkownika po deszyfrowaniu. Format musi obsługiwać tekst, liczby, mapy, listy i dane binarne. Ważne jest też deterministyczne kodowanie, bo format ma być możliwy do odtworzenia przez inną implementację

## Decyzja
Wybieramy CBOR jako format body

## Uzasadnienie
CBOR jest formatem binarnym, obsługuje dane bajtowe bez używania base64 i dobrze pasuje do canonical encoding. W Rust użyjemy biblioteki `ciborium`

## Konsekwencje
Musimy dokładnie pilnować zasad canonical CBOR w `SPEC.md`. Parser body musi odrzucać niepoprawne lub nieznane struktury w wersji v1
