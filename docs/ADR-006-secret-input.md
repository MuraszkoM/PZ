# ADR-006: Wczytywanie sekretow bez echa (rpassword)

## Status
Proposed (czeka na akceptacje zespolu i prowadzacego)

## Kontekst
Wymagania F-15 i F-19 mowia, ze haslo glowne oraz inne sekrety:
- nie moga byc przekazywane jako argumenty linii polecen,
- nie moga byc logowane,
- maja byc wprowadzane interaktywnie BEZ echa (znaki nie widoczne na ekranie).

Standardowa biblioteka Rusta nie ma gotowego, przenosnego sposobu na czytanie
z terminala bez echa. Reczna obsluga wymaga kodu zaleznego od platformy
(termios na Unix, Console API na Windows) i bloku `unsafe`, co jest trudniejsze
do poprawnego napisania i przejrzenia w review.

Biala lista bibliotek (§10.2) nie zawiera crate'a do tego zadania, dlatego
zgodnie z regula "kazda inna biblioteka wymaga zatwierdzenia" dodajemy ten ADR.

## Decyzja
Uzywamy crate'a `rpassword` (wersja "7") do wczytywania sekretow bez echa.

## Uzasadnienie
- robi dokladnie jedno: czyta linie z terminala bez echa, przenosnie
  (Linux/macOS/Windows),
- maly, dojrzaly, szeroko uzywany w ekosystemie Rust,
- pozwala unikac wlasnego `unsafe` wokol API terminala,
- nie dotyka kryptografii ani formatu pliku - jest tylko w warstwie CLI.

## Konsekwencje
- nowa zaleznosc poza pierwotna biala lista -> wymaga zgody prowadzacego
  (ten ADR jest tym zgloszeniem),
- przypieta do wersji ("7") zgodnie z NF-10,
- objeta `cargo audit` w CI jak kazda inna zaleznosc,
- jesli prowadzacy odrzuci, alternatywa jest wlasna implementacja na
  termios/Console API w module CLI (wiecej kodu i `unsafe`).