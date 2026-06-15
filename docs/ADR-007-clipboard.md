# ADR-007: Kopiowanie do schowka (arboard)

## Status
Proposed (czeka na akceptacje zespolu i prowadzacego)

## Kontekst
Wymaganie F-04 mowi, ze `vault get <id|nazwa> --clip` ma kopiowac wybrane pole
do schowka systemowego zamiast wypisywac je na ekran. Wymaganie F-18 dokłada,
ze schowek ma byc czyszczony po 30 s, ale tylko jesli dalej trzyma wartosc
wpisana przez vault (jesli user skopiowal cos innego w miedzyczasie - nie ruszamy).

Standardowa biblioteka Rusta nie ma dostepu do schowka. Reczna obsluga wymaga
kodu zaleznego od platformy (X11/Wayland na Linux, NSPasteboard na macOS,
Win32 Clipboard API na Windows) i bloku `unsafe`, co jest trudne do poprawnego
napisania i przejrzenia w review.

Biala lista bibliotek (§10.2) nie zawiera crate'a do schowka, dlatego zgodnie
z regula "kazda inna biblioteka wymaga zatwierdzenia" dodajemy ten ADR
(analogicznie do ADR-006 / rpassword).

## Decyzja
Uzywamy crate'a `arboard` (wersja "3") z WYLACZONYMI domyslnymi featurami
(`default-features = false`).

## Uzasadnienie
- jedna biblioteka obsluguje wszystkie trzy platformy (Linux/macOS/Windows),
  co pokrywa cel docelowy z §15.2 (Windows x86_64) i CI na Linux,
- pozwala unikac wlasnego `unsafe` wokol API schowka kazdego systemu,
- jest aktywnie utrzymywana i szeroko uzywana,
- `default-features = false` odcina obsluge OBRAZKOW w schowku (feature
  `image-data`), ktora domyslnie ciagnie ciezki stos zaleznosci (`image`,
  `tiff`, dekodery JPEG/PNG). Nam wystarcza sam tekst - mniejsza powierzchnia
  do audytu (`cargo audit`) i prostszy review.

## Konsekwencje
- nowa zaleznosc poza pierwotna biala lista -> wymaga zgody prowadzacego
  (ten ADR jest tym zgloszeniem),
- przypieta do wersji ("3") zgodnie z NF-10, dokladne wersje w `Cargo.lock`,
- objeta `cargo audit` w CI jak kazda inna zaleznosc,
- F-18 (auto-czyszczenie): `get --clip` blokuje proces na 30 s, po czym czysci
  schowek tylko jesli dalej trzyma nasza wartosc. Blokowanie jest tu celowe -
  na X11 utrzymuje wlasnosc schowka przez ten czas (po zamknieciu procesu X11
  i tak traci zawartosc). User moze przerwac wczesniej (Ctrl-C).
- logika F-18 jest za traitem `Clipboard` (modul `clip`), wiec jest testowana
  jednostkowo z atrapa, bez prawdziwego schowka i bez czekania 30 s.
- jesli prowadzacy odrzuci arboard, alternatywa jest wlasna implementacja na
  API kazdej platformy (wiecej kodu i `unsafe`) albo rezygnacja z --clip.