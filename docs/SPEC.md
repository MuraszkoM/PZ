# SPEC.md — format pliku vault v1

Status: draft v1.0  
Projekt: bezpieczny menedżer sekretów `vault`


## 1. Cel dokumentu
Ten dokument opisuje format pliku vault v1 oraz zasady jego parsowania, szyfrowania i walidacji

Specyfikacja ma być na tyle dokładna, żeby druga implementacja mogła odtworzyć format pliku zgodnie bajt po bajcie


## 2. Założenia ogólne
Vault jest pojedynczym plikiem binarnym zaszyfrowanym hasłem głównym użytkownika

Plik składa się z:
1. nagłówka
2. MAC nagłówka
3. nonce body
4. zaszyfrowanego body

Schemat

``` 
file = header_without_mac || header_mac || nonce_body || ct_body
```
Nagłówek zawiera parametry potrzebne do wyprowadzenia kluczy i odszyfrowania body. Body zawiera rekordy użytkownika zapisane w CBOR.

## 3. Prymitywy Kryptograficzne

| Funkcja | Algorytm | Parametry |
|-|-|-|
| KDF z hasła | Argon2id | m = 65536 KiB, t = 3, p = 1 |
| KDF z klucza | HKDF-SHA256 | osobne klucze pochodne |
| AEAD | ChaCha20-Poly1305 | klucz 32 B, nonce 12 B, tag 16 B |
| MAC | HMAC-SHA256 | 32 B |
| RNG | OS CSPRNG | źródło losowości systemu operacyjnego |
| Format body | CBOR | canonical encoding |         

stała kontekstowa:
```
CONTEXT = "vault-v1"
```

master_key z hasła nie jest używany bezpośrednio do szyfrowania czy do MAC tylko służy do wyprowadzenia kluczy pochodnych



## 4. Hierarchia kluczy

Z hasła głównego użytkownika P i soli kdf_salt wyprowadzany jest:
```
master_key = Argon2id(P, kdf_salt, params)
```
Następnie przez HKDF-SHA256 wyprowadzane są:
```
wrap_key       = HKDF(master_key, info = CONTEXT || "wrap-dek-key")
header_mac_key = HKDF(master_key, info = CONTEXT || "header-mac")
```
wrap_key służy do opakowania DEK.
header_mac_key służy do obliczenia HMAC nagłówka.

DEK jest losowym kluczem 32 B wygenerowanym przy vault init. DEK szyfruje body.



## 5. Format nagłówka

Wszystkie liczby wielobajtowe są zapisane jako big-endian.
Canonical header to dokładnie pierwsze 100 bajtów pliku, bez pola header_mac.

| Offset | Rozmiar | Pole | Opis |
|-|-|-|-|
| 0 | 4 | magic | ASCII `VLT1` |
| 4 | 2 | version | `0x0001` |
| 6 | 2 | flags | zarezerwowane, musi być `0x0000` |
| 8 | 1 | kdf_id | `1` = Argon2id |
| 9 | 4 | kdf_memory_kib | domyślnie `65536` |
| 13 | 4 | kdf_iterations | domyślnie `3` |
| 17 | 1 | kdf_parallelism | domyślnie `1` |
| 18 | 1 | kdf_salt_len | `16` |
| 19 | 16 | kdf_salt | losowa sól |
| 35 | 1 | aead_id | `1` = ChaCha20-Poly1305 |
| 36 | 12 | nonce_dek | nonce dla opakowanego DEK |
| 48 | 4 | wrapped_dek_len | `48` |
| 52 | 48 | wrapped_dek | opakowany DEK |

nastepnie:
| Offset | Rozmiar | Pole | Opis |
|-|-|-|-|
| 100 | 32 | header_mac | HMAC-SHA256(header_mac_key, bajty 0..99) |
| 132 | 12 | nonce_body | nonce dla body |
| 144 | N | ct_body | zaszyfrowane body CBOR |



## 6. Obliczanie header_mac

liczymy to z canonical header:
header_mac = HMAC-SHA256(header_mac_key, file[0..100])


## 7. Wrapped DEK

DEK ma rozmiar 32 B
jest opakowany przez ChaCha20-Poly1305:
```
wrapped_dek = AEAD.encrypt(
    key = wrap_key,
    nonce = nonce_dek,
    plaintext = DEK,
    aad = CONTEXT || "wrap-dek"
)
```

I wynik ma 48 B
```
32 B DEK ciphertext + 16 B tag
```

## 8. Szyfrowanie body

Body jest szyfrowane przez ChaCha20-Poly1305 z kluczem DEK

AAD dla body:
```
aad_body = file[0..132]
```
czyli
```
canonical_header || header_mac
```
Syfrowanie:
```
ct_body = AEAD.encrypt(
    key = DEK,
    nonce = nonce_body,
    plaintext = body_cbor,
    aad = canonical_header || header_mac
)
```
Każdy zapis nowego vaylta musi dać nowy nonce_body


## 9. Body po deszyfrowaniu

Body zapisane jako canonical CBOR.
Struktura logiczna
```
Vault = {
  "schema_version": uint,
  "records": [Record, Record, ...]
}
```
Rekord:
```
Record = {
  "id": bytes(16),
  "type": text,
  "title": text,
  "tags": [text, ...],
  "notes": text,
  "created_at": uint,
  "modified_at": uint,
  "fields": map(text => text/bytes/uint)
}
```


## 10. Typy rekordów

W MVP obowiązkowy typ
```
login
```
Pola fields dla login:
```
{
  "url": text,
  "username": text,
  "password": text
}
```
typy planowanbe jako rozszerzenia:
```
note
apikey
totp
sshkey
attachment
```


## 11. Canonical encoding body

Body musi być serializowane deterministycznie
Zasady:

1. Body używa canonical CBOR
2. Klucze map są tekstowe
3. Klucze map są serializowane w porządku kanonicznym CBOR
4. Pola wymagane muszą występować zawsze
5. Brakujące wymagane pole oznacza błąd parsera
6. Nieznane pola w rekordzie v1 są traktowane jako błąd
7. records zachowuje kolejność zapisu rekordów
8. id jest bajtowym UUID v4 o długości 16 B
9. created_at i modified_at są zapisane jako Unix nanos
10. Załączniki binarne w przyszłości będą zapisywane jako bajty CBOR, nie jako base64


## 12. Walidacja strukturalna bez hasła

vault verify <plik> - bez hasła sprawdza tylko strukturę pliku:
- minimalną długość pliku
- magic VLT1
- wersję
- flags równe 0
- znany kdf_id
- poprawne długości pól
- znany aead_id
- wrapped_dek_len = 48
- obecność nonce_body
- obecność ct_body

verify bez hasła nie potwierdza integralności kryptograficznej body.


## 13. Walidacja z hasłem

vault verify <plik> --with-password wykonuje tę samą ścieżkę kryptograficzną co open, ale bez uruchamiania sesji
Sprawdza:
- strukturę pliku
- HMAC nagłówka
- poprawność wrapped DEK
- tag AEAD body
- poprawność parsowania CBOR


## 14. Obsługa błędów

Błędy z etapów kryptograficznych mają zwracać jeden ogólny komunikat:
```
ERR_BAD_PASSWORD_OR_CORRUPTED
```

Ten komunikat obejmuje między innymi:
- błędne hasło
- zmieniony header_mac
- zmieniony wrapped DEK
- zmieniony ciphertext body
- uszkodzone body
- truncation pliku po nagłówku


## 15. Init

Dla vault init <plik>:
1. Wygeneruj kdf_salt 16 B
2. Wygeneruj DEK 32 B
3. Wczytaj hasło P interaktywnie, z potwierdzeniem
4. Wyprowadź master_key = Argon2id(P, kdf_salt, params)
5. Wyprowadź wrap_key i header_mac_key
6. Wygeneruj nonce_dek 12 B
7. Oblicz wrapped_dek
8. Zbuduj canonical header
9. Oblicz header_mac
10. Utwórz body z pustą listą rekordów
11. Wygeneruj nonce_body 12 B
12. Zaszyfruj body z AAD canonical_header || header_mac
13. Zapisz plik atomowo
14. Wyzeruj hasło i klucze pośrednie


## 16. Open

Dla vault open <plik>:
1. Wczytaj plik
2. Sparsuj nagłówek
3. Wczytaj hasło
4. Wyprowadź master_key, wrap_key, header_mac_key
5. Sprawdź header_mac
6. Odszyfruj DEK
7. Odszyfruj body
8. Sparsuj CBOR
9. Wyzeruj hasło i klucze pośrednie



## 17. Zapis po modyfikacji

Przy każdej modyfikacji rekordów:
1. Zserializuj body do canonical CBOR
2. Wygeneruj nowy nonce_body
3. Zaszyfruj body aktualnym DEK
4. Zapisz plik atomowo

Nie wolno używać ponownie starego nonce_body


## 18. Changepass

vault changepass zmienia hasło główne bez zmiany DEK.

Procedura:
1. Otwórz vault starym hasłem
2. Wczytaj nowe hasło z potwierdzeniem
3. Wygeneruj nową sól
4. Wyprowadź nowe klucze z nowego hasła
5. Ponownie opakuj ten sam DEK
6. Zaktualizuj nagłówek i header_mac
7. Ponownie zaszyfruj body, bo zmienił się AAD
8. Zapisz plik atomowo

Stare hasło nie powinno otwierać aktualnej wersji pliku. Nie chroni to starych kopii vaulta


## 19. Zapis atomowy

Plik vault nie może być zapisywany w miejscu

Procedura zapisu:
1. Zapisz pełną nową zawartość do pliku tymczasowego
2. Wykonaj fsync pliku tymczasowego
3. Wykonaj rename na docelową ścieżkę
4. Wykonaj fsync katalogu, jeśli platforma to umożliwia


## 20. Limity

- Maksymalny rozmiar pliku vault: 100 MiB
- Maksymalny rozmiar pojedynczego załącznika: 5 MiB
- MVP implementuje typ login
- Rozszerzenia są realizowane dopiero po stabilnym MVP



## 21. Identyfikatory algorytmów

| ID | Znaczenie |
|-|-|
| kdf_id = 1 | Argon2id |
| aead_id = 1 | ChaCha20-Poly1305 |

Inne wartości w v1 są błędem.
