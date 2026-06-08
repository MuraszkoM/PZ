# ADR-003: Wybór algorytmu AEAD

## Status
Proposed


## Kontekst
Vault musi szyfrować body pliku i jednocześnie zapewniać integralność danych.


## Decyzja
Planowany algorytm AEAD: ChaCha20-Poly1305.


## Uzasadnienie
ChaCha20-Poly1305 jest wskazany w specyfikacji projektu jako jedna z dopuszczalnych opcji. Ma klucz 32 B, nonce 12 B i
tag 16 B.


## Konsekwencje
Musimy pilnować, żeby nonce dla body nigdy nie był użyty ponownie.
