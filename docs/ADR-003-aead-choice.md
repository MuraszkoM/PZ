# ADR-003: Wybór algorytmu AEAD

## Status
Accepted

## Kontekst
Vault musi szyfrować body pliku i jednocześnie wykrywać modyfikacje danych. Potrzebujemy algorytmu AEAD zgodnego ze specyfikacją projektu

## Decyzja
Wybieramy ChaCha20-Poly1305

## Uzasadnienie
ChaCha20-Poly1305 jest dopuszczony w wymaganiach projektu i pasuje do przykładowej specyfikacji kryptograficznej. Ma klucz 32 B, nonce 12 B i tag 16 B. W Rust użyjemy biblioteki `chacha20poly1305`

## Konsekwencje
Każde szyfrowanie musi używać świeżego nonce. Szczególnie przy zapisie body nie wolno ponownie użyć tego samego `nonce_body` z tym samym DEK
