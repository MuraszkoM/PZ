// Testy adwersarialne – scenariusze z modelu zagrożeń (§9.4)
// Każdy test generuje zmodyfikowany plik vault i sprawdza że vault open zwraca błąd.

#[cfg(test)]
mod adversarial {
    // A1 — Modyfikacja bajtu w body
    // Atakujący zmienia jeden bajt szyfrogramu body.
    // Oczekiwane: tag AEAD nie pasuje, open zwraca błąd.
    #[test]
    fn a1_modified_body_byte() {
        todo!("Wygeneruj vault, zmień jeden bajt w ct_body, sprawdź błąd przy open")
    }

    // A2 — Modyfikacja parametrów KDF
    // Atakujący zmienia kdf_iterations z 3 na 1.
    // Oczekiwane: HMAC nagłówka nie pasuje, open zwraca błąd.
    #[test]
    fn a2_modified_kdf_iterations() {
        todo!("Wygeneruj vault, zmień bajt kdf_iterations w nagłówku, sprawdź błąd")
    }

    // A3 — Podmiana algorytmu AEAD
    // Atakujący zmienia aead_id.
    // Oczekiwane: HMAC nagłówka nie pasuje.
    #[test]
    fn a3_modified_aead_id() {
        todo!("Wygeneruj vault, zmień bajt aead_id w nagłówku, sprawdź błąd")
    }

    // A4 — Podmiana wrapped DEK
    // Atakujący zastępuje wrapped_dek swoim.
    // Oczekiwane: HMAC nie pasuje.
    #[test]
    fn a4_replaced_wrapped_dek() {
        todo!("Wygeneruj vault, nadpisz wrapped_dek losowymi bajtami, sprawdź błąd")
    }

    // A5 — Brute force słabego hasła
    // Mierzy ile prób/sekundę osiąga się przy Argon2id.
    // Oczekiwane: koszt jest wysoki (<<1 próba/s).
    #[test]
    fn a5_brute_force_cost() {
        todo!("Zmierz czas jednej operacji Argon2id, zaloguj wynik, assert czas > 100ms")
    }

    // A6 — Reuse hasła po changepass
    // Atakujący próbuje otworzyć vault starym hasłem po zmianie hasła.
    // Oczekiwane: błąd.
    #[test]
    fn a6_old_password_after_changepass() {
        todo!("Wygeneruj vault, changepass, spróbuj open starym hasłem, sprawdź błąd")
    }

    // A7 — Truncation pliku
    // Plik ucięty w środku body.
    // Oczekiwane: tag AEAD nie pasuje, błąd.
    #[test]
    fn a7_truncated_file() {
        todo!("Wygeneruj vault, utnij plik w połowie, sprawdź błąd przy open")
    }

    // A8 — Plik pusty / o niewłaściwym magic
    // Oczekiwane: kontrolowany błąd, nie crash.
    #[test]
    fn a8_empty_or_wrong_magic() {
        todo!("Podaj pusty plik i plik z błędnym magic, sprawdź kontrolowany błąd")
    }
}