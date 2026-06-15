// clip - kopiowanie pola do schowka systemowego (get --clip), F-04 + F-18
//
// wymogi ze specyfikacji:
//  - F-04: get moze skopiowac wybrane pole do schowka zamiast wypisywac je na ekran
//  - F-18: schowek czyscimy po 30 s, ALE tylko jesli dalej trzyma to, co wpisal
//          vault (jak user skopiowal cos innego w miedzyczasie - nie ruszamy)
//
// logike auto-czyszczenia trzymam za traitem Clipboard, zeby dalo sie ja
// przetestowac bez prawdziwego schowka (i bez czekania 30 s). Prawdziwy schowek
// (arboard) jest tylko w cienkim adapterze SystemClipboard.

use std::time::Duration;

// ile czekamy zanim wyczyscimy schowek (F-18)
pub const CLIPBOARD_CLEAR_SECS: u64 = 30;

// abstrakcja schowka - dzieki temu logika jest testowalna z atrapa
pub trait Clipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String>;
    fn get_text(&mut self) -> Result<String, String>;
}

// rdzen F-18: wstaw wartosc, odczekaj, i wyczysc TYLKO jesli schowek dalej
// trzyma to co wpisalismy. generyczne po Clipboard -> testowalne z atrapa.
pub fn copy_with_autoclear<C: Clipboard>(
    clipboard: &mut C,
    value: &str,
    wait: Duration,
) -> Result<(), String> {
    clipboard.set_text(value)?;
    std::thread::sleep(wait);
    // czyscimy tylko jesli to nadal nasza wartosc (F-18)
    if let Ok(current) = clipboard.get_text() {
        if current == value {
            clipboard.set_text("")?;
        }
    }
    Ok(())
}

// adapter na prawdziwy schowek (arboard). cienki, bez wlasnej logiki -
// nie testujemy go jednostkowo (wymaga sesji graficznej / schowka systemowego).
pub struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl SystemClipboard {
    pub fn new() -> Result<Self, String> {
        let inner = arboard::Clipboard::new().map_err(|e| e.to_string())?;
        Ok(SystemClipboard { inner })
    }
}

impl Clipboard for SystemClipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String> {
        self.inner
            .set_text(text.to_string())
            .map_err(|e| e.to_string())
    }
    fn get_text(&mut self) -> Result<String, String> {
        self.inner.get_text().map_err(|e| e.to_string())
    }
}

// wygodne wejscie dla service: skopiuj wartosc do systemowego schowka i
// wyczysc po CLIPBOARD_CLEAR_SECS. blokuje na czas oczekiwania - dzieki temu
// na X11 utrzymujemy wlasnosc schowka, a po czasie go zwalniamy.
pub fn copy_to_clipboard(value: &str) -> Result<(), String> {
    let mut cb = SystemClipboard::new()?;
    copy_with_autoclear(&mut cb, value, Duration::from_secs(CLIPBOARD_CLEAR_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    // atrapa schowka w pamieci - pozwala testowac logike F-18 bez systemu i czekania
    struct FakeClipboard {
        content: String,
    }
    impl Clipboard for FakeClipboard {
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            self.content = text.to_string();
            Ok(())
        }
        fn get_text(&mut self) -> Result<String, String> {
            Ok(self.content.clone())
        }
    }

    #[test]
    fn copies_value_then_clears_if_still_ours() {
        let mut cb = FakeClipboard {
            content: String::new(),
        };
        copy_with_autoclear(&mut cb, "tajne123", Duration::ZERO).unwrap();
        // F-18: po czasie schowek wyczyszczony, bo trzymal nasza wartosc
        assert_eq!(cb.content, "");
    }

    #[test]
    fn does_not_clear_if_user_overwrote() {
        // atrapa, ktora po wstawieniu "udaje" ze user skopiowal cos innego
        struct OverwritingClipboard {
            content: String,
        }
        impl Clipboard for OverwritingClipboard {
            fn set_text(&mut self, text: &str) -> Result<(), String> {
                self.content = text.to_string();
                Ok(())
            }
            fn get_text(&mut self) -> Result<String, String> {
                // user wkleil cos innego w miedzyczasie
                Ok("cos innego od usera".to_string())
            }
        }
        let mut cb = OverwritingClipboard {
            content: String::new(),
        };
        copy_with_autoclear(&mut cb, "tajne123", Duration::ZERO).unwrap();
        // F-18: NIE czyscimy, bo schowek nie trzyma juz naszej wartosci
        assert_eq!(cb.content, "tajne123");
    }

    #[test]
    fn clear_timeout_is_30s() {
        assert_eq!(CLIPBOARD_CLEAR_SECS, 30);
    }
}
