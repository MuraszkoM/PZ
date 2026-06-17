// bledy aplikacji
//
// ważne: wszystkie bledy "po hasle" (zle haslo, ruszony header_mac, ruszony
// wrapped dek, zepsute body, ucięty plik) maja wygladac tak samo na zewnatrz.
// Stad jeden wariant BadPasswordOrCorrupted i jeden komunikat - zeby nie robic
// atakujacemu oracle'a (patrz ADR-005 i SPEC §14).

use std::fmt;

// jedyny komunikat jaki pokazujemy dla bledow po podaniu hasla
pub const ERR_BAD_PASSWORD_OR_CORRUPTED: &str = "ERR_BAD_PASSWORD_OR_CORRUPTED";

#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    // zle haslo ALBO uszkodzony plik - specjalnie tego nie rozrozniamy.
    // łapie tez ucięcie pliku po naglowku.
    BadPasswordOrCorrupted,

    // bledy struktury ktore widac jeszcze bez hasla (SPEC §12): zly magic,
    // zla wersja, flagi != 0, nieznany kdf_id/aead_id, zle dlugosci, brak body.
    // to NIE sprawdza integralnosci body - od tego jest open / verify z haslem.
    InvalidStructure(String),

    // cos sie wywalilo przy czytaniu/zapisie pliku
    Io(std::io::Error),

    // jeszcze nie napisane (szkielet MVP). zwracamy blad zamiast panikowac,
    // bo nie chcemy crasha - patrz A8 w threat modelu
    NotImplemented(&'static str),
}

impl VaultError {
    // kod wyjscia procesu, CLI tego uzywa w process::exit
    pub fn exit_code(&self) -> i32 {
        match self {
            VaultError::BadPasswordOrCorrupted => 2,
            VaultError::InvalidStructure(_) => 3,
            VaultError::Io(_) => 4,
            VaultError::NotImplemented(_) => 64, // "jeszcze nie gotowe"
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::BadPasswordOrCorrupted => f.write_str(ERR_BAD_PASSWORD_OR_CORRUPTED),
            VaultError::InvalidStructure(why) => write!(f, "ERR_INVALID_STRUCTURE: {why}"),
            VaultError::Io(e) => write!(f, "ERR_IO: {e}"),
            VaultError::NotImplemented(what) => write!(f, "ERR_NOT_IMPLEMENTED: {what}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

// skrot zeby nie pisac calego Result<T, VaultError> wszedzie
pub type Result<T> = std::result::Result<T, VaultError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    // ── Display: kazdy wariant ma swoj komunikat ──────────────────────────────

    #[test]
    fn display_bad_password_is_the_one_message() {
        // ADR-005 / §14: jeden ogolny komunikat, bez oracle'a
        assert_eq!(
            VaultError::BadPasswordOrCorrupted.to_string(),
            ERR_BAD_PASSWORD_OR_CORRUPTED
        );
    }

    #[test]
    fn display_invalid_structure_carries_reason() {
        let e = VaultError::InvalidStructure("zly magic".to_string());
        let s = e.to_string();
        assert!(s.contains("ERR_INVALID_STRUCTURE"));
        assert!(s.contains("zly magic"));
    }

    #[test]
    fn display_io_has_prefix() {
        let e = VaultError::Io(io::Error::other("boom"));
        assert!(e.to_string().contains("ERR_IO"));
    }

    #[test]
    fn display_not_implemented_carries_what() {
        let e = VaultError::NotImplemented("changepass");
        let s = e.to_string();
        assert!(s.contains("ERR_NOT_IMPLEMENTED"));
        assert!(s.contains("changepass"));
    }

    // ── exit_code: stabilne kody wyjscia ──────────────────────────────────────

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(VaultError::BadPasswordOrCorrupted.exit_code(), 2);
        assert_eq!(VaultError::InvalidStructure(String::new()).exit_code(), 3);
        assert_eq!(VaultError::Io(io::Error::other("x")).exit_code(), 4);
        assert_eq!(VaultError::NotImplemented("x").exit_code(), 64);
    }

    // ── From<io::Error> ───────────────────────────────────────────────────────

    #[test]
    fn from_io_error_maps_to_io_variant() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "nie ma pliku");
        let e: VaultError = io_err.into();
        assert!(matches!(e, VaultError::Io(_)));
    }

    // ── source(): tylko Io ma zrodlo ──────────────────────────────────────────

    #[test]
    fn source_present_only_for_io() {
        let io_e = VaultError::Io(io::Error::other("x"));
        assert!(io_e.source().is_some());

        assert!(VaultError::BadPasswordOrCorrupted.source().is_none());
        assert!(VaultError::InvalidStructure(String::new())
            .source()
            .is_none());
        assert!(VaultError::NotImplemented("x").source().is_none());
    }
    #[test]
    fn debug_format_works() {
        let e = VaultError::BadPasswordOrCorrupted;
        assert!(!format!("{:?}", e).is_empty());
        
        let e2 = VaultError::InvalidStructure("test".to_string());
        assert!(format!("{:?}", e2).contains("InvalidStructure"));
    }
}
