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
