// vault service - sklejka miedzy CLI a krypto/formatem/storage
//
// add_login zbiera dane i buduje rekord. list/get maja juz pelna logike
// prezentacji (view), ale zaladowanie rekordow z otwartego vaulta wymaga
// crypto+storage - dlatego na razie zatrzymuja sie na tym jednym kroku.

use crate::clip;
use crate::error::{Result, VaultError};
use crate::prompt;
use crate::record::Record;
use crate::{format, storage, view};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn init(_path: &Path) -> Result<()> {
    Err(VaultError::NotImplemented("init (SPEC §15)"))
}

pub fn open(_path: &Path) -> Result<()> {
    Err(VaultError::NotImplemented("open (SPEC §16)"))
}

// vault add login - zbiera dane interaktywnie i buduje rekord (§4.2)
pub fn add_login() -> Result<()> {
    let input = prompt::collect_login().map_err(VaultError::Io)?;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let now = now_nanos();
    let record = Record::new_login(input, id, now)
        .map_err(|why| VaultError::InvalidStructure(why.to_string()))?;
    println!("Zbudowano rekord: {}", record.summary());
    Err(VaultError::NotImplemented(
        "zapis rekordu (czeka na storage + crypto)",
    ))
}

// vault list [--type T] [--tag X] - metadane rekordow, bez sekretow (F-03).
// logika filtrowania i tabelki jest gotowa; brakuje tylko zaladowania rekordow.
pub fn list(type_filter: Option<&str>, tag_filter: Option<&str>) -> Result<()> {
    let records = load_open_vault()?;
    let filtered = view::filter(&records, type_filter, tag_filter);
    let owned: Vec<Record> = filtered.into_iter().cloned().collect();
    println!("{}", view::format_list(&owned));
    Ok(())
}

// vault get <id|nazwa> [--field F] [--clip] - pokazuje rekord (F-04).
// bez flag: pelny rekord; --field: surowa wartosc jednego pola;
// --clip: kopiuje wybrane pole do schowka (wymaga --field) i czysci po 30 s (F-18).
pub fn get(id_or_name: &str, field: Option<&str>, clip: bool) -> Result<()> {
    let records = load_open_vault()?;
    let record = view::find(&records, id_or_name)
        .ok_or_else(|| VaultError::InvalidStructure(format!("nie znaleziono: {id_or_name}")))?;

    // --clip kopiuje WYBRANE pole, wiec bez --field nie wiadomo co kopiowac
    if clip {
        let name = field
            .ok_or_else(|| VaultError::InvalidStructure("--clip wymaga --field".to_string()))?;
        let value = view::field_value(record, name)
            .ok_or_else(|| VaultError::InvalidStructure(format!("rekord nie ma pola: {name}")))?;
        // sekretu NIE wypisujemy na ekran - tylko info
        clip::copy_to_clipboard(&value).map_err(VaultError::InvalidStructure)?;
        println!(
            "Skopiowano pole '{name}' do schowka. Wyczyszcze za {} s (Ctrl-C przerywa).",
            clip::CLIPBOARD_CLEAR_SECS
        );
        return Ok(());
    }

    match field {
        Some(name) => match view::field_value(record, name) {
            Some(val) => println!("{val}"),
            None => {
                return Err(VaultError::InvalidStructure(format!(
                    "rekord nie ma pola: {name}"
                )))
            }
        },
        None => println!("{}", view::format_detail(record)),
    }
    Ok(())
}

pub fn changepass() -> Result<()> {
    Err(VaultError::NotImplemented("changepass (SPEC §18)"))
}

// vault verify <plik> [--with-password] - SPEC §12 / §13.
// bez hasla: tylko walidacja STRUKTURALNA (magic, wersja, flagi, dlugosci pol).
// nie potwierdza integralnosci body - od tego jest --with-password (laczy sie z open).
pub fn verify(path: &Path, with_password: bool) -> Result<()> {
    if with_password {
        // ta sama sciezka co open (HMAC, unwrap DEK, tag body) - dolaczy z `open`
        return Err(VaultError::NotImplemented(
            "verify --with-password (dolaczy z open, SPEC §13)",
        ));
    }
    let bytes = storage::read_vault_file(path).map_err(map_storage_err)?;
    verify_structure(&bytes)?;
    println!("OK: struktura pliku poprawna.");
    println!("(verify bez hasla nie potwierdza integralnosci - uzyj --with-password)");
    Ok(())
}

// czysta walidacja strukturalna na bajtach (SPEC §12) - testowalna bez plikow.
// bledy parsera traktujemy jako kontrolowany blad strukturalny (A8: nie crash).
fn verify_structure(bytes: &[u8]) -> Result<()> {
    format::parse_header(bytes).map_err(map_format_err)?;
    Ok(())
}

// bledy strukturalne formatu -> InvalidStructure (kontrolowany blad, SPEC §12, A8)
fn map_format_err(e: format::FormatError) -> VaultError {
    VaultError::InvalidStructure(e.to_string())
}

// bledy storage -> I/O zostaje I/O, reszta jako blad strukturalny
fn map_storage_err(e: storage::StorageError) -> VaultError {
    match e {
        storage::StorageError::Io(io) => VaultError::Io(io),
        storage::StorageError::TempFileError(io) => VaultError::Io(io),
        other => VaultError::InvalidStructure(other.to_string()),
    }
}

// zaladowanie rekordow z otwartego vaulta. docelowo: open -> deszyfrowanie ->
// parsowanie body (crypto + storage + format). na razie brak.
fn load_open_vault() -> Result<Vec<Record>> {
    Err(VaultError::NotImplemented(
        "zaladowanie rekordow (czeka na open: crypto + storage + format)",
    ))
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        KdfParams, VaultHeader, AEAD_ID_CHACHA20_POLY1305, HEADER_MAC_LEN, KDF_ID_ARGON2ID,
        KDF_SALT_LEN, NONCE_BODY_LEN, NONCE_DEK_LEN, VERSION, WRAPPED_DEK_LEN,
    };

    // strukturalnie poprawne bajty pliku (naglowek + 1 bajt udawanego ct_body)
    fn valid_bytes() -> Vec<u8> {
        let h = VaultHeader {
            version: VERSION,
            flags: 0,
            kdf_id: KDF_ID_ARGON2ID,
            kdf_params: KdfParams::default_v1(),
            kdf_salt: [0u8; KDF_SALT_LEN],
            aead_id: AEAD_ID_CHACHA20_POLY1305,
            nonce_dek: [1u8; NONCE_DEK_LEN],
            wrapped_dek: [2u8; WRAPPED_DEK_LEN],
            header_mac: [3u8; HEADER_MAC_LEN],
            nonce_body: [4u8; NONCE_BODY_LEN],
        };
        let mut b = h.serialize_full();
        b.push(0xAB); // minimalne ct_body
        b
    }

    #[test]
    fn verify_structure_accepts_valid_file() {
        assert!(verify_structure(&valid_bytes()).is_ok());
    }

    #[test]
    fn verify_structure_rejects_garbage() {
        let err = verify_structure(b"to nie jest vault").unwrap_err();
        assert!(matches!(err, VaultError::InvalidStructure(_)));
    }

    #[test]
    fn verify_structure_rejects_empty() {
        // A8: pusty plik -> kontrolowany blad, nie crash
        assert!(matches!(
            verify_structure(&[]),
            Err(VaultError::InvalidStructure(_))
        ));
    }

    #[test]
    fn verify_structure_rejects_bad_magic() {
        let mut b = valid_bytes();
        b[0] = b'X';
        assert!(matches!(
            verify_structure(&b),
            Err(VaultError::InvalidStructure(_))
        ));
    }

    #[test]
    fn verify_with_password_not_implemented_yet() {
        let err = verify(Path::new("x.vlt"), true).unwrap_err();
        assert!(matches!(err, VaultError::NotImplemented(_)));
    }
}
