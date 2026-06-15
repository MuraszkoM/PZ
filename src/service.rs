// vault service - sklejka miedzy CLI a krypto/formatem/storage
//
// add_login zbiera dane i buduje rekord. list/get maja juz pelna logike
// prezentacji (view), ale zaladowanie rekordow z otwartego vaulta wymaga
// crypto+storage - dlatego na razie zatrzymuja sie na tym jednym kroku.

use crate::clip;
use crate::error::{Result, VaultError};
use crate::prompt;
use crate::record::Record;
use crate::view;
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

pub fn verify(_path: &Path, with_password: bool) -> Result<()> {
    if with_password {
        Err(VaultError::NotImplemented(
            "verify --with-password (SPEC §13)",
        ))
    } else {
        Err(VaultError::NotImplemented("verify (SPEC §12)"))
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
