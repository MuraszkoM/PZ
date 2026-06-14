// vault service - sklejka miedzy CLI a krypto/formatem/storage
//
// w tym PR add_login realnie zbiera dane od usera (moja dzialka) i buduje rekord.
// sam ZAPIS (storage + szyfrowanie) jeszcze nie istnieje - to robota Halejcia i
// Palika, wiec na tym etapie zwracamy NotImplemented.

use crate::error::{Result, VaultError};
use crate::prompt;
use crate::record::Record;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// vault init <plik> - SPEC §15
pub fn init(_path: &Path) -> Result<()> {
    Err(VaultError::NotImplemented("init (SPEC §15)"))
}

// vault open <plik> - SPEC §16
pub fn open(_path: &Path) -> Result<()> {
    Err(VaultError::NotImplemented("open (SPEC §16)"))
}

// vault add login - zbiera dane interaktywnie i buduje rekord (§4.2).
pub fn add_login() -> Result<()> {
    // 1. zebranie danych od usera (haslo bez echa)
    let input = prompt::collect_login().map_err(VaultError::Io)?;

    // 2. id (UUID v4) i czas - to ustalamy tutaj, nie w modelu rekordu
    let id = *uuid::Uuid::new_v4().as_bytes();
    let now = now_nanos();

    // 3. zbudowanie rekordu + walidacja
    let record = Record::new_login(input, id, now)
        .map_err(|why| VaultError::InvalidStructure(why.to_string()))?;

    println!("Zbudowano rekord: {}", record.summary());

    // 4. zapis - jeszcze nie ma storage/crypto
    Err(VaultError::NotImplemented(
        "zapis rekordu (czeka na storage + crypto)",
    ))
}

// vault list
pub fn list() -> Result<()> {
    Err(VaultError::NotImplemented("list"))
}

// vault get <id|nazwa>
pub fn get(_id_or_name: &str) -> Result<()> {
    Err(VaultError::NotImplemented("get"))
}

// vault changepass - zmiana hasla bez ruszania DEK (SPEC §18)
pub fn changepass() -> Result<()> {
    Err(VaultError::NotImplemented("changepass (SPEC §18)"))
}

// vault verify <plik> [--with-password] - SPEC §12 / §13
pub fn verify(_path: &Path, with_password: bool) -> Result<()> {
    if with_password {
        Err(VaultError::NotImplemented(
            "verify --with-password (SPEC §13)",
        ))
    } else {
        Err(VaultError::NotImplemented("verify (SPEC §12)"))
    }
}

// czas teraz w nanosekundach od epoki (Unix nanos, jak w §8.2)
fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
