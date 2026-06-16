// vault service - sklejka miedzy CLI a krypto/formatem/storage
//
// model bezstanowy (stateless): kazda komenda dotykajaca vaulta dostaje sciezke,
// pyta o haslo, odszyfrowuje, robi swoje, zeruje DEK i konczy. "Sesja" trwa tyle
// co jedna komenda (SPEC §16: DEK w pamieci tylko na czas sesji).
//
// init  (§15): tworzy nowy, pusty vault.
// open  (§16): pelna sciezka deszyfrowania, wypisuje podsumowanie.
// list  (F-03): metadane rekordow, bez sekretow.
// get   (F-04): jeden rekord / pole / kopia do schowka.
// add login: dopisuje rekord i zapisuje plik (§17).
// changepass (§18): zmiana hasla bez zmiany DEK.
// verify (§12/§13): walidacja strukturalna albo pelna kryptograficzna.

use crate::clip;
use crate::crypto;
use crate::error::{Result, VaultError};
use crate::format::{KdfParams, VaultBody, VaultHeader};
use crate::prompt;
use crate::record::{FieldValue, Record, RecordType};
use crate::{format, storage, view};
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

// vault init <plik> - tworzy nowy, pusty vault zaszyfrowany haslem (SPEC §15).
pub fn init(path: &Path) -> Result<()> {
    // nie nadpisujemy istniejacego pliku - to byloby skasowanie cudzego vaulta
    if path.exists() {
        return Err(VaultError::InvalidStructure(format!(
            "plik juz istnieje: {}",
            path.display()
        )));
    }

    let password = prompt::read_secret_confirmed("Nowe haslo glowne").map_err(VaultError::Io)?;

    // losowosc z OS CSPRNG (SPEC §3): sol KDF, DEK i nonce'y
    let mut kdf_salt = [0u8; format::KDF_SALT_LEN];
    let mut dek_bytes = [0u8; 32];
    let mut nonce_dek = [0u8; format::NONCE_DEK_LEN];
    let mut nonce_body = [0u8; format::NONCE_BODY_LEN];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut dek_bytes);
    rng.fill_bytes(&mut nonce_dek);
    rng.fill_bytes(&mut nonce_body);

    let bytes = build_new_vault_bytes(&password, kdf_salt, dek_bytes, nonce_dek, nonce_body)?;
    storage::write_vault_file_atomic(path, &bytes).map_err(map_storage_err)?;

    // wyzeruj jawna kopie DEK (klucze pochodne zeroizuja sie same przy Drop, NF-11)
    dek_bytes.zeroize();

    println!("Utworzono nowy vault: {}", path.display());
    Ok(())
}

// rdzen init: buduje bajty nowego, pustego vaulta zaszyfrowanego haslem (§15).
// wydzielone z init() zeby dalo sie przetestowac bez terminala i bez dysku.
// sol/DEK/nonce'y wstrzykujemy z zewnatrz -> deterministyczne testy (RNG jest w init()).
fn build_new_vault_bytes(
    password: &str,
    kdf_salt: [u8; format::KDF_SALT_LEN],
    dek_bytes: [u8; 32],
    nonce_dek: [u8; format::NONCE_DEK_LEN],
    nonce_body: [u8; format::NONCE_BODY_LEN],
) -> Result<Vec<u8>> {
    let dek = crypto::Dek::from_bytes(dek_bytes);

    // puste body -> canonical CBOR
    let body = VaultBody {
        schema_version: 1,
        records: vec![],
    };
    let body_cbor = format::serialize_body(&body).map_err(map_format_err)?;

    // dalej leci wspolny zlozyciel pliku (ten sam co changepass)
    assemble_vault_bytes(password, &dek, &body_cbor, kdf_salt, nonce_dek, nonce_body)
}

// wspolny zlozyciel pliku vault: z hasla + DEK + gotowego body_cbor buduje pelne
// bajty pliku (naglowek z mac i nonce_body || ct_body). cala logika layoutu w
// jednym miejscu - uzywaja go init (swiezy DEK, puste body) i changepass
// (ten sam DEK, istniejace body, nowa sol/nonce'y). §15 kroki 4-13 / §18 kroki 4-7.
fn assemble_vault_bytes(
    password: &str,
    dek: &crypto::Dek,
    body_cbor: &[u8],
    kdf_salt: [u8; format::KDF_SALT_LEN],
    nonce_dek: [u8; format::NONCE_DEK_LEN],
    nonce_body: [u8; format::NONCE_BODY_LEN],
) -> Result<Vec<u8>> {
    let params = KdfParams::default_v1();

    // klucze z hasla
    let master = crypto::derive_master_key(
        password.as_bytes(),
        &kdf_salt,
        params.memory_kib,
        params.iterations,
        params.parallelism as u32,
    )
    .map_err(map_crypto_err)?;
    let keys = crypto::derive_keys(&master).map_err(map_crypto_err)?;

    // opakuj DEK aktualnym wrap_key
    let wrapped = crypto::wrap_dek(&keys.wrap_key, &nonce_dek, dek).map_err(map_crypto_err)?;

    // naglowek: najpierw bez maca, policz canonical, potem dolicz header_mac
    let mut header = VaultHeader {
        version: format::VERSION,
        flags: 0,
        kdf_id: format::KDF_ID_ARGON2ID,
        kdf_params: params,
        kdf_salt,
        aead_id: format::AEAD_ID_CHACHA20_POLY1305,
        nonce_dek,
        wrapped_dek: wrapped,
        header_mac: [0u8; format::HEADER_MAC_LEN],
        nonce_body,
    };
    header.header_mac =
        crypto::compute_header_mac(&keys.header_mac_key, &header.serialize_canonical());

    // zaszyfruj body; aad = canonical_header || header_mac (§8)
    let aad = header.aad_for_body();
    let ct_body =
        crypto::encrypt_body(dek, &nonce_body, body_cbor, &aad).map_err(map_crypto_err)?;

    // sklej plik: pelny naglowek (z mac i nonce_body) || ct_body
    let mut file = header.serialize_full();
    file.extend_from_slice(&ct_body);
    Ok(file)
}

// vault open <plik> - otwiera vault i wypisuje podsumowanie (SPEC §16).
// to drugi wariant F-02 ("otworz i pokaz"); praca na rekordach idzie przez
// osobne komendy list/get/add (model bezstanowy).
pub fn open(path: &Path) -> Result<()> {
    let password = prompt::read_secret("Haslo glowne").map_err(VaultError::Io)?;
    let records = decrypt_vault(path, &password)?;
    println!("Otworzono vault: {} rekordow.", records.len());
    Ok(())
}

// vault add login <plik> - dopisuje rekord login i zapisuje plik (F-05 + §17).
// najpierw weryfikujemy dostep (haslo), potem zbieramy dane - zeby nie kazac
// userowi wpisywac calego loginu, jesli i tak nie zna hasla.
pub fn add_login(path: &Path) -> Result<()> {
    // 1. otworz vault - dostajemy naglowek (do zapisu), DEK i sparsowane body
    let password = prompt::read_secret("Haslo glowne").map_err(VaultError::Io)?;
    let (header, dek, mut body) = decrypt_vault_body(path, &password)?;

    // 2. zbierz dane nowego loginu (jawne pola + haslo bez echa)
    let input = prompt::collect_login().map_err(VaultError::Io)?;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let now = now_nanos();
    let record = Record::new_login(input, id, now)
        .map_err(|why| VaultError::InvalidStructure(why.to_string()))?;

    // 3. dopisz rekord do body (mapujac na typ formatu pod CBOR)
    body.records.push(vault_record_from_record(&record)?);

    // 4. zapis po modyfikacji (§17): ten sam DEK, nowy nonce_body, zapis atomowy
    save_vault(path, &header, &dek, &body)?;

    println!("Dodano rekord: {}", record.summary());
    Ok(())
}

// vault list <plik> [--type T] [--tag X] - metadane rekordow, bez sekretow (F-03).
pub fn list(path: &Path, type_filter: Option<&str>, tag_filter: Option<&str>) -> Result<()> {
    let password = prompt::read_secret("Haslo glowne").map_err(VaultError::Io)?;
    let records = decrypt_vault(path, &password)?;
    let filtered = view::filter(&records, type_filter, tag_filter);
    let owned: Vec<Record> = filtered.into_iter().cloned().collect();
    println!("{}", view::format_list(&owned));
    Ok(())
}

// vault get <plik> <id|nazwa> [--field F] [--clip] - pokazuje rekord (F-04).
// bez flag: pelny rekord; --field: surowa wartosc jednego pola;
// --clip: kopiuje wybrane pole do schowka (wymaga --field) i czysci po 30 s (F-18).
pub fn get(path: &Path, id_or_name: &str, field: Option<&str>, clip: bool) -> Result<()> {
    let password = prompt::read_secret("Haslo glowne").map_err(VaultError::Io)?;
    let records = decrypt_vault(path, &password)?;
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

// vault changepass <plik> - zmienia haslo glowne BEZ zmiany DEK (SPEC §18).
//
// idea: DEK zostaje ten sam (rekordy nie wymagaja przeszyfrowania innym kluczem),
// zmienia sie tylko warstwa "opakowania": nowa sol -> nowy master_key -> nowy
// wrap_key i header_mac_key. DEK pakujemy na nowo, naglowek liczymy od zera, a
// body przeszyfrowujemy bo zmienil sie AAD (canonical_header || header_mac).
// po zmianie stare haslo nie otwiera juz biezacej wersji pliku (S-5 / A6).
pub fn changepass(path: &Path) -> Result<()> {
    // 1. otworz starym haslem -> dostajemy DEK i odszyfrowane body (§18.1)
    let old_password = prompt::read_secret("Stare haslo glowne").map_err(VaultError::Io)?;
    let (_old_header, dek, mut body_cbor) = decrypt_to_body_cbor(path, &old_password)?;

    // 2. nowe haslo z potwierdzeniem (§18.2)
    let new_password =
        prompt::read_secret_confirmed("Nowe haslo glowne").map_err(VaultError::Io)?;

    // 3 + 6. nowa sol i NOWE nonce'y z OS CSPRNG. nonce_body musi byc nowy -
    // ten sam DEK + ten sam nonce_body = katastrofalny reuse nonce w AEAD (ADR-003).
    let mut kdf_salt = [0u8; format::KDF_SALT_LEN];
    let mut nonce_dek = [0u8; format::NONCE_DEK_LEN];
    let mut nonce_body = [0u8; format::NONCE_BODY_LEN];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut nonce_dek);
    rng.fill_bytes(&mut nonce_body);

    // 4 + 5 + 7. ten sam DEK, nowe klucze z nowego hasla, body przeszyfrowane
    // (nowy AAD bo zmienil sie naglowek). cala robota w assemble_vault_bytes.
    let bytes = assemble_vault_bytes(
        &new_password,
        &dek,
        &body_cbor,
        kdf_salt,
        nonce_dek,
        nonce_body,
    )?;

    // 8. zapis atomowy - albo stara, albo nowa wersja, nigdy "w polowie" (§19)
    storage::write_vault_file_atomic(path, &bytes).map_err(map_storage_err)?;

    // wyzeruj jawne body (zawiera sekrety); DEK zeroizuje sie sam przy Drop (NF-11)
    body_cbor.zeroize();

    println!("Zmieniono haslo glowne dla: {}", path.display());
    Ok(())
}

// vault verify <plik> [--with-password] - SPEC §12 / §13.
// bez hasla: tylko walidacja STRUKTURALNA (magic, wersja, flagi, dlugosci pol).
// z haslem: ta sama sciezka co open (HMAC, DEK, tag body, CBOR), ale bez sesji.
pub fn verify(path: &Path, with_password: bool) -> Result<()> {
    if with_password {
        let password = prompt::read_secret("Haslo glowne").map_err(VaultError::Io)?;
        // pelna sciezka kryptograficzna - jak open, tylko nie trzymamy rekordow (§13)
        decrypt_vault(path, &password)?;
        println!("OK: plik poprawny (HMAC naglowka, DEK, tag body, CBOR).");
        return Ok(());
    }
    let bytes = storage::read_vault_file(path).map_err(map_storage_err)?;
    verify_structure(&bytes)?;
    println!("OK: struktura pliku poprawna.");
    println!("(verify bez hasla nie potwierdza integralnosci - uzyj --with-password)");
    Ok(())
}

// ─── Rdzen deszyfrowania (SPEC §16) ───────────────────────────────────────────

// pelna sciezka deszyfrowania do poziomu: naglowek + DEK + odszyfrowane body_cbor.
// plik -> naglowek -> klucze z hasla -> HMAC -> DEK -> body. NIE parsuje jeszcze
// CBOR ani nie mapuje rekordow. Wszystkie bledy kryptograficzne zwijaja sie do
// jednego BadPasswordOrCorrupted (ADR-005 / §14), zeby nie robic oracle'a.
fn decrypt_to_body_cbor(
    path: &Path,
    password: &str,
) -> Result<(VaultHeader, crypto::Dek, Vec<u8>)> {
    // 1-2. wczytaj plik i sparsuj naglowek (bledy strukturalne = §12)
    let bytes = storage::read_vault_file(path).map_err(map_storage_err)?;
    let header = format::parse_header(&bytes).map_err(map_format_err)?;

    // 3-4. wyprowadz master_key (Argon2id) i klucze pochodne (HKDF) z hasla
    let master = crypto::derive_master_key(
        password.as_bytes(),
        &header.kdf_salt,
        header.kdf_params.memory_kib,
        header.kdf_params.iterations,
        header.kdf_params.parallelism as u32,
    )
    .map_err(map_crypto_err)?;
    let keys = crypto::derive_keys(&master).map_err(map_crypto_err)?;

    // 5. HMAC naglowka (S-2/S-3): kazda zmiana naglowka -> niezgodnosc MAC
    crypto::verify_header_mac(
        &keys.header_mac_key,
        &header.serialize_canonical(),
        &header.header_mac,
    )
    .map_err(map_crypto_err)?;

    // 6. rozpakuj DEK (zle haslo -> tag nie pasuje)
    let dek = crypto::unwrap_dek(&keys.wrap_key, &header.nonce_dek, &header.wrapped_dek)
        .map_err(map_crypto_err)?;

    // 7. deszyfruj body; aad = canonical_header || header_mac (§8)
    // ct_body zaczyna sie zaraz po naglowku i nonce_body (offset 144).
    let ct_body = &bytes[format::FULL_HEADER_LEN + format::NONCE_BODY_LEN..];
    let aad = header.aad_for_body();
    let body_cbor =
        crypto::decrypt_body(&dek, &header.nonce_body, ct_body, &aad).map_err(map_crypto_err)?;

    Ok((header, dek, body_cbor))
}

// jak wyzej, ale dodatkowo parsuje CBOR -> VaultBody. uzywa add (potrzebuje
// naglowka do zapisu, DEK i listy rekordow w formacie wewnetrznym).
fn decrypt_vault_body(
    path: &Path,
    password: &str,
) -> Result<(VaultHeader, crypto::Dek, VaultBody)> {
    let (header, dek, body_cbor) = decrypt_to_body_cbor(path, password)?;
    // uszkodzone body po udanym deszyfrowaniu nie powinno sie zdarzyc, ale
    // traktujemy je jak korupcje (ten sam komunikat, §14).
    let body = format::parse_body(&body_cbor).map_err(|_| VaultError::BadPasswordOrCorrupted)?;
    Ok((header, dek, body))
}

// pelna sciezka open (§16): naglowek+DEK+body -> parsowanie -> rekordy aplikacji.
// uzywaja open / list / get / verify --with-password.
fn decrypt_vault(path: &Path, password: &str) -> Result<Vec<Record>> {
    let (_header, _dek, body) = decrypt_vault_body(path, password)?;
    body.records.iter().map(record_from_vault).collect()
}

// ─── Zapis po modyfikacji (SPEC §17) ──────────────────────────────────────────

// zapis zmodyfikowanego body: ten sam DEK i ten sam naglowek (sol, wrapped_dek,
// header_mac bez zmian -> AAD ten sam), tylko NOWY nonce_body i przeszyfrowane
// body, na koniec zapis atomowy (§19). nonce_body losujemy z OS CSPRNG.
fn save_vault(
    path: &Path,
    header: &VaultHeader,
    dek: &crypto::Dek,
    body: &VaultBody,
) -> Result<()> {
    let mut nonce_body = [0u8; format::NONCE_BODY_LEN];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut nonce_body);
    save_vault_with_nonce(path, header, dek, body, nonce_body)
}

// rdzen zapisu z wstrzyknietym nonce_body - deterministyczny, testowalny.
// nigdy nie wolno uzyc tego samego nonce_body z tym samym DEK (ADR-003), dlatego
// save_vault zawsze losuje swiezy. canonical header i header_mac sa nietkniete,
// wiec stare haslo dalej otwiera (to NIE jest changepass) - zmienia sie tylko body.
fn save_vault_with_nonce(
    path: &Path,
    header: &VaultHeader,
    dek: &crypto::Dek,
    body: &VaultBody,
    nonce_body: [u8; format::NONCE_BODY_LEN],
) -> Result<()> {
    let body_cbor = format::serialize_body(body).map_err(map_format_err)?;

    // aad = canonical_header || header_mac - oba poza nonce_body, wiec bez zmian
    let aad = header.aad_for_body();
    let ct_body =
        crypto::encrypt_body(dek, &nonce_body, &body_cbor, &aad).map_err(map_crypto_err)?;

    // ten sam naglowek, tylko podmieniony nonce_body (offset 132-143)
    let mut new_header = header.clone();
    new_header.nonce_body = nonce_body;

    let mut file = new_header.serialize_full();
    file.extend_from_slice(&ct_body);
    storage::write_vault_file_atomic(path, &file).map_err(map_storage_err)?;
    Ok(())
}

// ─── Mapowanie rekordow format <-> model aplikacji ────────────────────────────

// format::VaultRecord -> record::Record (po deszyfrowaniu, pod view/clip).
// W MVP obslugujemy tylko login (SPEC §3.3 / §10).
fn record_from_vault(vr: &format::VaultRecord) -> Result<Record> {
    let (rtype, fields) = match &vr.fields {
        format::RecordFields::Login {
            url,
            username,
            password,
        } => {
            // uklad pol taki sam jak w record::new_login (pod view/clip)
            let mut f: BTreeMap<String, FieldValue> = BTreeMap::new();
            f.insert("url".to_string(), FieldValue::Text(url.clone()));
            f.insert("username".to_string(), FieldValue::Text(username.clone()));
            f.insert("password".to_string(), FieldValue::Text(password.clone()));
            (RecordType::Login, f)
        }
        _ => {
            // typy rozszerzen (note/apikey/totp/sshkey) nie sa w MVP (SPEC §3.3).
            // krypto sie udalo, wiec to nie jest blad hasla - zglaszamy wprost.
            return Err(VaultError::InvalidStructure(format!(
                "nieobslugiwany typ rekordu w MVP: {}",
                vr.record_type
            )));
        }
    };

    Ok(Record {
        id: vr.id,
        rtype,
        title: vr.title.clone(),
        tags: vr.tags.clone(),
        notes: vr.notes.clone(),
        created_at: vr.created_at,
        modified_at: vr.modified_at,
        fields,
    })
}

// record::Record -> format::VaultRecord (pod zapis do CBOR). odwrotnosc
// record_from_vault. W MVP tylko login - pola url/username/password z mapy fields.
fn vault_record_from_record(r: &Record) -> Result<format::VaultRecord> {
    let fields = match r.rtype {
        RecordType::Login => {
            // wyciagnij pole tekstowe z mapy fields albo blad strukturalny
            let text = |k: &str| -> Result<String> {
                match r.fields.get(k) {
                    Some(FieldValue::Text(s)) => Ok(s.clone()),
                    _ => Err(VaultError::InvalidStructure(format!(
                        "rekord login bez pola: {k}"
                    ))),
                }
            };
            format::RecordFields::Login {
                url: text("url")?,
                username: text("username")?,
                password: text("password")?,
            }
        }
    };

    Ok(format::VaultRecord {
        id: r.id,
        record_type: r.rtype.as_str().to_string(),
        title: r.title.clone(),
        tags: r.tags.clone(),
        notes: r.notes.clone(),
        created_at: r.created_at,
        modified_at: r.modified_at,
        fields,
    })
}

// ─── Walidacja strukturalna bez hasla (SPEC §12) ──────────────────────────────

// czysta walidacja strukturalna na bajtach - testowalna bez plikow.
// bledy parsera traktujemy jako kontrolowany blad strukturalny (A8: nie crash).
fn verify_structure(bytes: &[u8]) -> Result<()> {
    format::parse_header(bytes).map_err(map_format_err)?;
    Ok(())
}

// ─── Mapowanie bledow warstw na VaultError ────────────────────────────────────

// bledy strukturalne formatu -> InvalidStructure (kontrolowany blad, §12, A8)
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

// bledy kryptograficzne -> jeden ogolny komunikat (ADR-005 / §14).
// celowo nie rozrozniamy zlego hasla od korupcji, zeby nie tworzyc oracle'a.
fn map_crypto_err(_e: crypto::CryptoError) -> VaultError {
    VaultError::BadPasswordOrCorrupted
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
    use crate::crypto::Dek;
    use crate::format::{
        serialize_body, RecordFields, VaultRecord, AEAD_ID_CHACHA20_POLY1305, HEADER_MAC_LEN,
        KDF_ID_ARGON2ID, KDF_SALT_LEN, NONCE_BODY_LEN, NONCE_DEK_LEN, VERSION, WRAPPED_DEK_LEN,
    };
    use crate::record::LoginInput;
    use std::io::Write;

    const TEST_PASSWORD: &str = "correct horse battery staple";

    // ── walidacja strukturalna (§12) - bajty bez krypto ───────────────────────

    // strukturalnie poprawne bajty pliku (naglowek + 1 bajt udawanego ct_body)
    fn structural_bytes() -> Vec<u8> {
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
        assert!(verify_structure(&structural_bytes()).is_ok());
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
        let mut b = structural_bytes();
        b[0] = b'X';
        assert!(matches!(
            verify_structure(&b),
            Err(VaultError::InvalidStructure(_))
        ));
    }

    // ── pelna sciezka open/decrypt (§16) - prawdziwy zaszyfrowany vault ────────

    // buduje prawdziwy, zaszyfrowany plik vault z jednym rekordem login.
    fn build_encrypted_vault() -> Vec<u8> {
        let kdf_salt = [7u8; KDF_SALT_LEN];
        let nonce_dek = [9u8; NONCE_DEK_LEN];
        let nonce_body = [11u8; NONCE_BODY_LEN];

        let master =
            crypto::derive_master_key(TEST_PASSWORD.as_bytes(), &kdf_salt, 65536, 3, 1).unwrap();
        let keys = crypto::derive_keys(&master).unwrap();

        let dek = Dek::from_bytes([42u8; 32]);
        let wrapped = crypto::wrap_dek(&keys.wrap_key, &nonce_dek, &dek).unwrap();

        let mut header = VaultHeader {
            version: VERSION,
            flags: 0,
            kdf_id: KDF_ID_ARGON2ID,
            kdf_params: KdfParams::default_v1(),
            kdf_salt,
            aead_id: AEAD_ID_CHACHA20_POLY1305,
            nonce_dek,
            wrapped_dek: wrapped,
            header_mac: [0u8; HEADER_MAC_LEN],
            nonce_body,
        };
        let canonical = header.serialize_canonical();
        header.header_mac = crypto::compute_header_mac(&keys.header_mac_key, &canonical);

        let body = VaultBody {
            schema_version: 1,
            records: vec![VaultRecord {
                id: [1u8; 16],
                record_type: "login".to_string(),
                title: "github".to_string(),
                tags: vec!["praca".to_string()],
                notes: String::new(),
                created_at: 1,
                modified_at: 1,
                fields: RecordFields::Login {
                    url: "https://github.com".to_string(),
                    username: "czarny".to_string(),
                    password: "tajne123".to_string(),
                },
            }],
        };
        let body_cbor = serialize_body(&body).unwrap();

        let aad = header.aad_for_body();
        let ct_body = crypto::encrypt_body(&dek, &nonce_body, &body_cbor, &aad).unwrap();

        let mut file = header.serialize_full();
        file.extend_from_slice(&ct_body);
        file
    }

    // zapisuje bajty do tymczasowego pliku (TempDir sam sie sprzata po tescie)
    fn write_temp(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vlt");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        (dir, path)
    }

    #[test]
    fn open_decrypts_records_with_correct_password() {
        let (_dir, path) = write_temp(&build_encrypted_vault());
        let records = decrypt_vault(&path, TEST_PASSWORD).unwrap();

        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.title, "github");
        assert_eq!(r.rtype, RecordType::Login);
        assert_eq!(view::field_value(r, "username").as_deref(), Some("czarny"));
        assert_eq!(
            view::field_value(r, "password").as_deref(),
            Some("tajne123")
        );
    }

    #[test]
    fn open_wrong_password_is_bad_or_corrupted() {
        let (_dir, path) = write_temp(&build_encrypted_vault());
        let err = decrypt_vault(&path, "zle haslo").unwrap_err();
        assert!(matches!(err, VaultError::BadPasswordOrCorrupted));
    }

    #[test]
    fn open_tampered_body_is_bad_or_corrupted() {
        // A1: zmiana bajtu w ct_body -> tag AEAD body nie pasuje
        let mut bytes = build_encrypted_vault();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let (_dir, path) = write_temp(&bytes);
        let err = decrypt_vault(&path, TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, VaultError::BadPasswordOrCorrupted));
    }

    #[test]
    fn open_tampered_header_is_bad_or_corrupted() {
        // A4: zmiana bajtu w wrapped_dek (offset 52, czesc canonical header)
        let mut bytes = build_encrypted_vault();
        bytes[52] ^= 0xFF;
        let (_dir, path) = write_temp(&bytes);
        let err = decrypt_vault(&path, TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, VaultError::BadPasswordOrCorrupted));
    }

    // ── init (§15): nowy vault round-trippuje z open ──────────────────────────

    #[test]
    fn init_then_open_roundtrip_empty_vault() {
        let bytes = build_new_vault_bytes(
            TEST_PASSWORD,
            [5u8; KDF_SALT_LEN],
            [6u8; 32],
            [7u8; NONCE_DEK_LEN],
            [8u8; NONCE_BODY_LEN],
        )
        .unwrap();
        let (_dir, path) = write_temp(&bytes);
        let records = decrypt_vault(&path, TEST_PASSWORD).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn init_vault_wrong_password_fails_to_open() {
        let bytes = build_new_vault_bytes(
            TEST_PASSWORD,
            [5u8; KDF_SALT_LEN],
            [6u8; 32],
            [7u8; NONCE_DEK_LEN],
            [8u8; NONCE_BODY_LEN],
        )
        .unwrap();
        let (_dir, path) = write_temp(&bytes);
        assert!(matches!(
            decrypt_vault(&path, "inne haslo"),
            Err(VaultError::BadPasswordOrCorrupted)
        ));
    }

    #[test]
    fn init_vault_passes_structural_verify() {
        let bytes = build_new_vault_bytes(
            TEST_PASSWORD,
            [5u8; KDF_SALT_LEN],
            [6u8; 32],
            [7u8; NONCE_DEK_LEN],
            [8u8; NONCE_BODY_LEN],
        )
        .unwrap();
        assert!(verify_structure(&bytes).is_ok());
    }

    // ── changepass (§18): nowe haslo otwiera, stare juz nie ────────────────────

    const NEW_PASSWORD: &str = "nowe haslo glowne super dlugie";

    fn rewrap_to_new_password(old_bytes: &[u8]) -> Vec<u8> {
        let (_dir, path) = write_temp(old_bytes);
        let (_h, dek, body_cbor) = decrypt_to_body_cbor(&path, TEST_PASSWORD).unwrap();
        assemble_vault_bytes(
            NEW_PASSWORD,
            &dek,
            &body_cbor,
            [13u8; KDF_SALT_LEN],
            [14u8; NONCE_DEK_LEN],
            [15u8; NONCE_BODY_LEN],
        )
        .unwrap()
    }

    #[test]
    fn changepass_new_password_opens_and_keeps_records() {
        let new_bytes = rewrap_to_new_password(&build_encrypted_vault());
        let (_dir, path) = write_temp(&new_bytes);
        let records = decrypt_vault(&path, NEW_PASSWORD).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].title, "github");
        assert_eq!(
            view::field_value(&records[0], "password").as_deref(),
            Some("tajne123")
        );
    }

    #[test]
    fn changepass_old_password_no_longer_opens() {
        // A6 / S-5: stare haslo nie otwiera juz biezacej wersji pliku
        let new_bytes = rewrap_to_new_password(&build_encrypted_vault());
        let (_dir, path) = write_temp(&new_bytes);
        assert!(matches!(
            decrypt_vault(&path, TEST_PASSWORD),
            Err(VaultError::BadPasswordOrCorrupted)
        ));
    }

    #[test]
    fn changepass_output_passes_structural_verify() {
        let new_bytes = rewrap_to_new_password(&build_encrypted_vault());
        assert!(verify_structure(&new_bytes).is_ok());
    }

    // ── zapis po modyfikacji (§17) + add (F-05) ───────────────────────────────

    #[test]
    fn save_adds_record_and_reopens() {
        // sesja: otwórz, dopisz rekord, zapisz (§17), otwórz ponownie -> 2 rekordy
        let (_dir, path) = write_temp(&build_encrypted_vault());
        let (header, dek, mut body) = decrypt_vault_body(&path, TEST_PASSWORD).unwrap();
        assert_eq!(body.records.len(), 1);

        body.records.push(VaultRecord {
            id: [2u8; 16],
            record_type: "login".to_string(),
            title: "gitlab".to_string(),
            tags: vec![],
            notes: String::new(),
            created_at: 2,
            modified_at: 2,
            fields: RecordFields::Login {
                url: "https://gitlab.com".to_string(),
                username: "u2".to_string(),
                password: "p2".to_string(),
            },
        });
        save_vault_with_nonce(&path, &header, &dek, &body, [77u8; NONCE_BODY_LEN]).unwrap();

        let records = decrypt_vault(&path, TEST_PASSWORD).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.title == "github"));
        assert!(records.iter().any(|r| r.title == "gitlab"));
    }

    #[test]
    fn save_rotates_nonce_body_but_keeps_header() {
        // §17: zapis zmienia tylko nonce_body i ct_body; naglowek (0..132) bez zmian
        let orig = build_encrypted_vault();
        let (_dir, path) = write_temp(&orig);
        let (header, dek, body) = decrypt_vault_body(&path, TEST_PASSWORD).unwrap();

        save_vault_with_nonce(&path, &header, &dek, &body, [99u8; NONCE_BODY_LEN]).unwrap();
        let after = std::fs::read(&path).unwrap();

        // canonical header + header_mac (0..132) nietkniete -> stare haslo dalej dziala
        assert_eq!(&orig[..132], &after[..132]);
        // nowy nonce_body (offset 132-143)
        assert_eq!(&after[132..144], &[99u8; NONCE_BODY_LEN]);
        assert_ne!(&orig[132..144], &after[132..144]);
        // i nadal otwiera sie tym samym haslem
        assert_eq!(decrypt_vault(&path, TEST_PASSWORD).unwrap().len(), 1);
    }

    #[test]
    fn record_maps_to_format_and_back() {
        // Record (model aplikacji) -> VaultRecord (format) -> Record, pola zachowane
        let inp = LoginInput {
            title: "x".to_string(),
            url: "https://u".to_string(),
            username: "usr".to_string(),
            password: "pw".to_string(),
            tags: vec!["t".to_string()],
            notes: "n".to_string(),
        };
        let rec = Record::new_login(inp, [3u8; 16], 5).unwrap();
        let vr = vault_record_from_record(&rec).unwrap();
        assert_eq!(vr.record_type, "login");

        let back = record_from_vault(&vr).unwrap();
        assert_eq!(back.title, "x");
        assert_eq!(view::field_value(&back, "username").as_deref(), Some("usr"));
        assert_eq!(view::field_value(&back, "password").as_deref(), Some("pw"));
    }
}
