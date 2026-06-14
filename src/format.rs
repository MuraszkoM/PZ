/// format.rs — parser i serializator formatu pliku vault v1
///
/// Ten moduł odpowiada za:
/// - parsowanie nagłówka binarnego (pierwsze 132 bajty pliku)
/// - serializację nagłówka do bajtów
/// - parsowanie body CBOR po deszyfrowaniu
/// - serializację rekordów do CBOR
///
/// Dokumentacja formatu: docs/SPEC.md
// Importy — w Rust musisz jawnie powiedzieć skąd bierzesz typy
use std::collections::BTreeMap;
use std::io::Cursor;

use ciborium::Value as CborValue;

/// Błędy które mogą wystąpić podczas parsowania/serializacji.
/// `#[derive(Debug)]` sprawia że możesz wypisać błąd przez {:?}
#[derive(Debug)]
pub enum FormatError {
    /// Plik za krótki żeby zawierać poprawny nagłówek
    FileTooShort,
    /// Pierwsze 4 bajty to nie "VLT1"
    InvalidMagic,
    /// Nieznana wersja formatu (obsługujemy tylko 0x0001)
    UnsupportedVersion(u16),
    /// Pole flags musi być 0x0000
    InvalidFlags,
    /// Nieznany identyfikator KDF (obsługujemy tylko 1 = Argon2id)
    UnsupportedKdfId(u8),
    /// Nieznany identyfikator AEAD (obsługujemy tylko 1 = ChaCha20-Poly1305)
    UnsupportedAeadId(u8),
    /// Pole wrapped_dek_len musi mieć wartość 48
    InvalidWrappedDekLen(u32),
    /// Pole kdf_salt_len musi mieć wartość 16
    InvalidKdfSaltLen(u8),
    /// Błąd podczas parsowania CBOR (body)
    CborError(String),
    /// Błąd podczas serializacji CBOR
    CborSerializeError(String),
    /// Brakuje wymaganego pola w rekordzie CBOR
    MissingField(String),
    /// Pole ma niepoprawny typ
    InvalidFieldType(String),
    /// Nieznany typ rekordu (w v1 to błąd)
    UnknownRecordType(String),
}

// Implementacja Display pozwala wypisać błąd jako ładny tekst dla użytkownika
impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::FileTooShort => write!(f, "Plik vault jest zbyt krótki"),
            FormatError::InvalidMagic => write!(f, "Nieprawidłowy nagłówek pliku (brak VLT1)"),
            FormatError::UnsupportedVersion(v) => write!(f, "Nieobsługiwana wersja formatu: {v}"),
            FormatError::InvalidFlags => write!(f, "Pole flags musi być 0x0000"),
            FormatError::UnsupportedKdfId(id) => write!(f, "Nieznany algorytm KDF: {id}"),
            FormatError::UnsupportedAeadId(id) => write!(f, "Nieznany algorytm AEAD: {id}"),
            FormatError::InvalidWrappedDekLen(l) => {
                write!(f, "Nieprawidłowa długość wrapped_dek: {l}, oczekiwano 48")
            }
            FormatError::InvalidKdfSaltLen(l) => {
                write!(f, "Nieprawidłowa długość kdf_salt: {l}, oczekiwano 16")
            }
            FormatError::CborError(msg) => write!(f, "Błąd parsowania CBOR: {msg}"),
            FormatError::CborSerializeError(msg) => write!(f, "Błąd serializacji CBOR: {msg}"),
            FormatError::MissingField(name) => {
                write!(f, "Brakujące wymagane pole rekordu: {name}")
            }
            FormatError::InvalidFieldType(name) => {
                write!(f, "Nieprawidłowy typ pola: {name}")
            }
            FormatError::UnknownRecordType(t) => {
                write!(f, "Nieznany typ rekordu w v1: {t}")
            }
        }
    }
}

// Implementacja standardowego traitu Error (potrzebna do integracji z resztą Rusta)
impl std::error::Error for FormatError {}

// ─── Stałe formatu ────────────────────────────────────────────────────────────

/// Pierwsze 4 bajty każdego pliku vault — "magic bytes"
pub const MAGIC: &[u8; 4] = b"VLT1";
/// Wersja formatu zapisana w nagłówku
pub const VERSION: u16 = 0x0001;
/// ID algorytmu KDF: Argon2id
pub const KDF_ID_ARGON2ID: u8 = 1;
/// ID algorytmu AEAD: ChaCha20-Poly1305
pub const AEAD_ID_CHACHA20_POLY1305: u8 = 1;

/// Długość soli KDF w bajtach
pub const KDF_SALT_LEN: usize = 16;
/// Długość nonce dla DEK w bajtach
pub const NONCE_DEK_LEN: usize = 12;
/// Długość opakowanego DEK: 32 B DEK + 16 B tag AEAD
pub const WRAPPED_DEK_LEN: usize = 48;
/// Długość HMAC-SHA256
pub const HEADER_MAC_LEN: usize = 32;
/// Długość nonce dla body
pub const NONCE_BODY_LEN: usize = 12;

/// Rozmiar canonical header (bajty 0..100 — bez header_mac)
pub const CANONICAL_HEADER_LEN: usize = 100;
/// Całkowity rozmiar nagłówka z MAC
pub const FULL_HEADER_LEN: usize = 132; // 100 + 32 MAC

/// Minimalna długość pliku: nagłówek (132 B) + nonce_body (12 B) + przynajmniej 1 bajt ct_body
pub const MIN_FILE_LEN: usize = FULL_HEADER_LEN + NONCE_BODY_LEN + 1;

// ─── Parametry KDF ────────────────────────────────────────────────────────────

/// Parametry Argon2id zapisane w nagłówku (i używane przy wyprowadzaniu kluczy)
#[derive(Debug, Clone, PartialEq)]
pub struct KdfParams {
    /// Zużycie pamięci w KiB (domyślnie 65536 = 64 MiB)
    pub memory_kib: u32,
    /// Liczba iteracji (domyślnie 3)
    pub iterations: u32,
    /// Równoległość (domyślnie 1)
    pub parallelism: u8,
}

impl KdfParams {
    /// Domyślne parametry zgodne z OWASP i wymaganiami projektu (ADR-004)
    pub fn default_v1() -> Self {
        KdfParams {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

// ─── Nagłówek pliku ───────────────────────────────────────────────────────────

/// Reprezentacja sparsowanego nagłówka pliku vault.
/// Odpowiada dokładnie strukturze binarnej opisanej w SPEC.md §5.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    // Bajty 0-3: magic (nie przechowujemy — zawsze VLT1)
    // Bajty 4-5: version
    pub version: u16,
    // Bajty 6-7: flags
    pub flags: u16,
    // Bajt 8: kdf_id
    pub kdf_id: u8,
    // Bajty 9-12: kdf_memory_kib
    // Bajty 13-16: kdf_iterations
    // Bajt 17: kdf_parallelism
    pub kdf_params: KdfParams,
    // Bajt 18: kdf_salt_len (zawsze 16 w v1)
    // Bajty 19-34: kdf_salt
    pub kdf_salt: [u8; KDF_SALT_LEN],
    // Bajt 35: aead_id
    pub aead_id: u8,
    // Bajty 36-47: nonce_dek
    pub nonce_dek: [u8; NONCE_DEK_LEN],
    // Bajty 48-51: wrapped_dek_len (zawsze 48)
    // Bajty 52-99: wrapped_dek
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    // Bajty 100-131: header_mac (przechowujemy osobno bo to nie jest canonical header)
    pub header_mac: [u8; HEADER_MAC_LEN],
    // Bajty 132-143: nonce_body
    pub nonce_body: [u8; NONCE_BODY_LEN],
}

impl VaultHeader {
    /// Serializuje canonical header (bajty 0..100) do Vec<u8>.
    /// To jest wejście do HMAC i AAD dla AEAD body (SPEC.md §6, §8).
    ///
    /// WAŻNE: canonical header NIE zawiera header_mac — tylko pierwsze 100 bajtów.
    pub fn serialize_canonical(&self) -> Vec<u8> {
        // Tworzymy bufor o dokładnie 100 bajtach
        let mut buf = Vec::with_capacity(CANONICAL_HEADER_LEN);

        // Offset 0-3: magic
        buf.extend_from_slice(MAGIC);

        // Offset 4-5: version (big-endian — to_be_bytes = "to big-endian bytes")
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Offset 6-7: flags
        buf.extend_from_slice(&self.flags.to_be_bytes());

        // Offset 8: kdf_id
        buf.push(self.kdf_id);

        // Offset 9-12: kdf_memory_kib
        buf.extend_from_slice(&self.kdf_params.memory_kib.to_be_bytes());

        // Offset 13-16: kdf_iterations
        buf.extend_from_slice(&self.kdf_params.iterations.to_be_bytes());

        // Offset 17: kdf_parallelism
        buf.push(self.kdf_params.parallelism);

        // Offset 18: kdf_salt_len (zawsze 16)
        buf.push(KDF_SALT_LEN as u8);

        // Offset 19-34: kdf_salt (16 bajtów)
        buf.extend_from_slice(&self.kdf_salt);

        // Offset 35: aead_id
        buf.push(self.aead_id);

        // Offset 36-47: nonce_dek (12 bajtów)
        buf.extend_from_slice(&self.nonce_dek);

        // Offset 48-51: wrapped_dek_len = 48
        buf.extend_from_slice(&(WRAPPED_DEK_LEN as u32).to_be_bytes());

        // Offset 52-99: wrapped_dek (48 bajtów)
        buf.extend_from_slice(&self.wrapped_dek);

        // Sanity check: canonical header musi mieć dokładnie 100 bajtów
        debug_assert_eq!(
            buf.len(),
            CANONICAL_HEADER_LEN,
            "błąd w serialize_canonical"
        );

        buf
    }

    /// Serializuje pełny nagłówek z header_mac i nonce_body (132 + 12 = 144 bajty).
    /// To jest to co faktycznie trafia na początek pliku.
    pub fn serialize_full(&self) -> Vec<u8> {
        let mut buf = self.serialize_canonical();

        // Offset 100-131: header_mac
        buf.extend_from_slice(&self.header_mac);

        // Offset 132-143: nonce_body
        buf.extend_from_slice(&self.nonce_body);

        debug_assert_eq!(buf.len(), FULL_HEADER_LEN + NONCE_BODY_LEN);

        buf
    }

    /// Oblicza AAD (Additional Authenticated Data) dla szyfrowania body.
    /// AAD = canonical_header || header_mac (bajty 0..132)
    /// Patrz SPEC.md §8.
    pub fn aad_for_body(&self) -> Vec<u8> {
        let mut aad = self.serialize_canonical();
        aad.extend_from_slice(&self.header_mac);
        // aad ma teraz 100 + 32 = 132 bajty
        debug_assert_eq!(aad.len(), FULL_HEADER_LEN);
        aad
    }
}

/// Parsuje nagłówek z surowych bajtów pliku.
///
/// `data` — pełna zawartość pliku (lub przynajmniej pierwsze 144 bajty)
///
/// Zwraca `Ok(VaultHeader)` jeśli nagłówek jest poprawny strukturalnie.
/// NIE sprawdza HMAC ani nie deszyfruje — to robi Vault Service.
pub fn parse_header(data: &[u8]) -> Result<VaultHeader, FormatError> {
    // Sprawdź minimalną długość pliku
    if data.len() < MIN_FILE_LEN {
        return Err(FormatError::FileTooShort);
    }

    // Sprawdź magic "VLT1"
    if &data[0..4] != MAGIC {
        return Err(FormatError::InvalidMagic);
    }

    // Parsuj version (big-endian u16 z bajtów 4-5)
    // u16::from_be_bytes przyjmuje tablicę [u8; 2], dlatego try_into()
    let version = u16::from_be_bytes(data[4..6].try_into().unwrap());
    if version != VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }

    // Parsuj flags — muszą być 0
    let flags = u16::from_be_bytes(data[6..8].try_into().unwrap());
    if flags != 0 {
        return Err(FormatError::InvalidFlags);
    }

    // Parsuj kdf_id — obsługujemy tylko 1 (Argon2id)
    let kdf_id = data[8];
    if kdf_id != KDF_ID_ARGON2ID {
        return Err(FormatError::UnsupportedKdfId(kdf_id));
    }

    // Parsuj parametry KDF
    let kdf_memory_kib = u32::from_be_bytes(data[9..13].try_into().unwrap());
    let kdf_iterations = u32::from_be_bytes(data[13..17].try_into().unwrap());
    let kdf_parallelism = data[17];

    // Sprawdź kdf_salt_len — musi być 16
    let kdf_salt_len = data[18];
    if kdf_salt_len != KDF_SALT_LEN as u8 {
        return Err(FormatError::InvalidKdfSaltLen(kdf_salt_len));
    }

    // Skopiuj kdf_salt (16 bajtów, offset 19-34)
    let mut kdf_salt = [0u8; KDF_SALT_LEN];
    kdf_salt.copy_from_slice(&data[19..35]);

    // Sprawdź aead_id — obsługujemy tylko 1 (ChaCha20-Poly1305)
    let aead_id = data[35];
    if aead_id != AEAD_ID_CHACHA20_POLY1305 {
        return Err(FormatError::UnsupportedAeadId(aead_id));
    }

    // Skopiuj nonce_dek (12 bajtów, offset 36-47)
    let mut nonce_dek = [0u8; NONCE_DEK_LEN];
    nonce_dek.copy_from_slice(&data[36..48]);

    // Sprawdź wrapped_dek_len — musi być 48
    let wrapped_dek_len = u32::from_be_bytes(data[48..52].try_into().unwrap());
    if wrapped_dek_len != WRAPPED_DEK_LEN as u32 {
        return Err(FormatError::InvalidWrappedDekLen(wrapped_dek_len));
    }

    // Skopiuj wrapped_dek (48 bajtów, offset 52-99)
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(&data[52..100]);

    // Skopiuj header_mac (32 bajty, offset 100-131)
    let mut header_mac = [0u8; HEADER_MAC_LEN];
    header_mac.copy_from_slice(&data[100..132]);

    // Skopiuj nonce_body (12 bajtów, offset 132-143)
    let mut nonce_body = [0u8; NONCE_BODY_LEN];
    nonce_body.copy_from_slice(&data[132..144]);

    Ok(VaultHeader {
        version,
        flags,
        kdf_id,
        kdf_params: KdfParams {
            memory_kib: kdf_memory_kib,
            iterations: kdf_iterations,
            parallelism: kdf_parallelism,
        },
        kdf_salt,
        aead_id,
        nonce_dek,
        wrapped_dek,
        header_mac,
        nonce_body,
    })
}

// ─── Rekordy ──────────────────────────────────────────────────────────────────

/// Pola specyficzne dla typu rekordu.
/// Na MVP implementujemy tylko Login, pozostałe typy są przygotowane jako stub.
#[derive(Debug, Clone)]
pub enum RecordFields {
    Login {
        url: String,
        username: String,
        password: String,
    },
    /// Rozszerzenia (M6) — na razie tylko placeholder
    Note {
        content: String,
    },
    ApiKey {
        key: String,
        environment: String,
    },
    Totp {
        secret_base32: String,
        algorithm: String,
        digits: u64,
        period: u64,
    },
    SshKey {
        public_key: String,
        private_key: String,
        passphrase: String,
    },
}

/// Jeden rekord z body vaulta.
/// Odpowiada strukturze Record z SPEC.md §9.
#[derive(Debug, Clone)]
pub struct VaultRecord {
    /// UUID v4 jako 16 bajtów
    pub id: [u8; 16],
    /// Typ rekordu: "login", "note", itp.
    pub record_type: String,
    /// Tytuł rekordu (nadawany przez użytkownika)
    pub title: String,
    /// Tagi (mogą być puste)
    pub tags: Vec<String>,
    /// Notatka wolnotekstowa (może być pusta)
    pub notes: String,
    /// Czas utworzenia (Unix nanoseconds)
    pub created_at: u64,
    /// Czas ostatniej modyfikacji (Unix nanoseconds)
    pub modified_at: u64,
    /// Pola specyficzne dla typu
    pub fields: RecordFields,
}

/// Cała zawartość body (po deszyfrowaniu i sparsowaniu CBOR).
#[derive(Debug, Clone)]
pub struct VaultBody {
    /// Wersja schematu CBOR (nie mylić z wersją formatu pliku)
    pub schema_version: u64,
    /// Lista rekordów
    pub records: Vec<VaultRecord>,
}

// ─── Serializacja body do CBOR ────────────────────────────────────────────────

/// Serializuje VaultBody do canonical CBOR (Vec<u8>).
/// Wynik trafia jako plaintext do AEAD.encrypt.
pub fn serialize_body(body: &VaultBody) -> Result<Vec<u8>, FormatError> {
    // Budujemy mapę CBOR dla całego vaulta
    let mut vault_map: Vec<(CborValue, CborValue)> = Vec::new();

    vault_map.push((
        CborValue::Text("schema_version".to_string()),
        CborValue::Integer(body.schema_version.into()),
    ));

    // Serializuj każdy rekord jako CBOR map
    let records_cbor: Vec<CborValue> = body
        .records
        .iter()
        .map(serialize_record)
        .collect::<Result<Vec<_>, _>>()?;

    vault_map.push((
        CborValue::Text("records".to_string()),
        CborValue::Array(records_cbor),
    ));

    let cbor_value = CborValue::Map(vault_map);

    // Serializuj do bajtów
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut buf)
        .map_err(|e| FormatError::CborSerializeError(e.to_string()))?;

    Ok(buf)
}

/// Pomocnicza funkcja serializująca jeden rekord do CborValue.
fn serialize_record(record: &VaultRecord) -> Result<CborValue, FormatError> {
    // BTreeMap zapewnia posortowane klucze (canonical ordering)
    let mut map: Vec<(CborValue, CborValue)> = Vec::new();

    // id — 16 bajtów UUID
    map.push((
        CborValue::Text("id".to_string()),
        CborValue::Bytes(record.id.to_vec()),
    ));

    // type
    map.push((
        CborValue::Text("type".to_string()),
        CborValue::Text(record.record_type.clone()),
    ));

    // title
    map.push((
        CborValue::Text("title".to_string()),
        CborValue::Text(record.title.clone()),
    ));

    // tags — lista stringów
    let tags_cbor: Vec<CborValue> = record
        .tags
        .iter()
        .map(|t| CborValue::Text(t.clone()))
        .collect();
    map.push((
        CborValue::Text("tags".to_string()),
        CborValue::Array(tags_cbor),
    ));

    // notes
    map.push((
        CborValue::Text("notes".to_string()),
        CborValue::Text(record.notes.clone()),
    ));

    // created_at
    map.push((
        CborValue::Text("created_at".to_string()),
        CborValue::Integer(record.created_at.into()),
    ));

    // modified_at
    map.push((
        CborValue::Text("modified_at".to_string()),
        CborValue::Integer(record.modified_at.into()),
    ));

    // fields — mapa specyficzna dla typu
    let fields_map = serialize_fields(&record.fields)?;
    map.push((CborValue::Text("fields".to_string()), fields_map));

    Ok(CborValue::Map(map))
}

/// Serializuje pola specyficzne dla typu rekordu.
fn serialize_fields(fields: &RecordFields) -> Result<CborValue, FormatError> {
    let mut map: Vec<(CborValue, CborValue)> = Vec::new();

    match fields {
        RecordFields::Login {
            url,
            username,
            password,
        } => {
            map.push((
                CborValue::Text("url".to_string()),
                CborValue::Text(url.clone()),
            ));
            map.push((
                CborValue::Text("username".to_string()),
                CborValue::Text(username.clone()),
            ));
            map.push((
                CborValue::Text("password".to_string()),
                CborValue::Text(password.clone()),
            ));
        }
        RecordFields::Note { content } => {
            map.push((
                CborValue::Text("content".to_string()),
                CborValue::Text(content.clone()),
            ));
        }
        RecordFields::ApiKey { key, environment } => {
            map.push((
                CborValue::Text("key".to_string()),
                CborValue::Text(key.clone()),
            ));
            map.push((
                CborValue::Text("environment".to_string()),
                CborValue::Text(environment.clone()),
            ));
        }
        RecordFields::Totp {
            secret_base32,
            algorithm,
            digits,
            period,
        } => {
            map.push((
                CborValue::Text("secret_base32".to_string()),
                CborValue::Text(secret_base32.clone()),
            ));
            map.push((
                CborValue::Text("algorithm".to_string()),
                CborValue::Text(algorithm.clone()),
            ));
            map.push((
                CborValue::Text("digits".to_string()),
                CborValue::Integer((*digits).into()),
            ));
            map.push((
                CborValue::Text("period".to_string()),
                CborValue::Integer((*period).into()),
            ));
        }
        RecordFields::SshKey {
            public_key,
            private_key,
            passphrase,
        } => {
            map.push((
                CborValue::Text("public_key".to_string()),
                CborValue::Text(public_key.clone()),
            ));
            map.push((
                CborValue::Text("private_key".to_string()),
                CborValue::Text(private_key.clone()),
            ));
            map.push((
                CborValue::Text("passphrase".to_string()),
                CborValue::Text(passphrase.clone()),
            ));
        }
    }

    Ok(CborValue::Map(map))
}

// ─── Parsowanie body z CBOR ───────────────────────────────────────────────────

/// Parsuje CBOR body do VaultBody.
/// `data` — bajty po deszyfrowaniu AEAD.
pub fn parse_body(data: &[u8]) -> Result<VaultBody, FormatError> {
    // Parsuj CBOR z bajtów
    let value: CborValue = ciborium::de::from_reader(Cursor::new(data))
        .map_err(|e| FormatError::CborError(e.to_string()))?;

    // Oczekujemy mapy na najwyższym poziomie
    let map = cbor_map(value, "vault root")?;

    // schema_version
    let schema_version = cbor_get_uint(&map, "schema_version")?;

    // records — lista
    let records_val = map
        .get("records")
        .ok_or_else(|| FormatError::MissingField("records".to_string()))?;

    let records_arr = match records_val {
        CborValue::Array(arr) => arr,
        _ => return Err(FormatError::InvalidFieldType("records".to_string())),
    };

    let records: Vec<VaultRecord> = records_arr
        .iter()
        .map(|v| parse_record(v.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VaultBody {
        schema_version,
        records,
    })
}

/// Parsuje jeden rekord z CborValue.
fn parse_record(value: CborValue) -> Result<VaultRecord, FormatError> {
    let map = cbor_map(value, "record")?;

    // id — 16 bajtów
    let id_bytes = cbor_get_bytes(&map, "id")?;
    if id_bytes.len() != 16 {
        return Err(FormatError::InvalidFieldType(
            "id (oczekiwano 16 bajtów)".to_string(),
        ));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_bytes);

    let record_type = cbor_get_text(&map, "type")?;

    // Walidacja typu w v1 (SPEC.md §11 — nieznane typy to błąd)
    let valid_types = ["login", "note", "apikey", "totp", "sshkey", "attachment"];
    if !valid_types.contains(&record_type.as_str()) {
        return Err(FormatError::UnknownRecordType(record_type));
    }

    let title = cbor_get_text(&map, "title")?;

    // tags — lista stringów
    let tags_val = map
        .get("tags")
        .ok_or_else(|| FormatError::MissingField("tags".to_string()))?;
    let tags = match tags_val {
        CborValue::Array(arr) => arr
            .iter()
            .map(|v| match v {
                CborValue::Text(s) => Ok(s.clone()),
                _ => Err(FormatError::InvalidFieldType("tags element".to_string())),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(FormatError::InvalidFieldType("tags".to_string())),
    };

    let notes = cbor_get_text(&map, "notes")?;
    let created_at = cbor_get_uint(&map, "created_at")?;
    let modified_at = cbor_get_uint(&map, "modified_at")?;

    // fields — mapa specyficzna dla typu
    let fields_val = map
        .get("fields")
        .ok_or_else(|| FormatError::MissingField("fields".to_string()))?
        .clone();
    let fields = parse_fields(fields_val, &record_type)?;

    Ok(VaultRecord {
        id,
        record_type,
        title,
        tags,
        notes,
        created_at,
        modified_at,
        fields,
    })
}

/// Parsuje mapę fields specyficzną dla danego typu rekordu.
fn parse_fields(value: CborValue, record_type: &str) -> Result<RecordFields, FormatError> {
    let map = cbor_map(value, "fields")?;

    match record_type {
        "login" => {
            let url = cbor_get_text(&map, "url")?;
            let username = cbor_get_text(&map, "username")?;
            let password = cbor_get_text(&map, "password")?;
            Ok(RecordFields::Login {
                url,
                username,
                password,
            })
        }
        "note" => {
            let content = cbor_get_text(&map, "content")?;
            Ok(RecordFields::Note { content })
        }
        "apikey" => {
            let key = cbor_get_text(&map, "key")?;
            let environment = cbor_get_text(&map, "environment")?;
            Ok(RecordFields::ApiKey { key, environment })
        }
        "totp" => {
            let secret_base32 = cbor_get_text(&map, "secret_base32")?;
            let algorithm = cbor_get_text(&map, "algorithm")?;
            let digits = cbor_get_uint(&map, "digits")?;
            let period = cbor_get_uint(&map, "period")?;
            Ok(RecordFields::Totp {
                secret_base32,
                algorithm,
                digits,
                period,
            })
        }
        "sshkey" => {
            let public_key = cbor_get_text(&map, "public_key")?;
            let private_key = cbor_get_text(&map, "private_key")?;
            let passphrase = cbor_get_text(&map, "passphrase")?;
            Ok(RecordFields::SshKey {
                public_key,
                private_key,
                passphrase,
            })
        }
        _ => Err(FormatError::UnknownRecordType(record_type.to_string())),
    }
}

// ─── Pomocnicze funkcje CBOR ──────────────────────────────────────────────────
// Te funkcje zamieniają CborValue na konkretne typy Rusta i zwracają czytelne błędy.

/// Konwertuje CborValue na BTreeMap<String, CborValue> (alias dla mapy CBOR).
fn cbor_map(value: CborValue, context: &str) -> Result<BTreeMap<String, CborValue>, FormatError> {
    match value {
        CborValue::Map(pairs) => {
            let mut map = BTreeMap::new();
            for (k, v) in pairs {
                match k {
                    CborValue::Text(key) => {
                        map.insert(key, v);
                    }
                    _ => {
                        return Err(FormatError::InvalidFieldType(format!(
                            "{context}: klucz mapy nie jest tekstem"
                        )))
                    }
                }
            }
            Ok(map)
        }
        _ => Err(FormatError::InvalidFieldType(format!(
            "{context}: oczekiwano mapy CBOR"
        ))),
    }
}

/// Wyciąga pole tekstowe z mapy CBOR.
fn cbor_get_text(map: &BTreeMap<String, CborValue>, field: &str) -> Result<String, FormatError> {
    match map.get(field) {
        Some(CborValue::Text(s)) => Ok(s.clone()),
        Some(_) => Err(FormatError::InvalidFieldType(field.to_string())),
        None => Err(FormatError::MissingField(field.to_string())),
    }
}

/// Wyciąga pole uint (u64) z mapy CBOR.
fn cbor_get_uint(map: &BTreeMap<String, CborValue>, field: &str) -> Result<u64, FormatError> {
    match map.get(field) {
        Some(CborValue::Integer(i)) => {
            // ciborium::Integer obsługuje i128, my chcemy u64
            let v: i128 = (*i).into();
            u64::try_from(v).map_err(|_| FormatError::InvalidFieldType(field.to_string()))
        }
        Some(_) => Err(FormatError::InvalidFieldType(field.to_string())),
        None => Err(FormatError::MissingField(field.to_string())),
    }
}

/// Wyciąga pole bajtowe z mapy CBOR.
fn cbor_get_bytes(map: &BTreeMap<String, CborValue>, field: &str) -> Result<Vec<u8>, FormatError> {
    match map.get(field) {
        Some(CborValue::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(FormatError::InvalidFieldType(field.to_string())),
        None => Err(FormatError::MissingField(field.to_string())),
    }
}

// ─── Testy jednostkowe ────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje minimalny poprawny nagłówek do testów.
    fn make_test_header() -> VaultHeader {
        VaultHeader {
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
        }
    }

    /// Buduje minimalny poprawny plik binarny do testów parsera nagłówka.
    fn make_test_file_bytes(header: &VaultHeader) -> Vec<u8> {
        let mut bytes = header.serialize_full();
        // Dodaj fałszywe ct_body (1 bajt wystarczy do MIN_FILE_LEN)
        bytes.push(0xAB);
        bytes
    }

    // ── Testy serializacji nagłówka ───────────────────────────────────────────

    #[test]
    fn canonical_header_has_correct_length() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        assert_eq!(canonical.len(), CANONICAL_HEADER_LEN);
    }

    #[test]
    fn canonical_header_starts_with_magic() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        assert_eq!(&canonical[0..4], b"VLT1");
    }

    #[test]
    fn canonical_header_version_big_endian() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        // version = 0x0001 w big-endian to [0x00, 0x01]
        assert_eq!(&canonical[4..6], &[0x00, 0x01]);
    }

    #[test]
    fn canonical_header_flags_zero() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        assert_eq!(&canonical[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn canonical_header_kdf_id() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        assert_eq!(canonical[8], KDF_ID_ARGON2ID);
    }

    #[test]
    fn canonical_header_kdf_memory_big_endian() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        // 65536 = 0x00010000
        let expected = 65536u32.to_be_bytes();
        assert_eq!(&canonical[9..13], &expected);
    }

    #[test]
    fn canonical_header_salt_len_field() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        // offset 18 = kdf_salt_len = 16
        assert_eq!(canonical[18], 16u8);
    }

    #[test]
    fn canonical_header_wrapped_dek_len_field() {
        let h = make_test_header();
        let canonical = h.serialize_canonical();
        // offset 48-51 = wrapped_dek_len = 48 = 0x00000030
        let expected = 48u32.to_be_bytes();
        assert_eq!(&canonical[48..52], &expected);
    }

    #[test]
    fn full_header_length() {
        let h = make_test_header();
        let full = h.serialize_full();
        assert_eq!(full.len(), FULL_HEADER_LEN + NONCE_BODY_LEN);
    }

    #[test]
    fn aad_for_body_length() {
        let h = make_test_header();
        let aad = h.aad_for_body();
        assert_eq!(aad.len(), FULL_HEADER_LEN); // 100 + 32 = 132
    }

    // ── Testy parsowania nagłówka ─────────────────────────────────────────────

    #[test]
    fn parse_valid_header_roundtrip() {
        let original = make_test_header();
        let bytes = make_test_file_bytes(&original);
        let parsed = parse_header(&bytes).expect("powinien sparsować poprawny nagłówek");

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.kdf_id, original.kdf_id);
        assert_eq!(parsed.kdf_params.memory_kib, original.kdf_params.memory_kib);
        assert_eq!(parsed.kdf_params.iterations, original.kdf_params.iterations);
        assert_eq!(parsed.kdf_salt, original.kdf_salt);
        assert_eq!(parsed.aead_id, original.aead_id);
        assert_eq!(parsed.nonce_dek, original.nonce_dek);
        assert_eq!(parsed.wrapped_dek, original.wrapped_dek);
        assert_eq!(parsed.header_mac, original.header_mac);
        assert_eq!(parsed.nonce_body, original.nonce_body);
    }

    #[test]
    fn parse_rejects_empty_file() {
        let result = parse_header(&[]);
        assert!(matches!(result, Err(FormatError::FileTooShort)));
    }

    #[test]
    fn parse_rejects_too_short_file() {
        let result = parse_header(&[0u8; 10]);
        assert!(matches!(result, Err(FormatError::FileTooShort)));
    }

    #[test]
    fn parse_rejects_wrong_magic() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        // Zmień pierwsze 4 bajty na coś złego
        bytes[0] = b'X';
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::InvalidMagic)));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        // Zmień wersję na 0x0002
        bytes[4] = 0x00;
        bytes[5] = 0x02;
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::UnsupportedVersion(2))));
    }

    #[test]
    fn parse_rejects_nonzero_flags() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        bytes[6] = 0xFF;
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::InvalidFlags)));
    }

    #[test]
    fn parse_rejects_unknown_kdf_id() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        bytes[8] = 99; // nieznany KDF
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::UnsupportedKdfId(99))));
    }

    #[test]
    fn parse_rejects_unknown_aead_id() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        bytes[35] = 99; // nieznany AEAD
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::UnsupportedAeadId(99))));
    }

    #[test]
    fn parse_rejects_wrong_wrapped_dek_len() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        // wrapped_dek_len na offset 48-51
        bytes[48] = 0x00;
        bytes[49] = 0x00;
        bytes[50] = 0x00;
        bytes[51] = 0x10; // 16 zamiast 48
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::InvalidWrappedDekLen(16))));
    }

    #[test]
    fn parse_rejects_wrong_kdf_salt_len() {
        let h = make_test_header();
        let mut bytes = make_test_file_bytes(&h);
        bytes[18] = 8; // 8 zamiast 16
        let result = parse_header(&bytes);
        assert!(matches!(result, Err(FormatError::InvalidKdfSaltLen(8))));
    }

    // ── Testy CBOR body ───────────────────────────────────────────────────────

    fn make_test_body() -> VaultBody {
        VaultBody {
            schema_version: 1,
            records: vec![VaultRecord {
                id: [
                    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f,
                    0xd4, 0x30, 0xc8,
                ],
                record_type: "login".to_string(),
                title: "Test login".to_string(),
                tags: vec!["test".to_string()],
                notes: "Testowa notatka".to_string(),
                created_at: 1_700_000_000_000_000_000,
                modified_at: 1_700_000_001_000_000_000,
                fields: RecordFields::Login {
                    url: "https://example.com".to_string(),
                    username: "user@example.com".to_string(),
                    password: "secret_password".to_string(),
                },
            }],
        }
    }

    #[test]
    fn body_serialize_parse_roundtrip() {
        let original = make_test_body();
        let cbor_bytes = serialize_body(&original).expect("serializacja powinna się udać");
        let parsed = parse_body(&cbor_bytes).expect("parsowanie powinno się udać");

        assert_eq!(parsed.schema_version, original.schema_version);
        assert_eq!(parsed.records.len(), original.records.len());

        let orig_rec = &original.records[0];
        let parsed_rec = &parsed.records[0];

        assert_eq!(parsed_rec.id, orig_rec.id);
        assert_eq!(parsed_rec.record_type, orig_rec.record_type);
        assert_eq!(parsed_rec.title, orig_rec.title);
        assert_eq!(parsed_rec.tags, orig_rec.tags);
        assert_eq!(parsed_rec.notes, orig_rec.notes);
        assert_eq!(parsed_rec.created_at, orig_rec.created_at);
        assert_eq!(parsed_rec.modified_at, orig_rec.modified_at);

        // Sprawdź pola login
        if let RecordFields::Login {
            url,
            username,
            password,
        } = &parsed_rec.fields
        {
            assert_eq!(url, "https://example.com");
            assert_eq!(username, "user@example.com");
            assert_eq!(password, "secret_password");
        } else {
            panic!("oczekiwano RecordFields::Login");
        }
    }

    #[test]
    fn body_empty_records() {
        let body = VaultBody {
            schema_version: 1,
            records: vec![],
        };
        let bytes = serialize_body(&body).expect("serializacja pustego body");
        let parsed = parse_body(&bytes).expect("parsowanie pustego body");
        assert_eq!(parsed.records.len(), 0);
        assert_eq!(parsed.schema_version, 1);
    }

    #[test]
    fn parse_body_rejects_garbage() {
        let garbage = b"to nie jest CBOR!!!";
        let result = parse_body(garbage);
        assert!(matches!(result, Err(FormatError::CborError(_))));
    }
}
