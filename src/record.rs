// schemat rekordow (model w pamieci) - moja dzialka jako Application Engineer
//
// to sa struktury logiczne wg specyfikacji §4.2 / §8.2. NIE robimy tu CBOR ani
// szyfrowania - serializacja do canonical CBOR to robota Format (Halejcio),
// a krypto bierze Palik. tutaj tylko typy + walidacja danych od usera.
//
// w MVP obowiazkowy jest tylko typ login (§3.3). reszta typow (note, apikey,
// totp, sshkey, attachment) to rozszerzenia - dlozymy je pozniej.

use std::collections::BTreeMap;

// typ rekordu. na razie tylko login, reszta przyjdzie z rozszerzeniami.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Login,
}

impl RecordType {
    // tekstowa nazwa jaka wyladuje w polu "type" body (§8.2)
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::Login => "login",
        }
    }
}

// jedna wartosc pola. w §8.2 fields to mapa tstr => tstr/bytes/uint.
// na potrzeby logina wystarcza tekst, ale zostawiam wariant na bajty/liczbe
// zeby pozniejsze typy (attachment, totp) mialy sie gdzie wpiac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Text(String),
    Bytes(Vec<u8>),
    Uint(u64),
}

// wspolne pola dla kazdego rekordu (§4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: [u8; 16], // UUID v4 jako 16 bajtow, niezmienny
    pub rtype: RecordType,
    pub title: String,
    pub tags: Vec<String>,
    pub notes: String,
    pub created_at: u64,                      // Unix nanos
    pub modified_at: u64,                     // Unix nanos
    pub fields: BTreeMap<String, FieldValue>, // BTreeMap -> klucze posortowane (pod canonical CBOR)
}

// dane ktore user podaje przy "add login". id/timestampy dorabiamy sami.
#[derive(Debug, Clone)]
pub struct LoginInput {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub tags: Vec<String>,
    pub notes: String,
}

impl Record {
    // budowa rekordu login z danych usera.
    // id i czasy wstrzykujemy z zewnatrz, zeby ta funkcja byla deterministyczna
    // i testowalna (RNG/zegar siedza w warstwie wyzej, nie tutaj).
    pub fn new_login(
        input: LoginInput,
        id: [u8; 16],
        now_nanos: u64,
    ) -> Result<Record, &'static str> {
        if input.title.trim().is_empty() {
            return Err("tytul nie moze byc pusty");
        }
        if input.username.is_empty() {
            return Err("username nie moze byc pusty");
        }

        let mut fields = BTreeMap::new();
        fields.insert("url".to_string(), FieldValue::Text(input.url));
        fields.insert("username".to_string(), FieldValue::Text(input.username));
        fields.insert("password".to_string(), FieldValue::Text(input.password));

        Ok(Record {
            id,
            rtype: RecordType::Login,
            title: input.title,
            tags: input.tags,
            notes: input.notes,
            created_at: now_nanos,
            modified_at: now_nanos,
            fields,
        })
    }

    // krotki UUID w formie hex do pokazania userowi (np. w list/get)
    pub fn id_hex(&self) -> String {
        self.id.iter().map(|b| format!("{b:02x}")).collect()
    }

    // podglad bezpieczny do "list" - BEZ wartosci sekretow (F-03).
    // pokazujemy tylko id, typ i tytul.
    pub fn summary(&self) -> String {
        format!("{}  {}  {}", self.id_hex(), self.rtype.as_str(), self.title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LoginInput {
        LoginInput {
            title: "github".to_string(),
            url: "https://github.com".to_string(),
            username: "czarny".to_string(),
            password: "tajne123".to_string(),
            tags: vec!["praca".to_string()],
            notes: String::new(),
        }
    }

    #[test]
    fn builds_login_record() {
        let r = Record::new_login(sample(), [0u8; 16], 42).unwrap();
        assert_eq!(r.rtype, RecordType::Login);
        assert_eq!(r.created_at, 42);
        assert_eq!(r.modified_at, 42);
        // pola specyficzne dla logina obecne
        assert!(r.fields.contains_key("url"));
        assert!(r.fields.contains_key("username"));
        assert!(r.fields.contains_key("password"));
    }

    #[test]
    fn empty_title_is_rejected() {
        let mut inp = sample();
        inp.title = "   ".to_string();
        assert!(Record::new_login(inp, [0u8; 16], 1).is_err());
    }

    #[test]
    fn empty_username_is_rejected() {
        let mut inp = sample();
        inp.username = String::new();
        assert!(Record::new_login(inp, [0u8; 16], 1).is_err());
    }

    #[test]
    fn summary_does_not_leak_password() {
        // wazne: list nie moze pokazywac hasla (F-03)
        let r = Record::new_login(sample(), [0xabu8; 16], 1).unwrap();
        let s = r.summary();
        assert!(!s.contains("tajne123"));
        assert!(s.contains("github"));
    }

    #[test]
    fn id_hex_has_32_chars() {
        let r = Record::new_login(sample(), [0xffu8; 16], 1).unwrap();
        assert_eq!(r.id_hex().len(), 32);
        assert_eq!(r.id_hex(), "ff".repeat(16));
    }
}
