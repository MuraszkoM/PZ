// view - formatowanie wyjscia dla CLI (list / get)
//
// czysta logika prezentacji, bez I/O i bez krypto. operuje na gotowej liscie
// rekordow w pamieci (typ record::Record). docelowo te rekordy dostarczy Vault
// Service po odszyfrowaniu vaulta, ale samo wyswietlanie nalezy do CLI (moja dzialka).
//
// podzial wg specyfikacji:
//  - list (F-03): tylko tytuly i metadane, BEZ wartosci sekretow
//  - get  (F-04): pokazuje rekord (z wartosciami), --field wypisuje jedno pole

use crate::record::{FieldValue, Record};

// czy dane pole danego typu rekordu jest sekretem. na razie tylko login.password.
// przyda sie pod przyszle --clip i kolejne typy (apikey.key itd.)
pub fn is_secret_field(record_type: &str, field: &str) -> bool {
    matches!((record_type, field), ("login", "password"))
}

// wartosc pola jako tekst (Bytes pokazujemy jako rozmiar, nie surowe bajty)
fn value_to_string(v: &FieldValue) -> String {
    match v {
        FieldValue::Text(s) => s.clone(),
        FieldValue::Uint(n) => n.to_string(),
        FieldValue::Bytes(b) => format!("<{} bajtow>", b.len()),
    }
}

// filtrowanie po typie i/lub tagu (F-03: --type / --tag). None = brak filtra.
pub fn filter<'a>(
    records: &'a [Record],
    type_filter: Option<&str>,
    tag_filter: Option<&str>,
) -> Vec<&'a Record> {
    records
        .iter()
        .filter(|r| match type_filter {
            Some(t) => r.rtype.as_str() == t,
            None => true,
        })
        .filter(|r| match tag_filter {
            Some(tag) => r.tags.iter().any(|t| t == tag),
            None => true,
        })
        .collect()
}

// szukanie rekordu po id (akceptujemy prefiks hex) albo po dokladnym tytule.
// get przyjmuje <id|nazwa> (F-04), wiec obslugujemy oba.
pub fn find<'a>(records: &'a [Record], query: &str) -> Option<&'a Record> {
    let q = query.trim();
    records
        .iter()
        .find(|r| (!q.is_empty() && r.id_hex().starts_with(q)) || r.title == q)
}

// tabelka dla `list` - kolumny: ID (8 znakow), TYP, TYTUL, TAGI.
// BEZ wartosci sekretow (F-03) - same metadane.
pub fn format_list(records: &[Record]) -> String {
    if records.is_empty() {
        return "Brak rekordow.".to_string();
    }

    let id_w = 8usize; // skrocony id (pierwsze 8 znakow hex)
    let type_w = records
        .iter()
        .map(|r| r.rtype.as_str().len())
        .max()
        .unwrap_or(3)
        .max("TYP".len());
    let title_w = records
        .iter()
        .map(|r| r.title.len())
        .max()
        .unwrap_or(5)
        .max("TYTUL".len());

    let mut out = String::new();
    out.push_str(&format!(
        "{:<id_w$}  {:<type_w$}  {:<title_w$}  {}\n",
        "ID", "TYP", "TYTUL", "TAGI"
    ));
    for r in records {
        let short_id: String = r.id_hex().chars().take(id_w).collect();
        let tags = r.tags.join(", ");
        out.push_str(&format!(
            "{:<id_w$}  {:<type_w$}  {:<title_w$}  {}\n",
            short_id,
            r.rtype.as_str(),
            r.title,
            tags
        ));
    }
    out.trim_end().to_string()
}

// szczegoly jednego rekordu dla `get` (F-04: pokazuje rekord, z wartosciami).
pub fn format_detail(record: &Record) -> String {
    let mut out = String::new();
    out.push_str(&format!("ID:      {}\n", record.id_hex()));
    out.push_str(&format!("Typ:     {}\n", record.rtype.as_str()));
    out.push_str(&format!("Tytul:   {}\n", record.title));
    if !record.tags.is_empty() {
        out.push_str(&format!("Tagi:    {}\n", record.tags.join(", ")));
    }
    if !record.notes.is_empty() {
        out.push_str(&format!("Notatki: {}\n", record.notes));
    }
    out.push_str("Pola:\n");
    for (name, value) in &record.fields {
        out.push_str(&format!("  {name}: {}\n", value_to_string(value)));
    }
    out.trim_end().to_string()
}

// surowa wartosc pojedynczego pola dla `get --field NAZWA` (F-04).
// obsluguje pola z mapy fields oraz pola wspolne title/notes.
pub fn field_value(record: &Record, field: &str) -> Option<String> {
    match field {
        "title" => Some(record.title.clone()),
        "notes" => Some(record.notes.clone()),
        other => record.fields.get(other).map(value_to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::LoginInput;

    fn login(title: &str, tags: Vec<&str>, id_byte: u8) -> Record {
        let inp = LoginInput {
            title: title.to_string(),
            url: "https://example.com".to_string(),
            username: "user".to_string(),
            password: "tajne123".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            notes: String::new(),
        };
        Record::new_login(inp, [id_byte; 16], 1).unwrap()
    }

    #[test]
    fn list_hides_password() {
        // F-03: list nie moze pokazywac wartosci sekretow
        let recs = vec![login("github", vec!["praca"], 0xaa)];
        let out = format_list(&recs);
        assert!(!out.contains("tajne123"));
        assert!(out.contains("github"));
        assert!(out.contains("login"));
    }

    #[test]
    fn list_empty_message() {
        assert!(format_list(&[]).contains("Brak"));
    }

    #[test]
    fn filter_by_type() {
        let recs = vec![login("a", vec![], 1), login("b", vec![], 2)];
        assert_eq!(filter(&recs, Some("login"), None).len(), 2);
        assert_eq!(filter(&recs, Some("note"), None).len(), 0);
    }

    #[test]
    fn filter_by_tag() {
        let recs = vec![login("a", vec!["praca"], 1), login("b", vec!["dom"], 2)];
        let got = filter(&recs, None, Some("praca"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].title, "a");
    }

    #[test]
    fn find_by_title() {
        let recs = vec![login("github", vec![], 1)];
        assert!(find(&recs, "github").is_some());
        assert!(find(&recs, "gitlab").is_none());
    }

    #[test]
    fn find_by_id_prefix() {
        let recs = vec![login("x", vec![], 0xab)];
        assert!(find(&recs, "abab").is_some());
        assert!(find(&recs, "ffff").is_none());
    }

    #[test]
    fn detail_shows_record_fields() {
        // F-04: get pokazuje rekord (z wartosciami)
        let r = login("github", vec!["praca"], 1);
        let out = format_detail(&r);
        assert!(out.contains("github"));
        assert!(out.contains("user"));
        assert!(out.contains("tajne123"));
        assert!(out.contains("praca"));
    }

    #[test]
    fn field_value_returns_raw() {
        let r = login("github", vec![], 1);
        assert_eq!(field_value(&r, "username").unwrap(), "user");
        assert_eq!(field_value(&r, "password").unwrap(), "tajne123");
        assert_eq!(field_value(&r, "title").unwrap(), "github");
        assert!(field_value(&r, "nieistnieje").is_none());
    }

    #[test]
    fn is_secret_only_password() {
        assert!(is_secret_field("login", "password"));
        assert!(!is_secret_field("login", "username"));
    }
}
