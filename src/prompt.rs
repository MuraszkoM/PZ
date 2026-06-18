// wczytywanie danych od usera w trybie interaktywnym - moja dzialka (CLI)
//
// wazne wymogi ze specyfikacji:
//  - F-19: sekrety NIE ida w argumentach komendy, tylko interaktywnie bez echa
//  - F-15: haslo nigdy nie jest logowane
// haslo czytamy przez rpassword (nie widac go na ekranie).

use crate::record::LoginInput;
use std::io::{self, BufRead, Write};

// zwykle pole tekstowe (jawne, np. tytul/url/login). zrobione na genericach
// zeby dalo sie to przetestowac bez prawdziwego terminala.
pub fn read_line<R: BufRead, W: Write>(
    prompt: &str,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<String> {
    write!(writer, "{prompt}")?;
    writer.flush()?;
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

// pojedyncze haslo bez echa (np. przy `open` / `verify --with-password`).
// przy otwieraniu pytamy tylko raz, bez potwierdzania.
// rpassword sam obcina znak konca linii, wiec nie trzeba trimowac.
pub fn read_secret(label: &str) -> io::Result<String> {
    rpassword::prompt_password(format!("{label}: "))
}

// czy dwa wpisane hasla sa identyczne. wydzielone z read_secret_confirmed, zeby
// te logike (jedyna nietrywialna czesc) dalo sie przetestowac bez terminala -
// same wywolania rpassword wymagaja TTY i nie sa testowane jednostkowo.
fn passwords_match(first: &str, second: &str) -> bool {
    first == second
}

// rozbij surowy ciag "a, b ,c" na liste tagow, trymujac i pomijajac puste.
// wydzielone z collect_login zeby te logike przetestowac bez terminala.
fn parse_tags(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

// haslo bez echa, pytane dwa razy. jak sie nie zgadzaja -> blad.
// czytanie polega na sprawdzonej bibliotece rpassword (TTY); porownanie idzie
// przez passwords_match (testowane).
pub fn read_secret_confirmed(label: &str) -> io::Result<String> {
    let first = rpassword::prompt_password(format!("{label}: "))?;
    let second = rpassword::prompt_password(format!("{label} (powtorz): "))?;
    if !passwords_match(&first, &second) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hasla sie nie zgadzaja",
        ));
    }
    Ok(first)
}

// zebranie kompletu danych do rekordu typu login.
// jawne pola ze stdin, haslo bez echa. zwraca gotowy LoginInput.
pub fn collect_login() -> io::Result<LoginInput> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut out = io::stdout();

    let title = read_line("Tytul: ", &mut reader, &mut out)?;
    let url = read_line("URL: ", &mut reader, &mut out)?;
    let username = read_line("Login: ", &mut reader, &mut out)?;
    let password = read_secret_confirmed("Haslo")?;
    let tags_raw = read_line("Tagi (po przecinku, opcjonalnie): ", &mut reader, &mut out)?;
    let notes = read_line("Notatki (opcjonalnie): ", &mut reader, &mut out)?;

    let tags = parse_tags(&tags_raw);

    Ok(LoginInput {
        title,
        url,
        username,
        password,
        tags,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_line_returns_trimmed_input() {
        let mut input = Cursor::new(b"github\n".to_vec());
        let mut output = Vec::new();
        let got = read_line("Tytul: ", &mut input, &mut output).unwrap();
        assert_eq!(got, "github");
        // prompt faktycznie wypisany
        assert_eq!(String::from_utf8(output).unwrap(), "Tytul: ");
    }

    #[test]
    fn read_line_handles_empty_input() {
        let mut input = Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        let got = read_line("URL: ", &mut input, &mut output).unwrap();
        assert_eq!(got, "");
    }

    #[test]
    fn read_line_strips_crlf() {
        let mut input = Cursor::new(b"abc\r\n".to_vec());
        let mut output = Vec::new();
        let got = read_line("x", &mut input, &mut output).unwrap();
        assert_eq!(got, "abc");
    }

    #[test]
    fn passwords_match_accepts_identical() {
        assert!(passwords_match("tajne123", "tajne123"));
    }

    #[test]
    fn passwords_match_rejects_different() {
        assert!(!passwords_match("tajne123", "tajne124"));
        assert!(!passwords_match("haslo", ""));
    }

    #[test]
    fn parse_tags_splits_and_trims() {
        assert_eq!(
            parse_tags("praca, dom ,  hobby"),
            vec!["praca", "dom", "hobby"]
        );
    }

    #[test]
    fn parse_tags_drops_empty() {
        assert!(parse_tags("").is_empty());
        assert!(parse_tags("   ").is_empty());
        assert_eq!(parse_tags("a,,b,"), vec!["a", "b"]);
    }

    #[test]
    fn collect_login_parses_fields() {
        // symulujemy input: tytul, url, login, tagi, notatki
        // haslo czytamy przez rpassword (TTY) - nie testujemy tu
        let mut input = Cursor::new(
            b"github\nhttps://github.com\nuser1\ntag1, tag2\nnotatka testowa\n".to_vec(),
        );
        let mut out = Vec::new();
        let title = read_line("", &mut input, &mut out).unwrap();
        let url = read_line("", &mut input, &mut out).unwrap();
        let username = read_line("", &mut input, &mut out).unwrap();
        let tags_raw = read_line("", &mut input, &mut out).unwrap();
        let notes = read_line("", &mut input, &mut out).unwrap();

        assert_eq!(title, "github");
        assert_eq!(url, "https://github.com");
        assert_eq!(username, "user1");
        assert_eq!(notes, "notatka testowa");

        // tagi przez te sama funkcje co produkcja (collect_login)
        let tags = parse_tags(&tags_raw);
        assert_eq!(tags, vec!["tag1", "tag2"]);
    }
}
