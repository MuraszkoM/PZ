// cli - komendy (clap) i rozdzielanie ich do service
//
// komendy z README: init, open, add login, list, get, changepass, verify

use crate::error::VaultError;
use crate::service;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "vault", version, about = "Bezpieczny menedzer sekretow", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    // utworz nowy vault (SPEC §15)
    Init {
        path: PathBuf,
    },
    // otworz istniejacy (SPEC §16)
    Open {
        path: PathBuf,
    },
    // dodaj rekord
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    // wypisz rekordy (tylko metadane, bez sekretow). filtry opcjonalne.
    List {
        // pokaz tylko rekordy danego typu, np. --type login
        #[arg(long = "type")]
        type_filter: Option<String>,
        // pokaz tylko rekordy z danym tagiem
        #[arg(long = "tag")]
        tag_filter: Option<String>,
    },
    // pobierz rekord po id albo nazwie (F-04: pokazuje rekord)
    Get {
        id_or_name: String,
        // wypisz tylko jedno pole (surowa wartosc), np. --field password
        #[arg(long)]
        field: Option<String>,
        // skopiuj wybrane pole do schowka zamiast wypisywac (F-04, F-18).
        // --clip kopiuje WYBRANE pole, wiec wymaga --field.
        #[arg(long, requires = "field")]
        clip: bool,
    },
    // zmien haslo glowne (SPEC §18)
    Changepass,
    // sprawdz plik (SPEC §12 / §13)
    Verify {
        path: PathBuf,
        #[arg(long = "with-password")]
        with_password: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AddKind {
    // login: url, username, password (SPEC §10)
    Login,
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let result = dispatch(cli.command);
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            e.exit_code()
        }
    }
}

fn dispatch(command: Command) -> Result<(), VaultError> {
    match command {
        Command::Init { path } => service::init(&path),
        Command::Open { path } => service::open(&path),
        Command::Add { kind } => match kind {
            AddKind::Login => service::add_login(),
        },
        Command::List {
            type_filter,
            tag_filter,
        } => service::list(type_filter.as_deref(), tag_filter.as_deref()),
        Command::Get {
            id_or_name,
            field,
            clip,
        } => service::get(&id_or_name, field.as_deref(), clip),
        Command::Changepass => service::changepass(),
        Command::Verify {
            path,
            with_password,
        } => service::verify(&path, with_password),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_init_with_path() {
        let cli = Cli::try_parse_from(["vault", "init", "/tmp/x.vlt"]).unwrap();
        assert!(matches!(cli.command, Command::Init { .. }));
    }

    #[test]
    fn parses_add_login() {
        let cli = Cli::try_parse_from(["vault", "add", "login"]).unwrap();
        match cli.command {
            Command::Add { kind } => assert!(matches!(kind, AddKind::Login)),
            _ => panic!("mialo byc Add"),
        }
    }

    #[test]
    fn parses_list_with_filters() {
        let cli =
            Cli::try_parse_from(["vault", "list", "--type", "login", "--tag", "praca"]).unwrap();
        match cli.command {
            Command::List {
                type_filter,
                tag_filter,
            } => {
                assert_eq!(type_filter.as_deref(), Some("login"));
                assert_eq!(tag_filter.as_deref(), Some("praca"));
            }
            _ => panic!("mialo byc List"),
        }
    }

    #[test]
    fn parses_list_without_filters() {
        let cli = Cli::try_parse_from(["vault", "list"]).unwrap();
        match cli.command {
            Command::List {
                type_filter,
                tag_filter,
            } => {
                assert!(type_filter.is_none());
                assert!(tag_filter.is_none());
            }
            _ => panic!("mialo byc List"),
        }
    }

    #[test]
    fn parses_get_with_field() {
        let cli = Cli::try_parse_from(["vault", "get", "github", "--field", "password"]).unwrap();
        match cli.command {
            Command::Get {
                id_or_name,
                field,
                clip,
            } => {
                assert_eq!(id_or_name, "github");
                assert_eq!(field.as_deref(), Some("password"));
                assert!(!clip);
            }
            _ => panic!("mialo byc Get"),
        }
    }

    #[test]
    fn parses_get_without_field() {
        let cli = Cli::try_parse_from(["vault", "get", "github"]).unwrap();
        match cli.command {
            Command::Get {
                id_or_name, field, ..
            } => {
                assert_eq!(id_or_name, "github");
                assert!(field.is_none());
            }
            _ => panic!("mialo byc Get"),
        }
    }

    #[test]
    fn clip_requires_field() {
        // --clip bez --field ma byc odrzucone juz przez clap
        assert!(Cli::try_parse_from(["vault", "get", "github", "--clip"]).is_err());
    }

    #[test]
    fn parses_get_with_clip() {
        let cli = Cli::try_parse_from(["vault", "get", "github", "--field", "password", "--clip"])
            .unwrap();
        match cli.command {
            Command::Get { clip, field, .. } => {
                assert!(clip);
                assert_eq!(field.as_deref(), Some("password"));
            }
            _ => panic!("mialo byc Get"),
        }
    }

    #[test]
    fn parses_verify_with_password_flag() {
        let cli = Cli::try_parse_from(["vault", "verify", "x.vlt", "--with-password"]).unwrap();
        match cli.command {
            Command::Verify { with_password, .. } => assert!(with_password),
            _ => panic!("mialo byc Verify"),
        }
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(Cli::try_parse_from(["vault", "frobnicate"]).is_err());
    }
}
