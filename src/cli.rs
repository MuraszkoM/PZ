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
    // wypisz rekordy
    List,
    // pobierz rekord po id albo nazwie
    Get {
        id_or_name: String,
    },
    // zmien haslo glowne (SPEC §18)
    Changepass,
    // sprawdz plik (SPEC §12 / §13)
    Verify {
        path: PathBuf,
        // pelna weryfikacja z haslem (SPEC §13)
        #[arg(long = "with-password")]
        with_password: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AddKind {
    // login: url, username, password (SPEC §10)
    Login,
}

// wejscie do CLI, zwraca kod wyjscia procesu
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

// rozdzielenie komendy do odpowiedniej funkcji w service
fn dispatch(command: Command) -> Result<(), VaultError> {
    match command {
        Command::Init { path } => service::init(&path),
        Command::Open { path } => service::open(&path),
        Command::Add { kind } => match kind {
            AddKind::Login => service::add_login(),
        },
        Command::List => service::list(),
        Command::Get { id_or_name } => service::get(&id_or_name),
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
        // clap sam sprawdza czy drzewo komend jest ok (panikuje jak nie)
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
    fn parses_verify_with_password_flag() {
        let cli = Cli::try_parse_from(["vault", "verify", "x.vlt", "--with-password"]).unwrap();
        match cli.command {
            Command::Verify { with_password, .. } => assert!(with_password),
            _ => panic!("mialo byc Verify"),
        }
    }

    #[test]
    fn verify_without_flag_defaults_false() {
        let cli = Cli::try_parse_from(["vault", "verify", "x.vlt"]).unwrap();
        match cli.command {
            Command::Verify { with_password, .. } => assert!(!with_password),
            _ => panic!("mialo byc Verify"),
        }
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(Cli::try_parse_from(["vault", "frobnicate"]).is_err());
    }
}
