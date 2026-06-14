// main.rs — punkt wejścia aplikacji vault
//
// Moduly sa zadeklarowane tutaj. Caly kod aplikacji siedzi w bibliotece (lib.rs),
// main tylko odpala CLI i oddaje jego kod wyjscia.

// Deklaracje modułów — Rust wymaga żebyś jawnie powiedział które pliki są modułami
pub mod format;
pub mod storage;

fn main() {
    // caly kod jest w lib, tu tylko odpalamy CLI i oddajemy jego kod wyjscia
    std::process::exit(vault::cli::run());
}
