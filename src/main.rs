// main.rs — punkt wejścia aplikacji vault
//
// Na tym etapie main.rs tylko deklaruje moduły i ma placeholder CLI.
// Pełna implementacja CLI będzie w osobnym PR przez Application Engineera.

// Deklaracje modułów — Rust wymaga żebyś jawnie powiedział które pliki są modułami
pub mod format;
pub mod storage;

fn main() {
    println!("vault — bezpieczny menedżer sekretów");
    println!("Użyj: vault <komenda> [argumenty]");
    println!("Dostępne komendy: (w budowie)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_test_passes() {
        assert_eq!(2 + 2, 4);
    }
}
