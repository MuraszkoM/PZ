// fuzz/fuzz_targets/header_parser.rs
// Cel fuzzingu: parser nagłówka vault
//
// Uruchomienie:
//   cargo fuzz run header_parser
// Długi przebieg (24h CPU, wymaganie M8):
//   cargo fuzz run header_parser -- -max_total_time=86400
//
// Fuzzer podaje losowe bajty jako "plik vault" i sprawdza że:
// 1. parse_header nigdy nie crashuje (panic, stack overflow, OOM)
// 2. Zwraca albo Ok(...) albo Err(...) — nigdy nie zawiesza się

#![no_main]

// libfuzzer_sys dostarcza makro fuzz_target!
use libfuzzer_sys::fuzz_target;
// Importujemy nasz parser
use vault::format::parse_header;

// fuzz_target! to makro które libFuzzer wywołuje z kolejnymi mutacjami danych
fuzz_target!(|data: &[u8]| {
    // Wywołaj parser na losowych danych.
    // Wynik ignorujemy — interesuje nas tylko że nie ma paniki ani crasha.
    // Parser MUSI zwrócić Ok lub Err, nigdy nie może się wysypać.
    let _ = parse_header(data);
});
