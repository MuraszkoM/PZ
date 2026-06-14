// fuzz/fuzz_targets/body_parser.rs
// Cel fuzzingu: parser body (CBOR) vault
//
// Uruchomienie:
//   cargo fuzz run body_parser
//
// Fuzzer podaje losowe bajty jako "odszyfrowane body" i sprawdza że:
// 1. parse_body nigdy nie crashuje
// 2. Nie ma OOM ani unbounded recursion (CBOR może być zagnieżdżony)

#![no_main]

use libfuzzer_sys::fuzz_target;
use vault::format::parse_body;

fuzz_target!(|data: &[u8]| {
    let _ = parse_body(data);
});
