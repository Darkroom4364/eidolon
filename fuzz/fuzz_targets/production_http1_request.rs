#![no_main]

use eidolon_proxy::production_runtime::fuzzing::{evaluate_both, MAX_FUZZ_INPUT_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let (whole, fragmented) = evaluate_both(input)
        .unwrap_or_else(|error| panic!("bounded production HTTP driver failed: {error:?}"));
    assert!(
        whole == fragmented,
        "whole and fragmented production HTTP observations differ"
    );
});
