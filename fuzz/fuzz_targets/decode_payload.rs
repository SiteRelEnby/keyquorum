// decode_payload() parses the V1 binary layer (magic, version, flags,
// CRC32, sharks data) from arbitrary decoded bytes. Fuzzed separately from
// parse_share so coverage isn't gated on inputs that survive base64/base32
// decoding.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyquorum_core::share_format::decode_payload(data);
});
