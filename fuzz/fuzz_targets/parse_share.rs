// parse_share() is the daemon's entry point for share data arriving over
// the socket: attacker-controlled, pre-authentication input. It must never
// panic, overflow, or hang regardless of input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = keyquorum_core::share_format::parse_share(s);
    }
});
