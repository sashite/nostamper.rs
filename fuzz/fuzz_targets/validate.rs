// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use nostamper::{attested_event_id, validate};
use nostr::util::JsonUtil;
use nostr::Event;

// Fuzzes the realistic untrusted path: arbitrary bytes are read as UTF-8, parsed
// as a Nostr event, then run through the crate's read path. The only assertion
// is the absence of panics — `validate` and `attested_event_id` must be total on
// every input. Seed the corpus with a real kind-1041 attestation JSON to speed
// up coverage of the `attests`-tag branches.
fuzz_target!(|data: &[u8]| {
    if let Ok(json) = core::str::from_utf8(data) {
        if let Ok(event) = Event::from_json(json) {
            let _ = validate(&event);
            let _ = attested_event_id(&event);
        }
    }
});
