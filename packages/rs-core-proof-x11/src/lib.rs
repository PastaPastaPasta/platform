//! Fixed-size safe wrapper around the SDK's existing X11 implementation.

pub fn hash(header: &[u8; 80]) -> [u8; 32] {
    // The dependency's safe API accepts arbitrary slices but its C routine
    // unconditionally reads 80 bytes. This array parameter guarantees that
    // precondition, including for attacker-controlled proof headers.
    rs_x11_hash::get_x11_hash(header)
}
