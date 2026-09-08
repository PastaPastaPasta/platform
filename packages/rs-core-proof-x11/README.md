This wrapper reuses the SDK's existing `rs-x11-hash` 0.1.8 dependency (MIT),
including its native and WASM support, without compiling a second copy of the
X11 C sources. Its only entry point requires an 80-byte header: the underlying
dependency accepts arbitrary slices but unconditionally reads 80 bytes.

The SDK verifier authenticates Core headers directly on the CPU; it needs no
proof VM or specialized hardware.
