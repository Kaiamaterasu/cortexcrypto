# CortexCrypt Project Rules

These rules define the core principles and constraints for CortexCrypt development.

## Core Principles

1. **Zero Cost**: Only free/open-source dependencies; CPU-only inference is acceptable
2. **Augment, Don't Replace**: Use standard AEAD ciphers (AES-256-GCM, XChaCha20-Poly1305); NN only augments KDF
3. **Environment-Bound**: .cortex files bound to USB volume (default) or machine; portability via physical media movement
4. **Deletion ≠ Uninstall**: Manual deletion triggers self-heal; only `cortexctl uninstall` properly removes
5. **Offline First**: No network required by default; everything works air-gapped
6. **Multi-Language**: Stable C ABI with thin wrappers for C++/Rust/Python
7. **Security Over Convenience**: Portability is not a goal; physical movement of bound media is

## Technical Constraints

- Standard cryptography only (AEAD + KDF)
- Neural network outputs feed into HKDF/Argon2id only
- All inference via ONNX Runtime C API
- Thread-safe C library implementation
- Deterministic model seeding for reproducibility
- Zero secrets in logs or temporary files

## Security Requirements

- All keys derived, never stored permanently
- Memory locked where possible, zeroized on exit
- Binding verification before every decrypt operation
- Anomaly detection influences KDF parameters dynamically
- Admin tokens required for sensitive operations

## Compliance

- Apache 2.0 license (permissive, zero cost)
- No telemetry or network communication
- Self-contained build system
- Complete offline operation capability
- Reproducible builds from source
