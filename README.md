# QMOOSA Post-Quantum Cryptography Tests (`qmoosa-pqc-mlkem-tests`)

[![NIST FIPS 203](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Multi-Repo Reality Gates](https://img.shields.io/badge/Reality%20Gates-Strict-success.svg)](https://github.com/elon00)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`@qmoosa/pqc-mlkem-tests` is the multi-repository reality gatekeeper and adversarial verification test suite for Batch 11 of the QMOOSA-1000 portfolio (Domain 2: Post-Quantum Cryptography & Quantum Security, Repository 055).

---

## 4-Tier Supply Chain & Reality Gates

1. **Gate 1: Archive Integrity Verification**: Computes cryptographic SHA-256 hashes of all bundled `.tgz` archives against `integrity-manifest.json`.
2. **Gate 2: Source Provenance Verification**: Verifies git ancestry of upstream repositories.
3. **Gate 3: Current-HEAD Alignment Verification**: Guarantees test suite HEAD strictly matches sibling repository commits.
4. **Gate 4: Adversarial Negative Control Suite**: Executes 12 comprehensive adversarial attack scenarios (1-bit ciphertext corruption, FO implicit rejection, replay attacks, auth tag forgery, cross-parameter key mixing).

---

## License

MIT © 2026 elon00 / QMOOSA Mission
