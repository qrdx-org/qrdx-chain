# Which library verifies ML-DSA-65

Every signature in QRDX is ML-DSA-65 (FIPS 204): blocks, votes, exchange transactions, 0x51
transactions, peer identities. Every signature is made and checked by liboqs (0.16.0, pinned;
`qrdx/crypto/pq/`). The library proves at startup that it computes FIPS 204, against a
known-answer vector from an independent implementation (`algorithms.self_test`).

liboqs describes itself as a research and prototyping library. This document compares it with
the alternatives (docs/MAINNET_READINESS.md §4, "PQ crypto implementation"), and describes the
mechanism built for a safe switch. **The choice is yours.**

## The options

| Library | Assurance | Reach from Python | Speed (verify, one core) |
|---|---|---|---|
| **liboqs 0.16** (today) | Open Quantum Safe's reference-quality code; not audited as a product; "not for production" in its own words | `liboqs-python`, pinned in the image | 38 µs |
| **OpenSSL 3.5+ / 4.0** | FIPS 204 in OpenSSL's default provider; the most widely deployed and reviewed crypto library (check the FIPS provider's validation status for ML-DSA before relying on it) | **already in the node image**: pyca/cryptography 50.0.2 (locked) bundles it, and has exposed ML-DSA since 48.0 | 123 µs |
| **mldsa-native 2.0** | Formally verified: CBMC proofs of the C code, HOL Light proofs of the AArch64 and x86_64 assembly (v2.0.0, PQ Code Package, Linux Foundation) | no Python package; a small C extension would have to be built reproducibly into the image | not measured |
| AWS-LC (FIPS) | FIPS-validated module | through pyca/cryptography built against it (not the published wheels) | not measured |

Times are one verification, including parsing the key, measured in the dev container.

## What was checked

`tests/test_pq_backends.py`:
* the known-answer signature, from an independent implementation, verifies under OpenSSL;
* each library verifies the other's signatures;
* on fuzzed inputs the two give the same verdict every time: flipped, truncated, extended and
  zeroed signatures and public keys, other messages, and arbitrary bytes. That is 3,000 cases in
  a deep run (`QRDX_FUZZ_EXAMPLES=3000`) and 150 in every CI run.

## How a switch would be made safely

Verification decides what a node accepts. Two nodes that disagree on one signature follow
different chains. So the switch is a network decision, and it is made on evidence:

1. **Shadow verification (built).** With `QRDX_PQ_SHADOW_VERIFY=1`, a node verifies every
   signature with liboqs, which still decides, and with OpenSSL. Any disagreement is logged as
   `[PQ-VERIFY-DISAGREEMENT]` with the input, and counted in
   `qrdx_pq_verify_disagreements_total`. It is node-local, and it costs about 120 µs a
   verification more.
2. **Run it** on the public testnet's nodes for weeks, at the soak's load, and alert on the
   counter.
3. **Switch verification** in a release, for every node at once, with the shadow inverted: OpenSSL
   decides and liboqs is asked.
4. **Signing** can stay with liboqs, or move key by key. OpenSSL builds a key from its 32-byte
   seed, and liboqs keeps only the expanded 4,032-byte key, from which the seed cannot be
   recovered. Validators would generate new keys, which is the key rotation the validator
   runbook already needs.

## Recommendation

* **Verification:** OpenSSL, after the shadow period.
  * It is already shipped, so nothing new enters the supply chain.
  * It is the most scrutinized implementation available from Python.
  * It costs about 85 µs a verification more. A full block's 128 votes and 400 transactions
    add roughly 45 ms of verification per block (528 × 85 µs), which the soak at 250 ms slots
    must confirm.
* **Signing:** liboqs for now. Revisit when validators rotate keys.
* **mldsa-native** is the strongest assurance on paper. It is worth it if a C extension, built
  reproducibly into the image, is acceptable. The same differential tests and shadow period
  would apply.
