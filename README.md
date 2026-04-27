# nested-musig2-python

A Python implementation of Nested MuSig2 over secp256k1, built on the base algorithms of MuSig2.

This repository explores how standard MuSig2 signing can be extended to a recursive cosigner tree, where nested subgroups behave like single signers at the level above. The final output is still a standard BIP 340 Schnorr signature under the root aggregate public key.

## References

- [BIP 327 - MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
- [Nested MuSig2 Paper (ePrint 2026/223)](https://eprint.iacr.org/2026/223.pdf)

## What this repository implements

### Standard MuSig2 components

Under `musig2/`, the repository implements the main building blocks of MuSig2:

- key aggregation
- key aggregation coefficients
- nonce generation
- nonce aggregation
- signing session creation
- partial signing
- partial signature verification
- final signature aggregation

These components follow the practical BIP 327 setting with $\nu = 2$ nonce points per signer.

### Nested MuSig2 components

Under `nested_musig2/`, the repository implements the recursive extension used for nested signing:

- nested subgroup representation
- subgroup aggregate key handling
- subgroup nonce extension (`SignAggExt`)
- nested signer transcript construction
- path-dependent nonce/challenge derivation
- nested partial signing
- nested partial signature verification
- recursive end-to-end signing across a cosigner tree

## Core idea

Ordinary MuSig2 signs with a flat set of signers.

Nested MuSig2 instead organizes signers into a tree.

At each internal node:

- a leaf signer contributes its own public key
- a nested subgroup contributes its subgroup aggregate public key
- the parent aggregates only its immediate child node keys

This means a subgroup can behave like a single MuSig2 participant to the level above, while still being internally composed of multiple signers.

For example, if:

- $Group_{AB} = {Alice, Bob}$
- $Group_{CD} = {Carol, Dave}$

then the root aggregates:

- $\tilde{X}_{AB}$
- $\tilde{X}_{CD}$

rather than directly aggregating all four leaf keys at the root level.

## Protocol shape

At a high level, the nested signing flow is:

1. Aggregate keys at each level of the tree.
2. Generate nonce tuples at the leaves.
3. Aggregate subgroup nonces bottom-up.
4. Apply nested nonce extension inside each subgroup.
5. Aggregate the top-level nonce tuple at the root.
6. Create the top-level MuSig2 signing session.
7. Build an explicit transcript for each leaf signer.
8. Derive path-dependent nested factors from that transcript.
9. Compute and verify leaf partial signatures.
10. Aggregate all valid leaf partial signatures into the final Schnorr signature.

The final signature is still a standard BIP 340 Schnorr signature and can be checked by an ordinary Schnorr verifier.

## Repository structure

### `musig2/`

Standard MuSig2 components.

- `keyagg.py`
  Key aggregation and coefficient derivation.

- `nonce.py`
  Round 1 nonce generation, nonce aggregation, and nonce-state handling.

- `sign.py`
  Session creation, partial signing, partial signature verification, and final aggregation.

### `nested_musig2/`

Nested MuSig2 extensions.

- `nonce_ext.py`
  Nested subgroup nonce extension (`SignAggExt`).

- `nested_sign.py`
  Tree model, subgroup round-one state, nested transcript handling, nested partial signing, nested partial verification, and recursive orchestration.

### `tests/`

Unit and end-to-end tests for both flat MuSig2 and nested signing flows.

### `examples/`

Small runnable examples demonstrating protocol behavior.

## Important implementation choices

### Immediate-child tree semantics

The implementation uses explicit immediate-child aggregation semantics.

A parent node aggregates only the public keys of its direct children. Descendants are not flattened into the parent keyset.

This makes the recursive tree structure explicit and matches the intended nested interpretation.

### Fixed nonce count

The protocol walkthrough uses the generic notation $\nu$, but the current implementation fixes:

- $\nu=2$

This follows the practical BIP 327 setting and is used consistently at both flat and nested levels.

### Explicit leaf transcript

Each leaf signer signs using an explicit transcript that contains:

- the root signing session
- the parent keyset at each level
- the signer's child-node key at each level
- the nested nonce bindings on its path

From this transcript, the signer derives:

- the effective nonce binding $\check{b}$
- the effective challenge $\check{c}$

This is the key mechanism that turns ordinary MuSig2 signing into nested signing.

### Explicit subgroup Round 1 state

Nested subgroup Round 1 output is stored explicitly in a `NestedGroupRound1State` object.

This includes:

- subgroup aggregate key cache
- internal aggregate nonce tuple
- external aggregate nonce tuple
- nested binding coefficient

This keeps subgroup behavior visible and testable in the code.

## Current scope

This repository currently focuses on the protocol structure and signing algebra.

Included in scope:

- secp256k1-based MuSig2 building blocks
- recursive nested subgroup structure
- path-dependent nested transcript handling
- final standard Schnorr signature output
- local orchestration for testing and understanding the protocol

Not currently in scope:

- authenticated distributed messaging
- transport/network protocol design
- production signer coordination
- persistence and operational state management
- full deployment hardening

## Security notes

This repository handles cryptographic nonce and signing state carefully, but it should still be treated as a reference-style implementation rather than production-ready infrastructure.

Important points:

- private keys must remain secret
- nonces must never be reused
- secret nonce material is single-use in the implementation
- malformed nonce tuples and malformed transcript paths are rejected
- aggregate keys and nonce points must not be the point at infinity

## Protocol walkthrough

A more detailed explanation of the notation, algorithms, and code mapping is available in:

- `docs/protocol-walkthrough.md`

## Quick start

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run the full test suite:

```bash
pytest -q
```

Run only the nested signing tests:

```bash
pytest -q tests/test_nested.py
```

## What the tests cover

The test suite includes checks for:

- standard MuSig2 signing and verification
- nested subgroup signing flows
- mixed-depth trees
- deeper recursive trees
- transcript-derived nested factors
- malformed path rejection
- malformed subgroup-state rejection
- final Schnorr verification under the root aggregate key

## Final output

Even though the internal signing process is recursive, the final result is simply:

- an aggregate nonce point $R$
- an aggregate scalar $s$
- a root aggregate public key $\tilde{X}$

Together these form a standard Schnorr signature:

- $\sigma = (R, s)$

So nested signing changes how signers cooperate internally, but not the format of the signature verified at the end.