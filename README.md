# cl-vrf

Standalone Verifiable Random Functions (VRF) implementation with **zero external dependencies**.

## Features

- **ECVRF**: Elliptic curve VRF (draft-irtf-cfrg-vrf-15)
- **Secp256k1**: Bitcoin/Ethereum compatible
- **Ed25519**: Edwards curve variant
- **Proof verification**: Verify randomness provenance
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-vrf)
```

## Quick Start

```lisp
(use-package :cl-vrf)

;; Generate keypair
(multiple-value-bind (public-key secret-key)
    (vrf-keygen)
  ;; Evaluate VRF
  (multiple-value-bind (output proof)
      (vrf-eval secret-key *input*)
    ;; Verify
    (vrf-verify public-key *input* output proof)))
```

## API Reference

### Key Generation

- `(vrf-keygen)` - Generate VRF keypair
- `(vrf-public-key secret-key)` - Derive public key

### Evaluation

- `(vrf-eval secret-key input)` - Evaluate VRF, returns (output, proof)
- `(vrf-hash-to-curve input)` - Hash input to curve point

### Verification

- `(vrf-verify public-key input output proof)` - Verify VRF proof
- `(vrf-proof-to-hash proof)` - Convert proof to hash output

### Utilities

- `(vrf-output-to-integer output)` - Convert output to integer
- `(vrf-output-to-bytes output)` - Convert output to bytes

## Testing

```lisp
(asdf:test-system :cl-vrf)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
