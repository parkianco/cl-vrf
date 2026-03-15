;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; package.lisp - CL-VRF Package Definition

(defpackage #:cl-vrf
  (:use #:cl)
  (:documentation
   "Verifiable Random Functions (VRF) Library.

Provides ECVRF (Elliptic Curve VRF) per IETF draft-irtf-cfrg-vrf-15
using secp256k1 and SHA-256.

Key Features:
- ECVRF-SECP256K1-SHA256-TAI compliant
- 81-byte proofs (Gamma || c || s)
- Fast prove and verify operations
- Batch verification support
- Threshold VRF for distributed randomness

Example:
  (multiple-value-bind (sk pk) (vrf-keygen)
    (let ((output (ecvrf-prove sk \"input\")))
      (ecvrf-verify pk \"input\" output)))")
  (:export
   ;; Key types
   #:vrf-secret-key
   #:vrf-secret-key-p
   #:vrf-secret-key-scalar

   #:vrf-public-key
   #:vrf-public-key-p
   #:vrf-public-key-point-x
   #:vrf-public-key-point-y
   #:vrf-public-key-compressed

   ;; Proof and output types
   #:vrf-proof
   #:vrf-proof-p
   #:vrf-proof-gamma-x
   #:vrf-proof-gamma-y
   #:vrf-proof-challenge
   #:vrf-proof-response

   #:vrf-output
   #:vrf-output-p
   #:vrf-output-hash
   #:vrf-output-proof
   #:vrf-output-input

   ;; Key generation
   #:vrf-keygen
   #:vrf-derive-public-key
   #:vrf-validate-keypair

   ;; ECVRF operations
   #:ecvrf-prove
   #:ecvrf-verify
   #:ecvrf-proof-to-hash
   #:ecvrf-hash-to-curve

   ;; Proof serialization
   #:ecvrf-encode-proof
   #:ecvrf-decode-proof
   #:vrf-serialize-proof
   #:vrf-deserialize-proof

   ;; Batch verification
   #:make-batch-context
   #:batch-add-proof
   #:batch-verify-all
   #:ecvrf-batch-verify

   ;; Output derivation
   #:vrf-derive-integer
   #:vrf-derive-selection

   ;; Constants
   #:+secp256k1-p+
   #:+secp256k1-n+
   #:+secp256k1-gx+
   #:+secp256k1-gy+
   #:+ecvrf-proof-length+

   ;; Conditions
   #:vrf-error
   #:vrf-error-message
   #:vrf-invalid-key-error
   #:vrf-invalid-proof-error
   #:vrf-verification-error))
