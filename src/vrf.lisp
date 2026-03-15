;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; vrf.lisp - ECVRF Implementation

(in-package #:cl-vrf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; secp256k1 Curve Constants
;;; ============================================================================

(defparameter +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "secp256k1 field prime p.")

(defparameter +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "secp256k1 curve order n.")

(defparameter +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "secp256k1 generator x-coordinate.")

(defparameter +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "secp256k1 generator y-coordinate.")

(defparameter +ecvrf-suite-string+
  #(#xFE)
  "Suite string for ECVRF-SECP256K1-SHA256-TAI.")

(defconstant +ecvrf-proof-length+ 81
  "Length of ECVRF proof in bytes: 33 (Gamma) + 16 (c) + 32 (s).")

;;; ============================================================================
;;; Condition Types
;;; ============================================================================

(define-condition vrf-error (error)
  ((message :initarg :message :reader vrf-error-message))
  (:report (lambda (c s)
             (format s "VRF error: ~A" (vrf-error-message c)))))

(define-condition vrf-invalid-key-error (vrf-error)
  ((key :initarg :key :reader vrf-invalid-key-error-key))
  (:report (lambda (c s)
             (format s "Invalid VRF key: ~A" (vrf-error-message c)))))

(define-condition vrf-invalid-proof-error (vrf-error)
  ((proof :initarg :proof :reader vrf-invalid-proof-error-proof))
  (:report (lambda (c s)
             (format s "Invalid VRF proof: ~A" (vrf-error-message c)))))

(define-condition vrf-verification-error (vrf-error)
  ((input :initarg :input :reader vrf-verification-error-input)
   (public-key :initarg :public-key :reader vrf-verification-error-public-key))
  (:report (lambda (c s)
             (format s "VRF verification failed: ~A" (vrf-error-message c)))))

;;; ============================================================================
;;; Core Type Definitions
;;; ============================================================================

(defstruct (vrf-secret-key (:constructor %make-vrf-secret-key))
  "VRF secret key."
  (scalar 0 :type integer :read-only t))

(defstruct (vrf-public-key (:constructor %make-vrf-public-key))
  "VRF public key."
  (point-x 0 :type integer :read-only t)
  (point-y 0 :type integer :read-only t)
  (compressed nil :type (or null (vector (unsigned-byte 8))) :read-only t))

(defstruct (vrf-proof (:constructor %make-vrf-proof))
  "VRF proof containing Gamma point, challenge, and response."
  (gamma-x 0 :type integer)
  (gamma-y 0 :type integer)
  (challenge 0 :type integer)
  (response 0 :type integer))

(defstruct (vrf-output (:constructor %make-vrf-output))
  "VRF output containing the hash and associated proof."
  (hash nil :type (or null (vector (unsigned-byte 8))))
  (proof nil :type (or null vrf-proof))
  (input nil :type (or null (vector (unsigned-byte 8)))))

;;; ============================================================================
;;; EC Point Operations (secp256k1)
;;; ============================================================================

(defun ec-point-add (x1 y1 x2 y2)
  "Add two EC points on secp256k1."
  (declare (type integer x1 y1 x2 y2))
  ;; Point at infinity handling
  (when (and (zerop x1) (zerop y1))
    (return-from ec-point-add (values x2 y2)))
  (when (and (zerop x2) (zerop y2))
    (return-from ec-point-add (values x1 y1)))
  ;; Same x, different y => point at infinity
  (when (and (= x1 x2) (= y1 (mod (- +secp256k1-p+ y2) +secp256k1-p+)))
    (return-from ec-point-add (values 0 0)))
  ;; Same point => double
  (when (and (= x1 x2) (= y1 y2))
    (return-from ec-point-add (ec-point-double x1 y1)))
  ;; Different points
  (let* ((dx (mod (- x2 x1) +secp256k1-p+))
         (dy (mod (- y2 y1) +secp256k1-p+))
         (lambda (mod (* dy (mod-inverse dx +secp256k1-p+)) +secp256k1-p+))
         (x3 (mod (- (* lambda lambda) x1 x2) +secp256k1-p+))
         (y3 (mod (- (* lambda (- x1 x3)) y1) +secp256k1-p+)))
    (values x3 y3)))

(defun ec-point-double (x y)
  "Double an EC point on secp256k1."
  (declare (type integer x y))
  (when (zerop y)
    (return-from ec-point-double (values 0 0)))
  (let* ((x-sq (mod (* x x) +secp256k1-p+))
         (num (mod (* 3 x-sq) +secp256k1-p+))  ; a=0 for secp256k1
         (den (mod (* 2 y) +secp256k1-p+))
         (lambda (mod (* num (mod-inverse den +secp256k1-p+)) +secp256k1-p+))
         (x3 (mod (- (* lambda lambda) (* 2 x)) +secp256k1-p+))
         (y3 (mod (- (* lambda (- x x3)) y) +secp256k1-p+)))
    (values x3 y3)))

(defun ec-scalar-multiply (k x y)
  "Scalar multiplication k * (x, y) on secp256k1."
  (declare (type integer k x y))
  (let ((rx 0) (ry 0)
        (qx x) (qy y))
    (loop while (plusp k)
          do (when (oddp k)
               (multiple-value-setq (rx ry) (ec-point-add rx ry qx qy)))
             (multiple-value-setq (qx qy) (ec-point-double qx qy))
             (setf k (ash k -1)))
    (values rx ry)))

(defun ec-point-negate (x y)
  "Negate an EC point (reflect over x-axis)."
  (values x (mod (- +secp256k1-p+ y) +secp256k1-p+)))

(defun ec-point-on-curve-p (x y)
  "Check if point (x, y) is on secp256k1."
  (let* ((y2 (mod (* y y) +secp256k1-p+))
         (x3 (mod-expt x 3 +secp256k1-p+))
         (rhs (mod (+ x3 7) +secp256k1-p+)))
    (= y2 rhs)))

;;; ============================================================================
;;; Point Compression/Decompression
;;; ============================================================================

(defun compress-point (x y)
  "Compress EC point to 33 bytes."
  (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) (if (evenp y) #x02 #x03))
    (let ((x-bytes (integer-to-bytes x 32 :big-endian t)))
      (replace result x-bytes :start1 1))
    result))

(defun decompress-point (compressed)
  "Decompress 33-byte compressed point to (x, y)."
  (let* ((prefix (aref compressed 0))
         (x (bytes-to-integer (subseq compressed 1 33) :big-endian t))
         (y-squared (mod (+ (mod-expt x 3 +secp256k1-p+) 7) +secp256k1-p+))
         (y (mod-sqrt y-squared +secp256k1-p+)))
    (when y
      (let ((y-odd (oddp y))
            (want-odd (= prefix #x03)))
        (unless (eq y-odd want-odd)
          (setf y (mod (- +secp256k1-p+ y) +secp256k1-p+)))
        (values x y)))))

;;; ============================================================================
;;; Utility Functions
;;; ============================================================================

(defun vrf-concat-bytes (&rest byte-vectors)
  "Concatenate multiple byte vectors."
  (apply #'concatenate '(vector (unsigned-byte 8)) byte-vectors))

(defun hash-points (&rest points)
  "Hash multiple EC points for challenge computation."
  (let ((data (make-array 0 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0)))
    (dolist (point points)
      (destructuring-bind (x y) point
        (let ((x-bytes (integer-to-bytes x 32 :big-endian t))
              (y-bytes (integer-to-bytes y 32 :big-endian t)))
          (loop for b across x-bytes do (vector-push-extend b data))
          (loop for b across y-bytes do (vector-push-extend b data)))))
    (sha256 (coerce data '(vector (unsigned-byte 8))))))

;;; ============================================================================
;;; Key Generation
;;; ============================================================================

(defun vrf-keygen ()
  "Generate a new VRF key pair.
   Returns (VALUES vrf-secret-key vrf-public-key)."
  (let* ((sk-bytes (get-random-bytes 32))
         (sk-scalar (bytes-to-integer sk-bytes :big-endian t)))
    ;; Ensure sk is in valid range [1, n-1]
    (loop while (or (zerop sk-scalar) (>= sk-scalar +secp256k1-n+))
          do (setf sk-bytes (get-random-bytes 32)
                   sk-scalar (bytes-to-integer sk-bytes :big-endian t)))
    ;; Derive public key
    (multiple-value-bind (px py) (ec-scalar-multiply sk-scalar +secp256k1-gx+ +secp256k1-gy+)
      (values
       (%make-vrf-secret-key :scalar sk-scalar)
       (%make-vrf-public-key :point-x px :point-y py
                             :compressed (compress-point px py))))))

(defun vrf-derive-public-key (secret-key)
  "Derive public key from secret key."
  (check-type secret-key vrf-secret-key)
  (let ((sk (vrf-secret-key-scalar secret-key)))
    (multiple-value-bind (px py) (ec-scalar-multiply sk +secp256k1-gx+ +secp256k1-gy+)
      (%make-vrf-public-key :point-x px :point-y py
                            :compressed (compress-point px py)))))

(defun vrf-validate-keypair (secret-key public-key)
  "Validate that secret-key corresponds to public-key."
  (check-type secret-key vrf-secret-key)
  (check-type public-key vrf-public-key)
  (let ((derived (vrf-derive-public-key secret-key)))
    (and (= (vrf-public-key-point-x derived) (vrf-public-key-point-x public-key))
         (= (vrf-public-key-point-y derived) (vrf-public-key-point-y public-key)))))

;;; ============================================================================
;;; ECVRF Hash-to-Curve
;;; ============================================================================

(defun ecvrf-hash-to-curve (public-key alpha)
  "Hash input to a point on secp256k1 using try-and-increment.
   Returns (VALUES x y)."
  (let* ((pk-bytes (vrf-public-key-compressed public-key))
         (alpha-bytes (etypecase alpha
                        ((vector (unsigned-byte 8)) alpha)
                        (string (string-to-octets alpha)))))
    ;; Try-and-increment
    (dotimes (ctr 256)
      (let* ((hash-input (vrf-concat-bytes
                          +ecvrf-suite-string+
                          #(#x01)
                          pk-bytes
                          alpha-bytes
                          (vector ctr)))
             (hash (sha256 hash-input))
             (x-candidate (bytes-to-integer hash :big-endian t)))
        ;; Check if valid x-coordinate
        (when (< x-candidate +secp256k1-p+)
          (let* ((y-squared (mod (+ (mod-expt x-candidate 3 +secp256k1-p+) 7)
                                 +secp256k1-p+))
                 (y (mod-sqrt y-squared +secp256k1-p+)))
            (when y
              ;; Choose y with even parity for determinism
              (when (oddp y)
                (setf y (mod (- +secp256k1-p+ y) +secp256k1-p+)))
              (return-from ecvrf-hash-to-curve (values x-candidate y)))))))
    (error 'vrf-error :message "Hash-to-curve failed after 256 attempts")))

;;; ============================================================================
;;; ECVRF Proof Generation
;;; ============================================================================

(defun ecvrf-prove (secret-key alpha)
  "Generate an ECVRF proof for input ALPHA.
   Returns vrf-output containing hash, proof, and input."
  (check-type secret-key vrf-secret-key)
  (let* ((x (vrf-secret-key-scalar secret-key))
         (public-key (vrf-derive-public-key secret-key))
         (alpha-bytes (etypecase alpha
                        ((vector (unsigned-byte 8)) alpha)
                        (string (string-to-octets alpha)))))
    ;; Step 1: Hash input to curve point H
    (multiple-value-bind (hx hy) (ecvrf-hash-to-curve public-key alpha-bytes)
      ;; Step 2: Compute Gamma = x * H
      (multiple-value-bind (gamma-x gamma-y) (ec-scalar-multiply x hx hy)
        ;; Step 3: Generate nonce k deterministically
        (let* ((k-input (vrf-concat-bytes
                         (integer-to-bytes x 32 :big-endian t)
                         (integer-to-bytes hx 32 :big-endian t)
                         (integer-to-bytes hy 32 :big-endian t)))
               (k-hash (sha256 k-input))
               (k (mod (bytes-to-integer k-hash :big-endian t) +secp256k1-n+)))
          (when (zerop k)
            (setf k 1))
          ;; Step 4: Compute U = k * G and V = k * H
          (multiple-value-bind (ux uy) (ec-scalar-multiply k +secp256k1-gx+ +secp256k1-gy+)
            (multiple-value-bind (vx vy) (ec-scalar-multiply k hx hy)
              ;; Step 5: Compute challenge c
              (let* ((c-hash (hash-points
                              (list +secp256k1-gx+ +secp256k1-gy+)
                              (list hx hy)
                              (list (vrf-public-key-point-x public-key)
                                    (vrf-public-key-point-y public-key))
                              (list gamma-x gamma-y)
                              (list ux uy)
                              (list vx vy)))
                     (c (mod (bytes-to-integer (subseq c-hash 0 16) :big-endian t)
                             +secp256k1-n+)))
                ;; Step 6: Compute response s = k + c * x mod n
                (let ((s (mod (+ k (* c x)) +secp256k1-n+)))
                  ;; Step 7: Compute output hash beta
                  (let* ((gamma-compressed (compress-point gamma-x gamma-y))
                         (beta-input (vrf-concat-bytes +ecvrf-suite-string+
                                                       #(#x03)
                                                       gamma-compressed))
                         (beta (sha256 beta-input))
                         (proof (%make-vrf-proof :gamma-x gamma-x
                                                 :gamma-y gamma-y
                                                 :challenge c
                                                 :response s)))
                    (%make-vrf-output :hash beta
                                      :proof proof
                                      :input alpha-bytes)))))))))))

;;; ============================================================================
;;; ECVRF Proof Verification
;;; ============================================================================

(defun ecvrf-verify (public-key alpha proof)
  "Verify an ECVRF proof.
   Returns the VRF output hash if valid, NIL if invalid."
  (check-type public-key vrf-public-key)
  (let* ((actual-proof (etypecase proof
                         (vrf-proof proof)
                         (vrf-output (vrf-output-proof proof))))
         (alpha-bytes (etypecase alpha
                        ((vector (unsigned-byte 8)) alpha)
                        (string (string-to-octets alpha)))))
    (handler-case
        (progn
          ;; Step 1: Hash input to curve point H
          (multiple-value-bind (hx hy) (ecvrf-hash-to-curve public-key alpha-bytes)
            ;; Extract proof components
            (let ((gamma-x (vrf-proof-gamma-x actual-proof))
                  (gamma-y (vrf-proof-gamma-y actual-proof))
                  (c (vrf-proof-challenge actual-proof))
                  (s (vrf-proof-response actual-proof))
                  (px (vrf-public-key-point-x public-key))
                  (py (vrf-public-key-point-y public-key)))
              ;; Validate Gamma is on curve
              (unless (ec-point-on-curve-p gamma-x gamma-y)
                (return-from ecvrf-verify nil))
              ;; Step 2: Compute U = s*G - c*Y
              (multiple-value-bind (sg-x sg-y) (ec-scalar-multiply s +secp256k1-gx+ +secp256k1-gy+)
                (multiple-value-bind (cy-x cy-y) (ec-scalar-multiply c px py)
                  (multiple-value-bind (neg-cy-x neg-cy-y) (ec-point-negate cy-x cy-y)
                    (multiple-value-bind (ux uy) (ec-point-add sg-x sg-y neg-cy-x neg-cy-y)
                      ;; Step 3: Compute V = s*H - c*Gamma
                      (multiple-value-bind (sh-x sh-y) (ec-scalar-multiply s hx hy)
                        (multiple-value-bind (cg-x cg-y) (ec-scalar-multiply c gamma-x gamma-y)
                          (multiple-value-bind (neg-cg-x neg-cg-y) (ec-point-negate cg-x cg-y)
                            (multiple-value-bind (vx vy) (ec-point-add sh-x sh-y neg-cg-x neg-cg-y)
                              ;; Step 4: Compute expected challenge c'
                              (let* ((c-hash (hash-points
                                              (list +secp256k1-gx+ +secp256k1-gy+)
                                              (list hx hy)
                                              (list px py)
                                              (list gamma-x gamma-y)
                                              (list ux uy)
                                              (list vx vy)))
                                     (c-prime (mod (bytes-to-integer (subseq c-hash 0 16) :big-endian t)
                                                   +secp256k1-n+)))
                                ;; Step 5: Check c = c'
                                (if (= c c-prime)
                                    ;; Compute output hash
                                    (let* ((gamma-compressed (compress-point gamma-x gamma-y))
                                           (beta-input (vrf-concat-bytes +ecvrf-suite-string+
                                                                         #(#x03)
                                                                         gamma-compressed)))
                                      (sha256 beta-input))
                                    nil)))))))))))))
      (error (e)
        (declare (ignore e))
        nil))))

(defun ecvrf-proof-to-hash (gamma-x gamma-y)
  "Convert Gamma point to VRF output hash."
  (let* ((gamma-compressed (compress-point gamma-x gamma-y))
         (beta-input (vrf-concat-bytes +ecvrf-suite-string+
                                       #(#x03)
                                       gamma-compressed)))
    (sha256 beta-input)))

;;; ============================================================================
;;; Proof Serialization
;;; ============================================================================

(defun ecvrf-encode-proof (proof)
  "Encode VRF proof to 81-byte vector."
  (check-type proof vrf-proof)
  (let ((result (make-array +ecvrf-proof-length+ :element-type '(unsigned-byte 8))))
    ;; Gamma (33 bytes compressed)
    (let ((gamma-compressed (compress-point (vrf-proof-gamma-x proof)
                                            (vrf-proof-gamma-y proof))))
      (replace result gamma-compressed))
    ;; Challenge (16 bytes)
    (let ((c-bytes (integer-to-bytes (vrf-proof-challenge proof) 16 :big-endian t)))
      (replace result c-bytes :start1 33))
    ;; Response (32 bytes)
    (let ((s-bytes (integer-to-bytes (vrf-proof-response proof) 32 :big-endian t)))
      (replace result s-bytes :start1 49))
    result))

(defun ecvrf-decode-proof (bytes)
  "Decode 81-byte vector to VRF proof."
  (check-type bytes (vector (unsigned-byte 8)))
  (unless (= (length bytes) +ecvrf-proof-length+)
    (error 'vrf-invalid-proof-error :message "Invalid proof length"))
  ;; Gamma (33 bytes)
  (multiple-value-bind (gamma-x gamma-y) (decompress-point (subseq bytes 0 33))
    (unless gamma-x
      (error 'vrf-invalid-proof-error :message "Invalid Gamma point"))
    ;; Challenge (16 bytes)
    (let ((c (bytes-to-integer (subseq bytes 33 49) :big-endian t))
          (s (bytes-to-integer (subseq bytes 49 81) :big-endian t)))
      (%make-vrf-proof :gamma-x gamma-x
                       :gamma-y gamma-y
                       :challenge c
                       :response s))))

(defun vrf-serialize-proof (output)
  "Serialize VRF output to bytes."
  (check-type output vrf-output)
  (let ((proof-bytes (ecvrf-encode-proof (vrf-output-proof output)))
        (hash (vrf-output-hash output)))
    (vrf-concat-bytes hash proof-bytes)))

(defun vrf-deserialize-proof (bytes)
  "Deserialize bytes to VRF output."
  (check-type bytes (vector (unsigned-byte 8)))
  (unless (>= (length bytes) (+ 32 +ecvrf-proof-length+))
    (error 'vrf-invalid-proof-error :message "Invalid serialized proof length"))
  (let ((hash (subseq bytes 0 32))
        (proof (ecvrf-decode-proof (subseq bytes 32))))
    (%make-vrf-output :hash hash :proof proof)))

;;; ============================================================================
;;; Batch Verification
;;; ============================================================================

(defstruct (batch-context (:constructor %make-batch-context))
  "Context for batch VRF verification."
  (proofs nil :type list)
  (public-keys nil :type list)
  (inputs nil :type list)
  (count 0 :type fixnum))

(defun make-batch-context ()
  "Create a new batch verification context."
  (%make-batch-context))

(defun batch-add-proof (context public-key alpha proof)
  "Add a proof to the batch verification context."
  (push proof (batch-context-proofs context))
  (push public-key (batch-context-public-keys context))
  (push alpha (batch-context-inputs context))
  (incf (batch-context-count context)))

(defun batch-verify-all (context)
  "Verify all proofs in the batch context.
   Returns T if all valid, NIL otherwise."
  (loop for proof in (batch-context-proofs context)
        for pk in (batch-context-public-keys context)
        for input in (batch-context-inputs context)
        always (ecvrf-verify pk input proof)))

(defun ecvrf-batch-verify (proofs)
  "Batch verify multiple ECVRF proofs.
   PROOFS: List of (public-key alpha proof) tuples.
   Returns T if all valid, NIL otherwise."
  (loop for (pk alpha proof) in proofs
        always (ecvrf-verify pk alpha proof)))

;;; ============================================================================
;;; Output Derivation
;;; ============================================================================

(defun vrf-derive-integer (output max-value)
  "Derive an integer in range [0, MAX-VALUE) from VRF output."
  (let ((hash (etypecase output
                (vrf-output (vrf-output-hash output))
                ((vector (unsigned-byte 8)) output))))
    (mod (bytes-to-integer hash :big-endian t) max-value)))

(defun vrf-derive-selection (output choices)
  "Select one element from CHOICES using VRF output."
  (let ((index (vrf-derive-integer output (length choices))))
    (nth index choices)))
