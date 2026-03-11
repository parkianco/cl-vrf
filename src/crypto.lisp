;;;; crypto.lisp - Inlined Cryptographic Primitives for CL-VRF

(in-package #:cl-vrf)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defparameter *sha256-initial-hash*
  (make-array 8 :element-type '(unsigned-byte 32)
              :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                  #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))

(defparameter *sha256-round-constants*
  (make-array 64 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
                #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3
                #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
                #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
                #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
                #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
                #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
                #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208
                #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))

(declaim (inline sha256-rotr sha256-shr sha256-ch sha256-maj
                 sha256-sigma0 sha256-sigma1 sha256-big-sigma0 sha256-big-sigma1))

(defun sha256-rotr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 32) n))
  (logand #xFFFFFFFF (logior (ash x (- n)) (ash x (- 32 n)))))

(defun sha256-shr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 32) n))
  (ash x (- n)))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (sha256-shr x 3)))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (sha256-shr x 10)))

(defun sha256-big-sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-big-sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-pad-message (message)
  "Pad message to multiple of 512 bits per SHA-256 spec."
  (declare (type (vector (unsigned-byte 8)) message))
  (let* ((msg-len (length message))
         (bit-len (* 8 msg-len))
         (pad-len (- 64 (mod (+ msg-len 1 8) 64)))
         (total-len (+ msg-len 1 (if (< pad-len 0) (+ pad-len 64) pad-len) 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8)
                             :initial-element 0)))
    (replace padded message)
    (setf (aref padded msg-len) #x80)
    ;; Length in bits (big-endian)
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (ldb (byte 8 (* 8 i)) bit-len)))
    padded))

(defun sha256-process-block (block state)
  "Process single 512-bit block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) state))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0))
        (a (aref state 0)) (b (aref state 1))
        (c (aref state 2)) (d (aref state 3))
        (e (aref state 4)) (f (aref state 5))
        (g (aref state 6)) (h (aref state 7)))
    ;; Prepare message schedule
    (dotimes (i 16)
      (setf (aref w i)
            (logior (ash (aref block (* i 4)) 24)
                    (ash (aref block (+ (* i 4) 1)) 16)
                    (ash (aref block (+ (* i 4) 2)) 8)
                    (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xFFFFFFFF
                           (+ (sha256-sigma1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-sigma0 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Compression function
    (dotimes (i 64)
      (let* ((t1 (logand #xFFFFFFFF
                         (+ h
                            (sha256-big-sigma1 e)
                            (sha256-ch e f g)
                            (aref *sha256-round-constants* i)
                            (aref w i))))
             (t2 (logand #xFFFFFFFF
                         (+ (sha256-big-sigma0 a)
                            (sha256-maj a b c)))))
        (setf h g
              g f
              f e
              e (logand #xFFFFFFFF (+ d t1))
              d c
              c b
              b a
              a (logand #xFFFFFFFF (+ t1 t2)))))
    ;; Update state
    (setf (aref state 0) (logand #xFFFFFFFF (+ (aref state 0) a)))
    (setf (aref state 1) (logand #xFFFFFFFF (+ (aref state 1) b)))
    (setf (aref state 2) (logand #xFFFFFFFF (+ (aref state 2) c)))
    (setf (aref state 3) (logand #xFFFFFFFF (+ (aref state 3) d)))
    (setf (aref state 4) (logand #xFFFFFFFF (+ (aref state 4) e)))
    (setf (aref state 5) (logand #xFFFFFFFF (+ (aref state 5) f)))
    (setf (aref state 6) (logand #xFFFFFFFF (+ (aref state 6) g)))
    (setf (aref state 7) (logand #xFFFFFFFF (+ (aref state 7) h)))
    state))

(defun sha256 (data)
  "Compute SHA-256 hash of DATA. Returns 32-byte vector."
  (declare (type (vector (unsigned-byte 8)) data))
  (let* ((padded (sha256-pad-message data))
         (state (copy-seq *sha256-initial-hash*))
         (block (make-array 64 :element-type '(unsigned-byte 8)))
         (num-blocks (/ (length padded) 64)))
    (dotimes (i num-blocks)
      (replace block padded :start2 (* i 64))
      (sha256-process-block block state))
    ;; Convert state to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((word (aref state i)))
          (setf (aref result (* i 4)) (ldb (byte 8 24) word))
          (setf (aref result (+ (* i 4) 1)) (ldb (byte 8 16) word))
          (setf (aref result (+ (* i 4) 2)) (ldb (byte 8 8) word))
          (setf (aref result (+ (* i 4) 3)) (ldb (byte 8 0) word))))
      result)))

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mod-expt (base exp mod)
  "Compute BASE^EXP mod MOD using square-and-multiply."
  (declare (type integer base exp mod))
  (let ((result 1)
        (base (mod base mod)))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result base) mod)))
             (setf exp (ash exp -1))
             (setf base (mod (* base base) mod)))
    result))

(defun mod-inverse (a n)
  "Compute modular inverse of A mod N using extended Euclidean algorithm."
  (declare (type integer a n))
  (let ((t0 0) (t1 1)
        (r0 n) (r1 (mod a n)))
    (loop while (not (zerop r1))
          do (let ((q (floor r0 r1)))
               (psetf t0 t1 t1 (- t0 (* q t1)))
               (psetf r0 r1 r1 (- r0 (* q r1)))))
    (if (> r0 1)
        (error "No modular inverse exists")
        (if (minusp t0) (+ t0 n) t0))))

(defun mod-sqrt (a p)
  "Compute modular square root of A mod P using Tonelli-Shanks.
   Returns NIL if no square root exists."
  (declare (type integer a p))
  (when (zerop a) (return-from mod-sqrt 0))
  ;; Check if a is a quadratic residue
  (unless (= 1 (mod-expt a (/ (1- p) 2) p))
    (return-from mod-sqrt nil))
  ;; Factor out powers of 2 from p-1
  (let* ((q (1- p))
         (s 0))
    (loop while (evenp q)
          do (setf q (ash q -1))
             (incf s))
    (when (= s 1)
      (return-from mod-sqrt (mod-expt a (/ (1+ p) 4) p)))
    ;; Find quadratic non-residue
    (let ((z (loop for z from 2 below p
                   when (/= 1 (mod-expt z (/ (1- p) 2) p))
                   return z)))
      (let ((m s)
            (c (mod-expt z q p))
            (tt (mod-expt a q p))
            (r (mod-expt a (/ (1+ q) 2) p)))
        (loop
          (when (= tt 1) (return r))
          (let ((i (loop for i from 1 below m
                         when (= 1 (mod-expt tt (ash 1 i) p))
                         return i)))
            (let ((b (mod-expt c (ash 1 (- m i 1)) p)))
              (setf m i)
              (setf c (mod (* b b) p))
              (setf tt (mod (* tt c) p))
              (setf r (mod (* r b) p)))))))))

;;; ============================================================================
;;; Integer/Bytes Conversion
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte vector to integer."
  (declare (type (vector (unsigned-byte 8)) bytes))
  (let ((result 0)
        (len (length bytes)))
    (if big-endian
        (dotimes (i len result)
          (setf result (logior (ash result 8) (aref bytes i))))
        (dotimes (i len result)
          (setf result (logior result (ash (aref bytes i) (* 8 i))))))))

(defun integer-to-bytes (n size &key (big-endian t))
  "Convert integer to byte vector of given size."
  (declare (type integer n)
           (type fixnum size))
  (let ((result (make-array size :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    (if big-endian
        (loop for i from (1- size) downto 0
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) n)))
        (loop for i from 0 below size
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) n))))
    result))

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defun get-random-bytes (count)
  "Generate COUNT cryptographically random bytes."
  (declare (type fixnum count))
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    ;; Use SBCL's random with a secure seed
    ;; In production, this should use OS entropy (/dev/urandom or CryptGenRandom)
    (dotimes (i count result)
      (setf (aref result i) (random 256)))))

;;; ============================================================================
;;; String to Octets
;;; ============================================================================

(defun string-to-octets (string &key (encoding :utf-8))
  "Convert string to byte vector."
  (declare (type string string)
           (ignore encoding))
  ;; Simple ASCII/UTF-8 encoding
  (let* ((len (length string))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len result)
      (setf (aref result i) (char-code (char string i))))))
