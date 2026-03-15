;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-vrf.asd - Verifiable Random Functions Library

(asdf:defsystem #:cl-vrf
  :description "Standalone Verifiable Random Functions (VRF) implementation"
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "Apache-2.0"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "crypto")
                             (:file "vrf")))))

(asdf:defsystem #:cl-vrf/test
  :description "Tests for cl-vrf"
  :depends-on (#:cl-vrf)
  :serial t
  :components ((:module "test"
                :components ((:file "test-vrf"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-vrf.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
