;;;; cl-vrf.asd - Verifiable Random Functions Library

(asdf:defsystem #:cl-vrf
  :description "Standalone Verifiable Random Functions (VRF) implementation"
  :version "1.0.0"
  :author "CLPIC Project"
  :license "BSD-3-Clause"
  :depends-on ()
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "crypto")
                             (:file "vrf")))))
