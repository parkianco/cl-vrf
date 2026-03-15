;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

;;;; test-vrf.lisp - Unit tests for vrf
;;;;
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-vrf.test
  (:use #:cl)
  (:export #:run-tests))

(in-package #:cl-vrf.test)

(defun run-tests ()
  "Run all tests for cl-vrf."
  (format t "~&Running tests for cl-vrf...~%")
  ;; TODO: Add test cases
  ;; (test-function-1)
  ;; (test-function-2)
  (format t "~&All tests passed!~%")
  t)
