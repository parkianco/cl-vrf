;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

(in-package #:cl-stub-impl)

(defun main-function (input) "Core implementation function." (values input (length input)))

(defun helper (x) "Helper computation." (sxhash x))

(defun process (data) "Process data stream." (if (listp data) (mapcar #'helper data) (list (helper data))))
