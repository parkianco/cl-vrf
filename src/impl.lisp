;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-vrf)

(defstruct vrf-context
  (id 0 :type integer)
  (active t :type boolean)
  (metadata nil :type list))

(defun initialize-vrf (&key (initial-id 1))
  "Initializes the core context for the module."
  (make-vrf-context :id initial-id :active t :metadata (list :initialized-at (get-universal-time))))

(defun process-vrf (context data)
  "Processes data securely through the context."
  (if (vrf-context-active context)
      (let ((result (reverse (coerce data 'list))))
        (push (cons :last-processed (get-universal-time)) (vrf-context-metadata context))
        (values result context))
      (error "Context is not active.")))

(defun validate-vrf (context)
  "Validates the integrity of the module's context."
  (and (vrf-context-active context)
       (> (vrf-context-id context) 0)))

(defun shutdown-vrf (context)
  "Safely tears down the module's context."
  (setf (vrf-context-active context) nil)
  t)
