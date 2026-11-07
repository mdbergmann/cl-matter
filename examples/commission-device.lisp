;;;; commission-device.lisp -- commission a real device with its pairing
;;;; code and read what it is.  The device's window must be open: a new
;;;; device opens it by itself; one that already has an administrator
;;;; (Apple Home, Google Home, chip-tool ...) gets it opened there ("pairing
;;;; mode"), which also shows the code to use here.
;;;;
;;;;   MATTER_CODE=01979306329 AMILISP_NO_USERINIT=1 amilisp --heap 128M --load examples/commission-device.lisp
;;;;   MATTER_CODE=01979306329 sbcl --load examples/commission-device.lisp
;;;;
;;;; Environment: MATTER_CODE (the manual pairing code, 11 or 21 digits),
;;;; MATTER_STORAGE (the commissioner's state file, default
;;;; ~/.cl-matter/commissioner.state), MATTER_ATTESTATION (verify, or
;;;; ignore -- the default, since a real device's PAA is rarely in the
;;;; trust store; the signature is still checked against the DAC),
;;;; MATTER_TRACE (set for the exchange trace), AMILISP_REPO (where
;;;; lib/quicklisp-compat.lisp is; default ../../amigasources/cl-amiga from here).
;;;;
;;;; The commissioner's fabric, keys and the node ids it handed out are kept
;;;; in the state file, so control-device.lisp can talk to the device later
;;;; without a window.  The device gets the next free node id (2 on a fresh
;;;; state).  First done against an Eve Energy plug on Thread, through the
;;;; window Apple Home opened (2026-11-07).

(require "asdf")
(load "~/quicklisp/setup.lisp")
#+amilisp
(let ((compat (merge-pathnames "lib/quicklisp-compat.lisp"
                               (uiop:ensure-directory-pathname
                                (or (uiop:getenv "AMILISP_REPO")
                                    (uiop:merge-pathnames* "../../amigasources/cl-amiga/"
                                                           (uiop:pathname-directory-pathname *load-truename*)))))))
  (when (probe-file compat) (load compat)))
(asdf:load-system :cl-matter)

(defpackage :commission-device (:use :cl :cl-matter))
(in-package :commission-device)

(defun env (name &optional default)
  (let ((value (uiop:getenv name)))
    (if (and value (plusp (length value))) value default)))

(defparameter *code* (or (env "MATTER_CODE") (error "MATTER_CODE, the manual pairing code, is not set")))
(defparameter *storage* (env "MATTER_STORAGE" (merge-pathnames ".cl-matter/commissioner.state" (user-homedir-pathname))))
(defparameter *attestation* (if (string-equal (env "MATTER_ATTESTATION" "ignore") "verify") :verify :ignore))

(defparameter *start* (get-internal-real-time))

(defun say (format &rest args)
  (format t "~&[~7,3f] ~?~%" (/ (- (get-internal-real-time) *start*) internal-time-units-per-second 1.0d0) format args)
  (finish-output))

(defun show-reports (reports)
  (dolist (report reports)
    (multiple-value-bind (value known) (attribute-report-value report)
      (say "    ~a = ~s~:[ (raw)~;~]" (attribute-report-path report) value known))))

(let* ((payload (decode-manual-pairing-code *code*))
       (passcode (onboarding-payload-passcode payload))
       (short (onboarding-payload-short-discriminator payload)))
  (say "pairing code ~a: short discriminator ~d" *code* short)
  (let ((nodes (discover-commissionable-nodes :short-discriminator short :timeout 4)))
    (unless nodes
      (say "no commissionable node with short discriminator ~d -- is the window open?" short)
      (uiop:quit 1))
    (when (rest nodes) (say "~d nodes match; taking the first" (length nodes)))
    (let* ((node (first nodes))
           (host (first (getf node :addresses)))
           (port (getf node :port)))
      (say "found ~s" node)
      (let* ((trace (and (env "MATTER_TRACE") (lambda (format &rest args) (apply #'say format args))))
             (transport (make-udp-transport :family :ipv6 :port 0))
             (manager (make-exchange-manager :transport transport :trace trace))
             (channel (make-secure-channel manager))
             (model (make-interaction-model manager))
             (state (read-state-file *storage*))
             (commissioner (if state
                               (make-commissioner channel model :state state)
                               (make-commissioner channel model :fabric-id #xC1 :vendor-id #xFFF1))))
        (say "commissioner ~a (~:[new~;from ~a~])" commissioner state *storage*)
        (unwind-protect
             (let* ((result (commission commissioner host port :passcode passcode :attestation *attestation* :timeout 90))
                    (session (getf result :session))
                    (dac (decode-certificate-der (getf result :dac)))
                    (pai (decode-certificate-der (getf result :pai))))
               (say "commissioned [~a]:~d as node ~d (its fabric index ~d), vendor ~d product ~d"
                    host port (getf result :node-id) (getf result :fabric-index) (getf result :vendor-id) (getf result :product-id))
               (write-state-file (commissioner-state commissioner) *storage*)
               (say "commissioner state saved to ~a" *storage*)
               (say "DAC ~s~%        issued by ~s" (certificate-subject dac) (certificate-issuer dac))
               (say "PAI issued by ~s" (certificate-issuer pai))
               (say "Basic Information:")
               (show-reports (read-attributes model session (list (attribute-path 0 +cluster-basic-information+ nil)) :timeout 20))
               (say "Descriptor of every endpoint:")
               (show-reports (read-attributes model session (list (attribute-path nil +cluster-descriptor+ nil)) :timeout 20))
               (close-session channel session))
          (exchange-manager-close manager))))))
(uiop:quit)
