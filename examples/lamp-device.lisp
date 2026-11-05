;;;; lamp-device.lisp -- a commissionable lamp on the real network, for a
;;;; real commissioner (chip-tool, the SDK's Python controller, a phone app
;;;; with test credentials enabled).
;;;;
;;;;   AMILISP_NO_USERINIT=1 amilisp --heap 64M --load examples/lamp-device.lisp
;;;;   sbcl --load examples/lamp-device.lisp          (no responder on SBCL yet)
;;;;
;;;; Environment: LAMP_PORT (5540), LAMP_PASSCODE (20202021), LAMP_DISCRIMINATOR
;;;; (3840), LAMP_INTERFACE (advertise and multicast on this interface only,
;;;; "en0"), LAMP_TRACE (set for the exchange trace), LAMP_STORAGE (the
;;;; state file, default ~/.cl-matter/lamp-device.state; empty for none),
;;;; AMILISP_REPO (where lib/quicklisp-compat.lisp is; default
;;;; ../../amigastuff/cl-amiga from here).
;;;;
;;;; The device listens on every IPv6 address (Matter is IPv6), advertises
;;;; itself over mDNS with the SDK's example credentials (vendor FFF1,
;;;; product 8000), prints its QR and manual pairing codes and serves until
;;;; killed.  Commission it with
;;;;
;;;;   chip-tool pairing code 1 34970112332
;;;;   chip-tool onoff toggle 1 1
;;;;
;;;; Its fabrics, ACL and resumption records are kept in the state file, so
;;;; a lamp started again is still commissioned: chip-tool finds it by its
;;;; operational advertisement and talks to it at once.  Delete the file
;;;; (or `chip-tool pairing unpair 1`) to start over.

(require "asdf")
(load "~/quicklisp/setup.lisp")
#+amilisp
(let ((compat (merge-pathnames "lib/quicklisp-compat.lisp"
                               (uiop:ensure-directory-pathname
                                (or (uiop:getenv "AMILISP_REPO")
                                    (uiop:merge-pathnames* "../../amigastuff/cl-amiga/"
                                                           (uiop:pathname-directory-pathname *load-truename*)))))))
  (when (probe-file compat) (load compat)))
(asdf:load-system :cl-matter)

(defpackage :lamp-device (:use :cl :cl-matter))
(in-package :lamp-device)

(defun env-integer (name default)
  (let ((value (uiop:getenv name)))
    (if (and value (plusp (length value))) (parse-integer value) default)))

(defparameter *port* (env-integer "LAMP_PORT" 5540))
(defparameter *passcode* (env-integer "LAMP_PASSCODE" 20202021))
(defparameter *discriminator* (env-integer "LAMP_DISCRIMINATOR" 3840))
(defparameter *salt* (map '(vector (unsigned-byte 8)) #'char-code "SPAKE2P Key Salt"))

(defparameter *interface* (uiop:getenv "LAMP_INTERFACE"))
(defparameter *storage*
  (let ((value (uiop:getenv "LAMP_STORAGE")))
    (cond ((null value) (merge-pathnames ".cl-matter/lamp-device.state" (user-homedir-pathname)))
          ((plusp (length value)) value)
          (t nil))))

(defun link-local-p (address)
  (and (> (length address) 4) (string-equal "fe80" address :end2 4)))

(defun ipv6-addresses ()
  "This machine's IPv6 addresses to advertise, zone identifiers removed: of
every interface that is up and has a routable address (so a VPN tunnel
with nothing but a link-local address is left out), or of *INTERFACE*."
  (let ((addresses '()))
    (dolist (interface (cl-matter.net:network-interfaces))
      (let* ((flags (getf interface :flags))
             (all (mapcar (lambda (a) (subseq a 0 (position #\% a))) (getf interface :addresses)))
             (routable (remove-if #'link-local-p all)))
        (when (and (member :up flags) (not (member :loopback flags))
                   (if *interface* (string= *interface* (getf interface :name)) routable))
          (dolist (address all)
            (when (find #\: address)
              (pushnew address addresses :test #'string=))))))
    (nreverse addresses)))

(defun say (format &rest args)
  (format t "~&~?~%" format args)
  (finish-output))

(let* ((start (get-internal-real-time))
       (trace (and (uiop:getenv "LAMP_TRACE")
                   (lambda (format &rest args)
                     (format t "~&[~7,3f] ~?~%" (/ (- (get-internal-real-time) start) internal-time-units-per-second 1.0d0)
                             format args)
                     (finish-output))))
       (transport (make-udp-transport :family :ipv6 :port *port*))
       (manager (make-exchange-manager :transport transport :trace trace))
       (light (make-on-off-cluster :on-change (lambda (cluster on) (declare (ignore cluster))
                                                (say "*** lamp ~a" (if on "ON" "OFF")))))
       (node (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id #x8000
                              :node-label "Lisp lamp" :hardware-version-string "cl-matter" :software-version-string "0.1"
                              :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                                :clusters (list (make-identify-cluster) light)))))
       (channel (make-secure-channel manager))
       (model (make-interaction-model manager :node node))
       (device (make-device :node node :channel channel :model model
                            :credentials (test-attestation-credentials)
                            :discriminator *discriminator* :passcode *passcode* :salt *salt* :iterations 1000
                            :storage *storage*
                            :on-commissioned (lambda (device fabric)
                                               (declare (ignore device))
                                               (say "*** commissioned into fabric ~16,'0x as node ~16,'0x (index ~d)"
                                                    (fabric-fabric-id fabric) (fabric-node-id fabric) (fabric-index fabric)))
                            :on-fabric-removed (lambda (device fabric)
                                                 (declare (ignore device))
                                                 (say "*** fabric ~16,'0x removed" (fabric-fabric-id fabric)))))
       (payload (device-onboarding-payload device *passcode*)))
  (multiple-value-bind (host port) (transport-local-endpoint transport)
    (say "listening on [~a]:~d" host port))
  (let ((addresses (ipv6-addresses)))
    (say "advertising ~{~a~^, ~}" addresses)
    (start-device-advertising device :addresses addresses :interface *interface* :device-name "Lamp"
                                     :device-type +device-type-on-off-light+ :pairing-hint 33))
  (when *storage* (say "state file ~a" *storage*))
  (if (device-fabrics device)
      (say "commissioned into ~d fabric~:p: ~{~a~^, ~} -- the window stays closed"
           (length (device-fabrics device)) (device-fabrics device))
      (say "discriminator ~d, passcode ~d" *discriminator* *passcode*))
  (say "QR code      ~a" (encode-qr-code payload))
  (say "manual code  ~a" (encode-manual-pairing-code payload))
  (say "on the air: ~{~a~^, ~}" (mapcar #'dns-sd:service-instance-name (device-advertised-services device)))
  (unwind-protect
       (exchange-manager-run manager :until (lambda () nil) :timeout (* 24 60 60))
    (stop-device-advertising device)
    (exchange-manager-close manager)))
