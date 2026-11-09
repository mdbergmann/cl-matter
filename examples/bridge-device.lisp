;;;; bridge-device.lisp -- a commissionable bridge on the real network, two
;;;; lights behind it, for a real commissioner (chip-tool, Apple Home with
;;;; the test credentials accepted as "Uncertified Accessory").
;;;;
;;;;   AMILISP_NO_USERINIT=1 amilisp --heap 64M --load examples/bridge-device.lisp
;;;;   sbcl --load examples/bridge-device.lisp         (no responder on SBCL yet)
;;;;
;;;; Environment: BRIDGE_PORT (5540), BRIDGE_PASSCODE (20202021),
;;;; BRIDGE_DISCRIMINATOR (3840), BRIDGE_INTERFACE (advertise and multicast
;;;; on this interface only, "en0"), BRIDGE_TRACE (set for the exchange
;;;; trace), BRIDGE_STORAGE (the state file, default
;;;; ~/.cl-matter/bridge-device.state; empty for none), BRIDGE_HALL_AFTER
;;;; (seconds after start the hall light is added, 0 for at once; it is
;;;; removed again that many seconds later and so on, to show a controller
;;;; following the PartsList; default 0), AMILISP_REPO (where
;;;; lib/quicklisp-compat.lisp is; default ../../amigasources/cl-amiga).
;;;;
;;;; The node is a bridge (Matter Device Library 9.12): endpoint 1 is the
;;;; Aggregator, endpoints 2 and 3 are Bridged Nodes, each an On/Off Light
;;;; with Bridged Device Basic Information naming it.  Commission it with
;;;;
;;;;   chip-tool pairing code 1 34970112332
;;;;   chip-tool descriptor read parts-list 1 1          ; => [2, 3]
;;;;   chip-tool bridgeddevicebasicinformation read node-label 1 2
;;;;   chip-tool onoff toggle 1 2                        ; the kitchen
;;;;   chip-tool onoff toggle 1 3                        ; the hall
;;;;
;;;; Apple Home shows two lights, "Kitchen" and "Hall", in a bridge "Bridge".

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

(defpackage :bridge-device (:use :cl :cl-matter))
(in-package :bridge-device)

(defun env-integer (name default)
  (let ((value (uiop:getenv name)))
    (if (and value (plusp (length value))) (parse-integer value) default)))

(defparameter *port* (env-integer "BRIDGE_PORT" 5540))
(defparameter *passcode* (env-integer "BRIDGE_PASSCODE" 20202021))
(defparameter *discriminator* (env-integer "BRIDGE_DISCRIMINATOR" 3840))
(defparameter *hall-after* (env-integer "BRIDGE_HALL_AFTER" 0))
(defparameter *salt* (map '(vector (unsigned-byte 8)) #'char-code "SPAKE2P Key Salt"))

(defparameter *interface* (uiop:getenv "BRIDGE_INTERFACE"))
(defparameter *storage*
  (let ((value (uiop:getenv "BRIDGE_STORAGE")))
    (cond ((null value) (merge-pathnames ".cl-matter/bridge-device.state" (user-homedir-pathname)))
          ((plusp (length value)) value)
          (t nil))))

(defun link-local-p (address)
  (and (> (length address) 4) (string-equal "fe80" address :end2 4)))

(defun ipv6-addresses ()
  "This machine's IPv6 addresses to advertise, zone identifiers removed: of
every interface that is up and has a routable address, or of *INTERFACE*."
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

(defconstant +aggregator+ 1)

(defun bridged-light (id label unique-id)
  "A bridged On/Off Light endpoint named LABEL, a part of the aggregator."
  (make-bridged-endpoint id :parent +aggregator+
                            :node-label label :unique-id unique-id
                            :vendor-name "ACME" :product-name "Lisp light"
                            :device-types (list (cons +device-type-on-off-light+ 3))
                            :clusters (list (make-identify-cluster)
                                            (make-on-off-cluster
                                             :on-change (lambda (cluster on) (declare (ignore cluster))
                                                          (say "*** ~a ~a" label (if on "ON" "OFF")))))))

(let* ((start (get-internal-real-time))
       (trace (and (uiop:getenv "BRIDGE_TRACE")
                   (lambda (format &rest args)
                     (format t "~&[~7,3f] ~?~%" (/ (- (get-internal-real-time) start) internal-time-units-per-second 1.0d0)
                             format args)
                     (finish-output))))
       (transport (make-udp-transport :family :ipv6 :port *port*))
       (manager (make-exchange-manager :transport transport :trace trace))
       (hall (bridged-light 3 "Hall" "cl-matter-bridge-hall"))
       (node (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Bridge" :product-id #x8000
                              :node-label "Lisp bridge" :hardware-version-string "cl-matter" :software-version-string "0.1"
                              :endpoints (list (make-aggregator-endpoint +aggregator+)
                                               (bridged-light 2 "Kitchen" "cl-matter-bridge-kitchen")
                                               hall)))
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
    (start-device-advertising device :addresses addresses :interface *interface* :device-name "Bridge"
                                     :device-type +device-type-aggregator+ :pairing-hint 33))
  (when *storage* (say "state file ~a" *storage*))
  (if (device-fabrics device)
      (say "commissioned into ~d fabric~:p: ~{~a~^, ~} -- the window stays closed"
           (length (device-fabrics device)) (device-fabrics device))
      (say "discriminator ~d, passcode ~d" *discriminator* *passcode*))
  (say "QR code      ~a" (encode-qr-code payload))
  (say "manual code  ~a" (encode-manual-pairing-code payload))
  (say "on the air: ~{~a~^, ~}" (mapcar #'dns-sd:service-instance-name (device-advertised-services device)))
  (say "endpoints: ~{~a~^, ~}" (mapcar #'endpoint-id (node-endpoints node)))
  ;; with BRIDGE_HALL_AFTER the hall light comes and goes: a subscribed
  ;; controller sees the aggregator's and the root's PartsList change
  (when (plusp *hall-after*)
    (remove-endpoint node hall)
    (let ((next (+ (exchange-manager-now manager) *hall-after*)))
      (add-timer manager (lambda (now)
                           (declare (ignore now))
                           (if (endpoint-node hall)
                               (progn (remove-endpoint node hall) (say "*** hall light removed"))
                               (progn (add-endpoint node hall) (say "*** hall light added")))
                           (incf next *hall-after*))
                 :at next)))
  (unwind-protect
       (exchange-manager-run manager :until (lambda () nil) :timeout (* 24 60 60))
    (stop-device-advertising device)
    (exchange-manager-close manager)))
