(defpackage :cl-matter.message.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.message.tests)

(def-suite message-tests :description "Matter message framing" :in cl-matter.tests:test-suite)
(in-suite message-tests)

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun hex (string)
  (let* ((digits (remove #\Space string))
         (out (make-array (floor (length digits) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer digits :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

;;; ------------------------------------------------------------------
;;; Message header

(test header-minimal
  (let ((header (make-message-header)))
    (is (equalp (hex "00 0000 00 00000000") (encode-message-header header)))
    (multiple-value-bind (back end) (decode-message-header (hex "00 0000 00 00000000"))
      (is (equalp header back))
      (is (= 8 end)))))

(test header-source-and-destination-node
  (let ((header (make-message-header :message-counter #x12345678
                                     :source-node-id #x0102030405060708
                                     :destination-node-id #xFFFFFFFD00000001)))
    (is (equalp (hex "05 0000 00 78563412 0807060504030201 01000000fdffffff")
                (encode-message-header header)))
    (multiple-value-bind (back end) (decode-message-header (encode-message-header header))
      (is (equalp header back))
      (is (= 24 end)))))

(test header-group-flags-and-extensions
  (let ((header (make-message-header :session-id #x1234 :session-type :group
                                     :privacy-p t :control-p t
                                     :message-counter 1
                                     :destination-group-id #x4321
                                     :extensions (octets #xAA #xBB))))
    (is (equalp (hex "02 3412 e1 01000000 2143 0200 aabb") (encode-message-header header)))
    (multiple-value-bind (back end) (decode-message-header (encode-message-header header))
      (is (equalp header back))
      (is (= 14 end))
      (is (eq :group (message-header-session-type back)))
      (is (message-header-privacy-p back))
      (is (message-header-control-p back))
      (is (null (message-header-destination-node-id back))))))

(test header-decode-with-start
  (let ((buffer (concatenate '(vector (unsigned-byte 8)) (octets 9 9 9)
                             (hex "04 0000 00 01000000 0807060504030201") (octets 7 7))))
    (multiple-value-bind (header end) (decode-message-header buffer :start 3)
      (is (= #x0102030405060708 (message-header-source-node-id header)))
      (is (= 19 end)))))

(defmacro rejects-header (hex-string)
  `(handler-case (progn (decode-message-header (hex ,hex-string)) (fail "~a accepted" ,hex-string))
     (message-decode-error (e) (is (integerp (message-decode-error-offset e))))))

(test header-rejects-malformed
  (rejects-header "00 0000 00 000000")           ; short
  (rejects-header "10 0000 00 00000000")         ; version 1
  (rejects-header "03 0000 00 00000000")         ; DSIZ 3
  (rejects-header "00 0000 02 00000000")         ; session type 2
  (rejects-header "04 0000 00 00000000 0102")    ; source node id short
  (rejects-header "00 0000 20 00000000 0400 aa") ; extensions short
  (handler-case (decode-message-header (hex "10 0000 00 00000000"))
    (message-decode-error (e) (is (= 0 (message-decode-error-offset e))))))

(test header-rejects-unencodable
  (signals message-encode-error
    (encode-message-header (make-message-header :destination-node-id 1 :destination-group-id 2)))
  (signals message-encode-error
    (encode-message-header (make-message-header :source-node-id (ash 1 64))))
  (signals message-encode-error
    (encode-message-header (make-message-header :destination-group-id #x10000)))
  (signals message-encode-error
    (encode-message-header (make-message-header :extensions "ab"))))

;;; ------------------------------------------------------------------
;;; Protocol header

(test protocol-header-plain
  (let ((header (make-protocol-header :initiator-p t :reliability-p t
                                      :opcode +opcode-pbkdf-param-request+
                                      :exchange-id 1
                                      :protocol-id +protocol-secure-channel+
                                      :payload (octets #x15 #x18))))
    (is (equalp (hex "05 20 0100 0000 1518") (encode-protocol-header header)))
    (let ((back (decode-protocol-header (encode-protocol-header header))))
      (is (equalp header back))
      (is (protocol-header-secure-channel-p back)))))

(test protocol-header-ack-vendor-extensions
  (let ((header (make-protocol-header :initiator-p t
                                      :ack-counter #xAABBCCDD
                                      :vendor-id #xFFF1
                                      :protocol-id +protocol-interaction-model+
                                      :opcode +opcode-im-status-response+
                                      :exchange-id 2
                                      :secured-extensions (octets 1 2 3))))
    (is (equalp (hex "1b 01 0200 f1ff 0100 ddccbbaa 0300 010203") (encode-protocol-header header)))
    (let ((back (decode-protocol-header (encode-protocol-header header))))
      (is (= #xAABBCCDD (protocol-header-ack-counter back)))
      (is (= #xFFF1 (protocol-header-vendor-id back)))
      (is (not (protocol-header-secure-channel-p back)))
      (is (equalp (octets 1 2 3) (protocol-header-secured-extensions back)))
      (is (= 0 (length (protocol-header-payload back)))))))

(test protocol-header-rejects
  (signals message-decode-error (decode-protocol-header (hex "00 01 00")))
  (signals message-decode-error (decode-protocol-header (hex "02 01 0000 0000 0102")))   ; ack short
  (signals message-decode-error (decode-protocol-header (hex "08 01 0000 0000 0500 01"))) ; ext short
  (signals message-encode-error (encode-protocol-header (make-protocol-header :ack-counter (ash 1 32))))
  (signals message-encode-error (encode-protocol-header (make-protocol-header :vendor-id -1)))
  (signals message-encode-error (encode-protocol-header (make-protocol-header :payload "text"))))

;;; ------------------------------------------------------------------
;;; Whole unsecured messages

(test unsecured-message-round-trip
  (let* ((header (make-message-header :message-counter #x12345678
                                      :source-node-id #x0102030405060708))
         (protocol (make-protocol-header :initiator-p t :reliability-p t
                                         :opcode +opcode-pbkdf-param-request+
                                         :exchange-id 1
                                         :protocol-id +protocol-secure-channel+
                                         :payload (octets #x15 #x18)))
         (frame (encode-unsecured-message header protocol)))
    (is (equalp (hex "04 0000 00 78563412 0807060504030201 05 20 0100 0000 1518") frame))
    (multiple-value-bind (h p) (decode-unsecured-message frame)
      (is (equalp header h))
      (is (equalp protocol p)))
    ;; inside a larger buffer
    (let ((buffer (concatenate '(vector (unsigned-byte 8)) (octets 1 2) frame (octets 3))))
      (multiple-value-bind (h p) (decode-unsecured-message buffer :start 2 :end (+ 2 (length frame)))
        (is (equalp header h))
        (is (equalp (octets #x15 #x18) (protocol-header-payload p)))))))

(test unsecured-refuses-secured-session
  (signals message-encode-error
    (encode-unsecured-message (make-message-header :session-id 1) (make-protocol-header)))
  (handler-case (progn (decode-unsecured-message (hex "00 0100 00 00000000 00 00 0000 0000"))
                       (fail "accepted"))
    (message-decode-error (e)
      (is (= 1 (message-decode-error-offset e)))
      (is (search "encrypted" (princ-to-string e)))))
  ;; the header of a secured message is still readable on its own
  (multiple-value-bind (h end) (decode-message-header (hex "00 0100 00 00000000 ff ff"))
    (is (= 1 (message-header-session-id h)))
    (is (= 8 end))))

;;; ------------------------------------------------------------------
;;; Status report

(test status-report
  (let ((success (make-status-report)))
    (is (equalp (hex "0000 00000000 0000") (encode-status-report success)))
    (is (equalp success (decode-status-report (encode-status-report success)))))
  (let ((report (make-status-report :general-code +status-failure+
                                    :protocol-id +protocol-secure-channel+
                                    :protocol-code 2    ; INVALID_PARAMETER
                                    :data (octets 9))))
    (is (equalp (hex "0100 00000000 0200 09") (encode-status-report report)))
    (is (equalp report (decode-status-report (encode-status-report report)))))
  (signals message-decode-error (decode-status-report (hex "0000 00000000 00"))))

;;; ------------------------------------------------------------------
;;; Counters

(test outgoing-counter
  (let ((counter (make-message-counter #xFFFFFFFF)))
    (is (= #xFFFFFFFF (next-message-counter counter)))
    (is (= 0 (next-message-counter counter)))
    (is (= 1 (next-message-counter counter))))
  (let ((counter (make-message-counter)))
    (is (< 0 (message-counter-value counter) (ash 1 32))))
  (is (/= 0 (random-message-counter))))

(test counter-window
  (let ((w (make-counter-window)))
    (is-true (counter-window-accept w 100))
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w 100))))
    (is-true (counter-window-accept w 101))
    (is-true (counter-window-accept w 99))                    ; late but new
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w 99))))
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w 100))))
    (is (equal '(nil :stale) (multiple-value-list (counter-window-accept w 68))))     ; 33 behind
    (is-true (counter-window-accept w 69))                                            ; 32 behind
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w 69))))
    ;; a leap of more than the window forgets everything behind
    (is-true (counter-window-accept w 1000))
    (is (= 1000 (counter-window-newest w)))
    (is (equal '(nil :stale) (multiple-value-list (counter-window-accept w 101))))
    (is-true (counter-window-accept w 999))))

(test counter-window-wraps
  (let ((w (make-counter-window)))
    (is-true (counter-window-accept w #xFFFFFFFE))
    (is-true (counter-window-accept w 1))                     ; 3 ahead, across the wrap
    (is (= 1 (counter-window-newest w)))
    (is-true (counter-window-accept w #xFFFFFFFF))            ; 2 behind
    (is-true (counter-window-accept w 0))
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w #xFFFFFFFE))))
    (is (equal '(nil :duplicate) (multiple-value-list (counter-window-accept w 1))))))

;;; ------------------------------------------------------------------
;;; MRP

(test mrp-backoff-formula
  (flet ((close-to (expected actual) (is (< (abs (- expected actual)) 1d-9))))
    ;; idle interval 0.5 s, no jitter: 0.55, 0.55, 0.88, 1.408
    (close-to 0.55d0 (mrp-backoff 1 :random 0))
    (close-to 0.55d0 (mrp-backoff 2 :random 0))
    (close-to 0.88d0 (mrp-backoff 3 :random 0))
    (close-to 1.408d0 (mrp-backoff 4 :random 0))
    ;; full jitter adds a quarter
    (close-to 0.6875d0 (mrp-backoff 1 :random 1))
    ;; an active peer: 0.3 s base
    (close-to 0.33d0 (mrp-backoff 1 :interval 0.3d0 :random 0))))

(test retransmission-table
  (let* ((table (make-retransmission-table :random-function (constantly 0)))
         (frame (octets 1 2 3))
         (message (mrp-track table 42 frame 0 :context :pase1)))
    (is (= 1 (pending-message-transmissions message)))
    (is (< (abs (- 0.55d0 (pending-message-next-at message))) 1d-9))
    (is (< (abs (- 0.55d0 (mrp-next-deadline table))) 1d-9))
    (is (null (mrp-due table 0.5d0)))
    (multiple-value-bind (again failed) (mrp-due table 0.6d0)
      (is (equal (list message) again))
      (is (null failed))
      (is (= 2 (pending-message-transmissions message)))
      (is (eq frame (pending-message-octets message)))
      (is (< (abs (- 1.15d0 (pending-message-next-at message))) 1d-9)))
    (is (null (mrp-acknowledge table 41)))
    (is (eq message (mrp-acknowledge table 42)))
    (is (null (retransmission-table-pending table)))
    (is (null (mrp-next-deadline table)))))

(test retransmission-gives-up
  (let* ((table (make-retransmission-table :random-function (constantly 0)))
         (message (mrp-track table 7 (octets 0) 0 :context :sigma1))
         (sends 1)
         (now 0))
    (loop :repeat 10
          :do (setf now (pending-message-next-at message))
              (multiple-value-bind (again failed) (mrp-due table now)
                (incf sends (length again))
                (when failed
                  (is (equal (list message) failed))
                  (is (eq :sigma1 (pending-message-context (first failed))))
                  (return))))
    (is (= *mrp-max-transmissions* sends))
    (is (null (retransmission-table-pending table)))
    ;; two messages are independent
    (let ((a (mrp-track table 1 (octets 1) 0))
          (b (mrp-track table 2 (octets 2) 0 :active t)))
      (is (< (pending-message-next-at b) (pending-message-next-at a)))
      (is (eq b (mrp-acknowledge table 2)))
      (is (equal (list a) (retransmission-table-pending table))))))
