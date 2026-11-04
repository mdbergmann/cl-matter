(in-package :cl-matter)

;;; Matter message framing (Core Specification chapter 4).
;;;
;;; A message on the wire is
;;;
;;;   message header   flags, session id, security flags, message counter,
;;;                    source / destination node id, message extensions
;;;   payload          encrypted unless the session id is 0:
;;;     protocol header  exchange flags, opcode, exchange id, vendor id,
;;;                      protocol id, acknowledged counter, extensions
;;;     application payload
;;;   MIC              16 octets, secured sessions only
;;;
;;; This file is the codec for both headers, the Secure Channel status
;;; report, the per-peer receive window that spots duplicate and stale
;;; message counters (section 4.5.4), and the MRP retransmission timing
;;; (section 4.11).  Encryption, sessions and exchanges build on it.

(define-condition message-error (error)
  ((message :initarg :message :reader message-error-message))
  (:report (lambda (c stream) (format stream "~a" (message-error-message c)))))

(define-condition message-encode-error (message-error) ()
  (:report (lambda (c stream)
             (format stream "cannot encode Matter message: ~a" (message-error-message c)))))

(define-condition message-decode-error (message-error)
  ((offset :initarg :offset :initform nil :reader message-decode-error-offset))
  (:report (lambda (c stream)
             (format stream "malformed Matter message~@[ at byte ~d~]: ~a"
                     (message-decode-error-offset c) (message-error-message c)))))

;;; ------------------------------------------------------------------
;;; Protocol ids and opcodes (section 4.4.3.5 and the protocol chapters)

(defconstant +protocol-secure-channel+   #x0000)
(defconstant +protocol-interaction-model+ #x0001)
(defconstant +protocol-bdx+              #x0002)
(defconstant +protocol-user-directed-commissioning+ #x0003)

;; Secure Channel opcodes
(defconstant +opcode-msg-counter-sync-req+ #x00)
(defconstant +opcode-msg-counter-sync-rsp+ #x01)
(defconstant +opcode-standalone-ack+       #x10)
(defconstant +opcode-pbkdf-param-request+  #x20)
(defconstant +opcode-pbkdf-param-response+ #x21)
(defconstant +opcode-pase-pake1+           #x22)
(defconstant +opcode-pase-pake2+           #x23)
(defconstant +opcode-pase-pake3+           #x24)
(defconstant +opcode-case-sigma1+          #x30)
(defconstant +opcode-case-sigma2+          #x31)
(defconstant +opcode-case-sigma3+          #x32)
(defconstant +opcode-case-sigma2-resume+   #x33)
(defconstant +opcode-status-report+        #x40)

;; Interaction Model opcodes
(defconstant +opcode-im-status-response+    #x01)
(defconstant +opcode-im-read-request+       #x02)
(defconstant +opcode-im-subscribe-request+  #x03)
(defconstant +opcode-im-subscribe-response+ #x04)
(defconstant +opcode-im-report-data+        #x05)
(defconstant +opcode-im-write-request+      #x06)
(defconstant +opcode-im-write-response+     #x07)
(defconstant +opcode-im-invoke-request+     #x08)
(defconstant +opcode-im-invoke-response+    #x09)
(defconstant +opcode-im-timed-request+      #x0A)

;; status report general codes (section 4.10.1.3)
(defconstant +status-success+          0)
(defconstant +status-failure+          1)
(defconstant +status-bad-precondition+ 2)
(defconstant +status-out-of-range+     3)
(defconstant +status-bad-request+      4)
(defconstant +status-unsupported+      5)
(defconstant +status-unexpected+       6)
(defconstant +status-resource-exhausted+ 7)
(defconstant +status-busy+             8)
(defconstant +status-timeout+          9)
(defconstant +status-continue+         10)
(defconstant +status-aborted+          11)
(defconstant +status-invalid-argument+ 12)
(defconstant +status-not-found+        13)
(defconstant +status-already-exists+   14)
(defconstant +status-permission-denied+ 15)
(defconstant +status-data-loss+        16)

(defconstant +mic-length+ 16)
(defconstant +unsecured-session-id+ 0)

;;; ------------------------------------------------------------------
;;; Headers

(defstruct message-header
  "Section 4.4.1.  SESSION-TYPE is :UNICAST or :GROUP.  One of
DESTINATION-NODE-ID (64 bits) and DESTINATION-GROUP-ID (16 bits) at most.
EXTENSIONS, when not NIL, are the message extensions octets."
  (session-id 0 :type (unsigned-byte 16))
  (session-type :unicast :type (member :unicast :group))
  (privacy-p nil :type boolean)
  (control-p nil :type boolean)
  (message-counter 0 :type (unsigned-byte 32))
  (source-node-id nil)
  (destination-node-id nil)
  (destination-group-id nil)
  (extensions nil))

(defstruct protocol-header
  "Section 4.4.3, with the application payload that follows it.
ACK-COUNTER is the acknowledged message counter or NIL; VENDOR-ID NIL
means the standard protocol namespace."
  (initiator-p nil :type boolean)
  (reliability-p nil :type boolean)
  (ack-counter nil)
  (vendor-id nil)
  (protocol-id 0 :type (unsigned-byte 16))
  (opcode 0 :type (unsigned-byte 8))
  (exchange-id 0 :type (unsigned-byte 16))
  (secured-extensions nil)
  (payload nil))

(defun protocol-header-secure-channel-p (header)
  (and (null (protocol-header-vendor-id header))
       (= +protocol-secure-channel+ (protocol-header-protocol-id header))))

;; message flags
(defconstant +flag-source-present+ #x04)
(defconstant +dsiz-mask+ #x03)
(defconstant +dsiz-none+ 0)
(defconstant +dsiz-node+ 1)
(defconstant +dsiz-group+ 2)
;; security flags
(defconstant +sflag-privacy+ #x80)
(defconstant +sflag-control+ #x40)
(defconstant +sflag-extensions+ #x20)
(defconstant +session-type-mask+ #x03)
;; exchange flags
(defconstant +xflag-initiator+ #x01)
(defconstant +xflag-ack+ #x02)
(defconstant +xflag-reliability+ #x04)
(defconstant +xflag-secured-extensions+ #x08)
(defconstant +xflag-vendor+ #x10)

;;; octet buffer helpers, little endian

(defun %new-buffer (&optional (size 64))
  (make-array size :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun %put-le (out value octets)
  (dotimes (i octets)
    (vector-push-extend (ldb (byte 8 (* 8 i)) value) out)))

(defun %put-octets (out octets)
  (loop :for b :across octets :do (vector-push-extend b out)))

(defun %finish-buffer (out)
  (let ((result (make-array (length out) :element-type '(unsigned-byte 8))))
    (replace result out)
    result))

(defun %octets-p (x)
  (and (vectorp x) (not (stringp x))))

(defun %check-octets (what x)
  (unless (%octets-p x)
    (error 'message-encode-error :message (format nil "~a must be an octet vector, got ~s" what x))))

(defun %check-range (what value bits)
  (unless (and (integerp value) (<= 0 value) (< value (ash 1 bits)))
    (error 'message-encode-error
           :message (format nil "~a must be an unsigned ~d-bit integer, got ~s" what bits value))))

(defstruct (%reader (:constructor %make-reader (octets pos end)))
  octets pos end)

(defun %rfail (reader format &rest args)
  (error 'message-decode-error :offset (%reader-pos reader)
                               :message (apply #'format nil format args)))

(defun %rneed (reader n what)
  (when (> (+ (%reader-pos reader) n) (%reader-end reader))
    (%rfail reader "~a needs ~d octet~:p, ~d left" what n (- (%reader-end reader) (%reader-pos reader)))))

(defun %rget-le (reader octets what)
  (%rneed reader octets what)
  (let ((value 0) (data (%reader-octets reader)) (base (%reader-pos reader)))
    (dotimes (i octets)
      (setf value (logior value (ash (aref data (+ base i)) (* 8 i)))))
    (incf (%reader-pos reader) octets)
    value))

(defun %rget-octets (reader n what)
  (%rneed reader n what)
  (let ((result (make-array n :element-type '(unsigned-byte 8)))
        (pos (%reader-pos reader)))
    (replace result (%reader-octets reader) :start2 pos :end2 (+ pos n))
    (incf (%reader-pos reader) n)
    result))

(defun %rget-extensions (reader what)
  "A 16-bit length and that many octets."
  (let ((length (%rget-le reader 2 what)))
    (%rget-octets reader length what)))

;;; message header

(defun message-header-security-flags (header)
  "The security flags octet of HEADER (section 4.4.1.4): privacy, control,
message-extensions flags and the session type.  The first octet of the
nonce of a secured message."
  (logior (if (message-header-privacy-p header) +sflag-privacy+ 0)
          (if (message-header-control-p header) +sflag-control+ 0)
          (if (message-header-extensions header) +sflag-extensions+ 0)
          (ecase (message-header-session-type header)
            (:unicast 0)
            (:group 1))))

(defun %put-message-header (header out)
  (let ((source (message-header-source-node-id header))
        (node (message-header-destination-node-id header))
        (group (message-header-destination-group-id header))
        (extensions (message-header-extensions header)))
    (when (and node group)
      (error 'message-encode-error :message "a message has a destination node id or a group id, not both"))
    (when source (%check-range "source node id" source 64))
    (when node (%check-range "destination node id" node 64))
    (when group (%check-range "destination group id" group 16))
    (when extensions
      (%check-octets "message extensions" extensions)
      (%check-range "message extensions length" (length extensions) 16))
    ;; message flags: version 0, S, DSIZ
    (vector-push-extend (logior (if source +flag-source-present+ 0)
                                (cond (node +dsiz-node+) (group +dsiz-group+) (t +dsiz-none+)))
                        out)
    (%put-le out (message-header-session-id header) 2)
    (vector-push-extend (message-header-security-flags header) out)
    (%put-le out (message-header-message-counter header) 4)
    (when source (%put-le out source 8))
    (when node (%put-le out node 8))
    (when group (%put-le out group 2))
    (when extensions
      (%put-le out (length extensions) 2)
      (%put-octets out extensions))))

(defun encode-message-header (header)
  "MESSAGE-HEADER -> its octets (the additional data of the AEAD, for a
secured message)."
  (let ((out (%new-buffer 32)))
    (%put-message-header header out)
    (%finish-buffer out)))

(defun decode-message-header (octets &key (start 0) end)
  "OCTETS[START,END) -> the MESSAGE-HEADER and, second, the offset of the
payload.  Signals MESSAGE-DECODE-ERROR for a short header, a version other
than 0 or a reserved field value."
  (let* ((end (or end (length octets)))
         (reader (%make-reader octets start end))
         (flags (%rget-le reader 1 "message flags")))
    (unless (zerop (ldb (byte 4 4) flags))
      (decf (%reader-pos reader))
      (%rfail reader "message version ~d is not supported" (ldb (byte 4 4) flags)))
    (let* ((dsiz (logand flags +dsiz-mask+))
           (session-id (%rget-le reader 2 "session id"))
           (security (%rget-le reader 1 "security flags"))
           (session-type (case (logand security +session-type-mask+)
                           (0 :unicast)
                           (1 :group)
                           (t (decf (%reader-pos reader))
                              (%rfail reader "reserved session type ~d"
                                      (logand security +session-type-mask+)))))
           (counter (%rget-le reader 4 "message counter"))
           (source (and (logtest flags +flag-source-present+) (%rget-le reader 8 "source node id")))
           (node nil) (group nil))
      (cond ((= dsiz +dsiz-node+) (setf node (%rget-le reader 8 "destination node id")))
            ((= dsiz +dsiz-group+) (setf group (%rget-le reader 2 "destination group id")))
            ((= dsiz 3) (%rfail reader "reserved destination size 3")))
      (let ((extensions (and (logtest security +sflag-extensions+)
                             (%rget-extensions reader "message extensions"))))
        (values (make-message-header :session-id session-id :session-type session-type
                                     :privacy-p (logtest security +sflag-privacy+)
                                     :control-p (logtest security +sflag-control+)
                                     :message-counter counter
                                     :source-node-id source
                                     :destination-node-id node
                                     :destination-group-id group
                                     :extensions extensions)
                (%reader-pos reader))))))

;;; protocol header + application payload

(defun encode-protocol-header (header)
  "PROTOCOL-HEADER, application payload included -> the plaintext payload
octets of a message."
  (let ((out (%new-buffer 64))
        (ack (protocol-header-ack-counter header))
        (vendor (protocol-header-vendor-id header))
        (extensions (protocol-header-secured-extensions header))
        (payload (protocol-header-payload header)))
    (when ack (%check-range "acknowledged message counter" ack 32))
    (when vendor (%check-range "protocol vendor id" vendor 16))
    (when extensions
      (%check-octets "secured extensions" extensions)
      (%check-range "secured extensions length" (length extensions) 16))
    (when payload (%check-octets "application payload" payload))
    (vector-push-extend (logior (if (protocol-header-initiator-p header) +xflag-initiator+ 0)
                                (if ack +xflag-ack+ 0)
                                (if (protocol-header-reliability-p header) +xflag-reliability+ 0)
                                (if extensions +xflag-secured-extensions+ 0)
                                (if vendor +xflag-vendor+ 0))
                        out)
    (vector-push-extend (protocol-header-opcode header) out)
    (%put-le out (protocol-header-exchange-id header) 2)
    (when vendor (%put-le out vendor 2))
    (%put-le out (protocol-header-protocol-id header) 2)
    (when ack (%put-le out ack 4))
    (when extensions
      (%put-le out (length extensions) 2)
      (%put-octets out extensions))
    (when payload (%put-octets out payload))
    (%finish-buffer out)))

(defun decode-protocol-header (octets &key (start 0) end)
  "Plaintext payload OCTETS[START,END) -> PROTOCOL-HEADER, the application
payload in its PAYLOAD slot."
  (let* ((end (or end (length octets)))
         (reader (%make-reader octets start end))
         (flags (%rget-le reader 1 "exchange flags"))
         (opcode (%rget-le reader 1 "protocol opcode"))
         (exchange-id (%rget-le reader 2 "exchange id"))
         (vendor (and (logtest flags +xflag-vendor+) (%rget-le reader 2 "protocol vendor id")))
         (protocol-id (%rget-le reader 2 "protocol id"))
         (ack (and (logtest flags +xflag-ack+) (%rget-le reader 4 "acknowledged message counter")))
         (extensions (and (logtest flags +xflag-secured-extensions+)
                          (%rget-extensions reader "secured extensions")))
         (payload (%rget-octets reader (- end (%reader-pos reader)) "application payload")))
    (make-protocol-header :initiator-p (logtest flags +xflag-initiator+)
                          :reliability-p (logtest flags +xflag-reliability+)
                          :ack-counter ack
                          :vendor-id vendor
                          :protocol-id protocol-id
                          :opcode opcode
                          :exchange-id exchange-id
                          :secured-extensions extensions
                          :payload payload)))

;;; whole unsecured messages

(defun encode-unsecured-message (header protocol-header)
  "A complete plaintext message for the unsecured session (session id 0)."
  (unless (= +unsecured-session-id+ (message-header-session-id header))
    (error 'message-encode-error
           :message (format nil "session ~d is secured; its payload must be encrypted"
                            (message-header-session-id header))))
  (let ((out (%new-buffer 96)))
    (%put-message-header header out)
    (%put-octets out (encode-protocol-header protocol-header))
    (%finish-buffer out)))

(defun decode-unsecured-message (octets &key (start 0) end)
  "OCTETS[START,END) -> MESSAGE-HEADER and PROTOCOL-HEADER of a message on
the unsecured session.  A secured message (session id other than 0) is
refused: decode its header with DECODE-MESSAGE-HEADER and decrypt first."
  (multiple-value-bind (header payload-start) (decode-message-header octets :start start :end end)
    (unless (= +unsecured-session-id+ (message-header-session-id header))
      (error 'message-decode-error :offset (+ 1 start)
                                   :message (format nil "session ~d is secured; the payload is encrypted"
                                                    (message-header-session-id header))))
    (values header (decode-protocol-header octets :start payload-start :end end))))

;;; ------------------------------------------------------------------
;;; Status report (section 4.10.1), Secure Channel opcode #x40

(defstruct status-report
  (general-code 0 :type (unsigned-byte 16))
  (protocol-id 0 :type (unsigned-byte 32))
  (protocol-code 0 :type (unsigned-byte 16))
  (data nil))

(defun encode-status-report (report)
  (let ((out (%new-buffer 16)))
    (%put-le out (status-report-general-code report) 2)
    (%put-le out (status-report-protocol-id report) 4)
    (%put-le out (status-report-protocol-code report) 2)
    (when (status-report-data report)
      (%check-octets "status report data" (status-report-data report))
      (%put-octets out (status-report-data report)))
    (%finish-buffer out)))

(defun decode-status-report (octets &key (start 0) end)
  (let* ((end (or end (length octets)))
         (reader (%make-reader octets start end))
         (general (%rget-le reader 2 "status report general code"))
         (protocol (%rget-le reader 4 "status report protocol id"))
         (code (%rget-le reader 2 "status report protocol code"))
         (rest (- end (%reader-pos reader))))
    (make-status-report :general-code general :protocol-id protocol :protocol-code code
                        :data (and (> rest 0) (%rget-octets reader rest "status report data")))))

;;; ------------------------------------------------------------------
;;; Message counters (section 4.5)

(defconstant +counter-window-size+ 32
  "Section 4.5.4.1: how many counters behind the newest are remembered.")

(defun random-message-counter ()
  "A fresh counter start: random, as section 4.5.1 asks, and never 0."
  (1+ (random #xFFFFFFFF)))

(defstruct (message-counter (:constructor make-message-counter
                                (&optional (value (random-message-counter)))))
  "The outgoing counter of a session or of the unsecured channel."
  (value 0 :type (unsigned-byte 32)))

(defun next-message-counter (counter)
  "The next value to send with; wraps at 2^32."
  (let ((value (message-counter-value counter)))
    (setf (message-counter-value counter) (logand (1+ value) #xFFFFFFFF))
    value))

(defstruct (counter-window (:constructor make-counter-window ()))
  "What a peer has sent us: the newest counter and a bitmap of the
+COUNTER-WINDOW-SIZE+ before it (section 4.5.4.1)."
  (newest nil)
  (bitmap 0 :type (unsigned-byte 32)))

(defun counter-window-accept (window counter)
  "Record COUNTER as received.  Returns T when it is new, or NIL and one
of :DUPLICATE (seen before) and :STALE (older than the window)."
  (let ((newest (counter-window-newest window)))
    (cond ((null newest)
           (setf (counter-window-newest window) counter)
           t)
          ((= counter newest) (values nil :duplicate))
          (t
           (let ((ahead (logand (- counter newest) #xFFFFFFFF)))
             (if (< ahead (ash 1 31))
                 ;; newer: slide the window, the old newest becomes bit 0
                 (progn
                   (setf (counter-window-bitmap window)
                         (if (> ahead +counter-window-size+)
                             0
                             (logand (logior (ash (counter-window-bitmap window) ahead)
                                             (ash 1 (1- ahead)))
                                     #xFFFFFFFF))
                         (counter-window-newest window) counter)
                   t)
                 (let ((behind (logand (- newest counter) #xFFFFFFFF)))
                   (cond ((> behind +counter-window-size+) (values nil :stale))
                         ((logbitp (1- behind) (counter-window-bitmap window))
                          (values nil :duplicate))
                         (t (setf (counter-window-bitmap window)
                                  (logior (counter-window-bitmap window) (ash 1 (1- behind))))
                            t)))))))))

;;; ------------------------------------------------------------------
;;; Message Reliability Protocol timing (section 4.11)

(defparameter *mrp-max-transmissions* 5
  "MRP_MAX_TRANSMISSIONS: the first send and four retries.")
(defparameter *mrp-backoff-threshold* 1 "MRP_BACKOFF_THRESHOLD")
(defparameter *mrp-backoff-margin* 1.1d0 "MRP_BACKOFF_MARGIN")
(defparameter *mrp-backoff-base* 1.6d0 "MRP_BACKOFF_BASE")
(defparameter *mrp-backoff-jitter* 0.25d0 "MRP_BACKOFF_JITTER")
(defparameter *mrp-standalone-ack-timeout* 0.2d0
  "MRP_STANDALONE_ACK_TIMEOUT: how long a receiver may wait for a message
to piggyback its acknowledgement on before sending a standalone one.")
(defparameter *mrp-default-idle-interval* 0.5d0 "SESSION_IDLE_INTERVAL, seconds.")
(defparameter *mrp-default-active-interval* 0.3d0 "SESSION_ACTIVE_INTERVAL, seconds.")

(defun mrp-backoff (transmissions &key (interval *mrp-default-idle-interval*)
                                       (random (random 1.0d0)))
  "Seconds to wait after the TRANSMISSIONS-th send (1 for the first) before
the next, section 4.11.8: interval * margin * base^max(0, n - threshold)
* (1 + random * jitter), n counting retransmissions from 0."
  (let ((n (1- transmissions)))
    (* interval
       *mrp-backoff-margin*
       (expt *mrp-backoff-base* (max 0 (- n *mrp-backoff-threshold*)))
       (+ 1 (* random *mrp-backoff-jitter*)))))

(defstruct (pending-message (:constructor %make-pending-message))
  "A reliable message awaiting its acknowledgement."
  counter      ; its message counter, which the ack names
  octets       ; the frame to retransmit, as sent
  (transmissions 1)
  next-at      ; when to retransmit, on the caller's clock
  context)     ; anything the sender wants back on failure

(defstruct (retransmission-table (:constructor make-retransmission-table
                                     (&key (idle-interval *mrp-default-idle-interval*)
                                           (active-interval *mrp-default-active-interval*)
                                           (random-function (lambda () (random 1.0d0))))))
  "The reliable messages of one peer that have not been acknowledged.  All
times are seconds on a clock the caller supplies, so nothing here waits."
  (pending nil :type list)
  idle-interval
  active-interval
  random-function)

(defun %mrp-next-at (table message now active)
  (+ now (mrp-backoff (pending-message-transmissions message)
                      :interval (if active
                                    (retransmission-table-active-interval table)
                                    (retransmission-table-idle-interval table))
                      :random (funcall (retransmission-table-random-function table)))))

(defun mrp-track (table counter octets now &key active context)
  "OCTETS, just sent with message COUNTER at time NOW, await an ack.  ACTIVE
says the peer is known to be awake, which shortens the intervals."
  (let ((message (%make-pending-message :counter counter :octets octets :context context)))
    (setf (pending-message-next-at message) (%mrp-next-at table message now active))
    (setf (retransmission-table-pending table)
          (append (retransmission-table-pending table) (list message)))
    message))

(defun mrp-acknowledge (table counter)
  "The peer acknowledged COUNTER: the PENDING-MESSAGE it closes, or NIL."
  (let ((message (find counter (retransmission-table-pending table) :key #'pending-message-counter)))
    (when message
      (setf (retransmission-table-pending table) (remove message (retransmission-table-pending table))))
    message))

(defun mrp-due (table now &key active)
  "At time NOW: the pending messages to send again, each counted as one
more transmission and rescheduled, and second the ones that have used up
*MRP-MAX-TRANSMISSIONS* and are dropped from TABLE."
  (let ((retransmit '()) (failed '()))
    (dolist (message (retransmission-table-pending table))
      (when (>= now (pending-message-next-at message))
        (if (>= (pending-message-transmissions message) *mrp-max-transmissions*)
            (push message failed)
            (progn
              (incf (pending-message-transmissions message))
              (setf (pending-message-next-at message) (%mrp-next-at table message now active))
              (push message retransmit)))))
    (when failed
      (setf (retransmission-table-pending table)
            (set-difference (retransmission-table-pending table) failed)))
    (values (nreverse retransmit) (nreverse failed))))

(defun mrp-next-deadline (table)
  "When the earliest pending message is due, or NIL."
  (let ((pending (retransmission-table-pending table)))
    (and pending (reduce #'min pending :key #'pending-message-next-at))))
