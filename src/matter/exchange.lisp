;;;; exchange.lisp -- exchanges (Matter Core Specification section 4.10) and
;;;; the Message Reliability Protocol (section 4.11) over a datagram
;;;; transport.
;;;;
;;;; An EXCHANGE pairs the messages of one request/response conversation:
;;;; the initiator picks a 16-bit exchange id, every message carries it with
;;;; the I flag saying which side initiated, and a protocol id that must not
;;;; change.  The EXCHANGE-MANAGER owns the transport, a SESSION-MANAGER and
;;;; the open exchanges, and runs MRP for all of them:
;;;;
;;;;   - a message with the R flag is acknowledged, piggybacked on the next
;;;;     message of the exchange (A flag + the counter) or as a standalone
;;;;     ack (Secure Channel opcode 0x10) after MRP_STANDALONE_ACK_TIMEOUT;
;;;;   - a reliable message we sent is retransmitted on the schedule of
;;;;     message.lisp until the peer acknowledges its counter, and the
;;;;     exchange fails after MRP_MAX_TRANSMISSIONS;
;;;;   - one reliable message may be in flight per exchange;
;;;;   - a duplicate is dropped but acknowledged again.
;;;;
;;;; Everything runs from EXCHANGE-MANAGER-POLL, one turn at a time, so a
;;;; test drives two managers in one thread; EXCHANGE-MANAGER-RUN loops it.
;;;; Protocols plug in as handler functions (EXCHANGE EVENT &REST DATA):
;;;; (:MESSAGE opcode payload) for each message, (:FAILURE reason) when
;;;; the exchange gives up (:RETRANSMISSION-LIMIT or :TIMEOUT).

(in-package :cl-matter)

(define-condition exchange-error (error)
  ((message :initarg :message :reader exchange-error-message))
  (:report (lambda (c stream) (format stream "~a" (exchange-error-message c)))))

(defun %exchange-fail (format &rest args)
  (error 'exchange-error :message (apply #'format nil format args)))

(defparameter *unsecured-session-lifetime* 10.0d0
  "Seconds an idle unsecured session context without an exchange is kept,
so that a late retransmission of the peer is still seen as a duplicate.")

(defparameter *receive-buffer-size* 2048)

;;; ------------------------------------------------------------------
;;; Transports

(defgeneric transport-send (transport octets host port)
  (:documentation "Send OCTETS as one datagram to HOST:PORT."))

(defgeneric transport-receive (transport buffer timeout)
  (:documentation "Receive one datagram into BUFFER, waiting at most TIMEOUT
seconds: (values length host port), or NIL when nothing came."))

(defgeneric transport-close (transport))

(defgeneric transport-local-endpoint (transport)
  (:documentation "(values host port) the transport is bound to."))

(defclass udp-transport ()
  ((socket :initarg :socket :reader udp-transport-socket))
  (:documentation "A CL-MATTER.NET datagram socket."))

(defun make-udp-transport (&key (port 0) address (family :ipv4) socket)
  "A UDP transport on SOCKET, or on a fresh socket bound to ADDRESS:PORT of
FAMILY (:ipv4 or :ipv6).  Matter proper runs over IPv6; IPv4 is for the
loopback tests and for a backend without IPv6."
  (make-instance 'udp-transport
                 :socket (or socket (cl-matter.net:open-udp-socket :port port :address address :family family))))

(defmethod transport-send ((transport udp-transport) octets host port)
  (cl-matter.net:send-to (udp-transport-socket transport) octets host port))

(defmethod transport-receive ((transport udp-transport) buffer timeout)
  (let ((socket (udp-transport-socket transport)))
    (setf (cl-matter.net:socket-timeout socket) (max timeout 0.001d0))
    (cl-matter.net:receive-from socket buffer)))

(defmethod transport-close ((transport udp-transport))
  (cl-matter.net:close-socket (udp-transport-socket transport)))

(defmethod transport-local-endpoint ((transport udp-transport))
  (cl-matter.net:socket-local-endpoint (udp-transport-socket transport)))

;;; ------------------------------------------------------------------
;;; Exchanges

(defstruct (exchange (:constructor %make-exchange))
  "One conversation on SESSION.  HANDLER receives its events.  STATE is
:OPEN, :CLOSING (the protocol is done, MRP is not) or :CLOSED."
  manager
  session
  (id 0 :type (unsigned-byte 16))
  (initiator-p nil :type boolean)
  (protocol-id 0 :type (unsigned-byte 16))
  (vendor-id nil)
  handler
  (state :open :type (member :open :closing :closed))
  (pending-ack nil)                     ; the peer's counter we owe an ack
  (ack-due nil)                         ; when a standalone ack goes out
  (outstanding nil)                     ; our PENDING-MESSAGE awaiting an ack
  (response-timeout nil)                ; seconds to wait for the peer after each send
  (response-due nil)
  (last-activity nil)
  (user-data nil))

(defmethod print-object ((e exchange) stream)
  (print-unreadable-object (e stream :type t)
    (format stream "~d ~a ~a protocol ~d" (exchange-id e)
            (if (exchange-initiator-p e) "initiator" "responder")
            (exchange-state e) (exchange-protocol-id e))))

(defun exchange-open-p (exchange) (eq :open (exchange-state exchange)))
(defun exchange-closed-p (exchange) (eq :closed (exchange-state exchange)))

;;; ------------------------------------------------------------------
;;; The manager

(defun %real-time-clock ()
  (/ (get-internal-real-time) (float internal-time-units-per-second 1d0)))

(defstruct (exchange-manager (:constructor %make-exchange-manager))
  "One node's exchanges over TRANSPORT.  CLOCK is a function returning
seconds; TRACE, when set, is called with a format string and arguments
for every notable event."
  transport
  session-manager
  (exchanges '() :type list)
  (protocol-handlers (make-hash-table :test 'equal))
  (clock #'%real-time-clock)
  (next-exchange-id (random #x10000) :type (unsigned-byte 16))
  (buffer (make-array *receive-buffer-size* :element-type '(unsigned-byte 8)))
  (timers '())                          ; (function . due), see ADD-TIMER
  (trace nil)
  (received 0)
  (sent 0))

(defun make-exchange-manager (&key transport session-manager clock trace
                                (session-parameters (default-session-parameters)))
  "A manager over TRANSPORT (a UDP transport, or anything with the four
TRANSPORT- methods).  SESSION-MANAGER defaults to a fresh one offering
SESSION-PARAMETERS; CLOCK to real time."
  (unless transport (%exchange-fail "an exchange manager needs a transport"))
  (%make-exchange-manager :transport transport
                          :session-manager (or session-manager
                                               (make-session-manager :session-parameters session-parameters))
                          :clock (or clock #'%real-time-clock)
                          :trace trace))

(defun exchange-manager-now (manager)
  (funcall (exchange-manager-clock manager)))

(defun exchange-manager-close (manager)
  "Drop every exchange and close the transport."
  (dolist (exchange (exchange-manager-exchanges manager))
    (setf (exchange-state exchange) :closed))
  (setf (exchange-manager-exchanges manager) '())
  (transport-close (exchange-manager-transport manager)))

(defun %trace (manager format &rest args)
  (let ((trace (exchange-manager-trace manager)))
    (when trace (apply trace format args))))

(defun add-timer (manager function &key at)
  "Call FUNCTION with the time once AT (default: now) has passed; it
returns when it wants to run next, or NIL to be removed.  The poll loop
wakes up for it."
  (push (cons function (or at (exchange-manager-now manager))) (exchange-manager-timers manager))
  function)

(defun wake-timer (manager function)
  "Run FUNCTION's timer at the next poll instead of when it last asked."
  (let ((entry (assoc function (exchange-manager-timers manager))))
    (when entry (setf (cdr entry) (exchange-manager-now manager)))
    (and entry t)))

(defun remove-timer (manager function)
  (setf (exchange-manager-timers manager) (remove function (exchange-manager-timers manager) :key #'car))
  nil)

(defun %protocol-key (protocol-id vendor-id)
  (cons protocol-id (or vendor-id 0)))

(defun register-protocol-handler (manager protocol-id handler &key vendor-id)
  "HANDLER, (lambda (exchange event &rest data)), takes the exchanges peers
open to us for PROTOCOL-ID; it becomes the handler of each such exchange.
NIL unregisters."
  (if handler
      (setf (gethash (%protocol-key protocol-id vendor-id) (exchange-manager-protocol-handlers manager)) handler)
      (remhash (%protocol-key protocol-id vendor-id) (exchange-manager-protocol-handlers manager)))
  handler)

(defun find-protocol-handler (manager protocol-id &key vendor-id)
  (values (gethash (%protocol-key protocol-id vendor-id) (exchange-manager-protocol-handlers manager))))

(defun %all-sessions (manager)
  (let ((sm (exchange-manager-session-manager manager)))
    (append (session-manager-sessions sm) (session-manager-unsecured sm))))

(defun %next-exchange-id (manager)
  (let ((id (exchange-manager-next-exchange-id manager)))
    (setf (exchange-manager-next-exchange-id manager) (logand (1+ id) #xFFFF))
    id))

(defun find-exchange (manager session id initiator-p)
  "The open or closing exchange ID on SESSION that we initiated (INITIATOR-P)
or the peer did."
  (find-if (lambda (e) (and (eq session (exchange-session e))
                            (= id (exchange-id e))
                            (eq initiator-p (exchange-initiator-p e))
                            (not (exchange-closed-p e))))
           (exchange-manager-exchanges manager)))

(defun open-exchange (manager session protocol-id &key vendor-id handler response-timeout)
  "Start an exchange on SESSION for PROTOCOL-ID as its initiator.  HANDLER
gets the peer's messages; RESPONSE-TIMEOUT, seconds, fails the exchange
when the peer stays silent that long after a message of ours."
  (unless (session-active-p session) (%exchange-fail "cannot open an exchange on closed ~a" session))
  (let ((exchange (%make-exchange :manager manager :session session
                                  :id (%next-exchange-id manager) :initiator-p t
                                  :protocol-id protocol-id :vendor-id vendor-id
                                  :handler handler :response-timeout response-timeout
                                  :last-activity (exchange-manager-now manager))))
    (push exchange (exchange-manager-exchanges manager))
    (%trace manager "open ~a on ~a" exchange session)
    exchange))

(defun %deliver (exchange event &rest data)
  (let ((handler (exchange-handler exchange)))
    (when handler (apply handler exchange event data))))

(defun %remove-exchange (exchange)
  (setf (exchange-state exchange) :closed)
  (let ((manager (exchange-manager exchange)))
    (setf (exchange-manager-exchanges manager) (remove exchange (exchange-manager-exchanges manager)))
    (%trace manager "closed ~a" exchange)))

(defun %exchange-maybe-finish (exchange)
  "A closing exchange is done once nothing is outstanding or owed."
  (when (and (eq :closing (exchange-state exchange))
             (null (exchange-outstanding exchange))
             (null (exchange-pending-ack exchange)))
    (%remove-exchange exchange)))

(defun %exchange-failed (exchange reason)
  (let ((pending (exchange-outstanding exchange)))
    (when pending
      (mrp-acknowledge (session-retransmissions (exchange-session exchange)) (pending-message-counter pending))
      (setf (exchange-outstanding exchange) nil)))
  (%trace (exchange-manager exchange) "~a failed: ~a" exchange reason)
  (%remove-exchange exchange)
  (%deliver exchange :failure reason))

;;; ------------------------------------------------------------------
;;; Sending

(defun %send-octets (manager session octets)
  (transport-send (exchange-manager-transport manager) octets
                  (session-peer-host session) (session-peer-port session))
  (incf (exchange-manager-sent manager)))

(defun %send-standalone-ack (manager session exchange-id initiator-p counter)
  "Acknowledge COUNTER with a message of its own (section 4.11.5.1)."
  (let ((header (make-protocol-header :initiator-p initiator-p :reliability-p nil
                                      :ack-counter counter
                                      :protocol-id +protocol-secure-channel+
                                      :opcode +opcode-standalone-ack+
                                      :exchange-id exchange-id)))
    (%trace manager "standalone ack of ~d on exchange ~d" counter exchange-id)
    (%send-octets manager session (session-encode session header))))

(defun %flush-ack (exchange)
  (let ((counter (exchange-pending-ack exchange)))
    (when counter
      (setf (exchange-pending-ack exchange) nil
            (exchange-ack-due exchange) nil)
      (%send-standalone-ack (exchange-manager exchange) (exchange-session exchange)
                            (exchange-id exchange) (exchange-initiator-p exchange) counter))))

(defun exchange-send (exchange opcode payload &key (reliable t))
  "Send (OPCODE, PAYLOAD octets or NIL) on EXCHANGE, acknowledging what the
peer sent on it.  RELIABLE asks for an acknowledgement and retransmits
until it comes; only one such message may be in flight.  Returns the
message counter."
  (unless (exchange-open-p exchange) (%exchange-fail "~a is not open" exchange))
  (when (and reliable (exchange-outstanding exchange))
    (%exchange-fail "~a has a reliable message in flight (counter ~d); wait for its acknowledgement"
                    exchange (pending-message-counter (exchange-outstanding exchange))))
  (let* ((manager (exchange-manager exchange))
         (session (exchange-session exchange))
         (now (exchange-manager-now manager))
         (header (make-protocol-header :initiator-p (exchange-initiator-p exchange)
                                       :reliability-p (and reliable t)
                                       :ack-counter (exchange-pending-ack exchange)
                                       :vendor-id (exchange-vendor-id exchange)
                                       :protocol-id (exchange-protocol-id exchange)
                                       :opcode opcode
                                       :exchange-id (exchange-id exchange)
                                       :payload payload)))
    (multiple-value-bind (octets counter) (session-encode session header)
      (setf (exchange-pending-ack exchange) nil
            (exchange-ack-due exchange) nil
            (exchange-last-activity exchange) now)
      (when (exchange-response-timeout exchange)
        (setf (exchange-response-due exchange) (+ now (exchange-response-timeout exchange))))
      (%trace manager "send #x~2,'0x ~d octets counter ~d on ~a" opcode (length octets) counter exchange)
      (%send-octets manager session octets)
      (when reliable
        (setf (exchange-outstanding exchange)
              (mrp-track (session-retransmissions session) counter octets now
                         :active (session-peer-active-p session now) :context exchange)))
      counter)))

(defun exchange-close (exchange)
  "The protocol is done with EXCHANGE: an owed acknowledgement goes out now,
and the exchange disappears once its last reliable message is acknowledged."
  (unless (exchange-closed-p exchange)
    (setf (exchange-state exchange) :closing
          (exchange-response-due exchange) nil)
    (%flush-ack exchange)
    (%exchange-maybe-finish exchange))
  exchange)

(defun exchange-abort (exchange)
  "Drop EXCHANGE at once, retransmissions included; no event is delivered."
  (let ((pending (exchange-outstanding exchange)))
    (when pending
      (mrp-acknowledge (session-retransmissions (exchange-session exchange)) (pending-message-counter pending))
      (setf (exchange-outstanding exchange) nil)))
  (%remove-exchange exchange)
  exchange)

;;; ------------------------------------------------------------------
;;; Receiving

(defun %acknowledged (manager session counter)
  "The peer acknowledged COUNTER."
  (let ((pending (mrp-acknowledge (session-retransmissions session) counter)))
    (when pending
      (%trace manager "ack of ~d received" counter)
      (let ((exchange (pending-message-context pending)))
        (when (and (exchange-p exchange) (eq pending (exchange-outstanding exchange)))
          (setf (exchange-outstanding exchange) nil)
          (%exchange-maybe-finish exchange))))))

(defun %standalone-ack-p (protocol-header)
  (and (protocol-header-secure-channel-p protocol-header)
       (= +opcode-standalone-ack+ (protocol-header-opcode protocol-header))))

(defun %locate-session (manager header octets end host port)
  "The session a message with HEADER arrived on, or NIL.  A new unsecured
context is made for an initiator's first message."
  (let ((sm (exchange-manager-session-manager manager)))
    (if (= +unsecured-session-id+ (message-header-session-id header))
        (or (find-unsecured-session sm header)
            (and (message-header-source-node-id header)
                 (let ((proto (nth-value 1 (decode-unsecured-message octets :end end))))
                   (and (protocol-header-initiator-p proto)
                        (not (%standalone-ack-p proto))
                        (find-unsecured-session sm header :peer-host host :peer-port port :create t)))))
        (find-session sm (message-header-session-id header)))))

(defun %dispatch (manager octets end host port now)
  "One datagram OCTETS[0,END) from HOST:PORT.  Returns the exchange it
reached, or NIL when it was dropped."
  (let* ((header (handler-case (decode-message-header octets :end end)
                   (message-decode-error (e)
                     (%trace manager "dropped: ~a" e)
                     (return-from %dispatch nil))))
         (session (%locate-session manager header octets end host port)))
    (unless session
      (%trace manager "dropped: no session ~d" (message-header-session-id header))
      (return-from %dispatch nil))
    (multiple-value-bind (header proto)
        (handler-case (session-decode session octets :end end)
          ((or message-decode-error crypto-error) (e)
            (%trace manager "dropped on ~a: ~a" session e)
            (return-from %dispatch nil)))
      (let ((counter (message-header-message-counter header))
            (exchange-id (protocol-header-exchange-id proto))
            (peer-initiated (protocol-header-initiator-p proto))
            (reliable (protocol-header-reliability-p proto)))
        (multiple-value-bind (new why) (session-accept-counter session counter)
          (unless new
            (%trace manager "~a counter ~d on ~a" why counter session)
            (when (and (eq why :duplicate) reliable)
              (%send-standalone-ack manager session exchange-id (not peer-initiated) counter))
            (return-from %dispatch nil)))
        (session-note-received session now host port)
        (when (protocol-header-ack-counter proto)
          (%acknowledged manager session (protocol-header-ack-counter proto)))
        (let ((exchange (find-exchange manager session exchange-id (not peer-initiated)))
              (ack-only (%standalone-ack-p proto)))
          (cond (ack-only
                 (when (and exchange reliable)   ; a standalone ack is never reliable; be lenient
                   (setf (exchange-pending-ack exchange) counter
                         (exchange-ack-due exchange) now))
                 (return-from %dispatch exchange))
                ((null exchange)
                 (let ((handler (and peer-initiated
                                     (find-protocol-handler manager (protocol-header-protocol-id proto)
                                                            :vendor-id (protocol-header-vendor-id proto)))))
                   (cond (handler
                          (setf exchange (%make-exchange :manager manager :session session
                                                         :id exchange-id :initiator-p nil
                                                         :protocol-id (protocol-header-protocol-id proto)
                                                         :vendor-id (protocol-header-vendor-id proto)
                                                         :handler handler :last-activity now))
                          (push exchange (exchange-manager-exchanges manager))
                          (%trace manager "peer opened ~a on ~a" exchange session))
                         (t
                          (%trace manager "dropped: no exchange ~d for protocol ~d opcode #x~2,'0x"
                                  exchange-id (protocol-header-protocol-id proto) (protocol-header-opcode proto))
                          (when reliable
                            (%send-standalone-ack manager session exchange-id (not peer-initiated) counter))
                          (return-from %dispatch nil)))))
                ((or (/= (protocol-header-protocol-id proto) (exchange-protocol-id exchange))
                     (not (eql (protocol-header-vendor-id proto) (exchange-vendor-id exchange))))
                 (%trace manager "dropped: protocol ~d on ~a" (protocol-header-protocol-id proto) exchange)
                 (return-from %dispatch nil)))
          (setf (exchange-last-activity exchange) now
                (exchange-response-due exchange) nil)
          (when reliable
            (setf (exchange-pending-ack exchange) counter
                  (exchange-ack-due exchange) (+ now *mrp-standalone-ack-timeout*)))
          (%trace manager "received #x~2,'0x ~d octets counter ~d on ~a"
                  (protocol-header-opcode proto) (length (protocol-header-payload proto)) counter exchange)
          (if (exchange-open-p exchange)
              (%deliver exchange :message (protocol-header-opcode proto) (protocol-header-payload proto))
              (%flush-ack exchange))
          (when (eq :closing (exchange-state exchange))
            (%flush-ack exchange)
            (%exchange-maybe-finish exchange))
          exchange)))))

;;; ------------------------------------------------------------------
;;; Timers

(defun %run-timers (manager now)
  ;; standalone acks and response timeouts
  (dolist (exchange (copy-list (exchange-manager-exchanges manager)))
    (unless (exchange-closed-p exchange)
      (when (and (exchange-ack-due exchange) (>= now (exchange-ack-due exchange)))
        (%flush-ack exchange)
        (%exchange-maybe-finish exchange))
      (when (and (exchange-response-due exchange) (>= now (exchange-response-due exchange))
                 (not (exchange-closed-p exchange)))
        (%exchange-failed exchange :timeout))))
  ;; retransmissions
  (dolist (session (%all-sessions manager))
    (multiple-value-bind (again failed)
        (mrp-due (session-retransmissions session) now :active (session-peer-active-p session now))
      (dolist (pending again)
        (%trace manager "retransmit counter ~d (transmission ~d) on ~a"
                (pending-message-counter pending) (pending-message-transmissions pending) session)
        (%send-octets manager session (pending-message-octets pending)))
      (dolist (pending failed)
        (let ((exchange (pending-message-context pending)))
          (when (and (exchange-p exchange) (not (exchange-closed-p exchange)))
            (setf (exchange-outstanding exchange) nil)
            (%exchange-failed exchange :retransmission-limit))))))
  ;; the application's timers
  (dolist (entry (copy-list (exchange-manager-timers manager)))
    (when (<= (cdr entry) now)
      (let ((next (funcall (car entry) now)))
        (if next
            (setf (cdr entry) next)
            (setf (exchange-manager-timers manager) (remove entry (exchange-manager-timers manager)))))))
  ;; idle unsecured contexts
  (let ((sm (exchange-manager-session-manager manager)))
    (dolist (session (session-manager-unsecured sm))
      (when (and (null (retransmission-table-pending (session-retransmissions session)))
                 (notany (lambda (e) (and (eq session (exchange-session e)) (not (exchange-closed-p e))))
                         (exchange-manager-exchanges manager))
                 (let ((last (session-last-received session)))
                   (or (null last) (>= (- now last) *unsecured-session-lifetime*))))
        (%trace manager "expired ~a" session)
        (remove-session sm session)))))

(defun %next-deadline (manager)
  (let ((deadline nil))
    (flet ((consider (time) (when (and time (or (null deadline) (< time deadline))) (setf deadline time))))
      (dolist (exchange (exchange-manager-exchanges manager))
        (consider (exchange-ack-due exchange))
        (consider (exchange-response-due exchange)))
      (dolist (session (%all-sessions manager))
        (consider (mrp-next-deadline (session-retransmissions session))))
      (dolist (entry (exchange-manager-timers manager))
        (consider (cdr entry))))
    deadline))

;;; ------------------------------------------------------------------
;;; Polling

(defun exchange-manager-poll (manager &key (timeout 0.1d0))
  "One turn: wait up to TIMEOUT seconds (less when a timer is due) for a
datagram and dispatch it, then run the timers.  Returns the exchange a
datagram reached, or NIL."
  (let* ((now (exchange-manager-now manager))
         (deadline (%next-deadline manager))
         (wait (if deadline (max 0 (min timeout (- deadline now))) timeout))
         (buffer (exchange-manager-buffer manager))
         (result nil))
    (multiple-value-bind (length host port) (transport-receive (exchange-manager-transport manager) buffer wait)
      (when length
        (incf (exchange-manager-received manager))
        (setf result (%dispatch manager (subseq buffer 0 length) length host port
                                (exchange-manager-now manager)))))
    (%run-timers manager (exchange-manager-now manager))
    result))

(defun exchange-manager-run (manager &key until (timeout 30) (poll-timeout 0.1d0))
  "Poll MANAGER until UNTIL, a function of no arguments, returns true (that
value is returned) or TIMEOUT seconds pass (NIL)."
  (let ((deadline (+ (exchange-manager-now manager) timeout)))
    (loop
      (let ((done (and until (funcall until))))
        (when done (return done)))
      (let ((left (- deadline (exchange-manager-now manager))))
        (when (<= left 0) (return nil))
        (exchange-manager-poll manager :timeout (min poll-timeout left))))))
