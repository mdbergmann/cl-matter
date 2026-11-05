;;;; session.lisp -- the session layer (Matter Core Specification section
;;;; 4.12): what a node remembers about each peer it talks to, and how a
;;;; message is framed, encrypted and checked for that peer.
;;;;
;;;; A SESSION is one of
;;;;
;;;;   :unsecured  the context of a PASE or CASE handshake in progress,
;;;;               session id 0, identified by the initiator's ephemeral
;;;;               node id (section 4.12.2.1).  Not encrypted.
;;;;   :pase       a session the passcode handshake established: no node
;;;;               ids, nonce source 0, I2R/R2I keys.
;;;;   :case       a session the certificate handshake established: node
;;;;               ids on a fabric, the sender's node id in the nonce.
;;;;
;;;; Each one has an outgoing message counter, the receive window that
;;;; rejects duplicate and stale counters, the peer's address, the MRP
;;;; parameters both sides exchanged and the retransmission table of the
;;;; reliable messages awaiting the peer's acknowledgement.  SESSION-ENCODE
;;;; and SESSION-DECODE turn a PROTOCOL-HEADER into a datagram and back.
;;;;
;;;; A SESSION-MANAGER holds the sessions of one node: the secured ones by
;;;; our local session id, the unsecured contexts by ephemeral node id, and
;;;; the global counter the unsecured messages share (section 4.5.1.1).
;;;; Nothing here touches a socket; exchange.lisp drives it.

(in-package :cl-matter)

(define-condition session-error (error)
  ((message :initarg :message :reader session-error-message))
  (:report (lambda (c stream) (format stream "~a" (session-error-message c)))))

(defun %session-fail (format &rest args)
  (error 'session-error :message (apply #'format nil format args)))

(defconstant +max-message-size+ 1280
  "Section 4.4.4: a Matter message over UDP fits the IPv6 minimum MTU.")

;;; ------------------------------------------------------------------
;;; Sessions

(defstruct (session (:constructor %make-session))
  "One peer context.  ROLE says who established it: the :INITIATOR encrypts
with the I2R key and decrypts with R2I, the :RESPONDER the other way round.
For an :UNSECURED session the initiator's LOCAL-NODE-ID (or the responder's
PEER-NODE-ID) is the ephemeral id of the handshake, not an operational one."
  (type :unsecured :type (member :unsecured :pase :case))
  (role :initiator :type (member :initiator :responder))
  (local-session-id 0 :type (unsigned-byte 16))
  (peer-session-id 0 :type (unsigned-byte 16))
  (local-node-id nil)
  (peer-node-id nil)
  (fabric nil)                          ; :case
  (peer-case-auth-tags nil)             ; :case
  (keys nil)                            ; SESSION-KEYS of a secured session
  (encrypt-key nil)
  (decrypt-key nil)
  (peer-host nil)
  (peer-port nil)
  (message-counter nil)                 ; MESSAGE-COUNTER, the unsecured sessions share one
  (counter-window (make-counter-window))
  (local-session-parameters nil)
  (peer-session-parameters nil)
  (retransmissions nil)                 ; RETRANSMISSION-TABLE
  (last-received nil)                   ; clock time of the peer's last message
  (resumption nil)                      ; :case, the CASE-RESUMPTION to keep
  (state :active :type (member :active :closed)))

(defmethod print-object ((s session) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "~a ~a ~d<->~d~@[ ~a~]~@[:~d~]"
            (session-type s) (session-role s)
            (session-local-session-id s) (session-peer-session-id s)
            (session-peer-host s) (session-peer-port s))))

(defun session-secured-p (session)
  (not (eq :unsecured (session-type session))))

(defun session-active-p (session)
  (eq :active (session-state session)))

(defun %session-parameters-seconds (parameters reader default)
  (let ((ms (and parameters (funcall reader parameters))))
    (if ms (/ ms 1000d0) default)))

(defun session-idle-interval (session)
  "Seconds the peer takes to notice a message when idle (SESSION_IDLE_INTERVAL)."
  (%session-parameters-seconds (session-peer-session-parameters session)
                               #'session-parameters-idle-interval *mrp-default-idle-interval*))

(defun session-active-interval (session)
  "Seconds the peer takes to notice a message when active (SESSION_ACTIVE_INTERVAL)."
  (%session-parameters-seconds (session-peer-session-parameters session)
                               #'session-parameters-active-interval *mrp-default-active-interval*))

(defun session-active-threshold (session)
  "Seconds after its last message during which the peer counts as active."
  (%session-parameters-seconds (session-peer-session-parameters session)
                               #'session-parameters-active-threshold *mrp-default-active-threshold*))

(defun session-peer-active-p (session now)
  "Section 4.11.2.1: the peer sent something within its active threshold."
  (let ((last (session-last-received session)))
    (and last (< (- now last) (session-active-threshold session)))))

(defun %make-retransmissions (session)
  (make-retransmission-table :idle-interval (session-idle-interval session)
                             :active-interval (session-active-interval session)))

(defun (setf session-peer-parameters) (parameters session)
  "Record the peer's SESSION-PARAMETERS; the MRP intervals follow them."
  (setf (session-peer-session-parameters session) parameters)
  (let ((table (session-retransmissions session)))
    (setf (retransmission-table-idle-interval table) (session-idle-interval session)
          (retransmission-table-active-interval table) (session-active-interval session)))
  parameters)

(defun make-unsecured-session (&key role ephemeral-node-id peer-host peer-port
                                 message-counter session-parameters)
  "The context of a handshake on session 0.  EPHEMERAL-NODE-ID is ours when
we are the :INITIATOR (we put it in the source node id field), the peer's
when we are the :RESPONDER (it came in the source field and goes back in
the destination field).  MESSAGE-COUNTER is the node's global unencrypted
counter, shared by all unsecured sessions."
  (unless (and (integerp ephemeral-node-id) (< 0 ephemeral-node-id (ash 1 64)))
    (%session-fail "the ephemeral node id must be a 64-bit integer, got ~s" ephemeral-node-id))
  (let ((session (%make-session :type :unsecured :role role
                                :local-session-id 0 :peer-session-id 0
                                :local-node-id (and (eq role :initiator) ephemeral-node-id)
                                :peer-node-id (and (eq role :responder) ephemeral-node-id)
                                :peer-host peer-host :peer-port peer-port
                                :message-counter (or message-counter (make-message-counter))
                                :local-session-parameters session-parameters)))
    (setf (session-retransmissions session) (%make-retransmissions session))
    session))

(defun make-secured-session (&key type role local-session-id peer-session-id keys
                               local-node-id peer-node-id fabric peer-case-auth-tags
                               peer-host peer-port local-session-parameters
                               peer-session-parameters resumption)
  "A session a finished handshake yields.  KEYS are its SESSION-KEYS; ROLE
decides which direction we encrypt in.  A :CASE session has node ids; a
:PASE session has none."
  (unless (member type '(:pase :case)) (%session-fail "a secured session is :PASE or :CASE, not ~s" type))
  (unless (session-keys-p keys) (%session-fail "KEYS must be the SESSION-KEYS of the handshake"))
  (unless (and (integerp local-session-id) (<= 1 local-session-id #xFFFF))
    (%session-fail "the local session id must be 1..65535, got ~s" local-session-id))
  (unless (and (integerp peer-session-id) (<= 1 peer-session-id #xFFFF))
    (%session-fail "the peer session id must be 1..65535, got ~s" peer-session-id))
  (when (eq type :case)
    (unless (and (operational-node-id-p local-node-id) (operational-node-id-p peer-node-id))
      (%session-fail "a CASE session needs the operational node ids of both ends")))
  (let ((session (%make-session :type type :role role
                                :local-session-id local-session-id :peer-session-id peer-session-id
                                :local-node-id (and (eq type :case) local-node-id)
                                :peer-node-id (and (eq type :case) peer-node-id)
                                :fabric fabric :peer-case-auth-tags peer-case-auth-tags
                                :keys keys
                                :encrypt-key (if (eq role :initiator) (session-keys-i2r keys) (session-keys-r2i keys))
                                :decrypt-key (if (eq role :initiator) (session-keys-r2i keys) (session-keys-i2r keys))
                                :peer-host peer-host :peer-port peer-port
                                :message-counter (make-message-counter)
                                :local-session-parameters local-session-parameters
                                :peer-session-parameters peer-session-parameters
                                :resumption resumption)))
    (setf (session-retransmissions session) (%make-retransmissions session))
    session))

(defun session-attestation-challenge (session)
  "The attestation challenge of a secured session's keys, or NIL."
  (and (session-keys session) (session-keys-attestation-challenge (session-keys session))))

;;; ------------------------------------------------------------------
;;; Framing

(defun %session-nonce-node-id (session sender)
  "The node id in the nonce of a message SESSION's SENDER (:LOCAL or :PEER)
sends: the operational id on a CASE session, 0 otherwise."
  (if (eq :case (session-type session))
      (ecase sender
        (:local (session-local-node-id session))
        (:peer (session-peer-node-id session)))
      0))

(defun session-encode (session protocol-header)
  "Frame PROTOCOL-HEADER (payload included) for SESSION's peer with the
next outgoing counter: (values octets message-counter).  Unsecured sessions
yield a plaintext message that names the ephemeral node id; secured ones
an encrypted message under the session's send key."
  (unless (session-active-p session) (%session-fail "~a is closed" session))
  (let* ((counter (next-message-counter (session-message-counter session)))
         (header (make-message-header :session-id (session-peer-session-id session)
                                      :message-counter counter))
         (octets
           (if (session-secured-p session)
               (encode-secured-message header protocol-header (session-encrypt-key session)
                                       :nonce-source-node-id (%session-nonce-node-id session :local))
               (progn
                 (ecase (session-role session)
                   (:initiator (setf (message-header-source-node-id header) (session-local-node-id session)))
                   (:responder (setf (message-header-destination-node-id header) (session-peer-node-id session))))
                 (encode-unsecured-message header protocol-header)))))
    (when (> (length octets) +max-message-size+)
      (%session-fail "a ~d-octet message exceeds the ~d-octet maximum" (length octets) +max-message-size+))
    (values octets counter)))

(defun session-decode (session octets &key (start 0) end)
  "OCTETS[START,END), a message the peer of SESSION sent: (values
message-header protocol-header).  Decrypts and verifies a secured message.
Signals MESSAGE-DECODE-ERROR or AEAD-AUTHENTICATION-ERROR; the counter is
not checked here (see SESSION-ACCEPT-COUNTER), so a duplicate can still be
acknowledged."
  (if (session-secured-p session)
      (decode-secured-message octets (session-decrypt-key session)
                              :nonce-source-node-id (%session-nonce-node-id session :peer)
                              :start start :end end)
      (decode-unsecured-message octets :start start :end end)))

(defun session-accept-counter (session counter)
  "Run COUNTER through the peer's receive window: T when new, else NIL and
:DUPLICATE or :STALE."
  (counter-window-accept (session-counter-window session) counter))

(defun session-note-received (session now host port)
  "The peer just sent from HOST:PORT at time NOW: remember both."
  (setf (session-last-received session) now)
  (when host (setf (session-peer-host session) host))
  (when port (setf (session-peer-port session) port))
  session)

;;; ------------------------------------------------------------------
;;; Session manager

(defstruct (session-manager (:constructor %make-session-manager))
  "The sessions of one node.  SECURED maps our local session id to a
SESSION; UNSECURED lists the handshake contexts, found by ephemeral node
id.  RESERVED are local ids handed out for handshakes not finished yet."
  (secured (make-hash-table))
  (reserved (make-hash-table))
  (unsecured '() :type list)
  (unsecured-counter (make-message-counter))
  (session-parameters (default-session-parameters)))

(defun make-session-manager (&key (session-parameters (default-session-parameters)))
  "A manager whose sessions offer SESSION-PARAMETERS (our MRP intervals) to peers."
  (%make-session-manager :session-parameters session-parameters))

(defun session-manager-sessions (manager)
  "The secured sessions, a fresh list."
  (loop :for s :being :the :hash-values :of (session-manager-secured manager) :collect s))

(defun find-session (manager local-session-id)
  "The secured session we address as LOCAL-SESSION-ID, or NIL."
  (values (gethash local-session-id (session-manager-secured manager))))

(defun allocate-session-id (manager)
  "A local session id no other session or pending handshake of MANAGER
uses.  Release it with RELEASE-SESSION-ID when the handshake fails, or
hand the session to ADD-SESSION."
  (let ((secured (session-manager-secured manager))
        (reserved (session-manager-reserved manager)))
    (when (>= (+ (hash-table-count secured) (hash-table-count reserved)) #xFFFF)
      (%session-fail "no free session id"))
    (loop :for id := (1+ (random #xFFFF))
          :unless (or (gethash id secured) (gethash id reserved))
            :do (setf (gethash id reserved) t)
                (return id))))

(defun release-session-id (manager id)
  "Give back an id ALLOCATE-SESSION-ID handed out."
  (remhash id (session-manager-reserved manager))
  id)

(defun add-session (manager session)
  "Install a secured SESSION under its local id (allocated or not)."
  (unless (session-secured-p session) (%session-fail "only secured sessions are installed; ~a is not" session))
  (let ((id (session-local-session-id session)))
    (when (gethash id (session-manager-secured manager))
      (%session-fail "local session id ~d is in use" id))
    (remhash id (session-manager-reserved manager))
    (setf (gethash id (session-manager-secured manager)) session)))

(defun remove-session (manager session)
  "Forget SESSION (secured or unsecured) and mark it closed."
  (setf (session-state session) :closed)
  (if (session-secured-p session)
      (remhash (session-local-session-id session) (session-manager-secured manager))
      (setf (session-manager-unsecured manager) (remove session (session-manager-unsecured manager))))
  session)

(defun random-ephemeral-node-id ()
  "Section 4.12.2.1: a random 64-bit id for one handshake."
  (1+ (random (1- (ash 1 64)))))

(defun open-unsecured-session (manager peer-host peer-port)
  "Our context for a handshake we initiate towards PEER-HOST:PEER-PORT."
  (let ((session (make-unsecured-session :role :initiator
                                         :ephemeral-node-id (random-ephemeral-node-id)
                                         :peer-host peer-host :peer-port peer-port
                                         :message-counter (session-manager-unsecured-counter manager)
                                         :session-parameters (session-manager-session-parameters manager))))
    (push session (session-manager-unsecured manager))
    session))

(defun find-unsecured-session (manager header &key peer-host peer-port create)
  "The unsecured context a message with HEADER belongs to: ours when the
destination node id names an id we chose, the peer's when the source node
id is one we have seen -- or, with CREATE, a new responder context for a
source id we have not.  NIL when there is none."
  (let ((source (message-header-source-node-id header))
        (destination (message-header-destination-node-id header)))
    (cond (source
           (or (find-if (lambda (s) (and (eq :responder (session-role s)) (eql source (session-peer-node-id s))))
                        (session-manager-unsecured manager))
               (and create
                    (let ((session (make-unsecured-session
                                    :role :responder :ephemeral-node-id source
                                    :peer-host peer-host :peer-port peer-port
                                    :message-counter (session-manager-unsecured-counter manager)
                                    :session-parameters (session-manager-session-parameters manager))))
                      (push session (session-manager-unsecured manager))
                      session))))
          (destination
           (find-if (lambda (s) (and (eq :initiator (session-role s)) (eql destination (session-local-node-id s))))
                    (session-manager-unsecured manager)))
          (t nil))))
