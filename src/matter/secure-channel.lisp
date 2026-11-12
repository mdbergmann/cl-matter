;;;; secure-channel.lisp -- the Secure Channel protocol (Matter Core
;;;; Specification section 4.10.1 and 4.14) over exchanges: the PASE and
;;;; CASE handshakes of pase.lisp and case.lisp carried on an unsecured
;;;; session, the secured session each one yields installed in the session
;;;; manager, and CloseSession.
;;;;
;;;; A SECURE-CHANNEL belongs to one EXCHANGE-MANAGER and is both sides at
;;;; once: it registers itself as the handler of the Secure Channel protocol
;;;; (so peers can open PASE or CASE sessions to us, when a verifier or a
;;;; fabric is configured) and it starts handshakes towards peers with
;;;; START-PASE / START-CASE.  A HANDSHAKE is one in flight; HANDSHAKE-WAIT
;;;; polls the manager until it is done.  ESTABLISH-PASE-SESSION and
;;;; ESTABLISH-CASE-SESSION do both in one call.

(in-package :cl-matter)

(defparameter *handshake-timeout* 30.0d0
  "Seconds a handshake may wait for the peer's next message.")

(defparameter *busy-wait-time* 500
  "Milliseconds a peer is told to wait when we are in a PASE handshake already.")

;;; ------------------------------------------------------------------
;;; Handshakes

(defstruct (handshake (:constructor %make-handshake))
  "One PASE or CASE handshake over an exchange.  STATE is :RUNNING,
:COMPLETE (SESSION is the result) or :FAILED (ERROR says why)."
  (kind :pase :type (member :pase :case))
  (role :initiator :type (member :initiator :responder))
  machine                               ; the PASE or CASE-SESSION state machine
  channel
  exchange
  unsecured                             ; the unsecured SESSION it runs on
  local-session-id
  (state :running :type (member :running :complete :failed))
  session
  error
  on-complete)                          ; (lambda (handshake)) when it is no longer running

(defmethod print-object ((h handshake) stream)
  (print-unreadable-object (h stream :type t)
    (format stream "~a ~a ~a" (handshake-kind h) (handshake-role h) (handshake-state h))))

(defun handshake-running-p (handshake) (eq :running (handshake-state handshake)))
(defun handshake-complete-p (handshake) (eq :complete (handshake-state handshake)))
(defun handshake-failed-p (handshake) (eq :failed (handshake-state handshake)))

;;; ------------------------------------------------------------------
;;; The channel

(defstruct (secure-channel (:constructor %make-secure-channel))
  "The Secure Channel protocol of one node.  PASE-VERIFIER, with its SALT
and ITERATIONS, is accepted from commissioners while set; FABRICS are the
ones peers may open CASE sessions on; RESUMPTIONS the CASE-RESUMPTIONs we
hold for both roles.  ON-SESSION is called with the channel and each
session a peer establishes with us; ON-SESSION-CLOSED with each one that
goes away; ON-HANDSHAKE-FAILED with the channel, the HANDSHAKE a peer
began with us and the error it failed with."
  manager
  pase-verifier
  pase-salt
  pase-iterations
  (fabrics '() :type list)
  (resumptions '() :type list)
  (handshakes '() :type list)
  on-session
  on-session-closed
  on-handshake-failed)

(defun make-secure-channel (manager &key fabrics pase-verifier pase-passcode pase-salt pase-iterations
                                      on-session on-session-closed on-handshake-failed)
  "The Secure Channel on exchange MANAGER.  A commissioning window opens
with PASE-VERIFIER (or PASE-PASSCODE, turned into one) plus PASE-SALT and
PASE-ITERATIONS; FABRICS makes us a CASE responder."
  (let ((channel (%make-secure-channel :manager manager :fabrics fabrics
                                       :on-session on-session :on-session-closed on-session-closed
                                       :on-handshake-failed on-handshake-failed)))
    (when (or pase-verifier pase-passcode)
      (set-pase-verifier channel (or pase-verifier (spake2p-verifier pase-passcode pase-salt pase-iterations))
                         pase-salt pase-iterations))
    (register-protocol-handler manager +protocol-secure-channel+
                               (lambda (exchange event &rest data)
                                 (apply #'%secure-channel-event channel exchange event data)))
    channel))

(defun secure-channel-session-manager (channel)
  (exchange-manager-session-manager (secure-channel-manager channel)))

(defun set-pase-verifier (channel verifier salt iterations)
  "Open the commissioning window: accept PASE with VERIFIER (97 octets, made
with SALT and ITERATIONS).  NIL closes it."
  (when verifier
    (unless (and (%octets-p verifier) (= (length verifier) +spake2p-verifier-length+))
      (%exchange-fail "a PASE verifier is ~d octets" +spake2p-verifier-length+))
    (%check-pbkdf-parameters salt iterations))
  (setf (secure-channel-pase-verifier channel) verifier
        (secure-channel-pase-salt channel) salt
        (secure-channel-pase-iterations channel) iterations)
  verifier)

(defun find-resumption (channel fabric peer-node-id)
  "The CASE-RESUMPTION we hold for PEER-NODE-ID on FABRIC, or NIL."
  (find-if (lambda (r) (and (eq fabric (case-resumption-fabric r))
                            (eql peer-node-id (case-resumption-peer-node-id r))))
           (secure-channel-resumptions channel)))

(defun %remember-resumption (channel resumption)
  (setf (secure-channel-resumptions channel)
        (cons resumption
              (remove-if (lambda (r) (and (eq (case-resumption-fabric r) (case-resumption-fabric resumption))
                                          (eql (case-resumption-peer-node-id r)
                                               (case-resumption-peer-node-id resumption))))
                         (secure-channel-resumptions channel)))))

(defun secure-channel-sessions (channel)
  "The secured sessions of the node."
  (session-manager-sessions (secure-channel-session-manager channel)))

;;; ------------------------------------------------------------------
;;; Running a handshake

(defun %handshake-handle (handshake opcode payload)
  "Feed the state machine: (values reply-opcode reply-payload complete-p)."
  (let ((machine (handshake-machine handshake)))
    (multiple-value-bind (out-opcode out-payload)
        (ecase (handshake-kind handshake)
          (:pase (pase-handle machine opcode payload))
          (:case (case-handle machine opcode payload)))
      (values out-opcode out-payload
              (ecase (handshake-kind handshake)
                (:pase (pase-complete-p machine))
                (:case (case-complete-p machine)))))))

(defun %handshake-status-report (handshake error)
  "The status report that tells the peer why we gave up."
  (ecase (handshake-kind handshake)
    (:pase (pase-status-report (pase-error-protocol-code error)))
    (:case (case-status-report (case-error-protocol-code error)))))

(defun %handshake-finish (handshake)
  (let ((channel (handshake-channel handshake)))
    (setf (secure-channel-handshakes channel) (remove handshake (secure-channel-handshakes channel))))
  (exchange-close (handshake-exchange handshake))
  (when (handshake-on-complete handshake)
    (funcall (handshake-on-complete handshake) handshake)))

(defun %handshake-fail (handshake error &key report)
  (when (handshake-running-p handshake)
    (%trace (secure-channel-manager (handshake-channel handshake)) "~a failed: ~a" handshake error)
    (setf (handshake-state handshake) :failed
          (handshake-error handshake) error)
    (when (handshake-local-session-id handshake)
      (release-session-id (secure-channel-session-manager (handshake-channel handshake))
                          (handshake-local-session-id handshake)))
    (when (and report (exchange-open-p (handshake-exchange handshake))
               (null (exchange-outstanding (handshake-exchange handshake))))
      (exchange-send (handshake-exchange handshake) +opcode-status-report+ (encode-status-report report)))
    (%handshake-finish handshake)
    (let ((channel (handshake-channel handshake)))
      (when (and (eq :responder (handshake-role handshake)) (secure-channel-on-handshake-failed channel))
        (funcall (secure-channel-on-handshake-failed channel) channel handshake error)))))

(defun %handshake-session (handshake)
  "The secured SESSION a complete handshake yields."
  (let* ((machine (handshake-machine handshake))
         (unsecured (handshake-unsecured handshake))
         (channel (handshake-channel handshake))
         (role (handshake-role handshake)))
    (ecase (handshake-kind handshake)
      (:pase
       (make-secured-session :type :pase :role role
                             :local-session-id (pase-local-session-id machine)
                             :peer-session-id (pase-peer-session-id machine)
                             :keys (pase-session-keys machine)
                             :peer-host (session-peer-host unsecured) :peer-port (session-peer-port unsecured)
                             :local-session-parameters (pase-local-session-parameters machine)
                             :peer-session-parameters (pase-peer-session-parameters machine)))
      (:case
       (let ((resumption (case-resumption-state machine))
             (fabric (case-fabric machine)))
         (%remember-resumption channel resumption)
         (make-secured-session :type :case :role role
                               :local-session-id (case-local-session-id machine)
                               :peer-session-id (case-peer-session-id machine)
                               :keys (case-session-keys machine)
                               :local-node-id (fabric-node-id fabric)
                               :peer-node-id (case-peer-node-id machine)
                               :fabric fabric
                               :peer-case-auth-tags (case-peer-case-auth-tags machine)
                               :peer-host (session-peer-host unsecured) :peer-port (session-peer-port unsecured)
                               :local-session-parameters (case-local-session-parameters machine)
                               :peer-session-parameters (case-peer-session-parameters machine)
                               :resumption resumption))))))

(defun %handshake-complete (handshake)
  (let* ((channel (handshake-channel handshake))
         (session (%handshake-session handshake)))
    (add-session (secure-channel-session-manager channel) session)
    (setf (handshake-state handshake) :complete
          (handshake-session handshake) session)
    (%trace (secure-channel-manager channel) "~a established ~a" handshake session)
    (%handshake-finish handshake)
    (when (and (eq :responder (handshake-role handshake)) (secure-channel-on-session channel))
      (funcall (secure-channel-on-session channel) channel session))
    session))

(defun %handshake-receive (handshake opcode payload)
  (when (handshake-running-p handshake)
    (handler-case
        (multiple-value-bind (out-opcode out-payload complete) (%handshake-handle handshake opcode payload)
          (when out-opcode
            (exchange-send (handshake-exchange handshake) out-opcode out-payload))
          (when complete
            (%handshake-complete handshake)))
      ((or pase-peer-failure case-peer-failure) (e)
        (%handshake-fail handshake e))
      ((or pase-error case-error) (e)
        (%handshake-fail handshake e :report (%handshake-status-report handshake e))))))

(defun %handshake-event (handshake exchange event &rest data)
  (declare (ignore exchange))
  (ecase event
    (:message (destructuring-bind (opcode payload) data
                (%handshake-receive handshake opcode payload)))
    (:failure (%handshake-fail handshake
                               (make-condition 'exchange-error
                                               :message (format nil "~a handshake: the exchange failed (~a)"
                                                                (handshake-kind handshake) (first data)))))))

(defun %handshake-handler (handshake)
  (lambda (exchange event &rest data)
    (apply #'%handshake-event handshake exchange event data)))

;;; ------------------------------------------------------------------
;;; Initiating

(defun %start-handshake (channel kind machine host port on-complete timeout local-session-id)
  (let* ((manager (secure-channel-manager channel))
         (unsecured (open-unsecured-session (secure-channel-session-manager channel) host port))
         (handshake (%make-handshake :kind kind :role :initiator :machine machine :channel channel
                                     :unsecured unsecured :local-session-id local-session-id
                                     :on-complete on-complete))
         (exchange (open-exchange manager unsecured +protocol-secure-channel+
                                  :handler (%handshake-handler handshake)
                                  :response-timeout timeout)))
    (setf (handshake-exchange handshake) exchange)
    (push handshake (secure-channel-handshakes channel))
    (multiple-value-bind (opcode payload)
        (ecase kind
          (:pase (pase-start machine))
          (:case (case-start machine)))
      (exchange-send exchange opcode payload))
    handshake))

(defun start-pase (channel host port &key passcode salt iterations
                                       (session-parameters (session-manager-session-parameters
                                                            (secure-channel-session-manager channel)))
                                       on-complete (timeout *handshake-timeout*))
  "Open a PASE session to the commissionee at HOST:PORT with PASSCODE; SALT
and ITERATIONS, when known from its onboarding payload, skip asking.
Returns the HANDSHAKE; drive the manager until it is done (HANDSHAKE-WAIT)."
  (let* ((sm (secure-channel-session-manager channel))
         (id (allocate-session-id sm))
         (machine (handler-case
                      (make-pase-initiator :passcode passcode :local-session-id id
                                           :session-parameters session-parameters
                                           :salt salt :iterations iterations)
                    (error (e) (release-session-id sm id) (error e)))))
    (%start-handshake channel :pase machine host port on-complete timeout id)))

(defun start-case (channel host port &key fabric peer-node-id (resume t)
                                       (session-parameters (session-manager-session-parameters
                                                            (secure-channel-session-manager channel)))
                                       on-complete (timeout *handshake-timeout*))
  "Open a CASE session to PEER-NODE-ID of FABRIC at HOST:PORT, resuming an
earlier one when RESUME and we hold its state.  Returns the HANDSHAKE."
  (let* ((sm (secure-channel-session-manager channel))
         (id (allocate-session-id sm))
         (machine (handler-case
                      (make-case-initiator :fabric fabric :peer-node-id peer-node-id :local-session-id id
                                           :session-parameters session-parameters
                                           :resumption (and resume (find-resumption channel fabric peer-node-id)))
                    (error (e) (release-session-id sm id) (error e)))))
    (%start-handshake channel :case machine host port on-complete timeout id)))

(defun handshake-abort (handshake)
  "Give up on a running HANDSHAKE without telling the peer."
  (when (handshake-running-p handshake)
    (exchange-abort (handshake-exchange handshake))
    (setf (handshake-state handshake) :failed
          (handshake-error handshake) (make-condition 'exchange-error :message "the handshake was aborted"))
    (release-session-id (secure-channel-session-manager (handshake-channel handshake))
                        (handshake-local-session-id handshake))
    (let ((channel (handshake-channel handshake)))
      (setf (secure-channel-handshakes channel) (remove handshake (secure-channel-handshakes channel)))))
  handshake)

(defun handshake-wait (handshake &key (timeout *handshake-timeout*))
  "Poll the manager until HANDSHAKE is done: the SESSION, or the error it
failed with is signalled.  After TIMEOUT seconds it is aborted and an
EXCHANGE-ERROR signalled."
  (let ((manager (secure-channel-manager (handshake-channel handshake))))
    (exchange-manager-run manager :until (lambda () (not (handshake-running-p handshake))) :timeout timeout)
    (when (handshake-running-p handshake)
      (handshake-abort handshake)
      (%exchange-fail "the ~a handshake did not finish within ~a seconds" (handshake-kind handshake) timeout))
    (if (handshake-complete-p handshake)
        (handshake-session handshake)
        (error (handshake-error handshake)))))

(defun establish-pase-session (channel host port &rest args &key (timeout *handshake-timeout*) &allow-other-keys)
  "START-PASE and wait: the SESSION, or an error."
  (let ((handshake (apply #'start-pase channel host port :allow-other-keys t args)))
    (handshake-wait handshake :timeout timeout)))

(defun establish-case-session (channel host port &rest args &key (timeout *handshake-timeout*) &allow-other-keys)
  "START-CASE and wait: the SESSION, or an error."
  (let ((handshake (apply #'start-case channel host port :allow-other-keys t args)))
    (handshake-wait handshake :timeout timeout)))

;;; ------------------------------------------------------------------
;;; Responding

(defun %integer-octets-le (n length)
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) n)))))

(defun %busy-report ()
  "Section 4.14.1.5: BUSY with the minimum wait in milliseconds."
  (make-status-report :general-code +status-busy+ :protocol-id +protocol-secure-channel+
                      :protocol-code +secure-channel-status-busy+
                      :data (%integer-octets-le *busy-wait-time* 2)))

(defun %respond-handshake (channel exchange kind opcode payload)
  "A peer's first PASE or CASE message on EXCHANGE: run the responder."
  (let* ((manager (secure-channel-manager channel))
         (sm (exchange-manager-session-manager manager))
         (session (exchange-session exchange)))
    (cond ((session-secured-p session)
           (%trace manager "dropped: ~a opened on a secured session" kind)
           (exchange-close exchange))
          ((and (eq kind :pase) (null (secure-channel-pase-verifier channel)))
           (%trace manager "dropped: PASE while no commissioning window is open")
           (exchange-close exchange))
          ((and (eq kind :pase)
                (find-if (lambda (h) (and (eq :pase (handshake-kind h)) (eq :responder (handshake-role h))))
                         (secure-channel-handshakes channel)))
           (%trace manager "busy: a PASE handshake is running")
           (exchange-send exchange +opcode-status-report+ (encode-status-report (%busy-report)))
           (exchange-close exchange))
          ((and (eq kind :case) (null (secure-channel-fabrics channel)))
           (%trace manager "dropped: CASE while we are on no fabric")
           (exchange-close exchange))
          (t
           (let* ((id (allocate-session-id sm))
                  (parameters (session-manager-session-parameters sm))
                  (machine (ecase kind
                             (:pase (make-pase-responder :verifier (secure-channel-pase-verifier channel)
                                                         :salt (secure-channel-pase-salt channel)
                                                         :iterations (secure-channel-pase-iterations channel)
                                                         :local-session-id id
                                                         :session-parameters parameters))
                             (:case (make-case-responder :fabrics (secure-channel-fabrics channel)
                                                         :local-session-id id
                                                         :session-parameters parameters
                                                         :resumptions (secure-channel-resumptions channel)))))
                  (handshake (%make-handshake :kind kind :role :responder :machine machine :channel channel
                                              :exchange exchange :unsecured session :local-session-id id)))
             (push handshake (secure-channel-handshakes channel))
             (setf (exchange-handler exchange) (%handshake-handler handshake)
                   (exchange-response-timeout exchange) *handshake-timeout*)
             (%handshake-receive handshake opcode payload))))))

(defun %secure-channel-event (channel exchange event &rest data)
  "Unsolicited Secure Channel messages: the first message of a handshake,
or a status report on a secured session (CloseSession)."
  (when (eq event :message)
    (destructuring-bind (opcode payload) data
      (cond ((= opcode +opcode-pbkdf-param-request+) (%respond-handshake channel exchange :pase opcode payload))
            ((= opcode +opcode-case-sigma1+) (%respond-handshake channel exchange :case opcode payload))
            ((= opcode +opcode-status-report+)
             (let ((session (exchange-session exchange))
                   (report (ignore-errors (decode-status-report payload))))
               (when (and report (session-secured-p session)
                          (= +protocol-secure-channel+ (status-report-protocol-id report))
                          (= +secure-channel-status-close-session+ (status-report-protocol-code report)))
                 (%trace (secure-channel-manager channel) "peer closed ~a" session)
                 (%forget-session channel session)))
             (exchange-close exchange))
            (t
             (%trace (secure-channel-manager channel) "dropped: Secure Channel opcode #x~2,'0x" opcode)
             (exchange-close exchange))))))

;;; ------------------------------------------------------------------
;;; Closing sessions

(defun %forget-session (channel session)
  (let ((manager (secure-channel-manager channel)))
    (dolist (exchange (copy-list (exchange-manager-exchanges manager)))
      (when (eq session (exchange-session exchange))
        (exchange-abort exchange)))
    (remove-session (secure-channel-session-manager channel) session)
    (when (secure-channel-on-session-closed channel)
      (funcall (secure-channel-on-session-closed channel) channel session))
    session))

(defun close-session (channel session)
  "Tell the peer with a CloseSession status report (unreliably, as the SDK
does) and forget SESSION."
  (when (session-active-p session)
    (let ((exchange (open-exchange (secure-channel-manager channel) session +protocol-secure-channel+)))
      (exchange-send exchange +opcode-status-report+
                     (encode-status-report
                      (make-status-report :general-code +status-success+
                                          :protocol-id +protocol-secure-channel+
                                          :protocol-code +secure-channel-status-close-session+))
                     :reliable nil)
      (exchange-close exchange))
    (%forget-session channel session)))
