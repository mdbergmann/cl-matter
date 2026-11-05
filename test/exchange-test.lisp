(defpackage :cl-matter.exchange.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.exchange.tests)

(def-suite exchange-tests :description "Sessions, exchanges, MRP and the Secure Channel over a transport"
  :in cl-matter.tests:test-suite)
(in-suite exchange-tests)

(defun ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun octets-from (a b)
  (coerce (loop :for i :from a :below b :collect i) '(vector (unsigned-byte 8))))

(defun zeros (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defparameter *salt* (ascii "SPAKE2P Key Salt"))
(defparameter *passcode* 20202021)

;;; ------------------------------------------------------------------
;;; A clock the tests advance and a network that loses what they say

(defstruct (clock (:constructor make-clock (&optional (now 1000d0))))
  now)

(defun clock-function (clock)
  (lambda () (clock-now clock)))

(defun advance (clock seconds)
  (incf (clock-now clock) seconds))

(defstruct (network (:constructor make-network ()))
  "Datagrams in flight between memory transports, each (octets from-host from-port to-host to-port)."
  (queue '())
  (drop nil)        ; (lambda (octets from-port to-port)) -> true to lose the datagram
  (tap nil)         ; (lambda (octets from-port to-port)) sees every datagram sent
  (sent 0)
  (lost 0))

(defclass memory-transport ()
  ((network :initarg :network :reader transport-network)
   (port :initarg :port :reader transport-port)))

(defvar *next-port* 40000)

(defun make-memory-transport (network)
  (make-instance 'memory-transport :network network :port (incf *next-port*)))

(defmethod transport-send ((transport memory-transport) octets host port)
  (declare (ignore host))
  (let ((network (transport-network transport))
        (copy (copy-seq octets)))
    (incf (network-sent network))
    (when (network-tap network) (funcall (network-tap network) copy (transport-port transport) port))
    (if (and (network-drop network) (funcall (network-drop network) copy (transport-port transport) port))
        (incf (network-lost network))
        (setf (network-queue network)
              (append (network-queue network) (list (list copy "mem" (transport-port transport) port)))))
    (length octets)))

(defmethod transport-receive ((transport memory-transport) buffer timeout)
  (declare (ignore timeout))
  (let* ((network (transport-network transport))
         (datagram (find (transport-port transport) (network-queue network) :key #'fourth)))
    (when datagram
      (setf (network-queue network) (remove datagram (network-queue network) :count 1))
      (destructuring-bind (octets host port to) datagram
        (declare (ignore to))
        (replace buffer octets)
        (values (length octets) host port)))))

(defmethod transport-close ((transport memory-transport)) t)

(defmethod transport-local-endpoint ((transport memory-transport))
  (values "mem" (transport-port transport)))

(defun inject (network octets from-port to-port)
  "Put a datagram on the wire by hand (a replay)."
  (setf (network-queue network) (append (network-queue network) (list (list (copy-seq octets) "mem" from-port to-port)))))

(defstruct (rig (:constructor %make-rig))
  "Two managers, A and B, on one memory network and one clock."
  clock network a b a-port b-port)

(defun make-rig (&key trace (session-parameters-a (default-session-parameters))
                   (session-parameters-b (default-session-parameters)))
  (let* ((clock (make-clock))
         (network (make-network))
         (ta (make-memory-transport network))
         (tb (make-memory-transport network))
         (trace-fn (and trace (lambda (fmt &rest args) (format t "~&  ~?~%" fmt args)))))
    (%make-rig :clock clock :network network
               :a (make-exchange-manager :transport ta :clock (clock-function clock) :trace trace-fn
                                         :session-parameters session-parameters-a)
               :b (make-exchange-manager :transport tb :clock (clock-function clock) :trace trace-fn
                                         :session-parameters session-parameters-b)
               :a-port (transport-port ta) :b-port (transport-port tb))))

(defun pump (rig &key (rounds 4))
  "Let both managers handle what is queued, ROUNDS times."
  (loop :repeat rounds
        :do (exchange-manager-poll (rig-a rig) :timeout 0)
            (exchange-manager-poll (rig-b rig) :timeout 0)))

(defun run-rig (rig until &key (step 0.05d0) (max-rounds 2000))
  "Pump and advance the clock by STEP until UNTIL returns true; that value or NIL."
  (loop :repeat max-rounds
        :do (let ((done (funcall until)))
              (when done (return done)))
            (pump rig :rounds 1)
            (advance (rig-clock rig) step)
        :finally (return (funcall until))))

(defun secured-pair (rig &key (type :pase) (local-a 11) (local-b 22))
  "A matching pair of secured sessions installed on both managers of RIG."
  (let* ((keys (derive-session-keys (octets-from 0 32)))
         (node-a #x1111) (node-b #x2222)
         (sa (make-secured-session :type type :role :initiator :local-session-id local-a :peer-session-id local-b
                                   :keys keys :local-node-id node-a :peer-node-id node-b
                                   :peer-host "mem" :peer-port (rig-b-port rig)))
         (sb (make-secured-session :type type :role :responder :local-session-id local-b :peer-session-id local-a
                                   :keys keys :local-node-id node-b :peer-node-id node-a
                                   :peer-host "mem" :peer-port (rig-a-port rig))))
    (add-session (exchange-manager-session-manager (rig-a rig)) sa)
    (add-session (exchange-manager-session-manager (rig-b rig)) sb)
    (values sa sb)))

(defun recorder ()
  "A handler that keeps its events: (values handler events-cell)."
  (let ((events (list nil)))
    (values (lambda (exchange event &rest data)
              (declare (ignore exchange))
              (push (cons event data) (car events)))
            events)))

(defun events (cell) (reverse (car cell)))

(defun echo-handler (&key (close t) (opcode 1) (payload (ascii "echo")) (reliable t))
  "A protocol handler answering every message with (OPCODE PAYLOAD)."
  (lambda (exchange event &rest data)
    (declare (ignore data))
    (when (eq event :message)
      (exchange-send exchange opcode payload :reliable reliable)
      (when close (exchange-close exchange)))))

;;; ------------------------------------------------------------------
;;; Sessions

(test session-constructors
  (let ((keys (derive-session-keys (octets-from 0 32))))
    (let ((s (make-secured-session :type :pase :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys)))
      (is (session-secured-p s))
      (is (session-active-p s))
      (is (equalp (session-keys-i2r keys) (session-encrypt-key s)))
      (is (equalp (session-keys-r2i keys) (session-decrypt-key s)))
      (is (null (session-local-node-id s)))
      (is (equalp (session-keys-attestation-challenge keys) (session-attestation-challenge s)))
      (is (= 1 (session-local-session-id s)))
      (is (= 2 (session-peer-session-id s))))
    (let ((s (make-secured-session :type :case :role :responder :local-session-id 1 :peer-session-id 2 :keys keys
                                   :local-node-id 5 :peer-node-id 6)))
      (is (equalp (session-keys-r2i keys) (session-encrypt-key s)))
      (is (equalp (session-keys-i2r keys) (session-decrypt-key s)))
      (is (= 5 (session-local-node-id s)))
      (is (= 6 (session-peer-node-id s))))
    (signals session-error (make-secured-session :type :pase :role :initiator :local-session-id 0 :peer-session-id 2 :keys keys))
    (signals session-error (make-secured-session :type :pase :role :initiator :local-session-id 1 :peer-session-id 70000 :keys keys))
    (signals session-error (make-secured-session :type :pase :role :initiator :local-session-id 1 :peer-session-id 2 :keys nil))
    (signals session-error (make-secured-session :type :group :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys))
    ;; a CASE session needs operational node ids
    (signals session-error (make-secured-session :type :case :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys
                                                 :local-node-id 0 :peer-node-id 6))
    (signals session-error (make-secured-session :type :case :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys
                                                 :local-node-id 5 :peer-node-id nil)))
  (let ((u (make-unsecured-session :role :initiator :ephemeral-node-id #x1234 :peer-host "h" :peer-port 5540)))
    (is (not (session-secured-p u)))
    (is (= #x1234 (session-local-node-id u)))
    (is (null (session-peer-node-id u)))
    (is (= 0 (session-local-session-id u)))
    (is (string= "h" (session-peer-host u))))
  (let ((u (make-unsecured-session :role :responder :ephemeral-node-id #x1234)))
    (is (null (session-local-node-id u)))
    (is (= #x1234 (session-peer-node-id u))))
  (signals session-error (make-unsecured-session :role :initiator :ephemeral-node-id 0))
  (signals session-error (make-unsecured-session :role :initiator :ephemeral-node-id (ash 1 64))))

(test session-mrp-parameters
  (let ((s (make-unsecured-session :role :initiator :ephemeral-node-id 1)))
    (is (= *mrp-default-idle-interval* (session-idle-interval s)))
    (is (= *mrp-default-active-interval* (session-active-interval s)))
    (is (= *mrp-default-active-threshold* (session-active-threshold s)))
    (is (not (session-peer-active-p s 100d0)))
    (setf (session-peer-parameters s) (make-session-parameters :idle-interval 5000 :active-interval 300
                                                               :active-threshold 1000))
    (is (= 5d0 (session-idle-interval s)))
    (is (= 0.3d0 (session-active-interval s)))
    (is (= 1d0 (session-active-threshold s)))
    (is (= 5d0 (retransmission-table-idle-interval (session-retransmissions s))))
    (is (= 0.3d0 (retransmission-table-active-interval (session-retransmissions s))))
    (session-note-received s 100d0 "h" 1)
    (is (session-peer-active-p s 100.5d0))
    (is (not (session-peer-active-p s 101.5d0)))
    (is (string= "h" (session-peer-host s)))
    (is (= 1 (session-peer-port s)))
    ;; a parameter left out keeps the default
    (setf (session-peer-parameters s) (make-session-parameters :idle-interval 2000))
    (is (= 2d0 (session-idle-interval s)))
    (is (= *mrp-default-active-interval* (session-active-interval s)))))

(test unsecured-session-framing
  "Initiator messages name our ephemeral id as source, responder messages
name the peer's as destination; both decode on the other side."
  (let* ((counter (make-message-counter 100))
         (i (make-unsecured-session :role :initiator :ephemeral-node-id #xABCDEF :message-counter counter))
         (r (make-unsecured-session :role :responder :ephemeral-node-id #xABCDEF))
         (proto (make-protocol-header :initiator-p t :reliability-p t :exchange-id 7 :opcode #x20
                                      :payload (ascii "hi"))))
    (multiple-value-bind (octets counter) (session-encode i proto)
      (is (= 100 counter))
      (is (= 101 (message-counter-value (session-message-counter i))))
      (multiple-value-bind (header back) (session-decode r octets)
        (is (= 0 (message-header-session-id header)))
        (is (= #xABCDEF (message-header-source-node-id header)))
        (is (null (message-header-destination-node-id header)))
        (is (= 100 (message-header-message-counter header)))
        (is (equalp proto back))))
    (multiple-value-bind (octets) (session-encode r (make-protocol-header :exchange-id 7 :opcode #x21))
      (multiple-value-bind (header back) (session-decode i octets)
        (is (null (message-header-source-node-id header)))
        (is (= #xABCDEF (message-header-destination-node-id header)))
        (is (= #x21 (protocol-header-opcode back)))))
    ;; the window
    (is (session-accept-counter r 100))
    (is (equal '(nil :duplicate) (multiple-value-list (session-accept-counter r 100))))
    (is (session-accept-counter r 101))
    (is (equal '(nil :stale) (multiple-value-list (session-accept-counter r 50))))))

(test secured-session-framing
  "PASE sessions encrypt with a zero nonce node id, CASE sessions with the
sender's node id; the peer's session id is on the wire."
  (let* ((keys (derive-session-keys (octets-from 0 32)))
         (other (derive-session-keys (octets-from 1 33)))
         (proto (make-protocol-header :initiator-p t :reliability-p t :exchange-id 9 :opcode 2
                                      :protocol-id 1 :payload (octets-from 0 100))))
    (dolist (type '(:pase :case))
      (let ((a (make-secured-session :type type :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys
                                     :local-node-id 10 :peer-node-id 20))
            (b (make-secured-session :type type :role :responder :local-session-id 2 :peer-session-id 1 :keys keys
                                     :local-node-id 20 :peer-node-id 10))
            (c (make-secured-session :type type :role :responder :local-session-id 2 :peer-session-id 1 :keys other
                                     :local-node-id 20 :peer-node-id 10)))
        (multiple-value-bind (octets counter) (session-encode a proto)
          (is (= (+ 8 (length (encode-protocol-header proto)) 16) (length octets)))
          (is (= 2 (message-header-session-id (decode-message-header octets))))
          (is (= counter (message-header-message-counter (decode-message-header octets))))
          (multiple-value-bind (header back) (session-decode b octets)
            (is (= 2 (message-header-session-id header)))
            (is (equalp proto back)))
          (signals aead-authentication-error (session-decode c octets))
          ;; the other direction
          (multiple-value-bind (octets2) (session-encode b proto)
            (is (equalp proto (nth-value 1 (session-decode a octets2))))
            (is (not (equalp octets octets2)))))
        ;; a CASE message decrypts only with the right node id in the nonce
        (when (eq type :case)
          (let ((wrong (make-secured-session :type :case :role :responder :local-session-id 2 :peer-session-id 1 :keys keys
                                             :local-node-id 20 :peer-node-id 11)))
            (signals aead-authentication-error (session-decode wrong (session-encode a proto)))))))
    ;; too big
    (let ((a (make-secured-session :type :pase :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys)))
      (signals session-error (session-encode a (make-protocol-header :exchange-id 1 :payload (zeros 1260))))
      (finishes (session-encode a (make-protocol-header :exchange-id 1 :payload (zeros 1200)))))
    ;; closed
    (let ((a (make-secured-session :type :pase :role :initiator :local-session-id 1 :peer-session-id 2 :keys keys)))
      (setf (session-state a) :closed)
      (signals session-error (session-encode a proto)))))

(test session-manager-ids-and-lookup
  (let* ((sm (make-session-manager))
         (keys (derive-session-keys (octets-from 0 32)))
         (ids (loop :repeat 50 :collect (allocate-session-id sm))))
    (is (= 50 (length (remove-duplicates ids))))
    (is (every (lambda (id) (<= 1 id #xFFFF)) ids))
    (let ((s (make-secured-session :type :pase :role :initiator :local-session-id (first ids) :peer-session-id 5 :keys keys)))
      (add-session sm s)
      (is (eq s (find-session sm (first ids))))
      (is (null (find-session sm 5)))
      (is (equal (list s) (session-manager-sessions sm)))
      ;; the id is in use
      (signals session-error (add-session sm (make-secured-session :type :pase :role :initiator :local-session-id (first ids)
                                                                   :peer-session-id 6 :keys keys)))
      (remove-session sm s)
      (is (null (find-session sm (first ids))))
      (is (not (session-active-p s))))
    (dolist (id (rest ids)) (release-session-id sm id))
    (signals session-error (add-session sm (make-unsecured-session :role :initiator :ephemeral-node-id 1)))
    ;; unsecured contexts
    (let ((u (open-unsecured-session sm "peer" 5540)))
      (is (member u (session-manager-unsecured sm)))
      (is (eq :initiator (session-role u)))
      (is (eq (session-manager-unsecured-counter sm) (session-message-counter u)))
      ;; found by our ephemeral id in the destination field
      (is (eq u (find-unsecured-session sm (make-message-header :destination-node-id (session-local-node-id u)))))
      (is (null (find-unsecured-session sm (make-message-header :destination-node-id 12345))))
      (is (null (find-unsecured-session sm (make-message-header :source-node-id (session-local-node-id u)))))
      ;; a peer's id in the source field: only CREATE makes a context
      (is (null (find-unsecured-session sm (make-message-header :source-node-id 777))))
      (let ((r (find-unsecured-session sm (make-message-header :source-node-id 777) :peer-host "h" :peer-port 1 :create t)))
        (is (eq :responder (session-role r)))
        (is (= 777 (session-peer-node-id r)))
        (is (eq r (find-unsecured-session sm (make-message-header :source-node-id 777))))
        (is (string= "h" (session-peer-host r))))
      (is (null (find-unsecured-session sm (make-message-header))))
      (remove-session sm u)
      (is (not (member u (session-manager-unsecured sm)))))))

;;; ------------------------------------------------------------------
;;; Exchanges over the memory network

(test exchange-request-response
  "A reliable request, a reliable reply carrying the ack, a standalone ack for the reply."
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler (rig-b rig) 1 (echo-handler :opcode 5 :payload (ascii "pong")))
      (multiple-value-bind (handler cell) (recorder)
        (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler)))
          (is (exchange-initiator-p ex))
          (is (= 1 (exchange-protocol-id ex)))
          (is (exchange-open-p ex))
          (exchange-send ex 2 (ascii "ping"))
          (is (exchange-outstanding ex))
          (is (= 1 (network-sent (rig-network rig))))
          (pump rig :rounds 1)
          ;; B answered; its answer acknowledged our request, which A sees next round
          (is (= 2 (network-sent (rig-network rig))))
          (is (exchange-outstanding ex))
          (pump rig :rounds 1)
          (is (null (exchange-outstanding ex)))
          (is (equalp (list (list :message 5 (ascii "pong"))) (events cell)))
          ;; we owe B an ack: nothing goes out before the standalone ack timeout
          (is (exchange-pending-ack ex))
          (pump rig)
          (is (= 2 (network-sent (rig-network rig))))
          (advance (rig-clock rig) *mrp-standalone-ack-timeout*)
          (pump rig :rounds 1)
          (is (= 3 (network-sent (rig-network rig))))
          (is (null (exchange-pending-ack ex)))
          ;; B's exchange closed once its reply was acknowledged
          (is (null (exchange-manager-exchanges (rig-b rig))))
          (is (exchange-open-p ex))
          (exchange-close ex)
          (is (exchange-closed-p ex))
          (is (null (exchange-manager-exchanges (rig-a rig)))))))))

(test exchange-close-flushes-ack
  "Closing an exchange that owes an ack sends the standalone ack at once."
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler (rig-b rig) 1 (echo-handler))
      (let ((ex (open-exchange (rig-a rig) sa 1 :handler (lambda (exchange event &rest data)
                                                          (declare (ignore data))
                                                          (when (eq event :message) (exchange-close exchange))))))
        (exchange-send ex 2 nil)
        (pump rig :rounds 2)
        (is (exchange-closed-p ex))
        (is (= 3 (network-sent (rig-network rig))))
        (pump rig)
        (is (null (exchange-manager-exchanges (rig-b rig))))))))

(test exchange-unreliable-messages
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler (rig-b rig) 1 (echo-handler :reliable nil))
      (multiple-value-bind (handler cell) (recorder)
        (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler)))
          (exchange-send ex 2 nil :reliable nil)
          (is (null (exchange-outstanding ex)))
          (pump rig)
          (advance (rig-clock rig) 1)
          (pump rig)
          ;; one request, one reply, no acks at all
          (is (= 2 (network-sent (rig-network rig))))
          (is (= 1 (length (events cell))))
          (is (null (exchange-pending-ack ex))))))))

(test exchange-one-reliable-message-in-flight
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (let ((ex (open-exchange (rig-a rig) sa 1)))
        (exchange-send ex 1 nil)
        (signals exchange-error (exchange-send ex 2 nil))
        (finishes (exchange-send ex 2 nil :reliable nil))
        (exchange-abort ex)
        (is (exchange-closed-p ex))
        (signals exchange-error (exchange-send ex 3 nil))
        (is (null (retransmission-table-pending (session-retransmissions sa))))))))

(test exchange-retransmission
  "A lost message goes again after the backoff; the peer sees it once."
  (let* ((rig (make-rig))
         (network (rig-network rig))
         (drop-next t))
    (setf (network-drop network) (lambda (octets from to)
                                   (declare (ignore octets from to))
                                   (prog1 drop-next (setf drop-next nil))))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler (rig-b rig) 1 (echo-handler))
      (multiple-value-bind (handler cell) (recorder)
        (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler))
              (t0 (clock-now (rig-clock rig))))
          (exchange-send ex 2 nil)
          (is (= 1 (network-lost network)))
          (pump rig)
          ;; idle peer: not before 0.5 s * 1.1
          (advance (rig-clock rig) 0.5d0)
          (pump rig)
          (is (= 1 (network-sent network)))
          (is (= 1 (pending-message-transmissions (exchange-outstanding ex))))
          ;; by 0.5 * 1.1 * 1.25 it is out again
          (advance (rig-clock rig) 0.2d0)
          (pump rig :rounds 1)
          (is (= 3 (network-sent network)))  ; the retransmission and B's reply
          (is (= 2 (pending-message-transmissions (exchange-outstanding ex))))
          (pump rig :rounds 1)
          (is (null (exchange-outstanding ex)))
          (is (= 1 (length (events cell))))
          (is (< (- (clock-now (rig-clock rig)) t0) 1)))))))

(test exchange-retransmission-limit
  "After MRP_MAX_TRANSMISSIONS without an ack the exchange fails."
  (let* ((rig (make-rig))
         (network (rig-network rig)))
    (setf (network-drop network) (constantly t))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (multiple-value-bind (handler cell) (recorder)
        (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler)))
          (exchange-send ex 2 nil)
          (run-rig rig (lambda () (exchange-closed-p ex)) :step 0.1d0 :max-rounds 400)
          (is (exchange-closed-p ex))
          (is (= *mrp-max-transmissions* (network-sent network)))
          (is (equal '((:failure :retransmission-limit)) (events cell)))
          (is (null (exchange-manager-exchanges (rig-a rig))))
          (is (null (retransmission-table-pending (session-retransmissions sa))))
          ;; the whole schedule: 0.55 + 0.55 + 0.88 + 1.41 + 2.25 s, up to 25% jitter each
          (let ((elapsed (- (clock-now (rig-clock rig)) 1000d0)))
            (is (< 5.5d0 elapsed 8d0))))))))

(test exchange-active-peer-shortens-backoff
  (let* ((rig (make-rig))
         (network (rig-network rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler (rig-b rig) 1 (echo-handler))
      ;; a first conversation makes B active from A's point of view
      (let ((ex (open-exchange (rig-a rig) sa 1 :handler (echo-handler :opcode 9 :close t))))
        (exchange-send ex 2 nil)
        (pump rig)
        (is (exchange-closed-p ex)))
      (is (session-peer-active-p sa (clock-now (rig-clock rig))))
      (setf (network-drop network) (let ((n 0)) (lambda (o f to) (declare (ignore o f to)) (= 1 (incf n)))))
      (let ((ex (open-exchange (rig-a rig) sa 1))
            (sent (network-sent network)))
        (exchange-send ex 2 nil)
        (pump rig)
        ;; active interval 0.3 s: retransmitted by 0.3 * 1.1 * 1.25 = 0.41 s
        (advance (rig-clock rig) 0.45d0)
        (pump rig :rounds 2)
        (is (>= (network-sent network) (+ sent 2)))
        (is (null (exchange-outstanding ex)))))))

(test exchange-duplicate-is-acked-not-delivered
  (let* ((rig (make-rig))
         (network (rig-network rig))
         (seen '()))
    (setf (network-tap network) (lambda (octets from to) (push (list octets from to) seen)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (multiple-value-bind (handler cell) (recorder)
        (register-protocol-handler (rig-b rig) 1 handler)
        (let ((ex (open-exchange (rig-a rig) sa 1)))
          (exchange-send ex 2 (ascii "once"))
          (pump rig :rounds 1)
          (is (= 1 (length (events cell))))
          ;; B owes an ack; replay the request before it is sent
          (let ((request (first (last seen))))
            (inject network (first request) (second request) (third request)))
          (pump rig :rounds 2)
          (is (= 1 (length (events cell))))
          ;; the duplicate was answered with a standalone ack at once
          (is (= 2 (network-sent network)))
          (is (null (exchange-outstanding ex)))
          (exchange-abort ex))))))

(test exchange-response-timeout
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      ;; B acknowledges but never answers
      (register-protocol-handler (rig-b rig) 1 (lambda (exchange event &rest data)
                                                 (declare (ignore exchange event data))))
      (multiple-value-bind (handler cell) (recorder)
        (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler :response-timeout 2)))
          (exchange-send ex 2 nil)
          (pump rig)
          (advance (rig-clock rig) 0.3d0)
          (pump rig)                      ; B's standalone ack arrives
          (is (null (exchange-outstanding ex)))
          (is (null (events cell)))
          (advance (rig-clock rig) 1.5d0)
          (pump rig)
          (is (exchange-open-p ex))
          (advance (rig-clock rig) 0.3d0)
          (pump rig)
          (is (exchange-closed-p ex))
          (is (equal '((:failure :timeout)) (events cell))))))))

(test exchange-dropped-messages
  "Unknown sessions, exchanges without a handler and protocol mismatches are dropped;
reliable ones among them are still acknowledged."
  (let* ((rig (make-rig))
         (network (rig-network rig)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      ;; no handler for protocol 7 on B
      (let ((ex (open-exchange (rig-a rig) sa 7)))
        (exchange-send ex 1 nil)
        (pump rig :rounds 2)
        (is (= 2 (network-sent network)))
        (is (null (exchange-outstanding ex)))
        (is (null (exchange-manager-exchanges (rig-b rig))))
        (exchange-abort ex))
      ;; a message for a session B does not have: no ack, nothing happens
      (let ((ghost (make-secured-session :type :pase :role :initiator :local-session-id 99 :peer-session-id 98
                                         :keys (derive-session-keys (octets-from 0 32))
                                         :peer-host "mem" :peer-port (rig-b-port rig))))
        (add-session (exchange-manager-session-manager (rig-a rig)) ghost)
        (let ((ex (open-exchange (rig-a rig) ghost 1))
              (sent (network-sent network))
              (received (exchange-manager-received (rig-b rig))))
          (exchange-send ex 1 nil)
          (pump rig)
          (is (= (1+ sent) (network-sent network)))
          (is (= (1+ received) (exchange-manager-received (rig-b rig))))
          (is (exchange-outstanding ex))
          (exchange-abort ex)))
      ;; a wrong key: dropped as well
      (let ((sent (network-sent network))
            (proto (make-protocol-header :initiator-p t :reliability-p t :exchange-id 5 :protocol-id 1 :opcode 1))
            (bad (make-secured-session :type :pase :role :initiator :local-session-id 11 :peer-session-id 22
                                       :keys (derive-session-keys (octets-from 5 37)))))
        (inject network (session-encode bad proto) (rig-a-port rig) (rig-b-port rig))
        (pump rig)
        (is (= sent (network-sent network))))
      ;; a message without the I flag for an exchange nobody has: acked, dropped
      (let ((sent (network-sent network))
            (proto (make-protocol-header :initiator-p nil :reliability-p t :exchange-id 4242 :protocol-id 1 :opcode 1)))
        (inject network (session-encode sa proto) (rig-a-port rig) (rig-b-port rig))
        (pump rig :rounds 1)
        (is (= (1+ sent) (network-sent network)))
        (is (null (exchange-manager-exchanges (rig-b rig)))))
      ;; a protocol change inside an exchange is dropped
      (register-protocol-handler (rig-b rig) 1 (lambda (exchange event &rest data)
                                                 (declare (ignore exchange event data))))
      (let ((ex (open-exchange (rig-a rig) sa 1)))
        (exchange-send ex 1 nil :reliable nil)
        (pump rig :rounds 1)
        (let ((bx (first (exchange-manager-exchanges (rig-b rig))))
              (sent (network-sent network)))
          (is (not (null bx)))
          (inject network
                  (session-encode sa (make-protocol-header :initiator-p t :reliability-p t :exchange-id (exchange-id ex)
                                                           :protocol-id 2 :opcode 1))
                  (rig-a-port rig) (rig-b-port rig))
          (pump rig)
          (is (= sent (network-sent network)))
          (is (null (exchange-pending-ack bx))))
        (exchange-abort ex))
      ;; garbage
      (let ((sent (network-sent network)))
        (inject network (octets-from 0 3) (rig-a-port rig) (rig-b-port rig))
        (inject network (octets-from 0 40) (rig-a-port rig) (rig-b-port rig))
        (pump rig)
        (is (= sent (network-sent network))))
      (is (session-active-p sb)))))

(test exchange-manager-basics
  (let ((rig (make-rig)))
    (is (= 1000d0 (exchange-manager-now (rig-a rig))))
    (is (null (find-protocol-handler (rig-a rig) 1)))
    (let ((h (lambda (e ev &rest d) (declare (ignore e ev d)))))
      (register-protocol-handler (rig-a rig) 1 h)
      (is (eq h (find-protocol-handler (rig-a rig) 1)))
      (is (null (find-protocol-handler (rig-a rig) 1 :vendor-id 5)))
      (register-protocol-handler (rig-a rig) 1 h :vendor-id 5)
      (is (eq h (find-protocol-handler (rig-a rig) 1 :vendor-id 5)))
      (register-protocol-handler (rig-a rig) 1 nil)
      (is (null (find-protocol-handler (rig-a rig) 1))))
    (signals exchange-error (make-exchange-manager))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (let ((e1 (open-exchange (rig-a rig) sa 1))
            (e2 (open-exchange (rig-a rig) sa 1 :vendor-id 3)))
        (is (/= (exchange-id e1) (exchange-id e2)))
        (is (eq e1 (find-exchange (rig-a rig) sa (exchange-id e1) t)))
        (is (null (find-exchange (rig-a rig) sa (exchange-id e1) nil)))
        (is (= 3 (exchange-vendor-id e2)))
        (exchange-manager-close (rig-a rig))
        (is (exchange-closed-p e1))
        (is (null (exchange-manager-exchanges (rig-a rig))))))
    ;; run stops on the predicate or the timeout
    (let ((n 0))
      (is (eq :done (exchange-manager-run (rig-b rig) :until (lambda () (and (> (incf n) 3) :done)) :timeout 10)))
      (is (null (exchange-manager-run (rig-b rig) :until (constantly nil) :timeout 0))))))

(test unsecured-session-expiry
  (let ((rig (make-rig)))
    (let* ((sm (exchange-manager-session-manager (rig-a rig)))
           (u (open-unsecured-session sm "mem" (rig-b-port rig)))
           (ex (open-exchange (rig-a rig) u 0 :handler (lambda (e ev &rest d) (declare (ignore e ev d))))))
      (exchange-send ex #x20 (ascii "x") :reliable nil)
      (session-note-received u (clock-now (rig-clock rig)) nil nil)
      (pump rig)
      ;; B has no Secure Channel handler: a context was made and dropped again
      (is (= 1 (exchange-manager-received (rig-b rig))))
      (is (null (exchange-manager-exchanges (rig-b rig))))
      (is (member u (session-manager-unsecured sm)))
      (advance (rig-clock rig) (+ *unsecured-session-lifetime* 1))
      (pump rig)
      (is (member u (session-manager-unsecured sm)))  ; still has an exchange
      (exchange-close ex)
      (pump rig)
      (is (not (member u (session-manager-unsecured sm))))
      (is (not (session-active-p u))))))

;;; ------------------------------------------------------------------
;;; The Secure Channel: PASE and CASE over exchanges

(defun channels (rig &rest args-b)
  "Secure channels on both managers; ARGS-B configure B's."
  (values (make-secure-channel (rig-a rig))
          (apply #'make-secure-channel (rig-b rig) args-b)))

(defun finish (rig handshake)
  (run-rig rig (lambda () (not (handshake-running-p handshake))))
  (pump rig :rounds 8)                  ; let the acks settle
  handshake)

(test pase-over-exchanges
  (let ((rig (make-rig :session-parameters-b (make-session-parameters :idle-interval 1000 :active-interval 200
                                                                        :active-threshold 3000))))
    (multiple-value-bind (ca cb)
        (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (let* ((established '())
             (hs (progn
                   (setf (secure-channel-on-session cb) (lambda (channel session) (push (list channel session) established)))
                   (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*))))
        (is (handshake-running-p hs))
        (is (eq :pase (handshake-kind hs)))
        (is (= 1 (length (secure-channel-handshakes ca))))
        (finish rig hs)
        (is (handshake-complete-p hs))
        (let ((sa (handshake-session hs))
              (sb (first (secure-channel-sessions cb))))
          (is (session-p sa))
          (is (eq sa (first (secure-channel-sessions ca))))
          (is (eq :pase (session-type sa)))
          (is (eq :initiator (session-role sa)))
          (is (eq :responder (session-role sb)))
          (is (= (session-local-session-id sa) (session-peer-session-id sb)))
          (is (= (session-peer-session-id sa) (session-local-session-id sb)))
          (is (equalp (session-keys sa) (session-keys sb)))
          (is (equalp (session-encrypt-key sa) (session-decrypt-key sb)))
          (is (= (rig-b-port rig) (session-peer-port sa)))
          (is (= (rig-a-port rig) (session-peer-port sb)))
          (is (null (session-local-node-id sa)))
          (is (equal (list (list cb sb)) established))
          ;; the peer's MRP parameters travelled in the handshake
          (is (= 1d0 (session-idle-interval sa)))
          (is (= 0.2d0 (session-active-interval sa)))
          (is (= 3d0 (session-active-threshold sa)))
          (is (= *mrp-default-idle-interval* (session-idle-interval sb)))
          ;; handshakes done, exchanges gone, ids no longer reserved
          (is (null (secure-channel-handshakes ca)))
          (is (null (secure-channel-handshakes cb)))
          (is (null (exchange-manager-exchanges (rig-a rig))))
          (is (null (exchange-manager-exchanges (rig-b rig))))
          (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager ca)))))
          ;; PASE: request, response, pake1, pake2, pake3, status, standalone ack = 7 datagrams
          (is (= 7 (network-sent (rig-network rig))))
          ;; and the session works for an application protocol
          (register-protocol-handler (rig-b rig) 1 (echo-handler :opcode 5 :payload (ascii "pong")))
          (multiple-value-bind (handler cell) (recorder)
            (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler)))
              (exchange-send ex 2 (ascii "ping"))
              (pump rig)
              (is (equalp (list (list :message 5 (ascii "pong"))) (events cell)))
              (exchange-close ex)))
          ;; closing tells the peer
          (let ((closed '()))
            (setf (secure-channel-on-session-closed cb) (lambda (channel session) (push (list channel session) closed)))
            (close-session ca sa)
            (is (not (session-active-p sa)))
            (is (null (secure-channel-sessions ca)))
            (pump rig)
            (is (null (secure-channel-sessions cb)))
            (is (not (session-active-p sb)))
            (is (equal (list (list cb sb)) closed))))))))

(test pase-wrong-passcode
  (let ((rig (make-rig)))
    (multiple-value-bind (ca cb) (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (let ((hs (finish rig (start-pase ca "mem" (rig-b-port rig) :passcode 12341234))))
        ;; the initiator finds cB wrong in Pake2 and tells the responder with a status report
        (is (handshake-failed-p hs))
        (is (typep (handshake-error hs) 'pase-error))
        (is (not (typep (handshake-error hs) 'pase-peer-failure)))
        (is (= +secure-channel-status-invalid-parameter+ (pase-error-protocol-code (handshake-error hs))))
        (signals pase-error (handshake-wait hs))
        ;; request, response, pake1, pake2, status report, ack
        (is (= 6 (network-sent (rig-network rig))))
        (is (null (secure-channel-sessions ca)))
        (is (null (secure-channel-sessions cb)))
        (is (null (secure-channel-handshakes cb)))
        (is (null (exchange-manager-exchanges (rig-a rig))))
        (is (null (exchange-manager-exchanges (rig-b rig))))
        (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager ca)))))
        (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager cb)))))))))

(test pase-no-commissioning-window
  "Without a verifier the request is dropped; the initiator times out."
  (let ((rig (make-rig)))
    (multiple-value-bind (ca cb) (channels rig)
      (declare (ignore cb))
      (let ((hs (start-pase ca "mem" (rig-b-port rig) :passcode *passcode* :timeout 2)))
        (finish rig hs)
        (is (handshake-failed-p hs))
        (is (typep (handshake-error hs) 'exchange-error))
        (is (search "exchange failed" (exchange-error-message (handshake-error hs))))
        (is (null (secure-channel-sessions ca)))))))

(test pase-busy
  "A second commissioner during a handshake gets BUSY."
  (let ((rig (make-rig)))
    (multiple-value-bind (ca cb) (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (let ((h1 (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*)))
        (pump rig :rounds 1)             ; B is now in a handshake
        (is (= 1 (length (secure-channel-handshakes cb))))
        (let ((h2 (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*)))
          (finish rig h2)
          (is (handshake-failed-p h2))
          (is (typep (handshake-error h2) 'pase-peer-failure))
          (let ((report (pase-peer-failure-report (handshake-error h2))))
            (is (= +status-busy+ (status-report-general-code report)))
            (is (= +secure-channel-status-busy+ (status-report-protocol-code report)))
            (is (equalp (vector (ldb (byte 8 0) cl-matter::*busy-wait-time*) (ldb (byte 8 8) cl-matter::*busy-wait-time*))
                        (status-report-data report))))
          (finish rig h1)
          (is (handshake-complete-p h1))
          (is (= 1 (length (secure-channel-sessions cb)))))))))

(test pase-over-a-lossy-network
  "Every third datagram is lost; MRP carries the handshake through."
  (let* ((rig (make-rig))
         (n 0))
    (setf (network-drop (rig-network rig)) (lambda (o f to) (declare (ignore o f to)) (zerop (mod (incf n) 3))))
    (multiple-value-bind (ca cb) (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (let ((hs (finish rig (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*))))
        (is (handshake-complete-p hs))
        (is (> (network-lost (rig-network rig)) 2))
        (is (= 1 (length (secure-channel-sessions ca))))
        (is (= 1 (length (secure-channel-sessions cb))))
        (is (equalp (session-keys (first (secure-channel-sessions ca)))
                    (session-keys (first (secure-channel-sessions cb)))))))))

(test pase-known-parameters
  (let ((rig (make-rig)))
    (multiple-value-bind (ca cb) (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (declare (ignore cb))
      (let ((hs (finish rig (start-pase ca "mem" (rig-b-port rig) :passcode *passcode* :salt *salt* :iterations 1000))))
        (is (handshake-complete-p hs))))))

(test secure-channel-configuration
  (let ((rig (make-rig)))
    (let ((c (make-secure-channel (rig-a rig))))
      (is (eq (rig-a rig) (secure-channel-manager c)))
      (is (find-protocol-handler (rig-a rig) +protocol-secure-channel+))
      (is (null (cl-matter::secure-channel-pase-verifier c)))
      (signals error (set-pase-verifier c (octets-from 0 10) *salt* 1000))
      (signals error (set-pase-verifier c (spake2p-verifier *passcode* *salt* 1000) *salt* 10))
      (set-pase-verifier c (spake2p-verifier *passcode* *salt* 1000) *salt* 1000)
      (is (cl-matter::secure-channel-pase-verifier c))
      (set-pase-verifier c nil nil nil)
      (is (null (cl-matter::secure-channel-pase-verifier c)))
      ;; a bad passcode is refused before anything goes on the wire
      (signals pase-error (start-pase c "mem" 1 :passcode 11111111))
      (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager c)))))
      (signals case-error (start-case c "mem" 1 :fabric nil :peer-node-id 1))
      (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager c)))))
      (is (null (exchange-manager-exchanges (rig-a rig)))))))

(defun two-nodes ()
  "Two fabrics of one root: node #x10 and node #x20, the second with a CAT."
  (multiple-value-bind (a root-keypair) (make-test-fabric :fabric-id #x1234 :node-id #x10)
    (values a (fabric-add-node a #x20 :root-keypair root-keypair :case-auth-tags '(#xABCD0001)))))

(test case-over-exchanges-and-resumption
  (let ((rig (make-rig)))
    (multiple-value-bind (fa fb) (two-nodes)
      (multiple-value-bind (ca cb) (channels rig :fabrics (list fb))
        (setf (secure-channel-fabrics ca) (list fa))
        (let ((hs (finish rig (start-case ca "mem" (rig-b-port rig) :fabric fa :peer-node-id #x20))))
          (is (handshake-complete-p hs))
          (is (not (case-resumed-p (handshake-machine hs))))
          (let ((sa (handshake-session hs))
                (sb (first (secure-channel-sessions cb))))
            (is (eq :case (session-type sa)))
            (is (= #x10 (session-local-node-id sa)))
            (is (= #x20 (session-peer-node-id sa)))
            (is (= #x20 (session-local-node-id sb)))
            (is (= #x10 (session-peer-node-id sb)))
            (is (eq fa (session-fabric sa)))
            (is (eq fb (session-fabric sb)))
            (is (equal '(#xABCD0001) (session-peer-case-auth-tags sa)))
            (is (null (session-peer-case-auth-tags sb)))
            (is (equalp (session-keys sa) (session-keys sb)))
            (is (case-resumption-p (session-resumption sa)))
            (is (equalp (case-resumption-resumption-id (session-resumption sa))
                        (case-resumption-resumption-id (session-resumption sb))))
            ;; both channels remember the resumption state
            (is (eq (session-resumption sa) (find-resumption ca fa #x20)))
            (is (eq (session-resumption sb) (find-resumption cb fb #x10)))
            (is (null (find-resumption ca fa #x30)))
            ;; Sigma1, Sigma2, Sigma3, status, standalone ack
            (is (= 5 (network-sent (rig-network rig))))
            ;; a secured message with the node ids in the nonce
            (register-protocol-handler (rig-b rig) 1 (echo-handler :opcode 5 :payload (ascii "pong")))
            (multiple-value-bind (handler cell) (recorder)
              (let ((ex (open-exchange (rig-a rig) sa 1 :handler handler)))
                (exchange-send ex 2 (ascii "ping"))
                (pump rig)
                (is (equalp (list (list :message 5 (ascii "pong"))) (events cell)))
                (exchange-close ex)))
            ;; the next session resumes: Sigma1, Sigma2_Resume, status, ack
            (let ((sent (network-sent (rig-network rig)))
                  (hs2 (finish rig (start-case ca "mem" (rig-b-port rig) :fabric fa :peer-node-id #x20))))
              (is (handshake-complete-p hs2))
              (is (case-resumed-p (handshake-machine hs2)))
              (is (= 4 (- (network-sent (rig-network rig)) sent)))
              (let ((sa2 (handshake-session hs2)))
                (is (not (eq sa sa2)))
                (is (= 2 (length (secure-channel-sessions ca))))
                (is (= 2 (length (secure-channel-sessions cb))))
                (is (not (equalp (session-keys sa) (session-keys sa2))))
                ;; the new resumption id replaced the old one on both sides
                (is (eq (session-resumption sa2) (find-resumption ca fa #x20)))
                (is (= 1 (count-if (lambda (r) (= #x20 (case-resumption-peer-node-id r))) (secure-channel-resumptions ca))))
                (is (= 1 (count-if (lambda (r) (= #x10 (case-resumption-peer-node-id r))) (secure-channel-resumptions cb))))
                (is (equalp (case-resumption-resumption-id (session-resumption sa2))
                            (case-resumption-resumption-id (find-resumption cb fb #x10))))
                ;; without resumption it is a full handshake again
                (let ((hs3 (finish rig (start-case ca "mem" (rig-b-port rig) :fabric fa :peer-node-id #x20 :resume nil))))
                  (is (handshake-complete-p hs3))
                  (is (not (case-resumed-p (handshake-machine hs3)))))))))))))

(test case-no-shared-trust-roots
  (let ((rig (make-rig)))
    (multiple-value-bind (fa fb) (two-nodes)
      (declare (ignore fb))
      (multiple-value-bind (ca cb) (channels rig :fabrics (list (make-test-fabric :fabric-id #x99 :node-id #x20)))
        (let ((hs (finish rig (start-case ca "mem" (rig-b-port rig) :fabric fa :peer-node-id #x20))))
          (is (handshake-failed-p hs))
          (is (typep (handshake-error hs) 'case-peer-failure))
          (is (= +secure-channel-status-no-shared-trust-roots+ (case-error-protocol-code (handshake-error hs))))
          (is (null (secure-channel-sessions ca)))
          (is (null (secure-channel-sessions cb)))
          (is (null (exchange-manager-exchanges (rig-b rig)))))))))

(test case-responder-without-fabric-drops
  (let ((rig (make-rig)))
    (multiple-value-bind (fa fb) (two-nodes)
      (declare (ignore fb))
      (multiple-value-bind (ca cb) (channels rig)
        (declare (ignore cb))
        (let ((hs (finish rig (start-case ca "mem" (rig-b-port rig) :fabric fa :peer-node-id #x20 :timeout 1))))
          (is (handshake-failed-p hs))
          (is (typep (handshake-error hs) 'exchange-error)))))))

(test handshake-abort-and-wait-timeout
  (let ((rig (make-rig)))
    (multiple-value-bind (ca cb) (channels rig)
      (declare (ignore cb))
      (let ((hs (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*)))
        (signals exchange-error (handshake-wait hs :timeout 0))
        (is (handshake-failed-p hs))
        (is (null (secure-channel-handshakes ca)))
        (is (null (exchange-manager-exchanges (rig-a rig))))
        (is (= 0 (hash-table-count (cl-matter::session-manager-reserved (secure-channel-session-manager ca))))))
      (let ((hs (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*)))
        (handshake-abort hs)
        (is (handshake-failed-p hs))
        (handshake-abort hs)
        (signals exchange-error (handshake-wait hs))))))

(test handshake-on-complete-callback
  (let ((rig (make-rig))
        (done '()))
    (multiple-value-bind (ca cb) (channels rig :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
      (declare (ignore cb))
      (let ((hs (start-pase ca "mem" (rig-b-port rig) :passcode *passcode*
                            :on-complete (lambda (h) (push (handshake-state h) done)))))
        (finish rig hs)
        (is (equal '(:complete) done))
        (is (eq (handshake-session hs) (handshake-wait hs)))))))

;;; ------------------------------------------------------------------
;;; Over real UDP sockets on loopback, both implementations

(defmacro with-udp-rig ((a b host port) &body body)
  `(let* ((ta (make-udp-transport :address "127.0.0.1"))
          (tb (make-udp-transport :address "127.0.0.1"))
          (,a (make-exchange-manager :transport ta))
          (,b (make-exchange-manager :transport tb)))
     (unwind-protect
          (multiple-value-bind (,host ,port) (transport-local-endpoint tb)
            ,@body)
       (exchange-manager-close ,a)
       (exchange-manager-close ,b))))

(defun udp-finish (a b handshake &key (timeout 20))
  (let ((deadline (+ (exchange-manager-now a) timeout)))
    (loop :while (and (handshake-running-p handshake) (< (exchange-manager-now a) deadline))
          :do (exchange-manager-poll a :timeout 0.02)
              (exchange-manager-poll b :timeout 0.02))
    (loop :repeat 10 :do (exchange-manager-poll a :timeout 0.01) (exchange-manager-poll b :timeout 0.01))
    handshake))

(test udp-transport-basics
  (with-udp-rig (a b host port)
    (is (string= "127.0.0.1" host))
    (is (< 0 port 65536))
    (is (typep (exchange-manager-transport a) 'udp-transport))
    ;; nothing arrives: poll returns NIL after its timeout
    (let ((t0 (exchange-manager-now a)))
      (is (null (exchange-manager-poll a :timeout 0.05)))
      (is (<= 0.04 (- (exchange-manager-now a) t0) 1.0)))))

(test pase-over-udp
  (with-udp-rig (a b host port)
    (let* ((ca (make-secure-channel a))
           (cb (make-secure-channel b :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000))
           (hs (udp-finish a b (start-pase ca host port :passcode *passcode*))))
      (is (handshake-complete-p hs))
      (let ((sa (handshake-session hs)) (sb (first (secure-channel-sessions cb))))
        (is (equalp (session-keys sa) (session-keys sb)))
        (is (= port (session-peer-port sa)))
        (is (string= "127.0.0.1" (session-peer-host sb)))
        (register-protocol-handler b 1 (echo-handler :opcode 5 :payload (ascii "pong")))
        (multiple-value-bind (handler cell) (recorder)
          (let ((ex (open-exchange a sa 1 :handler handler)))
            (exchange-send ex 2 (ascii "ping"))
            (loop :repeat 50 :until (events cell)
                  :do (exchange-manager-poll a :timeout 0.02) (exchange-manager-poll b :timeout 0.02))
            (is (equalp (list (list :message 5 (ascii "pong"))) (events cell)))
            (exchange-close ex)))
        (is (null (exchange-manager-exchanges a)))))))

(test case-over-udp
  (with-udp-rig (a b host port)
    (multiple-value-bind (fa fb) (two-nodes)
      (let* ((ca (make-secure-channel a :fabrics (list fa)))
             (cb (make-secure-channel b :fabrics (list fb)))
             (hs (udp-finish a b (start-case ca host port :fabric fa :peer-node-id #x20)))
             (session (handshake-wait hs)))
        (is (session-p session))
        (is (eq :case (session-type session)))
        (is (= 1 (length (secure-channel-sessions cb))))
        (is (equalp (session-keys session) (session-keys (first (secure-channel-sessions cb)))))
        ;; and back the other way: B initiates to A and resumes
        (multiple-value-bind (host-a port-a) (transport-local-endpoint (exchange-manager-transport a))
          (let ((back (udp-finish a b (start-case cb host-a port-a :fabric fb :peer-node-id #x10))))
            (is (handshake-complete-p back))
            (is (case-resumed-p (handshake-machine back)))
            (is (= 2 (length (secure-channel-sessions ca))))
            (is (= 2 (length (secure-channel-sessions cb))))))))))

(test establish-pase-session-errors
  (with-udp-rig (a b host port)
    (let ((ca (make-secure-channel a))
          (cb (make-secure-channel b :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)))
      (declare (ignore cb))
      ;; HANDSHAKE-WAIT drives A only; B never polls, so A gives up at the timeout
      (signals exchange-error (establish-pase-session ca host port :passcode *passcode* :timeout 0.3))
      (is (null (secure-channel-handshakes ca)))
      (is (null (exchange-manager-exchanges a))))))
