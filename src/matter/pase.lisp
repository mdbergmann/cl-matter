;;;; pase.lisp -- Passcode-Authenticated Session Establishment (Matter Core
;;;; Specification section 4.14.1): the five Secure Channel messages that
;;;; turn a commissioning passcode into a secured unicast session.
;;;;
;;;;   initiator (commissioner)                 responder (commissionee)
;;;;   PBKDFParamRequest  0x20  --------------->
;;;;                            <---------------  PBKDFParamResponse 0x21
;;;;   PASE_Pake1  pA     0x22  --------------->
;;;;                            <---------------  PASE_Pake2  pB, cB  0x23
;;;;   PASE_Pake3  cA     0x24  --------------->
;;;;                            <---------------  StatusReport        0x40
;;;;
;;;; All of them are unsecured messages on session 0 of one exchange.  The
;;;; SPAKE2+ context is SHA-256("CHIP PAKE V1 Commissioning" || the
;;;; PBKDFParamRequest octets || the PBKDFParamResponse octets) and the
;;;; identities are empty.  Both sides end with
;;;;
;;;;   I2RKey || R2IKey || AttestationChallenge = HKDF(Ke, nil, "SessionKeys", 48)
;;;;
;;;; This file is the message codecs and the two state machines, driven
;;;; by PASE-HANDLE with (opcode, payload) and answering with the next
;;;; (opcode, payload) to send.  Transport, exchanges and MRP are the
;;;; caller's: the machines never touch a socket, so a whole handshake
;;;; runs in a test without one.

(in-package :cl-matter)

;;; ------------------------------------------------------------------
;;; Constants

(defconstant +pase-passcode-id+ 0 "The only passcode id of commissioning.")
(defconstant +pase-random-length+ 32)
(defconstant +pase-min-salt-length+ 16)
(defconstant +pase-max-salt-length+ 32)
(defconstant +pase-min-iterations+ 1000)
(defconstant +pase-max-iterations+ 100000)
(defconstant +session-key-length+ 16)
(defconstant +attestation-challenge-length+ 16)

(defparameter *pase-context-prefix* "CHIP PAKE V1 Commissioning")

;; Secure Channel protocol codes of a status report (section 4.10.1.3)
(defconstant +secure-channel-status-session-establishment-success+ 0)
(defconstant +secure-channel-status-no-shared-trust-roots+ 1)
(defconstant +secure-channel-status-invalid-parameter+ 2)
(defconstant +secure-channel-status-close-session+ 3)
(defconstant +secure-channel-status-busy+ 4)
(defconstant +secure-channel-status-session-not-found+ 5)

;; PBKDFParamRequest
(defconstant +tag-initiator-random+ 1)
(defconstant +tag-initiator-session-id+ 2)
(defconstant +tag-passcode-id+ 3)
(defconstant +tag-has-pbkdf-parameters+ 4)
(defconstant +tag-initiator-session-parameters+ 5)
;; PBKDFParamResponse
(defconstant +tag-responder-random+ 2)
(defconstant +tag-responder-session-id+ 3)
(defconstant +tag-pbkdf-parameters+ 4)
(defconstant +tag-responder-session-parameters+ 5)
(defconstant +tag-pbkdf-iterations+ 1)
(defconstant +tag-pbkdf-salt+ 2)
;; Pake1/2/3
(defconstant +tag-pa+ 1)
(defconstant +tag-pb+ 1)
(defconstant +tag-cb+ 2)
(defconstant +tag-ca+ 1)

;;; ------------------------------------------------------------------
;;; Conditions

(define-condition pase-error (error)
  ((message :initarg :message :reader pase-error-message)
   (protocol-code :initarg :protocol-code :initform +secure-channel-status-invalid-parameter+
                  :reader pase-error-protocol-code))
  (:report (lambda (c stream) (format stream "PASE failed: ~a" (pase-error-message c))))
  (:documentation "The handshake failed on our side.  PROTOCOL-CODE is the
Secure Channel code to put in the status report that tells the peer."))

(define-condition pase-peer-failure (pase-error)
  ((report :initarg :report :reader pase-peer-failure-report))
  (:report (lambda (c stream)
             (let ((report (pase-peer-failure-report c)))
               (format stream "PASE failed: the peer reported general code ~d, protocol code ~d"
                       (status-report-general-code report) (status-report-protocol-code report)))))
  (:documentation "The peer sent a status report other than success."))

(defun %pase-fail (format &rest args)
  (error 'pase-error :message (apply #'format nil format args)))

(defun pase-status-report (protocol-code)
  "The Secure Channel status report of PROTOCOL-CODE: success for
SESSION_ESTABLISHMENT_SUCCESS, else FAILURE."
  (make-status-report :general-code (if (= protocol-code +secure-channel-status-session-establishment-success+)
                                        +status-success+
                                        +status-failure+)
                      :protocol-id +protocol-secure-channel+
                      :protocol-code protocol-code))

;;; ------------------------------------------------------------------
;;; Passcodes (section 5.1.7.1)

(defparameter *invalid-passcodes*
  '(0 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 12345678 87654321))

(defun valid-passcode-p (passcode)
  "A passcode is 1..99999998 and none of the eleven trivial values."
  (and (integerp passcode)
       (<= 1 passcode 99999998)
       (not (member passcode *invalid-passcodes*))))

(defun %check-passcode (passcode)
  (unless (valid-passcode-p passcode)
    (%pase-fail "~s is not a valid passcode (1..99999998, not a trivial pattern)" passcode))
  passcode)

(defun %check-pbkdf-parameters (salt iterations)
  (unless (and (integerp iterations) (<= +pase-min-iterations+ iterations +pase-max-iterations+))
    (%pase-fail "PBKDF iterations must be ~d..~d, got ~s" +pase-min-iterations+ +pase-max-iterations+ iterations))
  (unless (and (%octets-p salt) (<= +pase-min-salt-length+ (length salt) +pase-max-salt-length+))
    (%pase-fail "the PBKDF salt must be ~d..~d octets, got ~a"
                +pase-min-salt-length+ +pase-max-salt-length+
                (if (%octets-p salt) (format nil "~d octets" (length salt)) salt)))
  (%octets salt))

(defun %check-session-id (id what)
  (unless (and (integerp id) (<= 1 id #xFFFF))
    (%pase-fail "~a must be 1..65535 (0 is the unsecured session), got ~s" what id))
  id)

;;; ------------------------------------------------------------------
;;; Session parameters (section 4.12.8), the structure both PBKDFParam
;;; messages (and CASE's Sigma1/Sigma2) may carry

(defstruct session-parameters
  "Every field optional (NIL = not sent).  Intervals and the threshold are
milliseconds; the revisions and the version are the peer's data model,
interaction model and specification numbers."
  (idle-interval nil)
  (active-interval nil)
  (active-threshold nil)
  (data-model-revision nil)
  (interaction-model-revision nil)
  (specification-version nil)
  (max-paths-per-invoke nil)
  (supported-transports nil)
  (max-tcp-payload-size nil))

(defun default-session-parameters ()
  "Our MRP intervals from the defaults of message.lisp."
  (make-session-parameters :idle-interval (round (* 1000 *mrp-default-idle-interval*))
                           :active-interval (round (* 1000 *mrp-default-active-interval*))
                           :active-threshold 4000))

(defmacro %session-parameter-table (&rest entries)
  "(tag accessor bits)... -> a list of (tag reader bits writer)."
  `(list ,@(loop :for (tag accessor bits) :in entries
                 :collect `(list ,tag #',accessor ,bits
                                 (lambda (parameters value) (setf (,accessor parameters) value))))))

(defparameter *session-parameter-tags*
  (%session-parameter-table
   (1 session-parameters-idle-interval 32)
   (2 session-parameters-active-interval 32)
   (3 session-parameters-active-threshold 16)
   (4 session-parameters-data-model-revision 16)
   (5 session-parameters-interaction-model-revision 16)
   (6 session-parameters-specification-version 32)
   (7 session-parameters-max-paths-per-invoke 16)
   (8 session-parameters-supported-transports 16)
   (9 session-parameters-max-tcp-payload-size 32)))

(defun session-parameters-tlv (tag parameters)
  "PARAMETERS -> a TLV structure tagged TAG with the fields that are set."
  (make-tlv-element
   tag :structure
   (loop :for (field-tag reader bits) :in *session-parameter-tags*
         :for value := (funcall reader parameters)
         :when value
           :collect (progn
                      (unless (and (integerp value) (<= 0 value) (< value (ash 1 bits)))
                        (%pase-fail "session parameter ~d must be an unsigned ~d-bit integer, got ~s"
                                    field-tag bits value))
                      (tlv field-tag :unsigned value)))))

(defun tlv-session-parameters (element)
  "A TLV structure -> SESSION-PARAMETERS; unknown tags are skipped, as the
specification asks."
  (unless (eq :structure (tlv-element-type element))
    (%pase-fail "session parameters must be a TLV structure, got ~a" (tlv-element-type element)))
  (let ((parameters (make-session-parameters)))
    (dolist (field (tlv-element-value element) parameters)
      (let ((spec (assoc (tlv-element-tag field) *session-parameter-tags*)))
        (when spec
          (destructuring-bind (field-tag reader bits writer) spec
            (declare (ignore reader))
            (let ((value (tlv-element-value field)))
              (unless (and (eq :unsigned (tlv-element-type field)) (< value (ash 1 bits)))
                (%pase-fail "session parameter ~d must be an unsigned ~d-bit integer, got ~s"
                            field-tag bits value))
              (funcall writer parameters value))))))))

;;; ------------------------------------------------------------------
;;; Message codecs

(defstruct pbkdf-param-request
  (initiator-random nil)
  (initiator-session-id 0)
  (passcode-id +pase-passcode-id+)
  (has-pbkdf-parameters-p nil)
  (session-parameters nil))

(defstruct pbkdf-param-response
  (initiator-random nil)
  (responder-random nil)
  (responder-session-id 0)
  (iterations nil)                      ; NIL with SALT: the parameters were omitted
  (salt nil)
  (session-parameters nil))

(defstruct pake1 (pa nil))
(defstruct pake2 (pb nil) (cb nil))
(defstruct pake3 (ca nil))

(defun %message-structure (&rest elements)
  "An anonymous TLV structure of the ELEMENTS that are not NIL (optional fields)."
  (make-tlv-element nil :structure (remove nil elements)))

(defun %concat-octets (&rest vectors)
  (let ((out (make-array (reduce #'+ vectors :key #'length) :element-type '(unsigned-byte 8)))
        (pos 0))
    (dolist (v vectors out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun %tlv-message (octets what)
  "OCTETS -> the one anonymous TLV structure they hold."
  (multiple-value-bind (element end)
      (handler-case (tlv-decode octets)
        (tlv-error (e) (%pase-fail "malformed ~a: ~a" what e)))
    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
      (%pase-fail "~a must be an anonymous TLV structure, got ~a" what element))
    (unless (= end (length octets))
      (%pase-fail "~a has ~d trailing octet~:p after the structure" what (- (length octets) end)))
    element))

(defun %tlv-field (structure tag type what &key optional length)
  "The value tagged TAG of STRUCTURE, which must have TYPE (and LENGTH octets
if given); NIL when OPTIONAL and absent."
  (let ((field (tlv-ref structure tag)))
    (cond ((null field)
           (if optional nil (%pase-fail "~a is missing (tag ~d)" what tag)))
          ((not (eq type (tlv-element-type field)))
           (%pase-fail "~a must be ~a, got ~a" what type (tlv-element-type field)))
          ((and length (/= length (length (tlv-element-value field))))
           (%pase-fail "~a must be ~d octets, got ~d" what length (length (tlv-element-value field))))
          (t (tlv-element-value field)))))

(defun encode-pbkdf-param-request (request)
  (tlv-encode
   (%message-structure
                  (tlv +tag-initiator-random+ :octets (pbkdf-param-request-initiator-random request))
                  (tlv +tag-initiator-session-id+ :unsigned (pbkdf-param-request-initiator-session-id request))
                  (tlv +tag-passcode-id+ :unsigned (pbkdf-param-request-passcode-id request))
                  (tlv +tag-has-pbkdf-parameters+ :boolean (pbkdf-param-request-has-pbkdf-parameters-p request))
                  (and (pbkdf-param-request-session-parameters request)
                       (session-parameters-tlv +tag-initiator-session-parameters+
                                               (pbkdf-param-request-session-parameters request))))))

(defun decode-pbkdf-param-request (octets)
  (let ((s (%tlv-message octets "PBKDFParamRequest")))
    (make-pbkdf-param-request
     :initiator-random (%tlv-field s +tag-initiator-random+ :octets "initiatorRandom" :length +pase-random-length+)
     :initiator-session-id (%tlv-field s +tag-initiator-session-id+ :unsigned "initiatorSessionId")
     :passcode-id (%tlv-field s +tag-passcode-id+ :unsigned "passcodeId")
     :has-pbkdf-parameters-p (%tlv-field s +tag-has-pbkdf-parameters+ :boolean "hasPBKDFParameters")
     :session-parameters (let ((p (tlv-ref s +tag-initiator-session-parameters+)))
                           (and p (tlv-session-parameters p))))))

(defun encode-pbkdf-param-response (response)
  (tlv-encode
   (%message-structure
                  (tlv +tag-initiator-random+ :octets (pbkdf-param-response-initiator-random response))
                  (tlv +tag-responder-random+ :octets (pbkdf-param-response-responder-random response))
                  (tlv +tag-responder-session-id+ :unsigned (pbkdf-param-response-responder-session-id response))
                  (and (pbkdf-param-response-iterations response)
                       (tlv-structure +tag-pbkdf-parameters+
                                      (tlv +tag-pbkdf-iterations+ :unsigned (pbkdf-param-response-iterations response))
                                      (tlv +tag-pbkdf-salt+ :octets (pbkdf-param-response-salt response))))
                  (and (pbkdf-param-response-session-parameters response)
                       (session-parameters-tlv +tag-responder-session-parameters+
                                               (pbkdf-param-response-session-parameters response))))))

(defun decode-pbkdf-param-response (octets)
  (let* ((s (%tlv-message octets "PBKDFParamResponse"))
         (parameters (tlv-ref s +tag-pbkdf-parameters+)))
    (when (and parameters (not (eq :structure (tlv-element-type parameters))))
      (%pase-fail "pbkdf_parameters must be a structure, got ~a" (tlv-element-type parameters)))
    (make-pbkdf-param-response
     :initiator-random (%tlv-field s +tag-initiator-random+ :octets "initiatorRandom" :length +pase-random-length+)
     :responder-random (%tlv-field s +tag-responder-random+ :octets "responderRandom" :length +pase-random-length+)
     :responder-session-id (%tlv-field s +tag-responder-session-id+ :unsigned "responderSessionId")
     :iterations (and parameters (%tlv-field parameters +tag-pbkdf-iterations+ :unsigned "pbkdf_parameters.iterations"))
     :salt (and parameters (%tlv-field parameters +tag-pbkdf-salt+ :octets "pbkdf_parameters.salt"))
     :session-parameters (let ((p (tlv-ref s +tag-responder-session-parameters+)))
                           (and p (tlv-session-parameters p))))))

(defun encode-pake1 (message)
  (tlv-encode (tlv-structure nil (tlv +tag-pa+ :octets (pake1-pa message)))))

(defun decode-pake1 (octets)
  (let ((s (%tlv-message octets "PASE_Pake1")))
    (make-pake1 :pa (%tlv-field s +tag-pa+ :octets "pA" :length +p256-point-length+))))

(defun encode-pake2 (message)
  (tlv-encode (tlv-structure nil
                             (tlv +tag-pb+ :octets (pake2-pb message))
                             (tlv +tag-cb+ :octets (pake2-cb message)))))

(defun decode-pake2 (octets)
  (let ((s (%tlv-message octets "PASE_Pake2")))
    (make-pake2 :pb (%tlv-field s +tag-pb+ :octets "pB" :length +p256-point-length+)
                :cb (%tlv-field s +tag-cb+ :octets "cB" :length 32))))

(defun encode-pake3 (message)
  (tlv-encode (tlv-structure nil (tlv +tag-ca+ :octets (pake3-ca message)))))

(defun decode-pake3 (octets)
  (let ((s (%tlv-message octets "PASE_Pake3")))
    (make-pake3 :ca (%tlv-field s +tag-ca+ :octets "cA" :length 32))))

;;; ------------------------------------------------------------------
;;; Session keys

(defstruct session-keys
  "What a finished handshake yields: the initiator encrypts with I2R and
the responder with R2I; the challenge is for device attestation."
  (i2r nil)
  (r2i nil)
  (attestation-challenge nil))

(defun derive-session-keys (ke)
  "I2RKey || R2IKey || AttestationChallenge = HKDF(KE, nil, \"SessionKeys\", 48)."
  (let ((material (hkdf-sha256 ke nil (%ascii-octets "SessionKeys")
                               (+ (* 2 +session-key-length+) +attestation-challenge-length+))))
    (make-session-keys :i2r (subseq material 0 +session-key-length+)
                       :r2i (subseq material +session-key-length+ (* 2 +session-key-length+))
                       :attestation-challenge (subseq material (* 2 +session-key-length+)))))

;;; ------------------------------------------------------------------
;;; The state machines

(defstruct (pase (:constructor %make-pase))
  "One side of a handshake.  STATE names the message awaited:
initiator :START -> :PBKDF-PARAM-RESPONSE -> :PAKE2 -> :STATUS-REPORT -> :COMPLETE
responder :PBKDF-PARAM-REQUEST -> :PAKE1 -> :PAKE3 -> :COMPLETE
and :FAILED after an error either way."
  (role :initiator :type (member :initiator :responder))
  (state :start :type keyword)
  (local-session-id 0)
  (peer-session-id nil)
  (local-session-parameters nil)
  (peer-session-parameters nil)
  (passcode nil)                        ; initiator
  (verifier-w0 nil)                     ; responder: 32 octets
  (verifier-l nil)                      ; responder: 65 octets
  (salt nil)
  (iterations nil)
  (initiator-random nil)
  (responder-random nil)
  (context-octets nil)                  ; prefix || request || response, until hashed
  (spake2p nil)
  (session-keys nil))

(defmethod print-object ((p pase) stream)
  (print-unreadable-object (p stream :type t)
    (format stream "~a ~a" (pase-role p) (pase-state p))))

(defun make-pase-initiator (&key passcode local-session-id
                              (session-parameters (default-session-parameters))
                              salt iterations)
  "The commissioner's side for PASSCODE.  LOCAL-SESSION-ID is the id we
want the responder to address us by.  SALT and ITERATIONS, when both are
given, are the device's PBKDF parameters known in advance (from its
onboarding payload); the request then asks the responder not to send them."
  (%check-passcode passcode)
  (%check-session-id local-session-id "the local session id")
  (when (or salt iterations)
    (setf salt (%check-pbkdf-parameters salt iterations)))
  (%make-pase :role :initiator :state :start
              :passcode passcode
              :local-session-id local-session-id
              :local-session-parameters session-parameters
              :salt salt :iterations iterations))

(defun make-pase-responder (&key verifier passcode salt iterations local-session-id
                              (session-parameters (default-session-parameters)))
  "The commissionee's side.  Either VERIFIER (the 97 octets w0 || L of
SPAKE2P-VERIFIER) or PASSCODE, in both cases with the SALT and ITERATIONS
the verifier was made with; a passcode is turned into a verifier here
and not kept."
  (%check-session-id local-session-id "the local session id")
  (let ((salt (%check-pbkdf-parameters salt iterations)))
    (multiple-value-bind (w0 l)
        (handler-case
            (spake2p-verifier-parts
             (cond (verifier verifier)
                   (passcode (spake2p-verifier (%check-passcode passcode) salt iterations))
                   (t (%pase-fail "a responder needs a verifier or a passcode"))))
          (crypto-error (e) (error 'pase-error :message (crypto-error-message e))))
      (%make-pase :role :responder :state :pbkdf-param-request
                  :verifier-w0 w0 :verifier-l l
                  :salt salt :iterations iterations
                  :local-session-id local-session-id
                  :local-session-parameters session-parameters))))

(defun pase-complete-p (pase) (eq :complete (pase-state pase)))

(defun pase-start (pase)
  "The initiator's first message: (values opcode payload-octets)."
  (unless (and (eq :initiator (pase-role pase)) (eq :start (pase-state pase)))
    (%pase-fail "PASE-START is for an initiator that has not started; this is ~a" pase))
  (let* ((random (random-octets +pase-random-length+))
         (request (make-pbkdf-param-request
                   :initiator-random random
                   :initiator-session-id (pase-local-session-id pase)
                   :has-pbkdf-parameters-p (and (pase-salt pase) t)
                   :session-parameters (pase-local-session-parameters pase)))
         (octets (encode-pbkdf-param-request request)))
    (setf (pase-initiator-random pase) random
          (pase-context-octets pase) (%concat-octets (%ascii-octets *pase-context-prefix*) octets)
          (pase-state pase) :pbkdf-param-response)
    (values +opcode-pbkdf-param-request+ octets)))

(defun pase-handle (pase opcode payload)
  "Feed the Secure Channel message (OPCODE, PAYLOAD octets) the peer sent.
Returns (values opcode payload) of the message to send back, or NIL when
there is nothing to send (the initiator after the final status report).
Signals PASE-ERROR when the message is wrong -- the responder then sends
(PASE-STATUS-REPORT (PASE-ERROR-PROTOCOL-CODE e)) -- and PASE-PEER-FAILURE
when the peer reported a failure; both leave PASE in state :FAILED."
  (handler-bind ((pase-error (lambda (e) (declare (ignore e)) (setf (pase-state pase) :failed)))
                 (crypto-error (lambda (e)
                                 (setf (pase-state pase) :failed)
                                 (error 'pase-error :message (crypto-error-message e)))))
    (let ((payload (%check-octet-vector "the message payload" payload)))
      (when (= opcode +opcode-status-report+)
        (return-from pase-handle (%pase-handle-status-report pase payload)))
      (let ((expected (ecase (pase-state pase)
                        (:pbkdf-param-request +opcode-pbkdf-param-request+)
                        (:pbkdf-param-response +opcode-pbkdf-param-response+)
                        (:pake1 +opcode-pase-pake1+)
                        (:pake2 +opcode-pase-pake2+)
                        (:pake3 +opcode-pase-pake3+)
                        ((:start :status-report :complete :failed) nil))))
        (unless (eql opcode expected)
          (%pase-fail "unexpected message opcode #x~2,'0x while awaiting ~a" opcode (pase-state pase))))
      (ecase (pase-state pase)
        (:pbkdf-param-request (%pase-handle-pbkdf-param-request pase payload))
        (:pbkdf-param-response (%pase-handle-pbkdf-param-response pase payload))
        (:pake1 (%pase-handle-pake1 pase payload))
        (:pake2 (%pase-handle-pake2 pase payload))
        (:pake3 (%pase-handle-pake3 pase payload))))))

(defun %pase-handle-status-report (pase payload)
  (let ((report (handler-case (decode-status-report payload)
                  (message-error (e) (%pase-fail "malformed status report: ~a" e)))))
    (cond ((and (eq :status-report (pase-state pase))
                (= +status-success+ (status-report-general-code report))
                (= +protocol-secure-channel+ (status-report-protocol-id report))
                (= +secure-channel-status-session-establishment-success+ (status-report-protocol-code report)))
           (setf (pase-state pase) :complete)
           nil)
          ((= +status-success+ (status-report-general-code report))
           (%pase-fail "unexpected success status report while awaiting ~a" (pase-state pase)))
          (t (setf (pase-state pase) :failed)
             (error 'pase-peer-failure :report report
                                       :message "the peer reported a failure"
                                       :protocol-code (status-report-protocol-code report))))))

(defun %pase-context (pase)
  "The SPAKE2+ context, hashed once both PBKDFParam messages are in."
  (sha256 (pase-context-octets pase)))

;; responder: PBKDFParamRequest -> PBKDFParamResponse

(defun %pase-handle-pbkdf-param-request (pase payload)
  (let ((request (decode-pbkdf-param-request payload)))
    (unless (= +pase-passcode-id+ (pbkdf-param-request-passcode-id request))
      (%pase-fail "passcode id ~d is not supported (only ~d)"
                  (pbkdf-param-request-passcode-id request) +pase-passcode-id+))
    (%check-session-id (pbkdf-param-request-initiator-session-id request) "the initiator session id")
    (let* ((random (random-octets +pase-random-length+))
           (response (make-pbkdf-param-response
                      :initiator-random (pbkdf-param-request-initiator-random request)
                      :responder-random random
                      :responder-session-id (pase-local-session-id pase)
                      :iterations (and (not (pbkdf-param-request-has-pbkdf-parameters-p request))
                                       (pase-iterations pase))
                      :salt (and (not (pbkdf-param-request-has-pbkdf-parameters-p request))
                                 (pase-salt pase))
                      :session-parameters (pase-local-session-parameters pase)))
           (octets (encode-pbkdf-param-response response)))
      (setf (pase-initiator-random pase) (pbkdf-param-request-initiator-random request)
            (pase-responder-random pase) random
            (pase-peer-session-id pase) (pbkdf-param-request-initiator-session-id request)
            (pase-peer-session-parameters pase) (pbkdf-param-request-session-parameters request)
            (pase-context-octets pase) (%concat-octets (%ascii-octets *pase-context-prefix*) payload octets)
            (pase-state pase) :pake1)
      (values +opcode-pbkdf-param-response+ octets))))

;; initiator: PBKDFParamResponse -> Pake1

(defun %pase-handle-pbkdf-param-response (pase payload)
  (let ((response (decode-pbkdf-param-response payload)))
    (unless (equalp (pbkdf-param-response-initiator-random response) (pase-initiator-random pase))
      (%pase-fail "the response echoes a different initiatorRandom"))
    (%check-session-id (pbkdf-param-response-responder-session-id response) "the responder session id")
    (cond ((pbkdf-param-response-iterations response)
           (setf (pase-salt pase) (%check-pbkdf-parameters (pbkdf-param-response-salt response)
                                                           (pbkdf-param-response-iterations response))
                 (pase-iterations pase) (pbkdf-param-response-iterations response)))
          ((null (pase-salt pase))
           (%pase-fail "the response carries no pbkdf_parameters and none were known in advance")))
    (setf (pase-responder-random pase) (pbkdf-param-response-responder-random response)
          (pase-peer-session-id pase) (pbkdf-param-response-responder-session-id response)
          (pase-peer-session-parameters pase) (pbkdf-param-response-session-parameters response)
          (pase-context-octets pase) (%concat-octets (pase-context-octets pase) payload))
    (multiple-value-bind (w0 w1) (spake2p-w0w1 (pase-passcode pase) (pase-salt pase) (pase-iterations pase))
      (let ((s (spake2p-start :prover :context (%pase-context pase) :w0 w0 :w1 w1)))
        (setf (pase-spake2p pase) s
              (pase-passcode pase) nil
              (pase-state pase) :pake2)
        (values +opcode-pase-pake1+ (encode-pake1 (make-pake1 :pa (spake2p-share s))))))))

;; responder: Pake1 -> Pake2

(defun %pase-handle-pake1 (pase payload)
  (let* ((message (decode-pake1 payload))
         (s (spake2p-start :verifier :context (%pase-context pase)
                           :w0 (pase-verifier-w0 pase) :l (pase-verifier-l pase)))
         (cb (spake2p-derive s (pake1-pa message))))
    (setf (pase-spake2p pase) s
          (pase-state pase) :pake3)
    (values +opcode-pase-pake2+ (encode-pake2 (make-pake2 :pb (spake2p-share s) :cb cb)))))

;; initiator: Pake2 -> Pake3

(defun %pase-handle-pake2 (pase payload)
  (let* ((message (decode-pake2 payload))
         (s (pase-spake2p pase))
         (ca (spake2p-derive s (pake2-pb message))))
    (spake2p-confirm s (pake2-cb message))
    (setf (pase-session-keys pase) (derive-session-keys (spake2p-shared-key s))
          (pase-state pase) :status-report)
    (values +opcode-pase-pake3+ (encode-pake3 (make-pake3 :ca ca)))))

;; responder: Pake3 -> StatusReport

(defun %pase-handle-pake3 (pase payload)
  (let ((message (decode-pake3 payload))
        (s (pase-spake2p pase)))
    (spake2p-confirm s (pake3-ca message))
    (setf (pase-session-keys pase) (derive-session-keys (spake2p-shared-key s))
          (pase-state pase) :complete)
    (values +opcode-status-report+
            (encode-status-report (pase-status-report +secure-channel-status-session-establishment-success+)))))
