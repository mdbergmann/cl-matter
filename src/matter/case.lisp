;;;; case.lisp -- Certificate-Authenticated Session Establishment (Matter
;;;; Core Specification section 4.14.2): the Sigma exchange that gives two
;;;; nodes of one fabric a secured session from their operational
;;;; certificates, and the resumption of a previous one.
;;;;
;;;;   initiator                                   responder
;;;;   Sigma1   0x30  random, session id, destination id,
;;;;                  ephemeral key [, resumption id, resume MIC]  --->
;;;;                  <---  Sigma2  0x31  random, session id, ephemeral key,
;;;;                                      encrypted {NOC, ICAC, signature, resumption id}
;;;;   Sigma3   0x32  encrypted {NOC, ICAC, signature}             --->
;;;;                  <---  StatusReport 0x40 success
;;;;
;;;; or, when the responder still holds the resumption state Sigma1 names,
;;;;
;;;;                  <---  Sigma2_Resume 0x33  new resumption id, MIC, session id
;;;;   StatusReport 0x40 success                                  --->
;;;;
;;;; SharedSecret = ECDH of the ephemeral keys.  With TT the running
;;;; transcript of the Sigma messages and IPK the fabric's identity
;;;; protection key:
;;;;
;;;;   S2K = HKDF(SharedSecret, IPK || responderRandom || responderEphPubKey || SHA256(Sigma1), "Sigma2", 16)
;;;;   S3K = HKDF(SharedSecret, IPK || SHA256(Sigma1 || Sigma2), "Sigma3", 16)
;;;;   I2RKey || R2IKey || AttestationChallenge
;;;;       = HKDF(SharedSecret, IPK || SHA256(Sigma1 || Sigma2 || Sigma3), "SessionKeys", 48)
;;;;   resume MIC = AES-CCM(HKDF(SharedSecret, initiatorRandom || resumptionID, "SigmaN_Resume", 16),
;;;;                        nonce "NCASE_SigmaSN", no plaintext, no AAD)
;;;;   resumed keys = HKDF(SharedSecret, initiatorRandom || Sigma1.resumptionID, "SessionResumptionKeys", 48)
;;;;
;;;; Like PASE, the two machines are driven by CASE-HANDLE with (opcode,
;;;; payload) and answer with the next (opcode, payload); the transport is
;;;; the caller's.

(in-package :cl-matter)

;;; ------------------------------------------------------------------
;;; Constants

(defconstant +case-random-length+ 32)
(defconstant +case-destination-id-length+ 32)
(defconstant +case-resumption-id-length+ 16)
(defconstant +sigma-key-length+ 16)

;; Sigma1
(defconstant +tag-sigma1-initiator-random+ 1)
(defconstant +tag-sigma1-initiator-session-id+ 2)
(defconstant +tag-sigma1-destination-id+ 3)
(defconstant +tag-sigma1-initiator-eph-pub-key+ 4)
(defconstant +tag-sigma1-initiator-session-parameters+ 5)
(defconstant +tag-sigma1-resumption-id+ 6)
(defconstant +tag-sigma1-resume-mic+ 7)
;; Sigma2
(defconstant +tag-sigma2-responder-random+ 1)
(defconstant +tag-sigma2-responder-session-id+ 2)
(defconstant +tag-sigma2-responder-eph-pub-key+ 3)
(defconstant +tag-sigma2-encrypted+ 4)
(defconstant +tag-sigma2-responder-session-parameters+ 5)
;; Sigma2_Resume
(defconstant +tag-sigma2-resume-resumption-id+ 1)
(defconstant +tag-sigma2-resume-mic+ 2)
(defconstant +tag-sigma2-resume-responder-session-id+ 3)
(defconstant +tag-sigma2-resume-responder-session-parameters+ 4)
;; Sigma3
(defconstant +tag-sigma3-encrypted+ 1)
;; TBS / TBE data of Sigma2 and Sigma3
(defconstant +tag-tbs-sender-noc+ 1)
(defconstant +tag-tbs-sender-icac+ 2)
(defconstant +tag-tbs-sender-eph-pub-key+ 3)
(defconstant +tag-tbs-receiver-eph-pub-key+ 4)
(defconstant +tag-tbe-sender-noc+ 1)
(defconstant +tag-tbe-sender-icac+ 2)
(defconstant +tag-tbe-signature+ 3)
(defconstant +tag-tbe-resumption-id+ 4)

(defparameter *sigma2-nonce* (%ascii-octets "NCASE_Sigma2N"))
(defparameter *sigma3-nonce* (%ascii-octets "NCASE_Sigma3N"))
(defparameter *sigma1-resume-nonce* (%ascii-octets "NCASE_SigmaS1"))
(defparameter *sigma2-resume-nonce* (%ascii-octets "NCASE_SigmaS2"))

;;; ------------------------------------------------------------------
;;; Conditions

(define-condition case-error (error)
  ((message :initarg :message :reader case-error-message)
   (protocol-code :initarg :protocol-code :initform +secure-channel-status-invalid-parameter+
                  :reader case-error-protocol-code))
  (:report (lambda (c stream) (format stream "CASE failed: ~a" (case-error-message c))))
  (:documentation "The handshake failed on our side.  PROTOCOL-CODE is the
Secure Channel code of the status report that tells the peer."))

(define-condition case-peer-failure (case-error)
  ((report :initarg :report :reader case-peer-failure-report))
  (:report (lambda (c stream)
             (let ((report (case-peer-failure-report c)))
               (format stream "CASE failed: the peer reported general code ~d, protocol code ~d"
                       (status-report-general-code report) (status-report-protocol-code report)))))
  (:documentation "The peer sent a status report other than success."))

(defun %case-fail (format &rest args)
  (error 'case-error :message (apply #'format nil format args)))

(defun %case-fail-code (code format &rest args)
  (error 'case-error :protocol-code code :message (apply #'format nil format args)))

(defun case-status-report (protocol-code)
  "The Secure Channel status report for PROTOCOL-CODE, as a STATUS-REPORT."
  (pase-status-report protocol-code))

;;; ------------------------------------------------------------------
;;; Message codecs

(defstruct sigma1
  (initiator-random nil)
  (initiator-session-id 0)
  (destination-id nil)
  (initiator-eph-pub-key nil)
  (session-parameters nil)
  (resumption-id nil)                   ; with RESUME-MIC: resumption requested
  (resume-mic nil))

(defstruct sigma2
  (responder-random nil)
  (responder-session-id 0)
  (responder-eph-pub-key nil)
  (encrypted nil)                       ; TBEData2 under S2K, with its MIC
  (session-parameters nil))

(defstruct sigma2-resume
  (resumption-id nil)
  (resume-mic nil)
  (responder-session-id 0)
  (session-parameters nil))

(defstruct sigma3 (encrypted nil))

(defstruct sigma-tbe
  "The plaintext of encrypted2 / encrypted3."
  (noc nil) (icac nil) (signature nil) (resumption-id nil))

(defun %case-message (octets what)
  "OCTETS -> the one anonymous TLV structure they hold."
  (multiple-value-bind (element end)
      (handler-case (tlv-decode octets)
        (tlv-error (e) (%case-fail "malformed ~a: ~a" what e)))
    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
      (%case-fail "~a must be an anonymous TLV structure, got ~a" what element))
    (unless (= end (length octets))
      (%case-fail "~a has ~d trailing octet~:p after the structure" what (- (length octets) end)))
    element))

(defun %case-field (structure tag type what &key optional length)
  (let ((field (tlv-ref structure tag)))
    (cond ((null field)
           (if optional nil (%case-fail "~a is missing (tag ~d)" what tag)))
          ((not (eq type (tlv-element-type field)))
           (%case-fail "~a must be ~a, got ~a" what type (tlv-element-type field)))
          ((and length (/= length (length (tlv-element-value field))))
           (%case-fail "~a must be ~d octets, got ~d" what length (length (tlv-element-value field))))
          (t (tlv-element-value field)))))

(defun %case-session-parameters (structure tag)
  (let ((element (tlv-ref structure tag)))
    (and element
         (handler-case (tlv-session-parameters element)
           (pase-error (e) (%case-fail "~a" (pase-error-message e)))))))

(defun encode-sigma1 (m)
  (unless (eq (and (sigma1-resumption-id m) t) (and (sigma1-resume-mic m) t))
    (%case-fail "Sigma1 carries a resumption id and a resume MIC together or not at all"))
  (tlv-encode
   (%message-structure
    (tlv +tag-sigma1-initiator-random+ :octets (sigma1-initiator-random m))
    (tlv +tag-sigma1-initiator-session-id+ :unsigned (sigma1-initiator-session-id m))
    (tlv +tag-sigma1-destination-id+ :octets (sigma1-destination-id m))
    (tlv +tag-sigma1-initiator-eph-pub-key+ :octets (sigma1-initiator-eph-pub-key m))
    (and (sigma1-session-parameters m)
         (session-parameters-tlv +tag-sigma1-initiator-session-parameters+ (sigma1-session-parameters m)))
    (and (sigma1-resumption-id m) (tlv +tag-sigma1-resumption-id+ :octets (sigma1-resumption-id m)))
    (and (sigma1-resume-mic m) (tlv +tag-sigma1-resume-mic+ :octets (sigma1-resume-mic m))))))

(defun decode-sigma1 (octets)
  (let* ((s (%case-message octets "Sigma1"))
         (m (make-sigma1
             :initiator-random (%case-field s +tag-sigma1-initiator-random+ :octets "initiatorRandom"
                                            :length +case-random-length+)
             :initiator-session-id (%case-field s +tag-sigma1-initiator-session-id+ :unsigned "initiatorSessionId")
             :destination-id (%case-field s +tag-sigma1-destination-id+ :octets "destinationId"
                                          :length +case-destination-id-length+)
             :initiator-eph-pub-key (%case-field s +tag-sigma1-initiator-eph-pub-key+ :octets "initiatorEphPubKey"
                                                 :length +p256-point-length+)
             :session-parameters (%case-session-parameters s +tag-sigma1-initiator-session-parameters+)
             :resumption-id (%case-field s +tag-sigma1-resumption-id+ :octets "resumptionID"
                                         :optional t :length +case-resumption-id-length+)
             :resume-mic (%case-field s +tag-sigma1-resume-mic+ :octets "initiatorResumeMIC"
                                      :optional t :length +mic-length+))))
    (unless (eq (and (sigma1-resumption-id m) t) (and (sigma1-resume-mic m) t))
      (%case-fail "Sigma1 carries only one of resumptionID and initiatorResumeMIC"))
    m))

(defun encode-sigma2 (m)
  (tlv-encode
   (%message-structure
    (tlv +tag-sigma2-responder-random+ :octets (sigma2-responder-random m))
    (tlv +tag-sigma2-responder-session-id+ :unsigned (sigma2-responder-session-id m))
    (tlv +tag-sigma2-responder-eph-pub-key+ :octets (sigma2-responder-eph-pub-key m))
    (tlv +tag-sigma2-encrypted+ :octets (sigma2-encrypted m))
    (and (sigma2-session-parameters m)
         (session-parameters-tlv +tag-sigma2-responder-session-parameters+ (sigma2-session-parameters m))))))

(defun decode-sigma2 (octets)
  (let ((s (%case-message octets "Sigma2")))
    (make-sigma2
     :responder-random (%case-field s +tag-sigma2-responder-random+ :octets "responderRandom"
                                    :length +case-random-length+)
     :responder-session-id (%case-field s +tag-sigma2-responder-session-id+ :unsigned "responderSessionId")
     :responder-eph-pub-key (%case-field s +tag-sigma2-responder-eph-pub-key+ :octets "responderEphPubKey"
                                         :length +p256-point-length+)
     :encrypted (%case-field s +tag-sigma2-encrypted+ :octets "encrypted2")
     :session-parameters (%case-session-parameters s +tag-sigma2-responder-session-parameters+))))

(defun encode-sigma2-resume (m)
  (tlv-encode
   (%message-structure
    (tlv +tag-sigma2-resume-resumption-id+ :octets (sigma2-resume-resumption-id m))
    (tlv +tag-sigma2-resume-mic+ :octets (sigma2-resume-resume-mic m))
    (tlv +tag-sigma2-resume-responder-session-id+ :unsigned (sigma2-resume-responder-session-id m))
    (and (sigma2-resume-session-parameters m)
         (session-parameters-tlv +tag-sigma2-resume-responder-session-parameters+
                                 (sigma2-resume-session-parameters m))))))

(defun decode-sigma2-resume (octets)
  (let ((s (%case-message octets "Sigma2_Resume")))
    (make-sigma2-resume
     :resumption-id (%case-field s +tag-sigma2-resume-resumption-id+ :octets "resumptionID"
                                 :length +case-resumption-id-length+)
     :resume-mic (%case-field s +tag-sigma2-resume-mic+ :octets "sigma2ResumeMIC" :length +mic-length+)
     :responder-session-id (%case-field s +tag-sigma2-resume-responder-session-id+ :unsigned "responderSessionID")
     :session-parameters (%case-session-parameters s +tag-sigma2-resume-responder-session-parameters+))))

(defun encode-sigma3 (m)
  (tlv-encode (%message-structure (tlv +tag-sigma3-encrypted+ :octets (sigma3-encrypted m)))))

(defun decode-sigma3 (octets)
  (make-sigma3 :encrypted (%case-field (%case-message octets "Sigma3") +tag-sigma3-encrypted+ :octets "encrypted3")))

(defun encode-sigma-tbs (noc icac sender-eph-pub-key receiver-eph-pub-key)
  "The TBSData2 / TBSData3 structure that is signed."
  (tlv-encode
   (%message-structure
    (tlv +tag-tbs-sender-noc+ :octets noc)
    (and icac (tlv +tag-tbs-sender-icac+ :octets icac))
    (tlv +tag-tbs-sender-eph-pub-key+ :octets sender-eph-pub-key)
    (tlv +tag-tbs-receiver-eph-pub-key+ :octets receiver-eph-pub-key))))

(defun encode-sigma-tbe (m)
  "The TBEData2 / TBEData3 structure that is encrypted."
  (tlv-encode
   (%message-structure
    (tlv +tag-tbe-sender-noc+ :octets (sigma-tbe-noc m))
    (and (sigma-tbe-icac m) (tlv +tag-tbe-sender-icac+ :octets (sigma-tbe-icac m)))
    (tlv +tag-tbe-signature+ :octets (sigma-tbe-signature m))
    (and (sigma-tbe-resumption-id m) (tlv +tag-tbe-resumption-id+ :octets (sigma-tbe-resumption-id m))))))

(defun decode-sigma-tbe (octets what &key resumption-id-p)
  (let ((s (%case-message octets what)))
    (make-sigma-tbe
     :noc (%case-field s +tag-tbe-sender-noc+ :octets "the sender's NOC")
     :icac (%case-field s +tag-tbe-sender-icac+ :octets "the sender's ICAC" :optional t)
     :signature (%case-field s +tag-tbe-signature+ :octets "the signature" :length +p256-signature-length+)
     :resumption-id (and resumption-id-p
                         (%case-field s +tag-tbe-resumption-id+ :octets "resumptionID"
                                      :length +case-resumption-id-length+)))))

;;; ------------------------------------------------------------------
;;; Key schedule

(defun %sigma-key (shared-secret salt info)
  (hkdf-sha256 shared-secret salt (%ascii-octets info) +sigma-key-length+))

(defun sigma2-key (shared-secret ipk responder-random responder-eph-pub-key sigma1-octets)
  "S2K."
  (%sigma-key shared-secret
              (%concat-octets ipk responder-random responder-eph-pub-key (sha256 sigma1-octets))
              "Sigma2"))

(defun sigma3-key (shared-secret ipk sigma1-octets sigma2-octets)
  "S3K."
  (%sigma-key shared-secret (%concat-octets ipk (sha256 (%concat-octets sigma1-octets sigma2-octets))) "Sigma3"))

(defun derive-case-session-keys (shared-secret ipk sigma1-octets sigma2-octets sigma3-octets)
  "The session keys of a full handshake."
  (derive-session-keys shared-secret
                       :salt (%concat-octets ipk (sha256 (%concat-octets sigma1-octets sigma2-octets sigma3-octets)))))

(defun derive-case-resumed-session-keys (shared-secret initiator-random resumption-id)
  "The session keys of a resumed session; RESUMPTION-ID is the one Sigma1 named."
  (derive-session-keys shared-secret :salt (%concat-octets initiator-random resumption-id)
                                     :info "SessionResumptionKeys"))

(defun sigma-resume-mic (shared-secret initiator-random resumption-id which)
  "The 16-octet resume MIC of Sigma1 (WHICH 1, over the old resumption id)
or Sigma2_Resume (WHICH 2, over the new one)."
  (let ((key (%sigma-key shared-secret (%concat-octets initiator-random resumption-id)
                         (ecase which (1 "Sigma1_Resume") (2 "Sigma2_Resume")))))
    (aes-ccm-encrypt key (ecase which (1 *sigma1-resume-nonce*) (2 *sigma2-resume-nonce*))
                     (make-array 0 :element-type '(unsigned-byte 8))
                     (make-array 0 :element-type '(unsigned-byte 8)))))

;;; ------------------------------------------------------------------
;;; Resumption state

(defstruct case-resumption
  "What a finished handshake leaves for resuming later: kept by both sides,
looked up by RESUMPTION-ID on the responder, by PEER-NODE-ID on the initiator."
  (resumption-id nil)
  (shared-secret nil)
  (fabric nil)                          ; the FABRIC the session was on
  (peer-node-id 0)
  (peer-case-auth-tags nil))

(defmethod print-object ((r case-resumption) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "peer ~16,'0x" (case-resumption-peer-node-id r))))

;;; ------------------------------------------------------------------
;;; The state machines

(defstruct (case-session (:constructor %make-case-session) (:conc-name case-))
  "One side of a handshake.  STATE names the message awaited:
initiator :START -> :SIGMA2 -> :STATUS-REPORT -> :COMPLETE
responder :SIGMA1 -> :SIGMA3 -> :COMPLETE, or :SIGMA1 -> :STATUS-REPORT -> :COMPLETE when resuming,
and :FAILED after an error either way."
  (role :initiator :type (member :initiator :responder))
  (state :start :type keyword)
  (fabric nil)                          ; initiator: the one fabric; responder: chosen from FABRICS
  (fabrics nil)                         ; responder: the candidates
  (local-session-id 0)
  (peer-session-id nil)
  (local-session-parameters nil)
  (peer-session-parameters nil)
  (peer-node-id nil)                    ; initiator: given; responder: from the NOC
  (peer-case-auth-tags nil)
  (initiator-random nil)
  (ephemeral nil)                       ; our P256-KEYPAIR
  (peer-eph-pub-key nil)
  (shared-secret nil)
  (sigma1-octets nil)
  (sigma2-octets nil)
  (resume-with nil)                     ; initiator: the CASE-RESUMPTION to try; responder: the one found
  (known-resumptions nil)               ; responder: the ones we still hold
  (resumed-p nil)
  (new-resumption-id nil)
  (session-keys nil))

(defmethod print-object ((c case-session) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a ~a" (case-role c) (case-state c))))

(defun make-case-initiator (&key fabric peer-node-id local-session-id
                              (session-parameters (default-session-parameters))
                              resumption)
  "Our side when opening a session to PEER-NODE-ID on FABRIC.  RESUMPTION,
a CASE-RESUMPTION from an earlier session with that node, makes Sigma1 ask
to resume; the responder may still answer with a full Sigma2."
  (unless (fabric-p fabric) (%case-fail "FABRIC must be a FABRIC"))
  (unless (operational-node-id-p peer-node-id) (%case-fail "~s is not an operational node id" peer-node-id))
  (%check-case-session-id local-session-id "the local session id")
  (when resumption
    (unless (case-resumption-p resumption) (%case-fail "RESUMPTION must be a CASE-RESUMPTION"))
    (unless (and (eq (case-resumption-fabric resumption) fabric)
                 (= (case-resumption-peer-node-id resumption) peer-node-id))
      (%case-fail "the resumption state is for another fabric or node")))
  (%make-case-session :role :initiator :state :start
                      :fabric fabric :peer-node-id peer-node-id
                      :local-session-id local-session-id
                      :local-session-parameters session-parameters
                      :resume-with resumption))

(defun make-case-responder (&key fabrics fabric local-session-id
                              (session-parameters (default-session-parameters))
                              resumptions)
  "Our side when a session is opened to us.  FABRICS (or the one FABRIC)
are the fabrics we belong to; Sigma1's destination id picks one.
RESUMPTIONS are the CASE-RESUMPTIONs we still hold."
  (let ((fabrics (or fabrics (and fabric (list fabric)))))
    (unless (and fabrics (every #'fabric-p fabrics)) (%case-fail "a responder needs at least one FABRIC"))
    (unless (every #'case-resumption-p resumptions) (%case-fail "RESUMPTIONS must be CASE-RESUMPTIONs"))
    (%check-case-session-id local-session-id "the local session id")
    (%make-case-session :role :responder :state :sigma1
                        :fabrics fabrics
                        :local-session-id local-session-id
                        :local-session-parameters session-parameters
                        :known-resumptions resumptions)))

(defun %check-case-session-id (id what)
  (unless (and (integerp id) (<= 1 id #xFFFF))
    (%case-fail "~a must be in 1..65535, got ~s" what id)))

(defun case-complete-p (c) (eq :complete (case-state c)))

(defun case-resumption-state (c)
  "After a complete handshake: the CASE-RESUMPTION to keep for next time."
  (unless (case-complete-p c) (%case-fail "the session is not established"))
  (make-case-resumption :resumption-id (case-new-resumption-id c)
                        :shared-secret (case-shared-secret c)
                        :fabric (case-fabric c)
                        :peer-node-id (case-peer-node-id c)
                        :peer-case-auth-tags (case-peer-case-auth-tags c)))

(defun case-start (c)
  "The initiator's Sigma1: (values opcode payload-octets)."
  (unless (and (eq :initiator (case-role c)) (eq :start (case-state c)))
    (%case-fail "CASE-START is for an initiator that has not started; this is ~a" c))
  (let* ((fabric (case-fabric c))
         (random (random-octets +case-random-length+))
         (ephemeral (generate-p256-keypair))
         (resumption (case-resume-with c))
         (message (make-sigma1
                   :initiator-random random
                   :initiator-session-id (case-local-session-id c)
                   :destination-id (fabric-destination-id fabric random (case-peer-node-id c))
                   :initiator-eph-pub-key (p256-keypair-public ephemeral)
                   :session-parameters (case-local-session-parameters c)
                   :resumption-id (and resumption (case-resumption-resumption-id resumption))
                   :resume-mic (and resumption
                                    (sigma-resume-mic (case-resumption-shared-secret resumption) random
                                                      (case-resumption-resumption-id resumption) 1))))
         (octets (encode-sigma1 message)))
    (setf (case-initiator-random c) random
          (case-ephemeral c) ephemeral
          (case-sigma1-octets c) octets
          (case-state c) :sigma2)
    (values +opcode-case-sigma1+ octets)))

(defun case-handle (c opcode payload)
  "Feed the Secure Channel message (OPCODE, PAYLOAD octets) the peer sent.
Returns (values opcode payload) of the message to send back, or NIL when
there is nothing to send.  Signals CASE-ERROR when the message is wrong --
the responder then sends (CASE-STATUS-REPORT (CASE-ERROR-PROTOCOL-CODE e))
-- and CASE-PEER-FAILURE when the peer reported a failure; both leave the
session in state :FAILED."
  (handler-bind ((case-error (lambda (e) (declare (ignore e)) (setf (case-state c) :failed)))
                 (crypto-error (lambda (e)
                                 (setf (case-state c) :failed)
                                 (error 'case-error :message (crypto-error-message e))))
                 (certificate-error (lambda (e)
                                      (setf (case-state c) :failed)
                                      (error 'case-error :message (certificate-error-message e)))))
    (let ((payload (%check-octet-vector "the message payload" payload)))
      (when (= opcode +opcode-status-report+)
        (return-from case-handle (%case-handle-status-report c payload)))
      (let ((expected (ecase (case-state c)
                        (:sigma1 (list +opcode-case-sigma1+))
                        (:sigma2 (list +opcode-case-sigma2+ +opcode-case-sigma2-resume+))
                        (:sigma3 (list +opcode-case-sigma3+))
                        ((:start :status-report :complete :failed) nil))))
        (unless (member opcode expected)
          (%case-fail "unexpected message opcode #x~2,'0x while awaiting ~a" opcode (case-state c))))
      (ecase (case-state c)
        (:sigma1 (%case-handle-sigma1 c payload))
        (:sigma2 (if (= opcode +opcode-case-sigma2-resume+)
                     (%case-handle-sigma2-resume c payload)
                     (%case-handle-sigma2 c payload)))
        (:sigma3 (%case-handle-sigma3 c payload))))))

(defun %case-handle-status-report (c payload)
  (let ((report (handler-case (decode-status-report payload)
                  (message-error (e) (%case-fail "malformed status report: ~a" e)))))
    (cond ((and (eq :status-report (case-state c))
                (= +status-success+ (status-report-general-code report))
                (= +protocol-secure-channel+ (status-report-protocol-id report))
                (= +secure-channel-status-session-establishment-success+ (status-report-protocol-code report)))
           (setf (case-state c) :complete)
           nil)
          ((= +status-success+ (status-report-general-code report))
           (%case-fail "unexpected success status report while awaiting ~a" (case-state c)))
          (t (setf (case-state c) :failed)
             (error 'case-peer-failure :report report
                                       :message "the peer reported a failure"
                                       :protocol-code (status-report-protocol-code report))))))

(defun %success-report ()
  (values +opcode-status-report+
          (encode-status-report (case-status-report +secure-channel-status-session-establishment-success+))))

;; responder: Sigma1 -> Sigma2 or Sigma2_Resume

(defun %find-fabric-by-destination (c message)
  (let ((random (sigma1-initiator-random message))
        (destination (sigma1-destination-id message)))
    (or (find-if (lambda (fabric) (%octets-equal-constant-time destination (fabric-destination-id fabric random)))
                 (case-fabrics c))
        (%case-fail-code +secure-channel-status-no-shared-trust-roots+
                         "the destination id names no fabric and node of ours"))))

(defun %case-handle-sigma1 (c payload)
  (let ((message (decode-sigma1 payload)))
    (%check-case-session-id (sigma1-initiator-session-id message) "the initiator session id")
    (unless (p256-point-p (sigma1-initiator-eph-pub-key message))
      (%case-fail "the initiator's ephemeral key is not a point on P-256"))
    (setf (case-initiator-random c) (sigma1-initiator-random message)
          (case-peer-session-id c) (sigma1-initiator-session-id message)
          (case-peer-session-parameters c) (sigma1-session-parameters message)
          (case-peer-eph-pub-key c) (sigma1-initiator-eph-pub-key message)
          (case-sigma1-octets c) payload)
    ;; resumption first: a valid MIC for a resumption id we hold skips the certificates
    (let ((resumption (and (sigma1-resumption-id message)
                           (find (sigma1-resumption-id message) (case-known-resumptions c)
                                 :key #'case-resumption-resumption-id :test #'equalp))))
      (when (and resumption
                 (%octets-equal-constant-time
                  (sigma1-resume-mic message)
                  (sigma-resume-mic (case-resumption-shared-secret resumption)
                                    (sigma1-initiator-random message) (sigma1-resumption-id message) 1)))
        (return-from %case-handle-sigma1 (%case-send-sigma2-resume c resumption))))
    (let* ((fabric (%find-fabric-by-destination c message))
           (ephemeral (generate-p256-keypair))
           (shared (p256-ecdh ephemeral (sigma1-initiator-eph-pub-key message)))
           (random (random-octets +case-random-length+))
           (resumption-id (random-octets +case-resumption-id-length+))
           (noc (certificate-octets* (fabric-noc fabric)))
           (icac (and (fabric-icac fabric) (certificate-octets* (fabric-icac fabric))))
           (tbs (encode-sigma-tbs noc icac (p256-keypair-public ephemeral) (sigma1-initiator-eph-pub-key message)))
           (tbe (encode-sigma-tbe (make-sigma-tbe :noc noc :icac icac
                                                  :signature (p256-sign (fabric-operational-keypair fabric) tbs)
                                                  :resumption-id resumption-id)))
           (s2k (sigma2-key shared (fabric-ipk fabric) random (p256-keypair-public ephemeral) payload))
           (message (make-sigma2 :responder-random random
                                 :responder-session-id (case-local-session-id c)
                                 :responder-eph-pub-key (p256-keypair-public ephemeral)
                                 :encrypted (aes-ccm-encrypt s2k *sigma2-nonce* tbe
                                                             (make-array 0 :element-type '(unsigned-byte 8)))
                                 :session-parameters (case-local-session-parameters c)))
           (octets (encode-sigma2 message)))
      (setf (case-fabric c) fabric
            (case-ephemeral c) ephemeral
            (case-shared-secret c) shared
            (case-new-resumption-id c) resumption-id
            (case-sigma2-octets c) octets
            (case-state c) :sigma3)
      (values +opcode-case-sigma2+ octets))))

(defun %case-send-sigma2-resume (c resumption)
  (let* ((new-id (random-octets +case-resumption-id-length+))
         (shared (case-resumption-shared-secret resumption))
         (message (make-sigma2-resume
                   :resumption-id new-id
                   :resume-mic (sigma-resume-mic shared (case-initiator-random c) new-id 2)
                   :responder-session-id (case-local-session-id c)
                   :session-parameters (case-local-session-parameters c))))
    (setf (case-fabric c) (case-resumption-fabric resumption)
          (case-resume-with c) resumption
          (case-shared-secret c) shared
          (case-peer-node-id c) (case-resumption-peer-node-id resumption)
          (case-peer-case-auth-tags c) (case-resumption-peer-case-auth-tags resumption)
          (case-new-resumption-id c) new-id
          (case-resumed-p c) t
          (case-session-keys c) (derive-case-resumed-session-keys shared (case-initiator-random c)
                                                           (case-resumption-resumption-id resumption))
          (case-state c) :status-report)
    (values +opcode-case-sigma2-resume+ (encode-sigma2-resume message))))

;; the peer's certificates, on either side

(defun %case-validate-peer (c tbe)
  "The peer's NOC and ICAC chain to our fabric's root; returns the NOC."
  (let* ((fabric (case-fabric c))
         (noc (decode-certificate (sigma-tbe-noc tbe)))
         (icac (and (sigma-tbe-icac tbe) (decode-certificate (sigma-tbe-icac tbe)))))
    (multiple-value-bind (node-id fabric-id cats)
        (validate-certificate-chain noc icac (fabric-rcac fabric))
      (unless (= fabric-id (fabric-fabric-id fabric))
        (%case-fail-code +secure-channel-status-no-shared-trust-roots+
                         "the peer's NOC is for fabric ~16,'0x, not ours" fabric-id))
      (when (and (case-peer-node-id c) (/= node-id (case-peer-node-id c)))
        (%case-fail "the peer's NOC is for node ~16,'0x, not the one we addressed" node-id))
      (setf (case-peer-node-id c) node-id
            (case-peer-case-auth-tags c) cats)
      noc)))

(defun %case-verify-tbs (c tbe noc sender-eph receiver-eph)
  (let ((tbs (encode-sigma-tbs (sigma-tbe-noc tbe) (sigma-tbe-icac tbe) sender-eph receiver-eph)))
    (unless (p256-verify (certificate-public-key noc) tbs (sigma-tbe-signature tbe))
      (%case-fail "the peer's signature over the TBS data does not verify"))))

(defun %case-decrypt (key nonce octets what)
  (handler-case (aes-ccm-decrypt key nonce octets (make-array 0 :element-type '(unsigned-byte 8)))
    (aead-authentication-error () (%case-fail "~a does not decrypt: wrong IPK, or a tampered message" what))))

;; initiator: Sigma2 -> Sigma3

(defun %case-handle-sigma2 (c payload)
  (let* ((message (decode-sigma2 payload))
         (fabric (case-fabric c)))
    (%check-case-session-id (sigma2-responder-session-id message) "the responder session id")
    (let* ((shared (p256-ecdh (case-ephemeral c) (sigma2-responder-eph-pub-key message)))
           (s2k (sigma2-key shared (fabric-ipk fabric) (sigma2-responder-random message)
                            (sigma2-responder-eph-pub-key message) (case-sigma1-octets c)))
           (tbe (decode-sigma-tbe (%case-decrypt s2k *sigma2-nonce* (sigma2-encrypted message) "encrypted2")
                                  "TBEData2" :resumption-id-p t))
           (noc (%case-validate-peer c tbe)))
      (%case-verify-tbs c tbe noc (sigma2-responder-eph-pub-key message) (p256-keypair-public (case-ephemeral c)))
      (setf (case-peer-session-id c) (sigma2-responder-session-id message)
            (case-peer-session-parameters c) (sigma2-session-parameters message)
            (case-peer-eph-pub-key c) (sigma2-responder-eph-pub-key message)
            (case-shared-secret c) shared
            (case-new-resumption-id c) (sigma-tbe-resumption-id tbe)
            (case-sigma2-octets c) payload)
      (let* ((our-noc (certificate-octets* (fabric-noc fabric)))
             (our-icac (and (fabric-icac fabric) (certificate-octets* (fabric-icac fabric))))
             (tbs (encode-sigma-tbs our-noc our-icac (p256-keypair-public (case-ephemeral c))
                                    (sigma2-responder-eph-pub-key message)))
             (tbe3 (encode-sigma-tbe (make-sigma-tbe :noc our-noc :icac our-icac
                                                     :signature (p256-sign (fabric-operational-keypair fabric) tbs))))
             (s3k (sigma3-key shared (fabric-ipk fabric) (case-sigma1-octets c) payload))
             (octets (encode-sigma3
                      (make-sigma3 :encrypted (aes-ccm-encrypt s3k *sigma3-nonce* tbe3
                                                               (make-array 0 :element-type '(unsigned-byte 8)))))))
        (setf (case-session-keys c) (derive-case-session-keys shared (fabric-ipk fabric)
                                                       (case-sigma1-octets c) payload octets)
              (case-state c) :status-report)
        (values +opcode-case-sigma3+ octets)))))

;; initiator: Sigma2_Resume -> StatusReport

(defun %case-handle-sigma2-resume (c payload)
  (let ((message (decode-sigma2-resume payload))
        (resumption (case-resume-with c)))
    (unless resumption (%case-fail "Sigma2_Resume, but we did not ask to resume"))
    (%check-case-session-id (sigma2-resume-responder-session-id message) "the responder session id")
    (let ((shared (case-resumption-shared-secret resumption)))
      (unless (%octets-equal-constant-time
               (sigma2-resume-resume-mic message)
               (sigma-resume-mic shared (case-initiator-random c) (sigma2-resume-resumption-id message) 2))
        (%case-fail "the Sigma2_Resume MIC does not verify"))
      (setf (case-peer-session-id c) (sigma2-resume-responder-session-id message)
            (case-peer-session-parameters c) (sigma2-resume-session-parameters message)
            (case-shared-secret c) shared
            (case-peer-case-auth-tags c) (case-resumption-peer-case-auth-tags resumption)
            (case-new-resumption-id c) (sigma2-resume-resumption-id message)
            (case-resumed-p c) t
            (case-session-keys c) (derive-case-resumed-session-keys shared (case-initiator-random c)
                                                             (case-resumption-resumption-id resumption))
            (case-state c) :complete)
      (%success-report))))

;; responder: Sigma3 -> StatusReport

(defun %case-handle-sigma3 (c payload)
  (let* ((message (decode-sigma3 payload))
         (fabric (case-fabric c))
         (shared (case-shared-secret c))
         (s3k (sigma3-key shared (fabric-ipk fabric) (case-sigma1-octets c) (case-sigma2-octets c)))
         (tbe (decode-sigma-tbe (%case-decrypt s3k *sigma3-nonce* (sigma3-encrypted message) "encrypted3")
                                "TBEData3"))
         (noc (%case-validate-peer c tbe)))
    (%case-verify-tbs c tbe noc (case-peer-eph-pub-key c) (p256-keypair-public (case-ephemeral c)))
    (setf (case-session-keys c) (derive-case-session-keys shared (fabric-ipk fabric)
                                                   (case-sigma1-octets c) (case-sigma2-octets c) payload)
          (case-state c) :complete)
    (%success-report)))
