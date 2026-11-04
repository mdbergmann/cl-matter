;;;; case-test.lisp -- CASE: the Sigma message codecs, the key schedule,
;;;; and whole handshakes between the SDK's test nodes and between
;;;; fabrics generated here.

(in-package :cl-matter.case.tests)

(def-suite case-tests :description "CASE: messages, key schedule and the Sigma handshake"
  :in cl-matter.tests:test-suite)
(in-suite case-tests)

(defparameter *random-a* (octets-from 0 32))
(defparameter *random-b* (octets-from 32 64))
(defparameter *destination* (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
(defparameter *resumption-id* (octets-from 0 16))
(defparameter *mic* (octets-from 16 32))

;;; ------------------------------------------------------------------
;;; Message codecs

(test sigma1-wire-format
  (let* ((key (sdk "node01-01" "publickey"))
         (m (make-sigma1 :initiator-random *random-a* :initiator-session-id 1
                         :destination-id *destination* :initiator-eph-pub-key key))
         (octets (encode-sigma1 m)))
    (is (equalp (cat (hex "15 3001 20") *random-a* (hex "2402 01") (hex "3003 20") *destination*
                     (hex "3004 41") key (hex "18"))
                octets))
    (let ((again (decode-sigma1 octets)))
      (is (equalp *random-a* (sigma1-initiator-random again)))
      (is (= 1 (sigma1-initiator-session-id again)))
      (is (equalp *destination* (sigma1-destination-id again)))
      (is (equalp key (sigma1-initiator-eph-pub-key again)))
      (is (null (sigma1-session-parameters again)))
      (is (null (sigma1-resumption-id again)))
      (is (null (sigma1-resume-mic again))))
    ;; with session parameters and a resumption request
    (let* ((full (make-sigma1 :initiator-random *random-a* :initiator-session-id #x1234
                              :destination-id *destination* :initiator-eph-pub-key key
                              :session-parameters (make-session-parameters :idle-interval 500 :active-interval 300)
                              :resumption-id *resumption-id* :resume-mic *mic*))
           (octets (encode-sigma1 full))
           (again (decode-sigma1 octets)))
      (is (equalp (cat (hex "15 3001 20") *random-a* (hex "2502 3412") (hex "3003 20") *destination*
                       (hex "3004 41") key
                       (hex "3505 2501 f401 2502 2c01 18")
                       (hex "3006 10") *resumption-id* (hex "3007 10") *mic* (hex "18"))
                  octets))
      (is (= #x1234 (sigma1-initiator-session-id again)))
      (is (= 500 (session-parameters-idle-interval (sigma1-session-parameters again))))
      (is (= 300 (session-parameters-active-interval (sigma1-session-parameters again))))
      (is (equalp *resumption-id* (sigma1-resumption-id again)))
      (is (equalp *mic* (sigma1-resume-mic again))))))

(test sigma1-rejections
  (let ((key (sdk "node01-01" "publickey")))
    (flet ((bad (&rest args)
             (signals case-error (decode-sigma1 (encode-sigma1 (apply #'make-sigma1 args))))))
      (bad :initiator-random (octets-from 0 31) :initiator-session-id 1 :destination-id *destination* :initiator-eph-pub-key key)
      (bad :initiator-random *random-a* :initiator-session-id 1 :destination-id (octets-from 0 33) :initiator-eph-pub-key key)
      (bad :initiator-random *random-a* :initiator-session-id 1 :destination-id *destination* :initiator-eph-pub-key (subseq key 1))
      (bad :initiator-random *random-a* :initiator-session-id 1 :destination-id *destination* :initiator-eph-pub-key key
           :resumption-id (octets-from 0 15) :resume-mic *mic*)
      (bad :initiator-random *random-a* :initiator-session-id 1 :destination-id *destination* :initiator-eph-pub-key key
           :resumption-id *resumption-id* :resume-mic (octets-from 0 15)))
    ;; only one of resumption id and MIC, at encoding and at decoding
    (signals case-error (encode-sigma1 (make-sigma1 :initiator-random *random-a* :initiator-session-id 1
                                                    :destination-id *destination* :initiator-eph-pub-key key
                                                    :resumption-id *resumption-id*)))
    (signals case-error (decode-sigma1 (cat (hex "15 3001 20") *random-a* (hex "2402 01") (hex "3003 20") *destination*
                                            (hex "3004 41") key (hex "3006 10") *resumption-id* (hex "18"))))
    ;; missing fields, wrong types, trailing octets, not a structure
    (signals case-error (decode-sigma1 (cat (hex "15 3001 20") *random-a* (hex "2402 01") (hex "3004 41") key (hex "18"))))
    (signals case-error (decode-sigma1 (cat (hex "15 3001 20") *random-a* (hex "3002 01 01") (hex "3003 20") *destination*
                                            (hex "3004 41") key (hex "18"))))
    (signals case-error (decode-sigma1 (cat (encode-sigma1 (make-sigma1 :initiator-random *random-a* :initiator-session-id 1
                                                                        :destination-id *destination* :initiator-eph-pub-key key))
                                            (hex "00"))))
    (signals case-error (decode-sigma1 (hex "16 18")))
    (signals case-error (decode-sigma1 (hex "15")))
    (signals case-error (decode-sigma1 (cat (hex "15 3001 20") *random-a* (hex "2402 01") (hex "3003 20") *destination*
                                            (hex "3004 41") key (hex "3505 0c01 00 18 18"))))))

(test sigma2-wire-format
  (let* ((key (sdk "node01-02" "publickey"))
         (encrypted (octets-from 0 10))
         (m (make-sigma2 :responder-random *random-b* :responder-session-id 2
                         :responder-eph-pub-key key :encrypted encrypted))
         (octets (encode-sigma2 m)))
    (is (equalp (cat (hex "15 3001 20") *random-b* (hex "2402 02") (hex "3003 41") key
                     (hex "3004 0a") encrypted (hex "18"))
                octets))
    (let ((again (decode-sigma2 octets)))
      (is (equalp *random-b* (sigma2-responder-random again)))
      (is (= 2 (sigma2-responder-session-id again)))
      (is (equalp key (sigma2-responder-eph-pub-key again)))
      (is (equalp encrypted (sigma2-encrypted again)))
      (is (null (sigma2-session-parameters again))))
    (let ((with (decode-sigma2 (encode-sigma2 (make-sigma2 :responder-random *random-b* :responder-session-id 2
                                                            :responder-eph-pub-key key :encrypted encrypted
                                                            :session-parameters (make-session-parameters :active-threshold 4000))))))
      (is (= 4000 (session-parameters-active-threshold (sigma2-session-parameters with)))))
    ;; a long encrypted blob takes the two-octet length form
    (let* ((big (octets-from 0 256))
           (octets (encode-sigma2 (make-sigma2 :responder-random *random-b* :responder-session-id 2
                                               :responder-eph-pub-key key :encrypted big))))
      (is (search (cat (hex "3104 0001") big) octets))
      (is (equalp big (sigma2-encrypted (decode-sigma2 octets)))))
    (signals case-error (decode-sigma2 (cat (hex "15 3001 20") *random-b* (hex "2402 02") (hex "3003 40") (subseq key 1)
                                            (hex "3004 0a") encrypted (hex "18"))))
    (signals case-error (decode-sigma2 (cat (hex "15 3001 20") *random-b* (hex "2402 02") (hex "3003 41") key (hex "18"))))
    (signals case-error (decode-sigma2 (cat (hex "15 3001 1f") (subseq *random-b* 1) (hex "2402 02") (hex "3003 41") key
                                            (hex "3004 0a") encrypted (hex "18"))))))

(test sigma2-resume-wire-format
  (let* ((m (make-sigma2-resume :resumption-id *resumption-id* :resume-mic *mic* :responder-session-id 2))
         (octets (encode-sigma2-resume m)))
    (is (equalp (cat (hex "15 3001 10") *resumption-id* (hex "3002 10") *mic* (hex "2403 02 18")) octets))
    (let ((again (decode-sigma2-resume octets)))
      (is (equalp *resumption-id* (sigma2-resume-resumption-id again)))
      (is (equalp *mic* (sigma2-resume-resume-mic again)))
      (is (= 2 (sigma2-resume-responder-session-id again)))
      (is (null (sigma2-resume-session-parameters again))))
    (let ((with (decode-sigma2-resume
                 (encode-sigma2-resume (make-sigma2-resume :resumption-id *resumption-id* :resume-mic *mic*
                                                           :responder-session-id 2
                                                           :session-parameters (make-session-parameters :idle-interval 1))))))
      (is (= 1 (session-parameters-idle-interval (sigma2-resume-session-parameters with)))))
    (signals case-error (decode-sigma2-resume (cat (hex "15 3001 0f") (subseq *resumption-id* 1) (hex "3002 10") *mic* (hex "2403 02 18"))))
    (signals case-error (decode-sigma2-resume (cat (hex "15 3001 10") *resumption-id* (hex "3002 0f") (subseq *mic* 1) (hex "2403 02 18"))))
    (signals case-error (decode-sigma2-resume (cat (hex "15 3001 10") *resumption-id* (hex "3002 10") *mic* (hex "18"))))))

(test sigma3-wire-format
  (let ((octets (encode-sigma3 (make-sigma3 :encrypted (octets-from 0 10)))))
    (is (equalp (cat (hex "15 3001 0a") (octets-from 0 10) (hex "18")) octets))
    (is (equalp (octets-from 0 10) (sigma3-encrypted (decode-sigma3 octets))))
    (signals case-error (decode-sigma3 (hex "15 18")))
    (signals case-error (decode-sigma3 (hex "15 2401 05 18")))))

(test sigma-tbs-and-tbe-wire-format
  (let* ((noc (sdk "node01-01" "chip")) (icac (sdk "ica01" "chip"))
         (a (sdk "node01-01" "publickey")) (b (sdk "node01-02" "publickey"))
         (signature (octets-from 0 64)))
    (flet ((octets-tlv (tag octets)
             (if (< (length octets) 256)
                 (cat (vector #x30 tag (length octets)) octets)
                 (cat (vector #x31 tag (ldb (byte 8 0) (length octets)) (ldb (byte 8 8) (length octets))) octets))))
      (is (equalp (cat (hex "15") (octets-tlv 1 noc) (octets-tlv 2 icac) (octets-tlv 3 a) (octets-tlv 4 b) (hex "18"))
                  (encode-sigma-tbs noc icac a b)))
      (is (equalp (cat (hex "15") (octets-tlv 1 noc) (octets-tlv 3 a) (octets-tlv 4 b) (hex "18"))
                  (encode-sigma-tbs noc nil a b)))
      (let ((tbe2 (encode-sigma-tbe (make-sigma-tbe :noc noc :icac icac :signature signature :resumption-id *resumption-id*)))
            (tbe3 (encode-sigma-tbe (make-sigma-tbe :noc noc :signature signature))))
        (is (equalp (cat (hex "15") (octets-tlv 1 noc) (octets-tlv 2 icac) (octets-tlv 3 signature)
                         (octets-tlv 4 *resumption-id*) (hex "18"))
                    tbe2))
        (is (equalp (cat (hex "15") (octets-tlv 1 noc) (octets-tlv 3 signature) (hex "18")) tbe3))
        (let ((again (decode-sigma-tbe tbe2 "TBEData2" :resumption-id-p t)))
          (is (equalp noc (sigma-tbe-noc again)))
          (is (equalp icac (sigma-tbe-icac again)))
          (is (equalp signature (sigma-tbe-signature again)))
          (is (equalp *resumption-id* (sigma-tbe-resumption-id again))))
        (let ((again (decode-sigma-tbe tbe3 "TBEData3")))
          (is (null (sigma-tbe-icac again)))
          (is (null (sigma-tbe-resumption-id again))))
        ;; TBEData2 needs the resumption id, TBEData3 ignores one
        (signals case-error (decode-sigma-tbe tbe3 "TBEData2" :resumption-id-p t))
        (is (null (sigma-tbe-resumption-id (decode-sigma-tbe tbe2 "TBEData3"))))
        (signals case-error (decode-sigma-tbe (encode-sigma-tbe (make-sigma-tbe :noc noc :signature (octets-from 0 63)))
                                              "TBEData3"))))))

;;; ------------------------------------------------------------------
;;; Key schedule

(test sigma-key-schedule
  (let* ((shared (octets-from 0 32)) (ipk (octets-from 0 16))
         (sigma1 (octets-from 0 100)) (sigma2 (octets-from 100 200)) (sigma3 (octets-from 200 250))
         (eph (sdk "node01-01" "publickey")))
    (is (equalp (hkdf-sha256 shared (cat ipk *random-b* eph (cl-matter:sha256 sigma1)) (ascii "Sigma2") 16)
                (sigma2-key shared ipk *random-b* eph sigma1)))
    (is (equalp (hkdf-sha256 shared (cat ipk (cl-matter:sha256 (cat sigma1 sigma2))) (ascii "Sigma3") 16)
                (sigma3-key shared ipk sigma1 sigma2)))
    (let ((keys (derive-case-session-keys shared ipk sigma1 sigma2 sigma3))
          (material (hkdf-sha256 shared (cat ipk (cl-matter:sha256 (cat sigma1 sigma2 sigma3))) (ascii "SessionKeys") 48)))
      (is (equalp (subseq material 0 16) (session-keys-i2r keys)))
      (is (equalp (subseq material 16 32) (session-keys-r2i keys)))
      (is (equalp (subseq material 32 48) (session-keys-attestation-challenge keys))))
    (let ((keys (derive-case-resumed-session-keys shared *random-a* *resumption-id*))
          (material (hkdf-sha256 shared (cat *random-a* *resumption-id*) (ascii "SessionResumptionKeys") 48)))
      (is (equalp (subseq material 0 16) (session-keys-i2r keys)))
      (is (equalp (subseq material 32 48) (session-keys-attestation-challenge keys))))
    ;; the resume MICs: AES-CCM of nothing under the resumption key
    (let ((empty (make-array 0 :element-type '(unsigned-byte 8))))
      (is (equalp (aes-ccm-encrypt (hkdf-sha256 shared (cat *random-a* *resumption-id*) (ascii "Sigma1_Resume") 16)
                                   (ascii "NCASE_SigmaS1") empty empty)
                  (sigma-resume-mic shared *random-a* *resumption-id* 1)))
      (is (equalp (aes-ccm-encrypt (hkdf-sha256 shared (cat *random-a* *resumption-id*) (ascii "Sigma2_Resume") 16)
                                   (ascii "NCASE_SigmaS2") empty empty)
                  (sigma-resume-mic shared *random-a* *resumption-id* 2)))
      (is (= 16 (length (sigma-resume-mic shared *random-a* *resumption-id* 1))))
      (is (not (equalp (sigma-resume-mic shared *random-a* *resumption-id* 1)
                       (sigma-resume-mic shared *random-a* *resumption-id* 2)))))
    ;; PASE's derivation is the same function without a salt
    (is (equalp (derive-session-keys shared) (derive-session-keys shared :salt nil :info "SessionKeys")))))

;;; ------------------------------------------------------------------
;;; Handshakes

(defparameter *epoch-key* (hex "235bf7e62823d358dca4ba50b1535f4b"))

(defun node-a () (sdk-fabric "node01-01" "ica01" :epoch-key *epoch-key*))
(defun node-b () (sdk-fabric "node01-02" nil :epoch-key *epoch-key*))

(defun run-case (initiator responder &key (trace nil))
  "Drive the two machines until neither has anything to send; returns the
list of (role opcode length) steps."
  (let ((steps '()))
    (multiple-value-bind (opcode payload) (case-start initiator)
      (loop :for (side . other) := (cons responder initiator) :then (cons other side)
            :while opcode
            :do (push (list (case-role side) opcode (length payload)) steps)
                (when trace (format t "~&-> ~a #x~2,'0x ~d octets~%" (case-role side) opcode (length payload)))
                (multiple-value-setq (opcode payload) (case-handle side opcode payload))))
    (nreverse steps)))

(test case-handshake-between-sdk-nodes
  (let* ((a (node-a)) (b (node-b))
         (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 11
                                 :session-parameters (make-session-parameters :idle-interval 1000)))
         (r (make-case-responder :fabric b :local-session-id 22
                                 :session-parameters (make-session-parameters :active-interval 200)))
         (steps (run-case i r)))
    (is (equal '((:responder #x30) (:initiator #x31) (:responder #x32) (:initiator #x40))
               (mapcar (lambda (s) (subseq s 0 2)) steps)))
    (is (case-complete-p i))
    (is (case-complete-p r))
    (is (not (case-resumed-p i)))
    (is (not (case-resumed-p r)))
    (is (session-keys-p (case-session-keys i)))
    (is (equalp (case-session-keys i) (case-session-keys r)))
    (is (= 16 (length (session-keys-i2r (case-session-keys i)))))
    (is (= 16 (length (session-keys-r2i (case-session-keys i)))))
    (is (= 16 (length (session-keys-attestation-challenge (case-session-keys i)))))
    (is (not (equalp (session-keys-i2r (case-session-keys i)) (session-keys-r2i (case-session-keys i)))))
    (is (= 32 (length (case-shared-secret i))))
    (is (equalp (case-shared-secret i) (case-shared-secret r)))
    (is (= (fabric-node-id b) (case-peer-node-id i)))
    (is (= (fabric-node-id a) (case-peer-node-id r)))
    (is (= 22 (case-peer-session-id i)))
    (is (= 11 (case-peer-session-id r)))
    (is (eq b (case-fabric r)))
    (is (= 200 (session-parameters-active-interval (case-peer-session-parameters i))))
    (is (= 1000 (session-parameters-idle-interval (case-peer-session-parameters r))))
    (is (null (case-peer-case-auth-tags i)))
    (let ((ri (case-resumption-state i)) (rr (case-resumption-state r)))
      (is (= 16 (length (case-resumption-resumption-id ri))))
      (is (equalp (case-resumption-resumption-id ri) (case-resumption-resumption-id rr)))
      (is (equalp (case-shared-secret i) (case-resumption-shared-secret ri)))
      (is (= (fabric-node-id b) (case-resumption-peer-node-id ri)))
      (is (= (fabric-node-id a) (case-resumption-peer-node-id rr)))
      (is (eq a (case-resumption-fabric ri)))
      (is (eq b (case-resumption-fabric rr))))
    ;; a second handshake differs in everything secret
    (let ((i2 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 11))
          (r2 (make-case-responder :fabric b :local-session-id 22)))
      (run-case i2 r2)
      (is (equalp (case-session-keys i2) (case-session-keys r2)))
      (is (not (equalp (case-session-keys i) (case-session-keys i2))))
      (is (not (equalp (case-shared-secret i) (case-shared-secret i2)))))
    ;; the roles swapped
    (let ((i3 (make-case-initiator :fabric b :peer-node-id (fabric-node-id a) :local-session-id 5))
          (r3 (make-case-responder :fabrics (list (node-b) a) :local-session-id 6)))
      (run-case i3 r3)
      (is (case-complete-p r3))
      (is (eq a (case-fabric r3)))
      (is (= (fabric-node-id b) (case-peer-node-id r3))))))

(test case-resumption
  (let* ((a (node-a)) (b (node-b))
         (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
         (r (make-case-responder :fabric b :local-session-id 2)))
    (run-case i r)
    (let* ((ri (case-resumption-state i)) (rr (case-resumption-state r))
           (i2 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 3 :resumption ri))
           (r2 (make-case-responder :fabric b :local-session-id 4 :resumptions (list rr)))
           (steps (run-case i2 r2)))
      (is (equal '((:responder #x30) (:initiator #x33) (:responder #x40))
                 (mapcar (lambda (s) (subseq s 0 2)) steps)))
      (is (case-complete-p i2))
      (is (case-complete-p r2))
      (is (case-resumed-p i2))
      (is (case-resumed-p r2))
      (is (equalp (case-session-keys i2) (case-session-keys r2)))
      (is (not (equalp (case-session-keys i) (case-session-keys i2))))
      (is (equalp (case-shared-secret i) (case-shared-secret i2)))
      (is (= 4 (case-peer-session-id i2)))
      (is (= 3 (case-peer-session-id r2)))
      (is (= (fabric-node-id a) (case-peer-node-id r2)))
      (is (eq b (case-fabric r2)))
      ;; both sides agree on the new resumption id, which is a new one
      (let ((ri2 (case-resumption-state i2)) (rr2 (case-resumption-state r2)))
        (is (equalp (case-resumption-resumption-id ri2) (case-resumption-resumption-id rr2)))
        (is (not (equalp (case-resumption-resumption-id ri) (case-resumption-resumption-id ri2))))
        (is (equalp (case-resumption-shared-secret ri) (case-resumption-shared-secret ri2)))
        ;; and it resumes again
        (let ((i3 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 5 :resumption ri2))
              (r3 (make-case-responder :fabric b :local-session-id 6 :resumptions (list rr rr2))))
          (run-case i3 r3)
          (is (case-resumed-p r3))
          (is (equalp (case-session-keys i3) (case-session-keys r3)))))
      ;; a responder that forgot the state falls back to the full handshake
      (let ((i4 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 7 :resumption ri))
            (r4 (make-case-responder :fabric b :local-session-id 8)))
        (is (equal '(#x30 #x31 #x32 #x40) (mapcar #'second (run-case i4 r4))))
        (is (case-complete-p i4))
        (is (not (case-resumed-p i4)))
        (is (not (case-resumed-p r4)))
        (is (equalp (case-session-keys i4) (case-session-keys r4))))
      ;; a resumption id the responder knows under a different secret is ignored, not an error
      (let* ((stale (make-case-resumption :resumption-id (case-resumption-resumption-id rr)
                                          :shared-secret (octets-from 0 32) :fabric b
                                          :peer-node-id (fabric-node-id a)))
             (i5 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 7 :resumption ri))
             (r5 (make-case-responder :fabric b :local-session-id 8 :resumptions (list stale))))
        (is (equal '(#x30 #x31 #x32 #x40) (mapcar #'second (run-case i5 r5))))
        (is (not (case-resumed-p r5)))
        (is (equalp (case-session-keys i5) (case-session-keys r5)))))))

(test case-handshake-between-generated-fabrics
  (multiple-value-bind (f root-keypair ica-keypair) (make-test-fabric :fabric-id #x1234 :node-id #x10 :icac t
                                                                      :case-auth-tags '(#xABCD0001 #x00020003))
    (let* ((g (fabric-add-node f #x20 :root-keypair root-keypair))
           (h (fabric-add-node f #x30 :ica-keypair ica-keypair :case-auth-tags '(#xFFFE0007)))
           (i (make-case-initiator :fabric f :peer-node-id #x20 :local-session-id 1))
           (r (make-case-responder :fabrics (list h g) :local-session-id 2)))
      (run-case i r)
      (is (case-complete-p i))
      (is (case-complete-p r))
      (is (equalp (case-session-keys i) (case-session-keys r)))
      (is (eq g (case-fabric r)))
      (is (= #x10 (case-peer-node-id r)))
      (is (equal '(#xABCD0001 #x00020003) (case-peer-case-auth-tags r)))
      (is (null (case-peer-case-auth-tags i)))
      ;; and to the node under the ICA, which has a CAT of its own
      (let ((i2 (make-case-initiator :fabric g :peer-node-id #x30 :local-session-id 3))
            (r2 (make-case-responder :fabrics (list g h) :local-session-id 4)))
        (run-case i2 r2)
        (is (case-complete-p r2))
        (is (eq h (case-fabric r2)))
        (is (equal '(#xFFFE0007) (case-peer-case-auth-tags i2)))
        (is (equalp (case-session-keys i2) (case-session-keys r2)))))))

;;; ------------------------------------------------------------------
;;; Failures

(defun first-failure (initiator responder)
  "Run the handshake; return the condition the first failing side signals
and the role that signalled it."
  (handler-case (progn (run-case initiator responder) nil)
    (case-error (e) (values e (if (eq :failed (case-state responder)) :responder :initiator)))))

(test case-no-shared-trust-roots
  ;; a different IPK epoch key: the destination id names nobody
  (let ((i (make-case-initiator :fabric (node-a) :peer-node-id #xDEDEDEDE00010002 :local-session-id 1))
        (r (make-case-responder :fabric (sdk-fabric "node01-02" nil :epoch-key (octets-from 0 16)) :local-session-id 2)))
    (multiple-value-bind (e role) (first-failure i r)
      (is (typep e 'case-error))
      (is (eq :responder role))
      (is (= +secure-channel-status-no-shared-trust-roots+ (case-error-protocol-code e)))
      (is (eq :failed (case-state r)))
      (is (= 1 (status-report-protocol-code (case-status-report (case-error-protocol-code e)))))))
  ;; the wrong node addressed
  (let ((i (make-case-initiator :fabric (node-a) :peer-node-id #xDEDEDEDE00010003 :local-session-id 1))
        (r (make-case-responder :fabric (node-b) :local-session-id 2)))
    (multiple-value-bind (e role) (first-failure i r)
      (is (eq :responder role))
      (is (= +secure-channel-status-no-shared-trust-roots+ (case-error-protocol-code e)))))
  ;; a responder on another fabric altogether
  (let ((i (make-case-initiator :fabric (node-a) :peer-node-id 1 :local-session-id 1))
        (r (make-case-responder :fabric (make-test-fabric :epoch-key *epoch-key*) :local-session-id 2)))
    (multiple-value-bind (e role) (first-failure i r)
      (is (eq :responder role))
      (is (= +secure-channel-status-no-shared-trust-roots+ (case-error-protocol-code e))))))

(test case-tampering
  (let* ((a (node-a)) (b (node-b)))
    ;; Sigma2 with its ephemeral key swapped: S2K differs, nothing decrypts
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
          (r (make-case-responder :fabric b :local-session-id 2)))
      (multiple-value-bind (op1 sigma1) (case-start i)
        (multiple-value-bind (op2 sigma2) (case-handle r op1 sigma1)
          (is (= #x31 op2))
          (let ((m (decode-sigma2 sigma2)))
            (setf (sigma2-responder-eph-pub-key m) (sdk "node02-01" "publickey"))
            (signals case-error (case-handle i op2 (encode-sigma2 m)))
            (is (eq :failed (case-state i)))))))
    ;; a flipped bit in encrypted2
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
          (r (make-case-responder :fabric b :local-session-id 2)))
      (multiple-value-bind (op1 sigma1) (case-start i)
        (multiple-value-bind (op2 sigma2) (case-handle r op1 sigma1)
          (let ((m (decode-sigma2 sigma2)))
            (setf (aref (sigma2-encrypted m) 5) (logxor (aref (sigma2-encrypted m) 5) 1))
            (signals case-error (case-handle i op2 (encode-sigma2 m)))))))
    ;; a flipped bit in encrypted3
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
          (r (make-case-responder :fabric b :local-session-id 2)))
      (multiple-value-bind (op1 sigma1) (case-start i)
        (multiple-value-bind (op2 sigma2) (case-handle r op1 sigma1)
          (multiple-value-bind (op3 sigma3) (case-handle i op2 sigma2)
            (let ((m (decode-sigma3 sigma3)))
              (setf (aref (sigma3-encrypted m) 5) (logxor (aref (sigma3-encrypted m) 5) 1))
              (signals case-error (case-handle r op3 (encode-sigma3 m)))
              (is (eq :failed (case-state r))))))))
    ;; Sigma1 with an off-curve ephemeral key, or a session id of 0
    (let ((r (make-case-responder :fabric b :local-session-id 2))
          (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (multiple-value-bind (op1 sigma1) (case-start i)
        (let ((m (decode-sigma1 sigma1)))
          (setf (aref (sigma1-initiator-eph-pub-key m) 64) (logxor (aref (sigma1-initiator-eph-pub-key m) 64) 1))
          (signals case-error (case-handle r op1 (encode-sigma1 m))))))
    (let ((r (make-case-responder :fabric b :local-session-id 2))
          (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (multiple-value-bind (op1 sigma1) (case-start i)
        (let ((m (decode-sigma1 sigma1)))
          (setf (sigma1-initiator-session-id m) 0)
          (signals case-error (case-handle r op1 (encode-sigma1 m))))))
    ;; a tampered Sigma2_Resume MIC
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
          (r (make-case-responder :fabric b :local-session-id 2)))
      (run-case i r)
      (let ((i2 (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 3
                                     :resumption (case-resumption-state i)))
            (r2 (make-case-responder :fabric b :local-session-id 4 :resumptions (list (case-resumption-state r)))))
        (multiple-value-bind (op1 sigma1) (case-start i2)
          (multiple-value-bind (op2 resume) (case-handle r2 op1 sigma1)
            (is (= #x33 op2))
            (let ((m (decode-sigma2-resume resume)))
              (setf (aref (sigma2-resume-resume-mic m) 0) (logxor (aref (sigma2-resume-resume-mic m) 0) 1))
              (signals case-error (case-handle i2 op2 (encode-sigma2-resume m))))))))
    ;; Sigma2_Resume to an initiator that did not ask
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (case-start i)
      (signals case-error
        (case-handle i #x33 (encode-sigma2-resume (make-sigma2-resume :resumption-id *resumption-id* :resume-mic *mic*
                                                                      :responder-session-id 2)))))))

(test case-status-reports
  (let* ((a (node-a)) (b (node-b))
         (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
         (r (make-case-responder :fabric b :local-session-id 2)))
    (case-start i)
    ;; a failure report from the peer at any point
    (signals case-peer-failure
      (case-handle i #x40 (encode-status-report (case-status-report +secure-channel-status-busy+))))
    (is (eq :failed (case-state i)))
    (signals case-peer-failure
      (case-handle r #x40 (encode-status-report (case-status-report +secure-channel-status-no-shared-trust-roots+))))
    (handler-case (case-handle r #x40 (encode-status-report (case-status-report 4)))
      (case-peer-failure (e)
        (is (= 4 (case-error-protocol-code e)))
        (is (= 4 (status-report-protocol-code (case-peer-failure-report e))))))
    ;; a success report when none is due
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (case-start i)
      (signals case-error (case-handle i #x40 (encode-status-report (case-status-report 0)))))
    ;; a malformed one
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (case-start i)
      (signals case-error (case-handle i #x40 (hex "00"))))
    ;; the status report the responder sends after a failure
    (is (equalp (hex "0100 00000000 0100")
                (encode-status-report (case-status-report +secure-channel-status-no-shared-trust-roots+))))))

(test case-state-machine-misuse
  (let* ((a (node-a)) (b (node-b))
         (i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
         (r (make-case-responder :fabric b :local-session-id 2)))
    (signals case-error (case-start r))
    (signals case-error (case-resumption-state i))
    (signals case-error (case-handle i #x31 (hex "15 18")))
    (is (eq :failed (case-state i)))
    (signals case-error (case-start i))
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1)))
      (case-start i)
      (signals case-error (case-start i))
      (signals case-error (case-handle i #x30 (hex "15 18")))
      (signals case-error (case-handle i #x99 (hex "15 18"))))
    (signals case-error (case-handle r #x32 (hex "15 18")))
    (let ((i (make-case-initiator :fabric a :peer-node-id (fabric-node-id b) :local-session-id 1))
          (r (make-case-responder :fabric b :local-session-id 2)))
      (run-case i r)
      (signals case-error (case-handle i #x31 (hex "15 18")))
      (signals case-error (case-handle r #x30 (hex "15 18")))
      (is (eq :failed (case-state i))))
    (signals case-error (case-handle r #x30 "not octets"))))

(test case-constructor-validation
  (let ((a (node-a)) (b (node-b)))
    (signals case-error (make-case-initiator :fabric nil :peer-node-id 1 :local-session-id 1))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 0 :local-session-id 1))
    (signals case-error (make-case-initiator :fabric a :peer-node-id #xFFFFFFFF00000001 :local-session-id 1))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 0))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 65536))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 1 :resumption 42))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 1
                                             :resumption (make-case-resumption :fabric b :peer-node-id 1)))
    (signals case-error (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 1
                                             :resumption (make-case-resumption :fabric a :peer-node-id 2)))
    (finishes (make-case-initiator :fabric a :peer-node-id 1 :local-session-id 1
                                   :resumption (make-case-resumption :fabric a :peer-node-id 1)))
    (signals case-error (make-case-responder :local-session-id 1))
    (signals case-error (make-case-responder :fabrics (list a 42) :local-session-id 1))
    (signals case-error (make-case-responder :fabric a :local-session-id 0))
    (signals case-error (make-case-responder :fabric a :local-session-id 1 :resumptions (list 42)))
    (finishes (make-case-responder :fabrics (list a b) :local-session-id 1))))
