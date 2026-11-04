(defpackage :cl-matter.pase.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.pase.tests)

(def-suite pase-tests :description "PASE: messages and the handshake" :in cl-matter.tests:test-suite)
(in-suite pase-tests)

(defun hex (string)
  (let* ((digits (remove #\Space string))
         (out (make-array (floor (length digits) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer digits :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun unhex (octets)
  (format nil "~(~{~2,'0x~}~)" (coerce octets 'list)))

(defun ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun octets-from (a b)
  (coerce (loop :for i :from a :below b :collect i) '(vector (unsigned-byte 8))))

(defparameter *salt* (ascii "SPAKE2P Key Salt"))
(defparameter *passcode* 20202021)
(defparameter *verifier* (spake2p-verifier *passcode* *salt* 1000))

;;; ------------------------------------------------------------------
;;; Message codecs

(test pbkdf-param-request-wire-format
  (let* ((random (octets-from 0 32))
         (request (make-pbkdf-param-request :initiator-random random :initiator-session-id #x1234
                                            :has-pbkdf-parameters-p nil))
         (octets (encode-pbkdf-param-request request)))
    ;; structure { 1: octets[32], 2: u16, 3: u8 0, 4: false }
    (is (string= (concatenate 'string "15" "3001" "20" (unhex random) "25023412" "240300" "2804" "18")
                 (unhex octets)))
    (is (equalp request (decode-pbkdf-param-request octets))))
  ;; with the parameters known and session parameters
  (let* ((request (make-pbkdf-param-request
                   :initiator-random (octets-from 0 32) :initiator-session-id 1
                   :has-pbkdf-parameters-p t
                   :session-parameters (make-session-parameters :idle-interval 500 :active-interval 300
                                                                :active-threshold 4000
                                                                :data-model-revision 18
                                                                :interaction-model-revision 12
                                                                :specification-version #x01040000
                                                                :max-paths-per-invoke 1)))
         (octets (encode-pbkdf-param-request request))
         (back (decode-pbkdf-param-request octets)))
    (is (equalp request back))
    (is (pbkdf-param-request-has-pbkdf-parameters-p back))
    (is (= 500 (session-parameters-idle-interval (pbkdf-param-request-session-parameters back))))
    (is (= #x01040000 (session-parameters-specification-version (pbkdf-param-request-session-parameters back))))
    ;; the session parameters are structure 5 with context tags 1..7
    (is (search (hex "35 05 2501f401 25022c01 2503a00f 240412 24050c 260600000401 240701 18") octets
                :test #'equalp))))

(test pbkdf-param-response-wire-format
  (let* ((response (make-pbkdf-param-response :initiator-random (octets-from 0 32)
                                              :responder-random (octets-from 32 64)
                                              :responder-session-id 7
                                              :iterations 1000 :salt *salt*))
         (octets (encode-pbkdf-param-response response)))
    (is (string= (concatenate 'string "15" "3001" "20" (unhex (octets-from 0 32))
                              "3002" "20" (unhex (octets-from 32 64))
                              "240307"
                              "3504" "2501e803" "3002" "10" (unhex *salt*) "18"
                              "18")
                 (unhex octets)))
    (is (equalp response (decode-pbkdf-param-response octets))))
  ;; parameters omitted, session parameters present
  (let* ((response (make-pbkdf-param-response :initiator-random (octets-from 0 32)
                                              :responder-random (octets-from 32 64)
                                              :responder-session-id #xFFFF
                                              :session-parameters (make-session-parameters :idle-interval 5000)))
         (back (decode-pbkdf-param-response (encode-pbkdf-param-response response))))
    (is (equalp response back))
    (is (null (pbkdf-param-response-iterations back)))
    (is (null (pbkdf-param-response-salt back)))
    (is (= 5000 (session-parameters-idle-interval (pbkdf-param-response-session-parameters back))))))

(test pake-messages-wire-format
  (let ((point (octets-from 0 65))
        (mac (octets-from 100 132)))
    (is (string= (concatenate 'string "15" "3001" "41" (unhex point) "18")
                 (unhex (encode-pake1 (make-pake1 :pa point)))))
    (is (equalp (make-pake1 :pa point) (decode-pake1 (encode-pake1 (make-pake1 :pa point)))))
    (is (string= (concatenate 'string "15" "3001" "41" (unhex point) "3002" "20" (unhex mac) "18")
                 (unhex (encode-pake2 (make-pake2 :pb point :cb mac)))))
    (is (equalp (make-pake2 :pb point :cb mac) (decode-pake2 (encode-pake2 (make-pake2 :pb point :cb mac)))))
    (is (string= (concatenate 'string "15" "3001" "20" (unhex mac) "18")
                 (unhex (encode-pake3 (make-pake3 :ca mac)))))
    (is (equalp (make-pake3 :ca mac) (decode-pake3 (encode-pake3 (make-pake3 :ca mac)))))))

(defmacro rejects (form)
  `(signals pase-error ,form))

(test message-decoders-reject-malformed
  (let ((good (encode-pbkdf-param-request
               (make-pbkdf-param-request :initiator-random (octets-from 0 32) :initiator-session-id 1))))
    (rejects (decode-pbkdf-param-request (subseq good 0 10)))                 ; truncated TLV
    (rejects (decode-pbkdf-param-request (concatenate 'vector good #(0))))   ; trailing octet
    (rejects (decode-pbkdf-param-request (tlv-encode (tlv nil :unsigned 1)))) ; not a structure
    (rejects (decode-pbkdf-param-request (tlv-encode (tlv-structure 1))))     ; tagged structure
    ;; a field missing, of the wrong type, of the wrong length
    (rejects (decode-pbkdf-param-request
              (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :unsigned 1) (tlv 3 :unsigned 0)))))
    (rejects (decode-pbkdf-param-request
              (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 31)) (tlv 2 :unsigned 1)
                                         (tlv 3 :unsigned 0) (tlv 4 :boolean nil)))))
    (rejects (decode-pbkdf-param-request
              (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :string "1")
                                         (tlv 3 :unsigned 0) (tlv 4 :boolean nil)))))
    (rejects (decode-pbkdf-param-request
              (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :unsigned 1)
                                         (tlv 3 :unsigned 0) (tlv 4 :boolean nil)
                                         (tlv 5 :unsigned 9)))))                ; session params not a structure
    ;; an unknown session parameter tag is skipped
    (let ((back (decode-pbkdf-param-request
                 (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :unsigned 1)
                                            (tlv 3 :unsigned 0) (tlv 4 :boolean t)
                                            (tlv-structure 5 (tlv 1 :unsigned 300) (tlv 42 :string "future")))))))
      (is (= 300 (session-parameters-idle-interval (pbkdf-param-request-session-parameters back))))
      (is (null (session-parameters-active-interval (pbkdf-param-request-session-parameters back)))))
    ;; a session parameter beyond its width
    (rejects (decode-pbkdf-param-request
              (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :unsigned 1)
                                         (tlv 3 :unsigned 0) (tlv 4 :boolean t)
                                         (tlv-structure 5 (tlv 3 :unsigned 65536))))))
    (rejects (encode-pbkdf-param-request
              (make-pbkdf-param-request :initiator-random (octets-from 0 32) :initiator-session-id 1
                                        :session-parameters (make-session-parameters :active-threshold 65536)))))
  (rejects (decode-pbkdf-param-response
            (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :octets (octets-from 0 32))
                                       (tlv 3 :unsigned 1) (tlv 4 :unsigned 1000)))))  ; pbkdf params not a structure
  (rejects (decode-pbkdf-param-response
            (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 32)) (tlv 2 :octets (octets-from 0 32))
                                       (tlv 3 :unsigned 1) (tlv-structure 4 (tlv 1 :unsigned 1000))))))  ; no salt
  (rejects (decode-pake1 (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 64))))))
  (rejects (decode-pake2 (tlv-encode (tlv-structure nil (tlv 1 :octets (octets-from 0 65)) (tlv 2 :octets (octets-from 0 31))))))
  (rejects (decode-pake3 (tlv-encode (tlv-structure nil (tlv 2 :octets (octets-from 0 32))))))
  (rejects (decode-pake3 (hex "15 30 01"))))

(test session-parameters-tlv-round-trip
  (let ((all (make-session-parameters :idle-interval 1 :active-interval 2 :active-threshold 3
                                      :data-model-revision 4 :interaction-model-revision 5
                                      :specification-version 6 :max-paths-per-invoke 7
                                      :supported-transports 8 :max-tcp-payload-size 9)))
    (is (equalp all (tlv-session-parameters (tlv-decode (tlv-encode (session-parameters-tlv 5 all))))))
    (is (= 9 (length (tlv-element-value (session-parameters-tlv 5 all)))))
    (is (= 0 (length (tlv-element-value (session-parameters-tlv 5 (make-session-parameters))))))
    (rejects (tlv-session-parameters (tlv nil :unsigned 1))))
  (let ((defaults (default-session-parameters)))
    (is (= 500 (session-parameters-idle-interval defaults)))
    (is (= 300 (session-parameters-active-interval defaults)))
    (is (= 4000 (session-parameters-active-threshold defaults)))))

;;; ------------------------------------------------------------------
;;; Session keys: an independent HKDF computation (python hmac/hashlib)

(test derive-session-keys-vector
  (let ((keys (derive-session-keys (octets-from 0 16))))
    (is (string= "8ea18f4b847bf7722c31a375361a44af" (unhex (session-keys-i2r keys))))
    (is (string= "546453a4a111ef24b6b1b87024930a2c" (unhex (session-keys-r2i keys))))
    (is (string= "84462414c1df6aab64cca76dac13b8d0" (unhex (session-keys-attestation-challenge keys))))))

;;; ------------------------------------------------------------------
;;; The handshake, both machines driven in one loop

(defun run-handshake (initiator responder &key (max-steps 10))
  "Carry messages between INITIATOR and RESPONDER until both are complete.
Returns the list of (sender opcode payload) exchanged."
  (let ((log '()))
    (multiple-value-bind (opcode payload) (pase-start initiator)
      (loop :repeat max-steps
            :while opcode
            :do (push (list :initiator opcode payload) log)
                (multiple-value-setq (opcode payload) (pase-handle responder opcode payload))
                (when opcode
                  (push (list :responder opcode payload) log)
                  (multiple-value-setq (opcode payload) (pase-handle initiator opcode payload)))))
    (nreverse log)))

(test handshake-with-verifier
  (let* ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 100))
         (responder (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000
                                         :local-session-id 200))
         (log (run-handshake initiator responder)))
    (is (equal '(:initiator #x20 :responder #x21 :initiator #x22 :responder #x23 :initiator #x24 :responder #x40)
               (loop :for (who opcode) :in log :collect who :collect opcode)))
    (is (pase-complete-p initiator))
    (is (pase-complete-p responder))
    (is (eq :complete (pase-state initiator)))
    ;; session ids crossed over
    (is (= 100 (pase-local-session-id initiator)))
    (is (= 200 (pase-peer-session-id initiator)))
    (is (= 200 (pase-local-session-id responder)))
    (is (= 100 (pase-peer-session-id responder)))
    ;; the same keys on both sides, three distinct ones
    (let ((a (pase-session-keys initiator)) (b (pase-session-keys responder)))
      (is (equalp a b))
      (is (= 16 (length (session-keys-i2r a))))
      (is (= 16 (length (session-keys-r2i a))))
      (is (= 16 (length (session-keys-attestation-challenge a))))
      (is (not (equalp (session-keys-i2r a) (session-keys-r2i a))))
      (is (not (equalp (session-keys-i2r a) (session-keys-attestation-challenge a))))
      (is (equalp a (derive-session-keys (spake2p-shared-key (pase-spake2p initiator))))))
    ;; the responder sent its PBKDF parameters, the initiator took them
    (is (= 1000 (pase-iterations initiator)))
    (is (equalp *salt* (pase-salt initiator)))
    (let ((response (decode-pbkdf-param-response (third (second log)))))
      (is (= 1000 (pbkdf-param-response-iterations response)))
      (is (equalp *salt* (pbkdf-param-response-salt response))))
    ;; the default session parameters went both ways
    (is (= 500 (session-parameters-idle-interval (pase-peer-session-parameters responder))))
    (is (= 500 (session-parameters-idle-interval (pase-peer-session-parameters initiator))))
    ;; randoms are what the messages carried
    (is (equalp (pase-initiator-random initiator) (pase-initiator-random responder)))
    (is (equalp (pase-responder-random initiator) (pase-responder-random responder)))
    (is (= 32 (length (pase-initiator-random initiator))))
    ;; the final status report is success / secure channel / 0
    (let ((report (decode-status-report (third (sixth log)))))
      (is (= +status-success+ (status-report-general-code report)))
      (is (= +protocol-secure-channel+ (status-report-protocol-id report)))
      (is (= +secure-channel-status-session-establishment-success+ (status-report-protocol-code report))))
    ;; the passcode is not kept once w0/w1 are derived
    (is (null (cl-matter::pase-passcode initiator)))
    ;; nothing more is accepted
    (rejects (pase-handle initiator #x23 (third (fourth log))))
    (rejects (pase-handle responder #x22 (third (third log))))))

(test handshake-with-known-pbkdf-parameters
  (let* ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1
                                         :salt *salt* :iterations 1000
                                         :session-parameters (make-session-parameters :idle-interval 777)))
         (responder (make-pase-responder :passcode *passcode* :salt *salt* :iterations 1000
                                         :local-session-id 2
                                         :session-parameters nil))
         (log (run-handshake initiator responder)))
    (is (pase-complete-p initiator))
    (is (pase-complete-p responder))
    (is (equalp (pase-session-keys initiator) (pase-session-keys responder)))
    ;; the request said so, and the response left the parameters out
    (is (pbkdf-param-request-has-pbkdf-parameters-p (decode-pbkdf-param-request (third (first log)))))
    (let ((response (decode-pbkdf-param-response (third (second log)))))
      (is (null (pbkdf-param-response-iterations response)))
      (is (null (pbkdf-param-response-session-parameters response))))
    (is (= 777 (session-parameters-idle-interval (pase-peer-session-parameters responder))))
    (is (null (pase-peer-session-parameters initiator)))))

(test handshakes-differ-per-run
  (let ((keys '()))
    (dotimes (i 2)
      (let ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1))
            (responder (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2)))
        (run-handshake initiator responder)
        (push (pase-session-keys initiator) keys)))
    (is (not (equalp (first keys) (second keys))))))

(test wrong-passcode-fails-at-pake2
  (let* ((initiator (make-pase-initiator :passcode 20202020 :local-session-id 1))
         (responder (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2)))
    (multiple-value-bind (op1 m1) (pase-start initiator)
      (multiple-value-bind (op2 m2) (pase-handle responder op1 m1)
        (multiple-value-bind (op3 m3) (pase-handle initiator op2 m2)
          (multiple-value-bind (op4 m4) (pase-handle responder op3 m3)
            (is (= #x23 op4))
            ;; the initiator sees cB first
            (handler-case (progn (pase-handle initiator op4 m4) (fail "a wrong passcode was accepted"))
              (pase-error (e)
                (is (= +secure-channel-status-invalid-parameter+ (pase-error-protocol-code e)))
                (is (search "passcode" (princ-to-string e)))))
            (is (eq :failed (pase-state initiator)))
            (is (null (pase-session-keys initiator)))
            ;; and the responder would see a wrong cA
            (let* ((bad-ca (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
              (handler-case (progn (pase-handle responder #x24 (encode-pake3 (make-pake3 :ca bad-ca)))
                                   (fail "a wrong cA was accepted"))
                (pase-error (e)
                  (is (= +secure-channel-status-invalid-parameter+ (pase-error-protocol-code e)))
                  ;; what the responder sends back
                  (is (equalp (hex "0100 00000000 0200")
                              (encode-status-report (pase-status-report (pase-error-protocol-code e)))))))
              (is (eq :failed (pase-state responder)))
              (is (null (pase-session-keys responder))))))))))

(test initiator-rejects-bad-responses
  (flet ((started ()
           (let ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1)))
             (multiple-value-bind (op m) (pase-start initiator)
               (values initiator op m))))
         (response (initiator &rest overrides)
           ;; the overrides first: the leftmost keyword wins
           (apply #'make-pbkdf-param-response
                  (append overrides
                          (list :initiator-random (pase-initiator-random initiator)
                                :responder-random (octets-from 32 64)
                                :responder-session-id 2 :iterations 1000 :salt *salt*)))))
    ;; another initiatorRandom
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :initiator-random (octets-from 64 96)))))
      (is (eq :failed (pase-state i))))
    ;; responder session id 0
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :responder-session-id 0)))))
    ;; parameters omitted though none were known
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :iterations nil :salt nil)))))
    ;; iterations and salt outside the limits
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :iterations 999)))))
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :iterations 100001)))))
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :salt (octets-from 0 15))))))
    (let ((i (started)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i :salt (octets-from 0 33))))))
    ;; the wrong message for the state, and garbage
    (let ((i (started)))
      (rejects (pase-handle i #x23 (encode-pake2 (make-pake2 :pb (octets-from 0 65) :cb (octets-from 0 32)))))
      (is (eq :failed (pase-state i)))
      (rejects (pase-handle i #x21 (encode-pbkdf-param-response (response i)))))
    (let ((i (started)))
      (rejects (pase-handle i #x21 (hex "15 18"))))
    (let ((i (started)))
      (rejects (pase-handle i #x21 "not octets")))
    ;; a Pake2 with a point off the curve
    (let ((i (started)))
      (pase-handle i #x21 (encode-pbkdf-param-response (response i)))
      (is (eq :pake2 (pase-state i)))
      (handler-case (progn (pase-handle i #x23 (encode-pake2 (make-pake2 :pb (octets-from 0 65) :cb (octets-from 0 32))))
                           (fail "an off-curve pB was accepted"))
        (pase-error (e) (is (search "pB" (pase-error-message e)))))
      (is (eq :failed (pase-state i))))
    ;; not started: nothing is expected yet
    (let ((i (make-pase-initiator :passcode *passcode* :local-session-id 1)))
      (rejects (pase-handle i #x21 (hex "15 18")))
      (rejects (pase-start (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2))))))

(test responder-rejects-bad-requests
  (flet ((responder ()
           (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2))
         (request (&rest overrides)
           (encode-pbkdf-param-request
            (apply #'make-pbkdf-param-request
                   (append overrides (list :initiator-random (octets-from 0 32) :initiator-session-id 1))))))
    (let ((r (responder)))
      (rejects (pase-handle r #x20 (request :passcode-id 1)))
      (is (eq :failed (pase-state r))))
    (let ((r (responder)))
      (rejects (pase-handle r #x20 (request :initiator-session-id 0))))
    (let ((r (responder)))
      (rejects (pase-handle r #x22 (encode-pake1 (make-pake1 :pa (octets-from 0 65))))))
    (let ((r (responder)))
      (pase-handle r #x20 (request))
      (is (eq :pake1 (pase-state r)))
      (handler-case (progn (pase-handle r #x22 (encode-pake1 (make-pake1 :pa (octets-from 0 65))))
                           (fail "an off-curve pA was accepted"))
        (pase-error (e) (is (search "pA" (pase-error-message e)))))
      (is (eq :failed (pase-state r))))))

(test status-reports-in-the-handshake
  (let* ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1))
         (responder (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2)))
    ;; a failure from the peer at any time
    (multiple-value-bind (op m) (pase-start initiator)
      (declare (ignore op m))
      (handler-case (progn (pase-handle initiator #x40 (encode-status-report
                                                        (pase-status-report +secure-channel-status-busy+)))
                           (fail "a failure report was ignored"))
        (pase-peer-failure (e)
          (is (= +secure-channel-status-busy+ (pase-error-protocol-code e)))
          (is (= +status-failure+ (status-report-general-code (pase-peer-failure-report e))))
          (is (search "protocol code 4" (princ-to-string e)))))
      (is (eq :failed (pase-state initiator))))
    ;; a success report at the wrong time
    (let ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1)))
      (pase-start initiator)
      (rejects (pase-handle initiator #x40 (encode-status-report
                                            (pase-status-report +secure-channel-status-session-establishment-success+))))
      (is (eq :failed (pase-state initiator))))
    ;; a malformed one
    (let ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1)))
      (pase-start initiator)
      (rejects (pase-handle initiator #x40 (hex "01"))))
    ;; the responder takes a close-session report too
    (signals pase-peer-failure
      (pase-handle responder #x40 (encode-status-report (pase-status-report +secure-channel-status-close-session+))))
    ;; the success report must be for the secure channel protocol
    (let ((initiator (make-pase-initiator :passcode *passcode* :local-session-id 1))
          (responder (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2)))
      (multiple-value-bind (op m) (pase-start initiator)
        (multiple-value-bind (op m) (pase-handle responder op m)
          (multiple-value-bind (op m) (pase-handle initiator op m)
            (multiple-value-bind (op m) (pase-handle responder op m)
              (pase-handle initiator op m)
              (is (eq :status-report (pase-state initiator)))
              (is (not (pase-complete-p initiator)))
              (is (session-keys-p (pase-session-keys initiator)))
              (rejects (pase-handle initiator #x40 (encode-status-report
                                                    (make-status-report :general-code 0 :protocol-id 1 :protocol-code 0)))))))))))

(test pase-status-report-codes
  (let ((ok (pase-status-report +secure-channel-status-session-establishment-success+))
        (bad (pase-status-report +secure-channel-status-invalid-parameter+)))
    (is (= +status-success+ (status-report-general-code ok)))
    (is (= +status-failure+ (status-report-general-code bad)))
    (is (= 2 (status-report-protocol-code bad)))
    (is (equalp (hex "0000 00000000 0000") (encode-status-report ok)))))

(test constructor-validation
  (dolist (bad '(0 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 12345678 87654321
                 99999999 -1 100000000 "20202021" nil 1.5))
    (is (not (valid-passcode-p bad)))
    (rejects (make-pase-initiator :passcode bad :local-session-id 1)))
  (is (valid-passcode-p 1))
  (is (valid-passcode-p 99999998))
  (is (valid-passcode-p 20202021))
  (rejects (make-pase-initiator :passcode 20202021 :local-session-id 0))
  (rejects (make-pase-initiator :passcode 20202021 :local-session-id 65536))
  (rejects (make-pase-initiator :passcode 20202021 :local-session-id 1 :salt *salt*))          ; iterations missing
  (rejects (make-pase-initiator :passcode 20202021 :local-session-id 1 :salt *salt* :iterations 10))
  (rejects (make-pase-initiator :passcode 20202021 :local-session-id 1 :salt (octets-from 0 8) :iterations 1000))
  (rejects (make-pase-responder :salt *salt* :iterations 1000 :local-session-id 2))            ; neither
  (rejects (make-pase-responder :passcode 11111111 :salt *salt* :iterations 1000 :local-session-id 2))
  (rejects (make-pase-responder :verifier (subseq *verifier* 1) :salt *salt* :iterations 1000 :local-session-id 2))
  (rejects (make-pase-responder :verifier *verifier* :salt *salt* :iterations 999 :local-session-id 2))
  (rejects (make-pase-responder :verifier *verifier* :salt "SPAKE2P Key Salt" :iterations 1000 :local-session-id 2))
  (rejects (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 0))
  (let ((r (make-pase-responder :verifier *verifier* :salt *salt* :iterations 1000 :local-session-id 2)))
    (is (eq :responder (pase-role r)))
    (is (eq :pbkdf-param-request (pase-state r)))
    (is (search "RESPONDER PBKDF-PARAM-REQUEST" (princ-to-string r)))))
