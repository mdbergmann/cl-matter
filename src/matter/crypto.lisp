;;;; crypto.lisp -- the primitives of the Matter secure channel (Core
;;;; Specification section 3): SHA-256 with HMAC, HKDF and PBKDF2, random
;;;; octets, and AES-CCM as the message AEAD, with the nonce and the
;;;; secured-message layout of section 4.
;;;;
;;;; The block cipher and the SBCL-side digests come from Ironclad.  On
;;;; AmiLisp the digests are the runtime's own (EXT:SHA256 & co., C): a
;;;; pure-Lisp SHA-256 runs through bignums on its 32-bit words, which puts
;;;; a PASE key derivation of a few thousand PBKDF2 iterations out of reach.
;;;; Ironclad has no CCM mode, so AES-CCM (RFC 3610 / NIST SP 800-38C) is
;;;; built here from AES in ECB mode.

(in-package :cl-matter)

(define-condition crypto-error (error)
  ((message :initarg :message :reader crypto-error-message))
  (:report (lambda (c stream) (write-string (crypto-error-message c) stream))))

(define-condition aead-authentication-error (crypto-error) ()
  (:default-initargs :message "AES-CCM authentication failed: the message is not from the holder of the key, or was altered")
  (:documentation "The tag of a secured message did not verify."))

(defun %crypto-fail (format &rest args)
  (error 'crypto-error :message (apply #'format nil format args)))

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun %octets (sequence)
  "SEQUENCE of octets -> a fresh simple octet vector."
  (let ((out (make-array (length sequence) :element-type '(unsigned-byte 8))))
    (replace out sequence)
    out))

(defun %check-octet-vector (what x)
  (unless (and (vectorp x) (not (stringp x)))
    (%crypto-fail "~a must be an octet vector, got ~s" what x))
  (if (typep x 'octets) x (%octets x)))

;;; ------------------------------------------------------------------
;;; Digests

(defun sha256 (octets)
  "SHA-256 of OCTETS: a fresh 32-octet vector."
  (let ((octets (%check-octet-vector "sha256 input" octets)))
    #+amilisp (ext:sha256 octets)
    #-amilisp (ironclad:digest-sequence :sha256 octets)))

(defun hmac-sha256 (key data)
  "HMAC-SHA256 (RFC 2104) of DATA under KEY: 32 octets."
  (let ((key (%check-octet-vector "hmac key" key))
        (data (%check-octet-vector "hmac data" data)))
    #+amilisp (ext:hmac-sha256 key data)
    #-amilisp (let ((mac (ironclad:make-hmac key :sha256)))
                (ironclad:update-hmac mac data)
                (ironclad:hmac-digest mac))))

(defun pbkdf2-sha256 (password salt iterations length)
  "PBKDF2 with HMAC-SHA256 (RFC 8018): LENGTH octets of key material."
  (let ((password (%check-octet-vector "pbkdf2 password" password))
        (salt (%check-octet-vector "pbkdf2 salt" salt)))
    (unless (and (integerp iterations) (plusp iterations))
      (%crypto-fail "PBKDF2 iterations must be a positive integer, got ~s" iterations))
    (unless (and (integerp length) (plusp length))
      (%crypto-fail "PBKDF2 key length must be a positive integer, got ~s" length))
    #+amilisp (ext:pbkdf2-sha256 password salt iterations length)
    #-amilisp (ironclad:derive-key (ironclad:make-kdf :pbkdf2 :digest :sha256)
                                   password salt iterations length)))

(defun hkdf-sha256 (ikm salt info length)
  "HKDF with SHA-256 (RFC 5869): extract IKM under SALT (NIL or empty = a
zero key), then expand with INFO to LENGTH octets (at most 255 * 32)."
  (let* ((ikm (%check-octet-vector "hkdf input key material" ikm))
         (salt (if (and salt (plusp (length salt)))
                   (%check-octet-vector "hkdf salt" salt)
                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
         (info (if info (%check-octet-vector "hkdf info" info) (%octets #()))))
    (unless (and (integerp length) (< 0 length (1+ (* 255 32))))
      (%crypto-fail "HKDF output length must be 1..~d octets, got ~s" (* 255 32) length))
    (let ((prk (hmac-sha256 salt ikm))
          (out (make-array length :element-type '(unsigned-byte 8)))
          (previous (%octets #()))
          (block (make-array (+ 32 (length info) 1) :element-type '(unsigned-byte 8)))
          (filled 0))
      (loop :for counter :from 1
            :while (< filled length)
            :do (let ((n (length previous)))
                  (replace block previous)
                  (replace block info :start1 n)
                  (setf (aref block (+ n (length info))) counter)
                  (setf previous (hmac-sha256 prk (subseq block 0 (+ n (length info) 1))))
                  (replace out previous :start1 filled)
                  (incf filled 32)))
      out)))

(defun random-octets (n)
  "N octets from the implementation's cryptographic random source."
  (ironclad:random-data n))

;;; ------------------------------------------------------------------
;;; AES-CCM (RFC 3610, NIST SP 800-38C)
;;;
;;; Matter uses AES-CCM-128 with a 13-octet nonce (L = 2) and a 16-octet
;;; tag (the MIC); the general parameters stay available so the published
;;; vectors with other nonce and tag sizes check the construction.

(defconstant +aes-block+ 16)

(defun %aes-ecb (key)
  (unless (member (length key) '(16 24 32))
    (%crypto-fail "an AES key has 16, 24 or 32 octets, got ~d" (length key)))
  (ironclad:make-cipher :aes :key key :mode :ecb))

(defun %aes-block (cipher in out)
  "OUT <- E_key(IN), one block."
  (ironclad:encrypt cipher in out)
  out)

(defun %ccm-parameters (nonce tag-length length-of-data)
  "The L of the nonce and the flags octet of B0; checks the sizes."
  (let ((l (- 15 (length nonce))))
    (unless (<= 2 l 8)
      (%crypto-fail "a CCM nonce has 7..13 octets, got ~d" (length nonce)))
    (unless (and (integerp tag-length) (evenp tag-length) (<= 4 tag-length 16))
      (%crypto-fail "a CCM tag has an even length from 4 to 16 octets, got ~s" tag-length))
    (when (>= length-of-data (ash 1 (* 8 l)))
      (%crypto-fail "~d octets of data do not fit the ~d-octet length field a ~d-octet nonce leaves"
                    length-of-data l (length nonce)))
    l))

(defun %ccm-mac (cipher nonce l tag-length aad data)
  "CBC-MAC over B0, the length-prefixed AAD and DATA, each zero-padded to
blocks: the first TAG-LENGTH octets of the last cipher block."
  (let ((x (make-array +aes-block+ :element-type '(unsigned-byte 8) :initial-element 0))
        (b (make-array +aes-block+ :element-type '(unsigned-byte 8) :initial-element 0)))
    (labels ((absorb ()
               (dotimes (i +aes-block+) (setf (aref b i) (logxor (aref b i) (aref x i))))
               (%aes-block cipher b x)
               (fill b 0))
             (absorb-octets (octets start)
               ;; feed OCTETS into B from START, absorbing full blocks
               (let ((pos start))
                 (loop :for octet :across octets
                       :do (setf (aref b pos) octet)
                           (incf pos)
                           (when (= pos +aes-block+) (absorb) (setf pos 0)))
                 (unless (zerop pos) (absorb)))))
      ;; B0 = flags || nonce || l(m)
      (setf (aref b 0) (logior (if (plusp (length aad)) #x40 0)
                               (ash (floor (- tag-length 2) 2) 3)
                               (1- l)))
      (replace b nonce :start1 1)
      (let ((len (length data)))
        (dotimes (i l)
          (setf (aref b (- 15 i)) (ldb (byte 8 (* 8 i)) len))))
      (absorb)
      ;; the AAD, prefixed by its length
      (when (plusp (length aad))
        (let ((la (length aad)))
          (cond ((< la (- (ash 1 16) (ash 1 8)))
                 (setf (aref b 0) (ldb (byte 8 8) la)
                       (aref b 1) (ldb (byte 8 0) la))
                 (absorb-octets aad 2))
                ((< la (ash 1 32))
                 (setf (aref b 0) #xff (aref b 1) #xfe)
                 (dotimes (i 4) (setf (aref b (+ 2 i)) (ldb (byte 8 (* 8 (- 3 i))) la)))
                 (absorb-octets aad 6))
                (t (%crypto-fail "~d octets of additional data exceed what CCM encodes here" la)))))
      ;; the data
      (when (plusp (length data))
        (absorb-octets data 0))
      (subseq x 0 tag-length))))

(defun %ccm-counter-xor (cipher nonce l data out tag tag-length)
  "CTR mode: OUT <- DATA xor S_1..; TAG <- TAG xor S_0 (the first TAG-LENGTH
octets).  OUT and TAG may be the same objects as the inputs."
  (let ((a (make-array +aes-block+ :element-type '(unsigned-byte 8) :initial-element 0))
        (s (make-array +aes-block+ :element-type '(unsigned-byte 8))))
    (setf (aref a 0) (1- l))
    (replace a nonce :start1 1)
    (flet ((keystream (counter)
             (dotimes (i l)
               (setf (aref a (- 15 i)) (ldb (byte 8 (* 8 i)) counter)))
             (%aes-block cipher a s)))
      (keystream 0)
      (dotimes (i tag-length)
        (setf (aref tag i) (logxor (aref tag i) (aref s i))))
      (let ((len (length data)))
        (loop :for start :from 0 :below len :by +aes-block+
              :for counter :from 1
              :do (keystream counter)
                  (loop :for i :from start :below (min len (+ start +aes-block+))
                        :do (setf (aref out i) (logxor (aref data i) (aref s (- i start))))))))
    (values out tag)))

(defun aes-ccm-encrypt (key nonce plaintext aad &key (tag-length +mic-length+))
  "AES-CCM: CIPHERTEXT || TAG for PLAINTEXT under KEY and NONCE, authenticating
AAD as well.  Matter: a 16-octet key, a 13-octet nonce (MESSAGE-NONCE), a
16-octet tag."
  (let* ((key (%check-octet-vector "AES key" key))
         (nonce (%check-octet-vector "CCM nonce" nonce))
         (plaintext (%check-octet-vector "plaintext" plaintext))
         (aad (if aad (%check-octet-vector "additional data" aad) (%octets #())))
         (l (%ccm-parameters nonce tag-length (length plaintext)))
         (cipher (%aes-ecb key))
         (tag (%ccm-mac cipher nonce l tag-length aad plaintext))
         (out (make-array (+ (length plaintext) tag-length) :element-type '(unsigned-byte 8))))
    (%ccm-counter-xor cipher nonce l plaintext out tag tag-length)
    (replace out tag :start1 (length plaintext))
    out))

(defun aes-ccm-decrypt (key nonce ciphertext aad &key (tag-length +mic-length+))
  "The inverse of AES-CCM-ENCRYPT: the plaintext of CIPHERTEXT || TAG, or
AEAD-AUTHENTICATION-ERROR when the tag does not verify (nothing of a
rejected message is returned)."
  (let* ((key (%check-octet-vector "AES key" key))
         (nonce (%check-octet-vector "CCM nonce" nonce))
         (ciphertext (%check-octet-vector "ciphertext" ciphertext))
         (aad (if aad (%check-octet-vector "additional data" aad) (%octets #()))))
    (unless (and (integerp tag-length) (<= tag-length (length ciphertext)))
      (%crypto-fail "a secured payload carries at least its ~d-octet tag, got ~d octets"
                    tag-length (length ciphertext)))
    (let* ((len (- (length ciphertext) tag-length))
           (l (%ccm-parameters nonce tag-length len))
           (cipher (%aes-ecb key))
           (plaintext (make-array len :element-type '(unsigned-byte 8)))
           (tag (subseq ciphertext len)))
      (%ccm-counter-xor cipher nonce l (subseq ciphertext 0 len) plaintext tag tag-length)
      (let ((expected (%ccm-mac cipher nonce l tag-length aad plaintext))
            (diff 0))
        ;; compare every octet whatever the outcome
        (dotimes (i tag-length)
          (setf diff (logior diff (logxor (aref tag i) (aref expected i)))))
        (unless (zerop diff)
          (fill plaintext 0)
          (error 'aead-authentication-error))
        plaintext))))

;;; ------------------------------------------------------------------
;;; Secured messages (section 4.7): nonce, AAD, layout

(defun message-nonce (security-flags message-counter source-node-id)
  "The 13-octet AES-CCM nonce of a message: the security flags octet, the
32-bit message counter and the 64-bit node id of the sender, little
endian.  The sender is the session's peer when decrypting; a PASE session
has no node ids and uses 0."
  (%check-range "security flags" security-flags 8)
  (%check-range "message counter" message-counter 32)
  (%check-range "nonce source node id" source-node-id 64)
  (let ((out (%new-buffer 13)))
    (vector-push-extend security-flags out)
    (%put-le out message-counter 4)
    (%put-le out source-node-id 8)
    (%finish-buffer out)))

(defun message-header-nonce (header &optional nonce-source-node-id)
  "The nonce of a message with HEADER.  NONCE-SOURCE-NODE-ID is the sender's
node id when the header does not carry it (a CASE unicast); it defaults to
the header's source node id, else 0 (PASE)."
  (message-nonce (message-header-security-flags header)
                 (message-header-message-counter header)
                 (or nonce-source-node-id (message-header-source-node-id header) 0)))

(defun encode-secured-message (header protocol-header key &key nonce-source-node-id)
  "A complete secured message: the plaintext header, then PROTOCOL-HEADER
(with its payload) encrypted under KEY with the header octets as additional
data, then the 16-octet MIC.  The session id must not be 0."
  (when (= +unsecured-session-id+ (message-header-session-id header))
    (error 'message-encode-error
           :message "session 0 is the unsecured session; use ENCODE-UNSECURED-MESSAGE"))
  (let* ((aad (encode-message-header header))
         (nonce (message-header-nonce header nonce-source-node-id))
         (sealed (aes-ccm-encrypt key nonce (encode-protocol-header protocol-header) aad))
         (out (make-array (+ (length aad) (length sealed)) :element-type '(unsigned-byte 8))))
    (replace out aad)
    (replace out sealed :start1 (length aad))
    out))

(defun decode-secured-message (octets key &key nonce-source-node-id (start 0) end)
  "OCTETS[START,END) -> MESSAGE-HEADER and PROTOCOL-HEADER of a secured
message, decrypted and verified under KEY.  NONCE-SOURCE-NODE-ID is the
sender's node id when the header omits it.  Signals MESSAGE-DECODE-ERROR
for a malformed header, a session id of 0 or a payload shorter than the
MIC, and AEAD-AUTHENTICATION-ERROR when the MIC does not verify."
  (let ((end (or end (length octets))))
    (multiple-value-bind (header payload-start) (decode-message-header octets :start start :end end)
      (when (= +unsecured-session-id+ (message-header-session-id header))
        (error 'message-decode-error :offset (+ 1 start)
                                     :message "session 0 is unsecured; use DECODE-UNSECURED-MESSAGE"))
      (when (< (- end payload-start) +mic-length+)
        (error 'message-decode-error :offset payload-start
                                     :message (format nil "a secured payload carries at least the ~d-octet MIC, ~d octet~:p left"
                                                      +mic-length+ (- end payload-start))))
      (let* ((aad (subseq octets start payload-start))
             (nonce (message-header-nonce header nonce-source-node-id))
             (plaintext (aes-ccm-decrypt key nonce (subseq octets payload-start end) aad)))
        (values header (decode-protocol-header plaintext))))))
