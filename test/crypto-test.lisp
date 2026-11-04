(defpackage :cl-matter.crypto.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.crypto.tests)

(def-suite crypto-tests :description "Matter crypto primitives and secured messages"
  :in cl-matter.tests:test-suite)
(in-suite crypto-tests)

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

;;; ------------------------------------------------------------------
;;; Digests (FIPS 180-4, RFC 4231, RFC 5869, RFC 7914)

(test sha256-vectors
  (is (string= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
               (unhex (sha256 (ascii "abc")))))
  (is (string= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
               (unhex (sha256 (ascii "")))))
  (is (string= "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
               (unhex (sha256 (ascii "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))))
  ;; a general vector is accepted too
  (is (string= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
               (unhex (sha256 #(97 98 99)))))
  (signals crypto-error (sha256 "abc")))

(test hmac-sha256-vectors
  (is (string= "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
               (unhex (hmac-sha256 (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
                                   (ascii "Hi There")))))
  (is (string= "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
               (unhex (hmac-sha256 (ascii "Jefe") (ascii "what do ya want for nothing?")))))
  (is (string= "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
               (unhex (hmac-sha256 (make-array 131 :element-type '(unsigned-byte 8) :initial-element #xaa)
                                   (ascii "Test Using Larger Than Block-Size Key - Hash Key First")))))
  (signals crypto-error (hmac-sha256 "key" (ascii "x"))))

(test hkdf-sha256-rfc5869
  ;; test case 1
  (is (string= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
               (unhex (hkdf-sha256 (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x0b)
                                   (hex "000102030405060708090a0b0c")
                                   (hex "f0f1f2f3f4f5f6f7f8f9")
                                   42))))
  ;; test case 2: 80-octet inputs, 82 octets out (three HMAC blocks)
  (is (string= (concatenate 'string
                            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                            "cc30c58179ec3e87c14c01d5c1f3434f1d87")
               (unhex (hkdf-sha256 (octets-from #x00 #x50) (octets-from #x60 #xb0) (octets-from #xb0 #x100) 82))))
  ;; test case 3: no salt, no info
  (is (string= "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
               (unhex (hkdf-sha256 (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x0b)
                                   nil nil 42))))
  (is (equalp (hkdf-sha256 (ascii "k") nil nil 16) (hkdf-sha256 (ascii "k") (hex "") (hex "") 16)))
  (signals crypto-error (hkdf-sha256 (ascii "k") nil nil 0))
  (signals crypto-error (hkdf-sha256 (ascii "k") nil nil (1+ (* 255 32)))))

(test pbkdf2-sha256-rfc7914
  (is (string= (concatenate 'string
                            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
               (unhex (pbkdf2-sha256 (ascii "passwd") (ascii "salt") 1 64))))
  (is (string= "fa9c158e678bfe94189b0b1a707a0921672fdc9f"
               (unhex (pbkdf2-sha256 (ascii "passwd") (ascii "salt") 1000 20))))
  (signals crypto-error (pbkdf2-sha256 (ascii "p") (ascii "s") 0 32))
  (signals crypto-error (pbkdf2-sha256 (ascii "p") (ascii "s") 1 0))
  (signals crypto-error (pbkdf2-sha256 "p" (ascii "s") 1 32)))

(test random-octets-fresh
  (let ((a (random-octets 32)) (b (random-octets 32)))
    (is (= 32 (length a)))
    (is (typep a '(vector (unsigned-byte 8))))
    (is (not (equalp a b)))
    (is (= 0 (length (random-octets 0))))))

;;; ------------------------------------------------------------------
;;; AES-CCM: published vectors

(defparameter *rfc3610-key* (hex "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"))

(test aes-ccm-rfc3610-packet-vectors
  ;; packet vector #1: 13-octet nonce, 8-octet aad, 23-octet payload, M = 8
  (is (string= "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384 17e8d12cfdf926e0"
               (let ((out (aes-ccm-encrypt *rfc3610-key* (hex "00000003020100a0a1a2a3a4a5")
                                           (octets-from 8 31) (octets-from 0 8) :tag-length 8)))
                 (format nil "~a ~a" (unhex (subseq out 0 23)) (unhex (subseq out 23))))))
  ;; #2: 24-octet payload, a whole number of blocks
  (is (string= "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916"
               (unhex (aes-ccm-encrypt *rfc3610-key* (hex "00000004030201a0a1a2a3a4a5")
                                       (octets-from 8 32) (octets-from 0 8) :tag-length 8))))
  ;; #9: M = 10
  (is (string= "82531a60cc24945a4b8279181ab5c84df21ce7f9b73f426ea8d1f66c24e99259f1"
               (unhex (aes-ccm-encrypt *rfc3610-key* (hex "0000000b0a0908a0a1a2a3a4a5")
                                       (octets-from 8 31) (octets-from 0 8) :tag-length 10))))
  ;; #17: 12-octet aad
  (is (string= "8b9bf26bf29a7ad9538b6b3cd486e90112141dd3e269963edd41cf"
               (unhex (aes-ccm-encrypt *rfc3610-key* (hex "00000013121110a0a1a2a3a4a5")
                                       (octets-from 12 31) (octets-from 0 12) :tag-length 8))))
  ;; and back
  (is (equalp (octets-from 8 31)
              (aes-ccm-decrypt *rfc3610-key* (hex "00000003020100a0a1a2a3a4a5")
                               (hex "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
                               (octets-from 0 8) :tag-length 8))))

(test aes-ccm-sp800-38c-examples
  (let ((key (hex "404142434445464748494a4b4c4d4e4f")))
    ;; example 1: 7-octet nonce (L = 8), 4-octet tag
    (is (string= "7162015b 4dac255d"
                 (let ((out (aes-ccm-encrypt key (hex "10111213141516") (hex "20212223")
                                             (hex "0001020304050607") :tag-length 4)))
                   (format nil "~a ~a" (unhex (subseq out 0 4)) (unhex (subseq out 4))))))
    ;; example 2: 8-octet nonce, 6-octet tag
    (is (string= "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd"
                 (unhex (aes-ccm-encrypt key (hex "1011121314151617") (octets-from #x20 #x30)
                                         (octets-from 0 16) :tag-length 6))))
    ;; example 3: 12-octet nonce, 8-octet tag
    (is (string= "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"
                 (unhex (aes-ccm-encrypt key (hex "101112131415161718191a1b") (octets-from #x20 #x38)
                                         (octets-from 0 20) :tag-length 8))))
    ;; 13-octet nonce, 16-octet tag, nothing to encrypt and nothing to authenticate but the nonce
    (is (string= "32d6f8243a26d0bd98d01b0f448e7773"
                 (unhex (aes-ccm-encrypt key (hex "101112131415161718191a1b1c") (hex "") nil))))))

;;; Matter-shaped vectors (13-octet nonce, 16-octet tag, the encoded message
;;; header as AAD), cross-checked against OpenSSL's AES-128-CCM.
(defparameter *matter-key* (hex "000102030405060708090a0b0c0d0e0f"))
(defparameter *matter-nonce* (hex "00 78563412 0807060504030201"))
(defparameter *matter-aad* (hex "04 3412 00 78563412 0807060504030201"))

(defparameter *matter-ccm-vectors*
  ;; plaintext, ciphertext, tag
  '(("" "" "0a21aac4494bf24b52cbe37dc004c069")
    ("616263" "de5419" "01509f0b19e95bf2f86564c067ca946f")
    ("000102030405060708090a0b0c0d0e" "bf3778a940ee0fdbf095205de90a8f" "323bfebb8078862c82ca5fe389fd811e")
    ("000102030405060708090a0b0c0d0e0f" "bf3778a940ee0fdbf095205de90a8faf" "5e53915362973a4a6a2967e691972e1d")
    ("000102030405060708090a0b0c0d0e0f10" "bf3778a940ee0fdbf095205de90a8fafec" "1674aa8c2590a5e3373712a8e12e2386")
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
     "bf3778a940ee0fdbf095205de90a8fafec9b97d1c4865132510fb73c4a833638ee" "e282b704da5104ea18b67b2dcc4b18e9")))

(test aes-ccm-matter-shaped-vectors
  (loop :for (plain cipher tag) :in *matter-ccm-vectors*
        :for sealed := (aes-ccm-encrypt *matter-key* *matter-nonce* (hex plain) *matter-aad*)
        :do (is (string= (concatenate 'string cipher tag) (unhex sealed)))
            (is (equalp (hex plain) (aes-ccm-decrypt *matter-key* *matter-nonce* sealed *matter-aad*))))
  ;; the AAD changes the tag, not the ciphertext
  (is (string= "de54194025fcc5c1bc14cc2d4ad7f84eca3446"
               (unhex (aes-ccm-encrypt *matter-key* *matter-nonce* (hex "616263") nil))))
  (is (string= "de54192ec7c6c89d19830153675b5a1ce83a06"
               (unhex (aes-ccm-encrypt *matter-key* *matter-nonce* (hex "616263")
                                       (concatenate '(vector (unsigned-byte 8)) *matter-aad*
                                                    (make-array 26 :element-type '(unsigned-byte 8) :initial-element 0))))))
  ;; a group message: security flags 01, broadcast counter and node id
  (is (string= "294776b0d6264833b197a37234c81caaa9072605"
               (unhex (aes-ccm-encrypt (hex "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
                                       (hex "01 ffffffff ffffffffffffffff")
                                       (hex "deadbeef")
                                       (hex "06 0000 01 ffffffff ffffffffffffffff 3412")))))
  ;; 1000 octets: 63 blocks, checked by digest
  (is (string= "5169d42e64490ef9a00a042638f2465ea9ecdb77164e44f610bc5d87f504a370"
               (unhex (sha256 (aes-ccm-encrypt *matter-key* *matter-nonce*
                                               (coerce (loop :for i :below 1000 :collect (logand i 255))
                                                       '(vector (unsigned-byte 8)))
                                               *matter-aad*))))))

(test aes-ccm-round-trips
  (dolist (n '(0 1 15 16 17 31 32 33 100 1280))
    (let* ((key (random-octets 16))
           (nonce (random-octets 13))
           (aad (random-octets 26))
           (plain (random-octets n))
           (sealed (aes-ccm-encrypt key nonce plain aad)))
      (is (= (+ n 16) (length sealed)))
      (is (equalp plain (aes-ccm-decrypt key nonce sealed aad)))))
  ;; 256-bit key
  (let* ((key (random-octets 32)) (nonce (random-octets 13)) (plain (ascii "matter")))
    (is (equalp plain (aes-ccm-decrypt key nonce (aes-ccm-encrypt key nonce plain nil) nil)))))

(test aes-ccm-rejects-tampering
  (let* ((plain (ascii "the quick brown fox"))
         (sealed (aes-ccm-encrypt *matter-key* *matter-nonce* plain *matter-aad*)))
    (flet ((flipped (octets index)
             (let ((copy (copy-seq octets)))
               (setf (aref copy index) (logxor 1 (aref copy index)))
               copy)))
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* (flipped sealed 0) *matter-aad*))
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* (flipped sealed (1- (length sealed))) *matter-aad*))
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* sealed (flipped *matter-aad* 3)))
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* (flipped *matter-nonce* 1) sealed *matter-aad*))
      (signals aead-authentication-error
        (aes-ccm-decrypt (flipped *matter-key* 0) *matter-nonce* sealed *matter-aad*))
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* sealed nil))
      ;; truncated below the tag
      (signals aead-authentication-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* (subseq sealed 1) *matter-aad*))
      (signals crypto-error
        (aes-ccm-decrypt *matter-key* *matter-nonce* (subseq sealed 0 15) *matter-aad*))
      ;; the condition is a crypto-error too
      (is (subtypep 'aead-authentication-error 'crypto-error)))))

(test aes-ccm-parameter-errors
  (signals crypto-error (aes-ccm-encrypt (random-octets 15) *matter-nonce* (hex "") nil))
  (signals crypto-error (aes-ccm-encrypt *matter-key* (random-octets 6) (hex "") nil))
  (signals crypto-error (aes-ccm-encrypt *matter-key* (random-octets 14) (hex "") nil))
  (signals crypto-error (aes-ccm-encrypt *matter-key* *matter-nonce* (hex "") nil :tag-length 7))
  (signals crypto-error (aes-ccm-encrypt *matter-key* *matter-nonce* (hex "") nil :tag-length 2))
  (signals crypto-error (aes-ccm-encrypt *matter-key* *matter-nonce* (hex "") nil :tag-length 18))
  (signals crypto-error (aes-ccm-encrypt *matter-key* *matter-nonce* "text" nil))
  ;; L = 2 holds a 16-bit length: 65535 octets go, 65536 do not
  (signals crypto-error
    (aes-ccm-encrypt *matter-key* *matter-nonce* (make-array 65536 :element-type '(unsigned-byte 8)) nil))
  (is (= (+ 65535 16)
         (length (aes-ccm-encrypt *matter-key* *matter-nonce*
                                  (make-array 65535 :element-type '(unsigned-byte 8)) nil)))))

;;; ------------------------------------------------------------------
;;; Nonce and secured messages

(test message-nonce-layout
  (is (equalp (hex "00 78563412 0807060504030201")
              (message-nonce 0 #x12345678 #x0102030405060708)))
  (is (equalp (hex "c1 01000000 0000000000000000")
              (message-nonce #xc1 1 0)))
  (signals message-encode-error (message-nonce 256 1 0))
  (signals message-encode-error (message-nonce 0 (ash 1 32) 0))
  (signals message-encode-error (message-nonce 0 1 (ash 1 64))))

(test message-header-nonce-sources
  (let ((with-source (make-message-header :session-id 1 :message-counter #x12345678
                                          :source-node-id #x0102030405060708))
        (without (make-message-header :session-id 1 :message-counter #x12345678
                                      :privacy-p t :session-type :group)))
    (is (equalp (hex "00 78563412 0807060504030201") (message-header-nonce with-source)))
    ;; an explicit sender overrides the header's
    (is (equalp (hex "00 78563412 0100000000000000") (message-header-nonce with-source 1)))
    ;; no source in the header: the explicit one, else 0 (PASE)
    (is (equalp (hex "81 78563412 0000000000000000") (message-header-nonce without)))
    (is (equalp (hex "81 78563412 2a00000000000000") (message-header-nonce without 42)))
    (is (= #x81 (message-header-security-flags without)))
    (is (= #x00 (message-header-security-flags with-source)))))

(defun sample-header ()
  (make-message-header :session-id #x1234 :message-counter #x12345678
                       :source-node-id #x0102030405060708))

(defun sample-protocol-header ()
  (make-protocol-header :initiator-p t :reliability-p t :exchange-id 1
                        :protocol-id +protocol-secure-channel+
                        :opcode +opcode-pbkdf-param-request+
                        :payload (ascii "hello")))

(test secured-message-fixed-vector
  ;; header 04 3412 00 78563412 0807060504030201, then CCM(protocol header + "hello")
  (let ((octets (encode-secured-message (sample-header) (sample-protocol-header) *matter-key*)))
    (is (string= (concatenate 'string
                              "04341200785634120807060504030201"
                              "ba167baa44eb61b994f045"
                              "fb989a525df08874a05db528edd3768b")
                 (unhex octets)))
    (multiple-value-bind (header protocol) (decode-secured-message octets *matter-key*)
      (is (equalp (sample-header) header))
      (is (equalp (sample-protocol-header) protocol)))))

(test secured-message-round-trips
  ;; a CASE-style unicast: no source node id in the header, the sender's
  ;; node id comes from the session on both sides
  (let* ((key (random-octets 16))
         (header (make-message-header :session-id 7 :message-counter 99
                                      :destination-node-id #xdeadbeef))
         (protocol (make-protocol-header :protocol-id +protocol-interaction-model+
                                         :opcode +opcode-im-read-request+
                                         :exchange-id 4242 :ack-counter 98
                                         :payload (random-octets 300)))
         (octets (encode-secured-message header protocol key :nonce-source-node-id #xcafe)))
    (multiple-value-bind (back-header back-protocol)
        (decode-secured-message octets key :nonce-source-node-id #xcafe)
      (is (equalp header back-header))
      (is (equalp protocol back-protocol)))
    ;; the wrong sender id for the nonce fails authentication
    (signals aead-authentication-error
      (decode-secured-message octets key :nonce-source-node-id #xcaff))
    (signals aead-authentication-error
      (decode-secured-message octets key))
    ;; inside a larger buffer
    (let ((buffer (concatenate '(vector (unsigned-byte 8)) (hex "ffff") octets (hex "ee"))))
      (multiple-value-bind (back-header back-protocol)
          (decode-secured-message buffer key :nonce-source-node-id #xcafe
                                             :start 2 :end (+ 2 (length octets)))
        (is (equalp header back-header))
        (is (equalp protocol back-protocol)))))
  ;; a group message with extensions in the header
  (let* ((key (random-octets 16))
         (header (make-message-header :session-id 5 :session-type :group :control-p t
                                      :message-counter 1 :source-node-id 77
                                      :destination-group-id #x4321 :extensions (hex "0102")))
         (protocol (make-protocol-header :protocol-id +protocol-secure-channel+
                                         :opcode +opcode-standalone-ack+ :exchange-id 1
                                         :ack-counter 5 :secured-extensions (hex "aa")
                                         :payload (hex "")))
         (octets (encode-secured-message header protocol key)))
    (multiple-value-bind (back-header back-protocol) (decode-secured-message octets key)
      (is (equalp header back-header))
      (is (equalp protocol back-protocol)))))

(test secured-message-rejections
  (let ((octets (encode-secured-message (sample-header) (sample-protocol-header) *matter-key*)))
    ;; session 0 belongs to the unsecured codec, both ways
    (signals message-encode-error
      (encode-secured-message (make-message-header) (sample-protocol-header) *matter-key*))
    (signals message-decode-error
      (decode-secured-message (encode-unsecured-message (make-message-header) (sample-protocol-header))
                              *matter-key*))
    ;; the unsecured decoder refuses the secured message
    (signals message-decode-error (decode-unsecured-message octets))
    ;; a payload shorter than the MIC
    (signals message-decode-error (decode-secured-message (subseq octets 0 (+ 16 15)) *matter-key*))
    (handler-case (decode-secured-message (subseq octets 0 (+ 16 15)) *matter-key*)
      (message-decode-error (e) (is (= 16 (message-decode-error-offset e)))))
    ;; any altered octet
    (dotimes (i (length octets))
      (let ((copy (copy-seq octets)))
        (setf (aref copy i) (logxor #x80 (aref copy i)))
        (signals error (decode-secured-message copy *matter-key*))))
    ;; the wrong key
    (signals aead-authentication-error (decode-secured-message octets (random-octets 16)))))
