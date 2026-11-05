;;;; attestation-test.lisp -- DER decoding, PEM, X.509 import, the CSR, the
;;;; certification declaration and device attestation, against the SDK's
;;;; vectors (sdk-attestation.lisp) and our own generated material.

(in-package :cl-matter.attestation.tests)

(def-suite attestation-tests :description "DER import, CSR, certification declaration, device attestation"
  :in cl-matter.tests:test-suite)
(in-suite attestation-tests)

(defun reason-of (thunk)
  "The ATTESTATION-ERROR reason THUNK signals, or :OK."
  (handler-case (progn (funcall thunk) :ok)
    (attestation-error (e) (attestation-error-reason e))))

(defun der-error-p* (thunk)
  (handler-case (progn (funcall thunk) nil)
    (der-error () t)))

(defun cert-error-p (thunk)
  (handler-case (progn (funcall thunk) nil)
    (certificate-error () t)))

(defun flip (octets index)
  (let ((copy (copy-seq octets)))
    (setf (aref copy index) (logxor 1 (aref copy index)))
    copy))

;;; ------------------------------------------------------------------
;;; DER decoding

(test der-decode-primitives
  "Everything the encoder writes, the decoder reads back."
  (is (= 0 (der-node-integer (der-decode (der-integer 0)))))
  (is (= 127 (der-node-integer (der-decode (der-integer 127)))))
  (is (= 128 (der-node-integer (der-decode (der-integer 128)))))
  (is (= -1 (der-node-integer (der-decode (der-integer -1)))))
  (is (= -129 (der-node-integer (der-decode (der-integer -129)))))
  (is (= (ash 1 70) (der-node-integer (der-decode (der-integer (ash 1 70))))))
  (is (equalp (hex "ff00") (der-node-unsigned-octets (der-decode (der-integer-octets (hex "00ff00"))))))
  (is (eq t (der-node-boolean (der-decode (der-boolean t)))))
  (is (eq nil (der-node-boolean (der-decode (der-boolean nil)))))
  (is (string= "1.2.840.10045.4.3.2" (der-node-oid (der-decode (der-oid "1.2.840.10045.4.3.2")))))
  (is (string= "2.5.29.19" (der-node-oid (der-decode (der-oid "2.5.29.19")))))
  (is (string= "0.9.2342.19200300.100.1.25" (der-node-oid (der-decode (der-oid "0.9.2342.19200300.100.1.25")))))
  (multiple-value-bind (string kind) (der-node-string (der-decode (der-utf8-string "Lämp")))
    (is (string= "Lämp" string)) (is (eq :utf8 kind)))
  (multiple-value-bind (string kind) (der-node-string (der-decode (der-printable-string "Lamp")))
    (is (string= "Lamp" string)) (is (eq :printable kind)))
  (multiple-value-bind (string kind) (der-node-string (der-decode (der-ia5-string "lamp.example")))
    (is (string= "lamp.example" string)) (is (eq :ia5 kind)))
  (multiple-value-bind (octets unused) (der-node-bit-string (der-decode (der-bit-string (hex "0102") 3)))
    (is (equalp (hex "0102") octets)) (is (= 3 unused)))
  (is (= #b101 (der-node-bit-string-flags (der-decode (der-bit-string-flags #b101)))))
  (is (= #x1FF (der-node-bit-string-flags (der-decode (der-bit-string-flags #x1FF)))))
  (is (= 0 (der-node-bit-string-flags (der-decode (der-bit-string-flags 0)))))
  (is (equalp (hex "abcd") (der-node-octet-string (der-decode (der-octet-string (hex "abcd"))))))
  ;; times, Matter epoch
  (is (= 0 (der-node-time (der-decode (der-generalized-time "99991231235959Z")))))
  (is (= 0 (der-node-time (der-decode (der-utc-time "000101000000Z")))))
  (is (= 86400 (der-node-time (der-decode (der-utc-time "000102000000Z")))))
  (is (= (matter-time (encode-universal-time 43 23 14 28 6 2021 0)) (der-node-time (der-decode (der-utc-time "210628142343Z")))))
  (is (= (matter-time (encode-universal-time 0 0 0 1 1 2050 0)) (der-node-time (der-decode (der-generalized-time "20500101000000Z")))))
  (is (= (matter-time (encode-universal-time 0 0 0 1 1 1999 0)) (der-node-time (der-decode (der-utc-time "990101000000Z"))))))

(test der-decode-structure
  (let* ((octets (der-sequence (der-integer 1) (der-set (der-boolean t)) (der-context 0 t (der-null)) (der-context 1 nil (hex "aa"))))
         (node (der-decode octets)))
    (is (= +der-sequence+ (der-node-tag node)))
    (is (der-node-constructed-p node))
    (is (= 4 (length (der-node-children node))))
    (is (equalp octets (der-node-whole node)))
    (is (= 1 (der-node-integer (der-child node 0 +der-integer+))))
    (is (= 1 (length (der-children (der-child node 1) +der-set+))))
    (is (= (der-context-tag 0) (der-node-tag (der-child node 2))))
    (is (= (der-context-tag 1 nil) (der-node-tag (der-child node 3))))
    (is (equalp (hex "aa") (der-node-content (der-child node 3))))
    (is (null (der-optional-child node 0 +der-boolean+)))
    (is (der-optional-child node 0 +der-integer+))
    (is (null (der-child node 9)))
    ;; whole content accounted for
    (is (equalp (der-integer 1) (der-node-whole (der-child node 0))))
    ;; a node inside keeps its position in the original octets
    (is (= 2 (der-node-start (der-child node 0))))
    ;; partial decoding
    (multiple-value-bind (first end) (der-decode (cat (der-integer 5) (der-integer 6)) :whole nil)
      (is (= 5 (der-node-integer first)))
      (is (= 3 end))
      (is (= 6 (der-node-integer (der-decode (cat (der-integer 5) (der-integer 6)) :start end)))))))

(test der-decode-rejections
  (flet ((bad (octets) (is (der-error-p* (lambda () (der-decode (hex octets)))) "~a should be rejected" octets)))
    (bad "")                            ; nothing
    (bad "02")                          ; no length
    (bad "0203")                        ; truncated content
    (bad "020101ff")                    ; trailing octet
    (bad "0280")                        ; indefinite length
    (bad "028101ff")                    ; non-minimal long form
    (bad "02820001ff")                  ; leading zero in long length
    (bad "0285010000000000")            ; a 5-octet length
    (bad "1f8100")                      ; multi-octet tag
    (bad "3002020101"))                 ; child runs past the SEQUENCE
  (is (der-error-p* (lambda () (der-node-integer (der-decode (hex "0200"))))))
  (is (der-error-p* (lambda () (der-node-integer (der-decode (hex "0101ff"))))))
  (is (der-error-p* (lambda () (der-node-boolean (der-decode (hex "01020000"))))))
  (is (der-error-p* (lambda () (der-node-oid (der-decode (hex "0600"))))))
  (is (der-error-p* (lambda () (der-node-oid (der-decode (hex "060181"))))))
  (is (der-error-p* (lambda () (der-node-string (der-decode (hex "0c01ff"))))))
  (is (der-error-p* (lambda () (der-node-string (der-decode (hex "1301ff"))))))
  (is (der-error-p* (lambda () (der-node-string (der-decode (hex "0400"))))))
  (is (der-error-p* (lambda () (der-node-bit-string (der-decode (hex "0300"))))))
  (is (der-error-p* (lambda () (der-node-bit-string (der-decode (hex "030208ff"))))))
  (is (der-error-p* (lambda () (der-node-time (der-decode (der-utc-time "21062814234Z"))))))
  (is (der-error-p* (lambda () (der-node-time (der-decode (der-utc-time "210628142343"))))))
  (is (der-error-p* (lambda () (der-node-time (der-decode (der-generalized-time "20211331000000Z"))))))
  (is (der-error-p* (lambda () (der-node-time (der-decode (der-octet-string (hex "00")))))))
  (is (der-error-p* (lambda () (der-expect (der-decode (der-integer 1)) +der-sequence+))))
  (is (der-error-p* (lambda () (der-expect nil +der-sequence+))))
  (is (der-error-p* (lambda () (der-children (der-decode (der-integer 1)) +der-sequence+))))
  (let ((*der-max-depth* 3))
    (is (der-error-p* (lambda () (der-decode (der-sequence (der-sequence (der-sequence (der-sequence (der-null))))))))))
  (signals der-error (der-decode "not octets")))

;;; ------------------------------------------------------------------
;;; Base64 and PEM

(test base64-round-trips
  (is (string= "" (base64-encode (hex ""))))
  (is (string= "Zg==" (base64-encode (ascii "f"))))
  (is (string= "Zm8=" (base64-encode (ascii "fo"))))
  (is (string= "Zm9v" (base64-encode (ascii "foo"))))
  (is (string= "Zm9vYg==" (base64-encode (ascii "foob"))))
  (is (string= "Zm9vYmE=" (base64-encode (ascii "fooba"))))
  (is (string= "Zm9vYmFy" (base64-encode (ascii "foobar"))))
  (is (equalp (ascii "foobar") (base64-decode "Zm9vYmFy")))
  (is (equalp (ascii "fooba") (base64-decode "Zm9vYmE=")))
  (is (equalp (ascii "f") (base64-decode "Zg==")))
  (is (equalp (hex "") (base64-decode "")))
  (is (equalp (ascii "foobar") (base64-decode (format nil " Zm9v~%YmFy~c~%" #\Return))))
  (is (equalp (hex "fbff") (base64-decode "+/8=")))
  (dotimes (n 10)
    (let ((octets (octets-from 0 (* 7 n))))
      (is (equalp octets (base64-decode (base64-encode octets))))
      (is (equalp octets (base64-decode (base64-encode octets :line-length 16))))))
  ;; 64-character lines
  (let ((lines (loop :with text := (base64-encode (octets-from 0 100) :line-length 64)
                     :for start := 0 :then (1+ end)
                     :for end := (position #\Newline text :start start)
                     :while end :collect (- end start))))
    (is (equal '(64 64 8) lines)))
  (is (der-error-p* (lambda () (base64-decode "Zm9v!"))))
  (is (der-error-p* (lambda () (base64-decode "Zm9"))))
  (is (der-error-p* (lambda () (base64-decode "Z==="))))
  (is (der-error-p* (lambda () (base64-decode "Zm9vYg="))))
  (is (der-error-p* (lambda () (base64-decode "Zm==9v"))))
  (is (der-error-p* (lambda () (base64-decode "====")))))

(test pem-blocks
  (let* ((a (octets-from 0 50)) (b (hex "0102"))
         (text (concatenate 'string "junk before" (string #\Newline) (pem-encode "CERTIFICATE" a)
                            (pem-encode "EC PRIVATE KEY" b) "junk after")))
    (is (equalp (list (cons "CERTIFICATE" a) (cons "EC PRIVATE KEY" b)) (pem-decode text)))
    (is (equalp a (pem-block text "CERTIFICATE")))
    (is (equalp b (pem-block text "EC PRIVATE KEY")))
    (is (der-error-p* (lambda () (pem-block text "PUBLIC KEY"))))
    (is (null (pem-decode "nothing here")))
    (is (der-error-p* (lambda () (pem-decode "-----BEGIN X-----"))))
    (is (der-error-p* (lambda () (pem-decode "-----BEGIN X-----\nAAAA\n-----END Y-----"))))
    (is (string= (format nil "-----BEGIN T-----~%AQI=~%-----END T-----~%") (pem-encode "T" b))))
  ;; the SDK's PEM files
  (is (= 2 (length (pem-decode (concatenate 'string *test-dac-pem* (string #\Newline) *test-dac-key-pem*)))))
  (is (string= "EC PRIVATE KEY" (car (first (pem-decode *test-dac-key-pem*)))))
  (let ((path (format nil "~a/cl-matter-pem-test.pem" (or (uiop:getenv "TMPDIR") "/tmp"))))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (write-string *test-dac-pem* out))
    (is (equalp (pem-block *test-dac-pem* "CERTIFICATE") (read-pem-file path "CERTIFICATE")))
    (is (= 1 (length (read-pem-file path))))
    (delete-file path)))

;;; ------------------------------------------------------------------
;;; X.509 import

(test x509-import-sdk-attestation-certificates
  (let ((dac (decode-certificate-pem *test-dac-pem*))
        (pai (decode-certificate-pem *test-pai-pem*))
        (paa (decode-certificate-pem (second *test-paa-pems*)))
        (paa-novid (decode-certificate-pem (first *test-paa-pems*))))
    (is (equal '((:common-name "Matter Test DAC 0000") (:matter-vid "FFF1") (:matter-pid "8000")) (certificate-subject dac)))
    (is (equal '((:common-name "Matter Test PAI") (:matter-vid "FFF1") (:matter-pid "8000")) (certificate-issuer dac)))
    (is (dn-equal (certificate-issuer dac) (certificate-subject pai)))
    (is (dn-equal (certificate-issuer pai) (certificate-subject paa)))
    (is (= #xFFF1 (certificate-vendor-id dac)))
    (is (= #x8000 (certificate-product-id dac)))
    (is (= #xFFF1 (certificate-vendor-id paa)))
    (is (null (certificate-product-id paa)))
    (is (null (certificate-vendor-id paa-novid)))
    (is (null (certificate-type dac)))  ; an application subject, not an operational one
    (is (= (matter-time (encode-universal-time 43 23 14 28 6 2021 0)) (certificate-not-before dac)))
    (is (= 0 (certificate-not-after dac)))
    (is (equalp (hex "1bd63818f144a797") (certificate-serial-number dac)))
    (is (equal '(:basic-constraints :ca nil) (certificate-extension dac :basic-constraints)))
    (is (equal '(:key-usage :digital-signature) (certificate-extension dac :key-usage)))
    (is (equal '(:basic-constraints :ca t :path-length 0) (certificate-extension pai :basic-constraints)))
    (is (equal '(:key-usage :key-cert-sign :crl-sign) (certificate-extension pai :key-usage)))
    (is (equal '(:basic-constraints :ca t :path-length 1) (certificate-extension paa :basic-constraints)))
    (is (equalp (hex "e57088f448e6ff9fe2009744528bf9ec082fc11f") (certificate-subject-key-id dac)))
    (is (equalp (hex "af42b7094debd515ec6ecf33b81115225f325288") (certificate-authority-key-id dac)))
    (is (equalp (certificate-authority-key-id dac) (certificate-subject-key-id pai)))
    (is (equalp (subject-key-identifier (certificate-public-key dac)) (certificate-subject-key-id dac)))
    (is (= 65 (length (certificate-public-key dac))))
    (is (= 64 (length (certificate-signature dac))))
    ;; signatures verify over the original TBS, and the DER comes back unchanged
    (is (verify-certificate-signature dac pai))
    (is (verify-certificate-signature pai paa))
    (is (verify-certificate-signature paa paa))
    (is (not (verify-certificate-signature dac paa)))
    (is (equalp (pem-block *test-dac-pem* "CERTIFICATE") (certificate-der dac)))
    (is (equalp (certificate-der dac) (certificate-der (decode-certificate-der (certificate-der dac)))))
    (is (equalp (certificate-der dac) (certificate-der (certificate-from-octets (certificate-der dac)))))
    ;; the SDK's DAC 0004 from the C vectors
    (let ((dac4 (decode-certificate-der *sdk-dac-0004-der*)))
      (is (equalp *sdk-dac-0004-public-key* (certificate-public-key dac4)))
      (is (equalp *sdk-dac-0004-skid* (certificate-subject-key-id dac4)))
      (is (equalp *sdk-dac-0004-public-key* (p256-public-key *sdk-dac-0004-private-key*)))
      (is (verify-certificate-signature dac4 (decode-certificate-der *sdk-pai-fff1-8000-der*)))
      (is (equalp *sdk-pai-fff1-8000-der* (certificate-der pai))))))

(test x509-import-of-our-own-certificates
  "A TLV certificate's DER decodes to the same certificate, and the
imported form verifies and converts back to the same TLV."
  (multiple-value-bind (fabric root-keypair ica-keypair) (make-test-fabric :fabric-id #x2B :node-id 7 :icac t :case-auth-tags '(#xABCD0001))
    (declare (ignore root-keypair ica-keypair))
    (dolist (c (list (fabric-rcac fabric) (fabric-icac fabric) (fabric-noc fabric)))
      (let ((imported (decode-certificate-der (certificate-der c))))
        (is (dn-equal (certificate-subject c) (certificate-subject imported)))
        (is (dn-equal (certificate-issuer c) (certificate-issuer imported)))
        (is (equalp (certificate-serial-number c) (certificate-serial-number imported)))
        (is (= (certificate-not-before c) (certificate-not-before imported)))
        (is (= (certificate-not-after c) (certificate-not-after imported)))
        (is (equalp (certificate-public-key c) (certificate-public-key imported)))
        (is (equalp (certificate-signature c) (certificate-signature imported)))
        (is (equalp (certificate-extensions c) (certificate-extensions imported)))
        (is (equalp (certificate-tbs-der c) (certificate-tbs-der imported)))
        (is (equalp (certificate-der c) (certificate-der imported)))
        (is (equalp (certificate-octets* c) (encode-certificate imported)))
        (is (eq (certificate-type c) (certificate-type imported)))))
    (let ((noc (decode-certificate-der (certificate-der (fabric-noc fabric)))))
      (is (= 7 (certificate-node-id noc)))
      (is (= #x2B (certificate-fabric-id noc)))
      (is (equal '(#xABCD0001) (certificate-case-auth-tags noc)))
      (is (equal '(:extended-key-usage :client-auth :server-auth) (certificate-extension noc :extended-key-usage)))
      ;; the imported chain validates like the original
      (is (= 7 (validate-certificate-chain noc (decode-certificate-der (certificate-der (fabric-icac fabric)))
                                           (decode-certificate-der (certificate-der (fabric-rcac fabric)))))))
    ;; a future extension in DER is kept and re-emitted
    (let* ((keypair (generate-p256-keypair))
           (extension (der-sequence (der-oid "1.3.6.1.4.1.37244.99.1") (der-octet-string (hex "aabb"))))
           (c (make-root-certificate :keypair keypair :rcac-id 5))
           (c2 (progn (setf (certificate-extensions c) (append (certificate-extensions c) (list (list :future extension))))
                      (sign-certificate c keypair)
                      (decode-certificate-der (certificate-der c)))))
      (is (equalp (certificate-extensions c) (certificate-extensions c2)))
      (is (verify-certificate-signature c2 c2))
      (is (equalp (certificate-octets* c) (encode-certificate c2))))))

(test x509-import-rejections
  (let ((der (pem-block *test-dac-pem* "CERTIFICATE")))
    (is (cert-error-p (lambda () (decode-certificate-der (subseq der 0 100)))))
    (is (cert-error-p (lambda () (decode-certificate-der (hex "3000")))))
    (is (cert-error-p (lambda () (decode-certificate-der (der-sequence (der-integer 1) (der-integer 2) (der-integer 3))))))
    (is (cert-error-p (lambda () (decode-certificate-der "text"))))
    (is (cert-error-p (lambda () (decode-certificate-pem "no block"))))
    (is (cert-error-p (lambda () (certificate-from-octets (hex "")))))
    ;; a flipped signature octet still decodes but no longer verifies
    (let ((bent (decode-certificate-der (flip der (- (length der) 10)))))
      (is (not (verify-certificate-signature bent (decode-certificate-pem *test-pai-pem*)))))
    ;; a flipped TBS octet (inside the issuer's name): the stored TBS is what is verified
    (let ((bent (decode-certificate-der (flip der 62))))
      (is (string/= "Matter Test PAI" (dn-attribute (certificate-issuer bent) :common-name)))
      (is (not (verify-certificate-signature bent (decode-certificate-pem *test-pai-pem*)))))
    ;; version 1 (no version member) and a wrong algorithm
    (let* ((c (make-root-certificate :keypair (generate-p256-keypair)))
           (tbs (der-decode (certificate-tbs-der c)))
           (members (der-node-children tbs)))
      (flet ((rebuild (tbs-der)
               (der-sequence tbs-der (der-sequence (der-oid "1.2.840.10045.4.3.2"))
                             (der-bit-string (ecdsa-signature-der (certificate-signature c))))))
        (is (cert-error-p (lambda () (decode-certificate-der
                                      (rebuild (apply #'der-sequence (mapcar #'der-node-whole (rest members))))))))
        (is (cert-error-p (lambda () (decode-certificate-der
                                      (rebuild (apply #'der-sequence
                                                      (der-node-whole (first members)) (der-node-whole (second members))
                                                      (der-sequence (der-oid "1.2.840.10045.4.3.3"))
                                                      (mapcar #'der-node-whole (cdddr members))))))))))
    ;; an unknown DN attribute is kept but cannot be re-encoded
    (let* ((keypair (generate-p256-keypair))
           (c (make-root-certificate :keypair keypair :rcac-id 1))
           (subject-der (der-sequence (der-set (der-sequence (der-oid "2.5.4.3") (der-utf8-string "Root")))
                                      (der-set (der-sequence (der-oid "1.2.3.4.5") (der-utf8-string "custom")))))
           (members (der-node-children (der-decode (certificate-tbs-der c))))
           (tbs (apply #'der-sequence
                       (append (mapcar #'der-node-whole (subseq members 0 3)) (list subject-der)
                               (mapcar #'der-node-whole (subseq members 4 5)) (list subject-der)
                               (mapcar #'der-node-whole (subseq members 6)))))
           (signature (p256-sign-digest keypair (cl-matter:sha256 tbs)))
           (imported (decode-certificate-der (der-sequence tbs (der-sequence (der-oid "1.2.840.10045.4.3.2"))
                                                           (der-bit-string (ecdsa-signature-der signature))))))
      (is (equal '((:common-name "Root") ((:oid "1.2.3.4.5") "custom")) (certificate-subject imported)))
      (is (verify-certificate-signature imported imported))
      (is (cert-error-p (lambda () (encode-certificate imported))))
      (is (null (certificate-vendor-id imported))))))

(test vendor-and-product-id-fallbacks
  (flet ((cert-with-subject (subject-der)
           (let* ((keypair (generate-p256-keypair))
                  (c (make-root-certificate :keypair keypair :rcac-id 1))
                  (members (der-node-children (der-decode (certificate-tbs-der c))))
                  (tbs (apply #'der-sequence
                              (append (mapcar #'der-node-whole (subseq members 0 5)) (list subject-der)
                                      (mapcar #'der-node-whole (subseq members 6)))))
                  (signature (p256-sign-digest keypair (cl-matter:sha256 tbs))))
             (decode-certificate-der (der-sequence tbs (der-sequence (der-oid "1.2.840.10045.4.3.2"))
                                                   (der-bit-string (ecdsa-signature-der signature)))))))
    (let ((c (cert-with-subject (der-sequence (der-set (der-sequence (der-oid "2.5.4.3") (der-utf8-string "ACME Mvid:FFF2 Mpid:1234")))))))
      (is (= #xFFF2 (certificate-vendor-id c)))
      (is (= #x1234 (certificate-product-id c))))
    (let ((c (cert-with-subject (der-sequence (der-set (der-sequence (der-oid "2.5.4.3") (der-printable-string "Mvid:FFF")))))))
      (is (null (certificate-vendor-id c))))
    (let ((c (cert-with-subject (der-sequence (der-set (der-sequence (der-oid "1.3.6.1.4.1.37244.2.1") (der-utf8-string "FFF3")))
                                              (der-set (der-sequence (der-oid "1.3.6.1.4.1.37244.2.2") (der-utf8-string "0ABC")))))))
      (is (= #xFFF3 (certificate-vendor-id c)))
      (is (= #x0ABC (certificate-product-id c)))
      (is (equal '((:matter-vid "FFF3") (:matter-pid "0ABC")) (certificate-subject c))))
    (let ((c (cert-with-subject (der-sequence (der-set (der-sequence (der-oid "1.3.6.1.4.1.37244.2.1") (der-utf8-string "FFF")))))))
      (is (cert-error-p (lambda () (certificate-vendor-id c)))))
    (let ((c (cert-with-subject (der-sequence (der-set (der-sequence (der-oid "1.3.6.1.4.1.37244.2.1") (der-utf8-string "FFF1")))
                                              (der-set (der-sequence (der-oid "1.3.6.1.4.1.37244.2.1") (der-utf8-string "FFF2")))))))
      (is (cert-error-p (lambda () (certificate-vendor-id c)))))))

(test ec-private-keys
  (let ((keypair (decode-ec-private-key-pem *test-dac-key-pem*))
        (dac (decode-certificate-pem *test-dac-pem*)))
    (is (equalp (certificate-public-key dac) (p256-keypair-public keypair)))
    (is (equalp (certificate-public-key (decode-certificate-pem *test-pai-pem*))
                (p256-keypair-public (decode-ec-private-key-pem *sdk-pai-fff1-8000-key-pem*))))
    (is (equalp (certificate-public-key (decode-certificate-pem (second *test-paa-pems*)))
                (p256-keypair-public (decode-ec-private-key-pem *sdk-paa-fff1-key-pem*))))
    (is (equalp (certificate-public-key (decode-certificate-pem (first *test-paa-pems*)))
                (p256-keypair-public (decode-ec-private-key-pem *sdk-paa-novid-key-pem*))))
    (is (equalp (certificate-public-key (decode-certificate-pem *sdk-cd-signing-cert-pem*))
                (p256-keypair-public (decode-ec-private-key-pem *sdk-cd-signing-key-pem*))))
    ;; our encoder is openssl's layout: decoding it gives the key back, byte-exact for the SDK key
    (is (equalp (pem-block *test-dac-key-pem* "EC PRIVATE KEY") (encode-ec-private-key keypair)))
    (is (equalp keypair (decode-ec-private-key (encode-ec-private-key keypair))))
    ;; PKCS#8 wrapping
    (let ((pkcs8 (der-sequence (der-integer 0)
                               (der-sequence (der-oid "1.2.840.10045.2.1") (der-oid "1.2.840.10045.3.1.7"))
                               (der-octet-string (encode-ec-private-key keypair)))))
      (is (equalp keypair (decode-ec-private-key pkcs8)))
      (is (equalp keypair (decode-ec-private-key-pem (pem-encode "PRIVATE KEY" pkcs8)))))
    ;; rejections
    (is (cert-error-p (lambda () (decode-ec-private-key-pem *test-dac-pem*))))
    (is (cert-error-p (lambda () (decode-ec-private-key (hex "3000")))))
    (is (cert-error-p (lambda () (decode-ec-private-key (der-sequence (der-integer 2) (der-octet-string (p256-keypair-private keypair)))))))
    (is (cert-error-p (lambda () (decode-ec-private-key (der-sequence (der-integer 1) (der-octet-string (p256-keypair-private keypair))
                                                                       (der-context 0 t (der-oid "1.3.132.0.34")))))))
    (let ((wrong-public (der-sequence (der-integer 1) (der-octet-string (p256-keypair-private keypair))
                                      (der-context 1 t (der-bit-string (p256-keypair-public (generate-p256-keypair)))))))
      (is (cert-error-p (lambda () (decode-ec-private-key wrong-public)))))))

;;; ------------------------------------------------------------------
;;; Attestation elements

(test attestation-elements-sdk-vector
  "ConstructAttestationElements' output, byte for byte, and back."
  (let ((elements (encode-attestation-elements
                   :certification-declaration *sdk-construction-cd*
                   :nonce *sdk-construction-nonce*
                   :timestamp 677103357
                   :vendor-reserved (list (list #xFFF1 #x003E 1 *sdk-construction-vendor-reserved-1*)
                                          (list #xFFF1 #x003E 3 *sdk-construction-vendor-reserved-3*)))))
    (is (equalp *sdk-construction-elements* elements))
    (let ((plist (decode-attestation-elements elements)))
      (is (equalp *sdk-construction-cd* (getf plist :certification-declaration)))
      (is (equalp *sdk-construction-nonce* (getf plist :nonce)))
      (is (= 677103357 (getf plist :timestamp)))
      (is (null (getf plist :firmware-info)))
      (is (= 2 (length (getf plist :vendor-reserved))))
      (is (equal (list #xFFF1 #x003E 1) (subseq (first (getf plist :vendor-reserved)) 0 3)))
      (is (equalp *sdk-construction-vendor-reserved-3* (fourth (second (getf plist :vendor-reserved))))))
    ;; the verifier's vector carries a whole CMS CD
    (let ((plist (decode-attestation-elements *sdk-attestation-elements*)))
      (is (equalp *sdk-attestation-nonce* (getf plist :nonce)))
      (is (= 677103357 (getf plist :timestamp)))
      (is (= 2 (length (getf plist :vendor-reserved))))
      (is (= #x1234 (getf (decode-certification-declaration (getf plist :certification-declaration)) :device-type-id))))))

(test attestation-elements-checks
  (let ((cd (hex "0102")) (nonce (octets-from 0 32)))
    (is (eq :invalid-argument (reason-of (lambda () (encode-attestation-elements :certification-declaration cd :nonce (octets-from 0 31))))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-attestation-elements :certification-declaration (hex "") :nonce nonce)))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-attestation-elements :certification-declaration cd :nonce nonce :timestamp -1)))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-attestation-elements :certification-declaration (make-array 900 :element-type '(unsigned-byte 8)) :nonce nonce)))))
    (let ((with-firmware (encode-attestation-elements :certification-declaration cd :nonce nonce :firmware-info (hex "ff"))))
      (is (equalp (hex "ff") (getf (decode-attestation-elements with-firmware) :firmware-info))))
    ;; decoder: order, types, required members
    (flet ((elements (&rest items) (tlv-encode (make-tlv-element nil :structure items)))
           (bad (octets) (is (eq :malformed (reason-of (lambda () (decode-attestation-elements octets)))))))
      (bad (elements (tlv 2 :octets nonce) (tlv 1 :octets cd) (tlv 3 :unsigned 0)))          ; out of order
      (bad (elements (tlv 1 :octets cd) (tlv 3 :unsigned 0)))                                  ; nonce missing
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets nonce)))                                ; timestamp missing
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets (octets-from 0 16)) (tlv 3 :unsigned 0))) ; short nonce
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :string "0")))            ; wrong type
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :unsigned 0)
                     (tlv '(:profile 1 2 3) :octets (hex "")) (tlv 4 :octets (hex ""))))      ; context after vendor
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :unsigned 0) (tlv '(:profile 1 2 3) :unsigned 1)))
      (bad (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :unsigned 0) (tlv '(:common 1) :octets (hex ""))))
      (bad (tlv-encode (tlv nil :octets cd)))
      (bad (tlv-encode (make-tlv-element 1 :structure (list (tlv 1 :octets cd)))))
      (bad (cat (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :unsigned 0)) (hex "00")))
      (bad (hex "15"))
      ;; an unknown context tag in order is fine (the SDK allows future ones)
      (is (= 0 (getf (decode-attestation-elements (elements (tlv 1 :octets cd) (tlv 2 :octets nonce) (tlv 3 :unsigned 0)
                                                             (tlv 9 :unsigned 1)))
                     :timestamp))))))

(test nocsr-elements
  (let* ((keypair (generate-p256-keypair))
         (csr (make-certificate-signing-request keypair))
         (nonce (octets-from 32 64))
         (elements (encode-nocsr-elements :csr csr :nonce nonce :vendor-reserved-1 (hex "01") :vendor-reserved-3 (hex "03"))))
    (let ((plist (decode-nocsr-elements elements)))
      (is (equalp csr (getf plist :csr)))
      (is (equalp nonce (getf plist :nonce)))
      (is (equalp (hex "01") (getf plist :vendor-reserved-1)))
      (is (null (getf plist :vendor-reserved-2)))
      (is (equalp (hex "03") (getf plist :vendor-reserved-3)))
      (is (null (getf plist :vendor-reserved))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-nocsr-elements :csr csr :nonce (octets-from 0 8))))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-nocsr-elements :csr (hex "") :nonce nonce)))))
    (is (eq :malformed (reason-of (lambda () (decode-nocsr-elements (tlv-encode (make-tlv-element nil :structure (list (tlv 1 :octets csr)))))))))
    ;; the SDK's vector
    (let ((plist (decode-nocsr-elements *sdk-nocsr-elements*)))
      (is (equalp *sdk-nocsr-nonce* (getf plist :nonce)))
      (is (equalp (ascii "sample_vendor_reserved1") (getf plist :vendor-reserved-1)))
      (is (equalp (ascii "vendor_reserved3_example") (getf plist :vendor-reserved-3)))
      (multiple-value-bind (public-key subject) (decode-certificate-signing-request (getf plist :csr))
        (is (= 65 (length public-key)))
        (is (equal '((:organization-name "CSA")) subject))))))

;;; ------------------------------------------------------------------
;;; Certificate signing requests

(test certificate-signing-requests
  (let* ((keypair (generate-p256-keypair))
         (csr (make-certificate-signing-request keypair)))
    (multiple-value-bind (public-key subject) (decode-certificate-signing-request csr)
      (is (equalp (p256-keypair-public keypair) public-key))
      (is (equal *csr-default-subject* subject)))
    (multiple-value-bind (public-key subject)
        (decode-certificate-signing-request (make-certificate-signing-request keypair :subject '((:common-name "Lamp" :printable) (:country-name "DE"))))
      (is (equalp (p256-keypair-public keypair) public-key))
      (is (equal '((:common-name "Lamp" :printable) (:country-name "DE")) subject)))
    ;; the structure openssl expects
    (let ((top (der-node-children (der-decode csr))))
      (is (= 3 (length top)))
      (is (= 4 (length (der-node-children (first top)))))
      (is (= 0 (der-node-integer (der-child (first top) 0))))
      (is (= (der-context-tag 0 nil) (der-node-tag (der-child (first top) 3))))
      (is (string= "1.2.840.10045.4.3.2" (der-node-oid (der-child (second top) 0)))))
    ;; tampering
    (is (eq :invalid-csr (reason-of (lambda () (decode-certificate-signing-request (flip csr 30))))))
    (is (eq :invalid-csr (reason-of (lambda () (decode-certificate-signing-request (flip csr (- (length csr) 5)))))))
    (is (eq :invalid-csr (reason-of (lambda () (decode-certificate-signing-request (subseq csr 0 50))))))
    (is (eq :invalid-csr (reason-of (lambda () (decode-certificate-signing-request (der-sequence (der-integer 1)))))))
    (is (eq :invalid-argument (reason-of (lambda () (make-certificate-signing-request (p256-keypair-public keypair))))))
    (signals certificate-error (make-certificate-signing-request keypair :subject '((:bogus "x"))))))

;;; ------------------------------------------------------------------
;;; Certification declarations

(test certification-declaration-sdk-vectors
  (multiple-value-bind (cd kid tlv) (decode-certification-declaration *test-certification-declaration*)
    (is (= 1 (getf cd :format-version)))
    (is (= #xFFF1 (getf cd :vendor-id)))
    (is (= 100 (length (getf cd :product-ids))))
    (is (= #x8000 (first (getf cd :product-ids))))
    (is (= #x8063 (car (last (getf cd :product-ids)))))
    (is (= #x16 (getf cd :device-type-id)))
    (is (string= "CSA00000SWC00000-00" (getf cd :certificate-id)))
    (is (= 0 (getf cd :security-level)))
    (is (= 0 (getf cd :security-information)))
    (is (= 1 (getf cd :version-number)))
    (is (= 0 (getf cd :certification-type)))
    (is (null (getf cd :dac-origin-vendor-id)))
    (is (null (getf cd :authorized-paa-list)))
    (is (equalp (hex "fe343f959947763b61ee4539131338494fe67d8e") kid)) ; CSA signing key 001
    (is (equalp tlv (encode-certification-declaration-tlv cd))))
  ;; the CD inside the SDK's attestation vector, signed by the test key
  (multiple-value-bind (cd kid) (decode-certification-declaration
                                 (getf (decode-attestation-elements *sdk-attestation-elements*) :certification-declaration))
    (is (equal '(#x8000) (getf cd :product-ids)))
    (is (= #x1234 (getf cd :device-type-id)))
    (is (string= "ZIG20141ZB330001-24" (getf cd :certificate-id)))
    (is (= 9876 (getf cd :version-number)))
    (is (equalp (hex "62fa823359acfaa9963e1cfa140addf504f37160") kid))
    (is (equalp (certificate-subject-key-id (decode-certificate-pem *sdk-cd-signing-cert-pem*)) kid)))
  ;; the test construction CD is not CMS at all
  (is (eq :malformed (reason-of (lambda () (decode-certification-declaration *sdk-construction-cd*))))))

(test certification-declaration-round-trip
  (let* ((keypair (decode-ec-private-key-pem *sdk-cd-signing-key-pem*))
         (cd (list :format-version 1 :vendor-id #x1234 :product-ids '(1 2 3) :device-type-id #x0100
                   :certificate-id "CSA00000SWC00000-01" :security-level 0 :security-information 0
                   :version-number 2 :certification-type 1
                   :dac-origin-vendor-id #x5678 :dac-origin-product-id 9
                   :authorized-paa-list (list (octets-from 0 20) (octets-from 20 40))))
         (cms (encode-certification-declaration cd keypair)))
    (multiple-value-bind (decoded kid) (decode-certification-declaration cms)
      (is (equalp cd decoded))
      (is (equalp (subject-key-identifier (p256-keypair-public keypair)) kid)))
    ;; the same layout as the SDK's CDs: ContentInfo, SignedData v3, SignerInfo v3 with a key id
    (let ((top (der-node-children (der-decode cms))))
      (is (string= "1.2.840.113549.1.7.2" (der-node-oid (first top))))
      (is (= 3 (der-node-integer (der-child (der-child (second top) 0) 0)))))
    ;; signed by an unknown key, by a known key with a bad signature, tampered content
    (let ((other (generate-p256-keypair)))
      (is (eq :cd-signer-unknown (reason-of (lambda () (decode-certification-declaration (encode-certification-declaration cd other))))))
      (is (eq :cd-signature-invalid
              (reason-of (lambda () (decode-certification-declaration
                                     (encode-certification-declaration cd other :key-id (subject-key-identifier (p256-keypair-public keypair))))))))
      (let ((*cd-signing-keys* (copy-list *cd-signing-keys*)))
        (add-cd-signing-key (p256-keypair-public other))
        (is (equalp cd (decode-certification-declaration (encode-certification-declaration cd other))))))
    (is (eq :cd-signature-invalid (reason-of (lambda () (decode-certification-declaration (flip cms 60))))))
    (is (eq :malformed (reason-of (lambda () (decode-certification-declaration (subseq cms 0 80))))))
    (is (eq :malformed (reason-of (lambda () (decode-certification-declaration (der-sequence (der-oid "1.2.840.113549.1.7.1") (der-context 0 t)))))))
    ;; the TLV encoder's checks
    (is (eq :invalid-argument (reason-of (lambda () (encode-certification-declaration-tlv (list* :product-ids '() (cddr cd)))))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-certification-declaration-tlv (list* :format-version 1 :vendor-id 1 :product-ids '(1) :device-type-id 1 :certificate-id "short" (nthcdr 10 cd)))))))
    (is (eq :invalid-argument (reason-of (lambda () (encode-certification-declaration-tlv (subseq cd 0 16))))))
    (let ((no-origin-pid (append (subseq cd 0 18) (list :dac-origin-vendor-id 1))))
      (is (eq :invalid-argument (reason-of (lambda () (encode-certification-declaration-tlv no-origin-pid))))))
    ;; the TLV decoder's checks
    (flet ((bad (element) (is (eq :malformed (reason-of (lambda () (decode-certification-declaration-tlv (tlv-encode element))))))))
      (bad (tlv-structure nil (tlv 0 :unsigned 1)))
      (bad (tlv-structure nil (tlv 0 :unsigned 1) (tlv 1 :unsigned 1) (tlv 2 :array (list (tlv nil :string "x")))))
      (bad (tlv-structure nil (tlv 0 :unsigned 1) (tlv 1 :unsigned 1) (tlv 2 :array (list (tlv nil :unsigned 1)))
                          (tlv 3 :unsigned 1) (tlv 4 :string "CSA00000SWC00000-01") (tlv 5 :unsigned 0) (tlv 6 :unsigned 0)
                          (tlv 7 :unsigned 1) (tlv 8 :unsigned 0) (tlv 10 :unsigned 1)))
      (bad (tlv-structure nil (tlv 0 :unsigned 1) (tlv 1 :unsigned 1) (tlv 2 :array (list (tlv nil :unsigned 1)))
                          (tlv 3 :unsigned 1) (tlv 4 :string "CSA00000SWC00000-01") (tlv 5 :unsigned 0) (tlv 6 :unsigned 0)
                          (tlv 7 :unsigned 1) (tlv 8 :unsigned 0) (tlv 11 :array (list (tlv nil :octets (hex "01"))))))
      (bad (tlv-structure nil (tlv 0 :unsigned 1) (tlv 1 :unsigned 1) (tlv 2 :array (list (tlv nil :unsigned 1)))
                          (tlv 3 :unsigned 1) (tlv 4 :string "CSA00000SWC00000-01") (tlv 5 :unsigned 0) (tlv 6 :unsigned 0)
                          (tlv 7 :unsigned 1) (tlv 8 :unsigned 0) (tlv 12 :unsigned 0)))
      (bad (tlv 1 :unsigned 1)))))

;;; ------------------------------------------------------------------
;;; The attestation chain and the trust store

(test attestation-chain-validation
  (let ((dac (decode-certificate-pem *test-dac-pem*))
        (pai (decode-certificate-pem *test-pai-pem*))
        (paa (decode-certificate-pem (second *test-paa-pems*)))
        (paa-novid (decode-certificate-pem (first *test-paa-pems*))))
    (is (equalp (certificate-der paa) (certificate-der (find-trusted-paa pai))))
    (is (null (find-trusted-paa pai (list paa-novid))))
    (is (null (find-trusted-paa dac)))
    (multiple-value-bind (d p a) (validate-attestation-chain dac pai paa)
      (is (eq dac d)) (is (eq pai p)) (is (eq paa a)))
    ;; from PEM / DER too, and at a time inside the validity
    (is (validate-attestation-chain *test-dac-pem* (certificate-der pai) (second *test-paa-pems*)
                                    :time (matter-time (encode-universal-time 0 0 0 1 1 2024 0))))
    (is (eq :dac-expired (reason-of (lambda () (validate-attestation-chain dac pai paa :time 0)))))
    (is (eq :paa-signature-invalid (reason-of (lambda () (validate-attestation-chain dac pai (decode-certificate-der (flip (certificate-der paa) (- (length (certificate-der paa)) 8))))))))
    (is (eq :pai-signature-invalid (reason-of (lambda () (validate-attestation-chain dac pai paa-novid)))))
    (is (eq :dac-signature-invalid (reason-of (lambda () (validate-attestation-chain (decode-certificate-der (flip (certificate-der dac) (- (length (certificate-der dac)) 8))) pai paa)))))
    ;; profile checks
    (is (eq :dac-format-invalid (reason-of (lambda () (validate-attestation-chain pai pai paa)))))
    (is (eq :pai-format-invalid (reason-of (lambda () (validate-attestation-chain dac dac paa)))))
    (is (eq :paa-format-invalid (reason-of (lambda () (validate-attestation-chain dac pai pai)))))
    (is (eq :paa-format-invalid (reason-of (lambda () (validate-paa dac)))))
    (is (eq :malformed (reason-of (lambda () (validate-attestation-chain (hex "00") pai paa)))))
    (is (eq :malformed (reason-of (lambda () (validate-attestation-chain dac "garbage" paa)))))
    ;; vendor and product id rules, with chains of our own
    (flet ((chain (&key (paa-vid "FFF1") (pai-vid "FFF1") (pai-pid "8000") (dac-vid "FFF1") (dac-pid "8000") (dac-pid-p t))
             (let* ((paa-key (generate-p256-keypair)) (pai-key (generate-p256-keypair)) (dac-key (generate-p256-keypair))
                    (paa (make-root-certificate :keypair paa-key :x509 t
                                                :subject (append '((:common-name "PAA")) (when paa-vid (list (list :matter-vid paa-vid))))))
                    (pai (make-ica-certificate :keypair pai-key :issuer paa :issuer-keypair paa-key :x509 t
                                               :subject (append '((:common-name "PAI")) (list (list :matter-vid pai-vid))
                                                                (when pai-pid (list (list :matter-pid pai-pid))))))
                    (dac (make-node-certificate :public-key dac-key :issuer pai :issuer-keypair pai-key :x509 t
                                                :subject (append '((:common-name "DAC")) (list (list :matter-vid dac-vid))
                                                                 (when dac-pid-p (list (list :matter-pid dac-pid)))))))
               (reason-of (lambda () (validate-attestation-chain (decode-certificate-der (certificate-der dac))
                                                                 (decode-certificate-der (certificate-der pai))
                                                                 (decode-certificate-der (certificate-der paa))))))))
      (is (eq :ok (chain)))
      (is (eq :ok (chain :paa-vid nil)))
      (is (eq :ok (chain :pai-pid nil)))
      (is (eq :dac-vendor-id-mismatch (chain :dac-vid "FFF2")))
      (is (eq :dac-product-id-mismatch (chain :dac-pid "8001")))
      (is (eq :pai-vendor-id-mismatch (chain :paa-vid "FFF2")))
      (is (eq :dac-format-invalid (chain :dac-pid-p nil))))
    ;; the trust store
    (let ((*paa-trust-store* '()))
      (is (null (find-trusted-paa pai)))
      (add-trusted-paa (second *test-paa-pems*))
      (is (find-trusted-paa pai))
      (is (eq :paa-format-invalid (reason-of (lambda () (add-trusted-paa (certificate-der pai))))))
      (is (= 1 (length *paa-trust-store*))))))

;;; ------------------------------------------------------------------
;;; Device attestation, both sides

(test verify-device-attestation-sdk-vector
  "The SDK verifier's vector: DAC 0004 under PAI FFF1-8000, elements with
a test-key CD, a signature over elements || challenge."
  (let ((args (list :dac *sdk-dac-0004-der* :pai *sdk-pai-fff1-8000-der*
                    :elements *sdk-attestation-elements* :signature *sdk-attestation-signature*
                    :challenge *sdk-attestation-challenge* :nonce *sdk-attestation-nonce*
                    :vendor-id #xFFF1 :product-id #x8000)))
    (let ((result (apply #'verify-device-attestation args)))
      (is (certificate-p (getf result :dac)))
      (is (equalp *sdk-dac-0004-public-key* (certificate-public-key (getf result :dac))))
      (is (= #xFFF1 (getf result :vendor-id)))
      (is (= #x8000 (getf result :product-id)))
      (is (string= "ZIG20141ZB330001-24" (getf (getf result :certification-declaration) :certificate-id)))
      (is (equalp *sdk-attestation-nonce* (getf (getf result :elements) :nonce))))
    (flet ((with (&rest changes)
             (let ((plist (copy-list args)))
               (loop :for (k v) :on changes :by #'cddr :do (setf (getf plist k) v))
               (reason-of (lambda () (apply #'verify-device-attestation plist))))))
      (is (eq :ok (with :vendor-id nil :product-id nil)))
      (is (eq :nonce-mismatch (with :nonce (flip *sdk-attestation-nonce* 0))))
      (is (eq :attestation-signature-invalid (with :signature (flip *sdk-attestation-signature* 0))))
      (is (eq :attestation-signature-invalid (with :challenge (flip *sdk-attestation-challenge* 0))))
      (is (eq :attestation-signature-invalid (with :elements (flip *sdk-attestation-elements* 100))))
      (is (eq :cd-vendor-id-mismatch (with :vendor-id #xFFF2)))
      (is (eq :cd-product-id-mismatch (with :product-id #x8001)))
      (is (eq :attestation-signature-invalid (with :dac *test-dac-pem*))) ; another DAC of the same PAI: the signature is not its
      (is (eq :paa-not-found (with :trust-store '())))
      (is (eq :paa-not-found (with :pai *test-dac-pem*)))
      (is (eq :cd-signer-unknown (with :cd-signing-keys '())))
      (is (eq :malformed (with :elements (hex "15")))))))

(test attestation-end-to-end-with-the-example-credentials
  "The device side with the SDK example credentials, checked by the commissioner side."
  (let* ((credentials (test-attestation-credentials))
         (challenge (octets-from 100 116))
         (nonce (octets-from 0 32))
         (elements (encode-attestation-elements
                    :certification-declaration (attestation-credentials-certification-declaration credentials)
                    :nonce nonce :timestamp 0))
         (signature (sign-attestation (attestation-credentials-keypair credentials) elements challenge)))
    (is (= #xFFF1 (attestation-credentials-vendor-id credentials)))
    (is (= #x8000 (attestation-credentials-product-id credentials)))
    (is (= 64 (length signature)))
    (is (verify-attestation-signature (certificate-public-key (decode-certificate-der (attestation-credentials-dac credentials)))
                                      elements challenge signature))
    (let ((result (verify-device-attestation :dac (attestation-credentials-dac credentials)
                                             :pai (attestation-credentials-pai credentials)
                                             :elements elements :signature signature :challenge challenge :nonce nonce
                                             :vendor-id #xFFF1 :product-id #x8000)))
      (is (= 100 (length (getf (getf result :certification-declaration) :product-ids)))))
    (is (eq :cd-product-id-mismatch
            (reason-of (lambda () (verify-device-attestation :dac (attestation-credentials-dac credentials)
                                                             :pai (attestation-credentials-pai credentials)
                                                             :elements elements :signature signature :challenge challenge :nonce nonce
                                                             :vendor-id #xFFF1 :product-id #x9000)))))
    ;; the CSR leg
    (let* ((node-keypair (generate-p256-keypair))
           (csr-nonce (octets-from 32 64))
           (nocsr (encode-nocsr-elements :csr (make-certificate-signing-request node-keypair) :nonce csr-nonce))
           (nocsr-signature (sign-attestation (attestation-credentials-keypair credentials) nocsr challenge)))
      (multiple-value-bind (public-key plist subject)
          (verify-nocsr :elements nocsr :signature nocsr-signature :challenge challenge :nonce csr-nonce
                        :dac-public-key (certificate-public-key (decode-certificate-der (attestation-credentials-dac credentials))))
        (is (equalp (p256-keypair-public node-keypair) public-key))
        (is (equalp csr-nonce (getf plist :nonce)))
        (is (equal *csr-default-subject* subject)))
      (is (eq :nonce-mismatch (reason-of (lambda () (verify-nocsr :elements nocsr :signature nocsr-signature :challenge challenge
                                                                  :nonce nonce :dac-public-key (p256-keypair-public (attestation-credentials-keypair credentials)))))))
      (is (eq :attestation-signature-invalid
              (reason-of (lambda () (verify-nocsr :elements nocsr :signature nocsr-signature :challenge challenge :nonce csr-nonce
                                                  :dac-public-key (p256-keypair-public node-keypair)))))))
    ;; the SDK's NOCSR vector
    (multiple-value-bind (public-key) (verify-nocsr :elements *sdk-nocsr-elements* :signature *sdk-nocsr-signature*
                                                    :challenge *sdk-nocsr-challenge* :nonce *sdk-nocsr-nonce*
                                                    :dac-public-key *sdk-nocsr-dac-public-key*)
      (is (= 65 (length public-key))))
    (is (eq :attestation-signature-invalid
            (reason-of (lambda () (verify-nocsr :elements *sdk-nocsr-elements* :signature *sdk-nocsr-wrong-signature*
                                                :challenge *sdk-nocsr-challenge* :nonce *sdk-nocsr-nonce*
                                                :dac-public-key *sdk-nocsr-dac-public-key*)))))
    ;; credentials must be consistent
    (is (eq :invalid-argument (reason-of (lambda () (make-attestation-credentials
                                                     :dac *test-dac-pem* :pai *test-pai-pem* :keypair (generate-p256-keypair)
                                                     :certification-declaration *test-certification-declaration*)))))
    (is (eq :invalid-argument (reason-of (lambda () (make-attestation-credentials
                                                     :dac *test-dac-pem* :pai (second *test-paa-pems*) :keypair *test-dac-key-pem*
                                                     :certification-declaration *test-certification-declaration*)))))
    (is (eq :malformed (reason-of (lambda () (make-attestation-credentials
                                              :dac *test-dac-pem* :pai *test-pai-pem* :keypair *test-dac-key-pem*
                                              :certification-declaration (hex "3000"))))))
    (is (eq :invalid-argument (reason-of (lambda () (attestation-tbs elements (octets-from 0 15))))))))
