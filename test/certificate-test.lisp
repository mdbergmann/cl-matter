;;;; certificate-test.lisp -- P-256 signatures, DER, Matter certificates
;;;; and fabrics, against the SDK's test certificates (sdk-certificates.lisp)
;;;; and the specification's identifier vectors.

(in-package :cl-matter.case.tests)

(def-suite certificate-tests :description "P-256, DER, operational certificates, fabrics"
  :in cl-matter.tests:test-suite)
(in-suite certificate-tests)

(defun cat (&rest vectors)
  (apply #'concatenate '(vector (unsigned-byte 8)) vectors))

(defun sdk (name part)
  "The SDK vector *SDK-CERT-<NAME>-<PART>*."
  (symbol-value (find-symbol (string-upcase (format nil "*sdk-cert-~a-~a*" name part)) :cl-matter.case.tests)))

(defun sdk-certificate (name) (decode-certificate (sdk name "chip")))

(defparameter *sdk-cert-names*
  '("root01" "root02" "root03" "ica01" "ica02" "ica01-1" "fwsign01"
    "node01-01" "node01-02" "node02-01" "node02-02" "node02-03" "node02-04"
    "node02-05" "node02-06" "node02-07" "node02-08"))

;;; ------------------------------------------------------------------
;;; P-256

(test p256-public-keys-of-sdk-private-keys
  "Every SDK private key yields its public key."
  (dolist (name *sdk-cert-names*)
    (is (equalp (sdk name "publickey") (p256-public-key (sdk name "privatekey"))) "~a" name)
    (let ((keypair (make-p256-keypair (sdk name "privatekey"))))
      (is (equalp (sdk name "publickey") (p256-keypair-public keypair)))
      (is (equalp (sdk name "privatekey") (p256-keypair-private keypair))))))

(test p256-keypair-serialization
  (let* ((keypair (generate-p256-keypair))
         (octets (p256-keypair-octets keypair)))
    (is (= 97 (length octets)))
    (is (equalp (p256-keypair-public keypair) (subseq octets 0 65)))
    (is (equalp keypair (p256-keypair-from-octets octets)))
    (let ((bad (copy-seq octets)))
      (setf (aref bad 10) (logxor (aref bad 10) 1))
      (signals p256-error (p256-keypair-from-octets bad)))
    (signals p256-error (p256-keypair-from-octets (subseq octets 1)))
    (signals p256-error (make-p256-keypair 0))
    (signals p256-error (make-p256-keypair *p256-order*))
    (signals p256-error (make-p256-keypair (octets-from 0 31)))
    (is (p256-keypair-p (make-p256-keypair 1)))))

(test p256-points
  (is (p256-point-p (sdk "root01" "publickey")))
  (is (not (p256-point-p (subseq (sdk "root01" "publickey") 0 64))))
  (let ((off (copy-seq (sdk "root01" "publickey"))))
    (setf (aref off 64) (logxor (aref off 64) 1))
    (is (not (p256-point-p off)))
    (signals p256-error (p256-decode-point off)))
  (is (equalp (sdk "root01" "publickey") (p256-encode-point (p256-decode-point (sdk "root01" "publickey"))))))

(test p256-ecdh
  "ECDH is symmetric, 32 octets, and depends on both keys."
  (let* ((a (generate-p256-keypair)) (b (generate-p256-keypair)) (c (generate-p256-keypair))
         (ab (p256-ecdh a (p256-keypair-public b)))
         (ba (p256-ecdh (p256-keypair-private b) (p256-keypair-public a))))
    (is (= 32 (length ab)))
    (is (equalp ab ba))
    (is (not (equalp ab (p256-ecdh a (p256-keypair-public c)))))
    (signals p256-error (p256-ecdh a (subseq (p256-keypair-public b) 1)))
    (signals p256-error (p256-ecdh 0 (p256-keypair-public b)))))

(test p256-ecdsa
  (let* ((keypair (make-p256-keypair (sdk "node01-01" "privatekey")))
         (message (ascii "The quick brown fox"))
         (digest (cl-matter:sha256 message))
         (signature (p256-sign keypair message)))
    (is (= 64 (length signature)))
    (is (p256-verify (p256-keypair-public keypair) message signature))
    (is (p256-verify-digest (sdk "node01-01" "publickey") digest signature))
    (is (p256-verify (sdk "node01-01" "publickey") message (p256-sign-digest (sdk "node01-01" "privatekey") digest)))
    ;; signatures are randomized, both verify
    (is (not (equalp signature (p256-sign keypair message))))
    ;; wrong key, wrong message, tampered signature
    (is (not (p256-verify (sdk "node01-02" "publickey") message signature)))
    (is (not (p256-verify (p256-keypair-public keypair) (ascii "The quick brown fax") signature)))
    (let ((bad (copy-seq signature)))
      (setf (aref bad 0) (logxor (aref bad 0) 1))
      (is (not (p256-verify (p256-keypair-public keypair) message bad))))
    ;; malformed: wrong length, r or s zero or >= n
    (is (not (p256-verify (p256-keypair-public keypair) message (subseq signature 1))))
    (is (not (p256-verify (p256-keypair-public keypair) message
                          (cat (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                               (subseq signature 32)))))
    (is (not (p256-verify (p256-keypair-public keypair) message
                          (cat (subseq signature 0 32)
                               (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))))
    (signals p256-error (p256-verify (subseq (p256-keypair-public keypair) 1) message signature))
    (signals p256-error (p256-sign-digest keypair (subseq digest 1)))))

;;; ------------------------------------------------------------------
;;; DER

(test der-primitives
  (is (equalp (hex "020100") (der-integer 0)))
  (is (equalp (hex "02017f") (der-integer 127)))
  (is (equalp (hex "02020080") (der-integer 128)))
  (is (equalp (hex "02020100") (der-integer 256)))
  (is (equalp (hex "0201ff") (der-integer -1)))
  (is (equalp (hex "020180") (der-integer -128)))
  (is (equalp (hex "0202ff7f") (der-integer -129)))
  (is (equalp (hex "0202 0080") (der-unsigned-octets (hex "80"))))
  (is (equalp (hex "0201 7f") (der-unsigned-octets (hex "00007f"))))
  (is (equalp (hex "0201 00") (der-unsigned-octets (hex "0000"))))
  (is (equalp (hex "0203 ab cd ef") (der-integer-octets (hex "abcdef"))))
  (is (equalp (hex "06082a8648ce3d040302") (der-oid "1.2.840.10045.4.3.2")))
  (is (equalp (hex "0603550403") (der-oid "2.5.4.3")))
  (is (equalp (hex "060a2b0601040182a27c0101") (der-oid "1.3.6.1.4.1.37244.1.1")))
  (is (equalp (hex "0101ff") (der-boolean t)))
  (is (equalp (hex "010100") (der-boolean nil)))
  (is (equalp (hex "0500") (der-null)))
  (is (equalp (hex "0403010203") (der-octet-string (hex "010203"))))
  (is (equalp (hex "03020780") (der-bit-string-flags 1)))        ; digitalSignature
  (is (equalp (hex "03020106") (der-bit-string-flags #x60)))     ; keyCertSign, cRLSign
  (is (equalp (hex "0303070080") (der-bit-string-flags #x100)))  ; decipherOnly
  (is (equalp (hex "030100") (der-bit-string-flags 0)))
  (is (equalp (hex "030300aabb") (der-bit-string (hex "aabb"))))
  (is (equalp (hex "0c03 41 c3 a4") (der-utf8-string (coerce (list #\A (code-char 228)) 'string))))
  (is (equalp (hex "1302 41 42") (der-printable-string "AB")))
  (is (equalp (hex "1601 41") (der-ia5-string "A")))
  (is (equalp (cat (hex "170d") (ascii "201015142343Z")) (der-utc-time "201015142343Z")))
  (is (equalp (cat (hex "180f") (ascii "99991231235959Z")) (der-generalized-time "99991231235959Z")))
  (is (equalp (hex "a003020102") (der-context 0 t (der-integer 2))))
  (is (equalp (hex "8002abcd") (der-context 0 nil (hex "abcd"))))
  (is (equalp (hex "3005 0101ff 0500") (der-sequence (der-boolean t) (der-null))))
  (is (equalp (hex "3102 0500") (der-set (der-null)))))

(test der-long-lengths
  (let ((v200 (make-array 200 :element-type '(unsigned-byte 8) :initial-element 7))
        (v300 (make-array 300 :element-type '(unsigned-byte 8) :initial-element 7))
        (v70000 (make-array 70000 :element-type '(unsigned-byte 8) :initial-element 7)))
    (is (equalp (cat (hex "0481c8") v200) (der-octet-string v200)))
    (is (equalp (cat (hex "0482012c") v300) (der-octet-string v300)))
    (is (equalp (cat (hex "04830111 70") v70000) (der-octet-string v70000)))))

;;; ------------------------------------------------------------------
;;; Times

(test matter-time
  (is (= 0 (matter-time (encode-universal-time 0 0 0 1 1 2000 0))))
  (is (= 1 (matter-time (encode-universal-time 1 0 0 1 1 2000 0))))
  (is (= (encode-universal-time 43 23 14 15 10 2020 0) (matter-time-universal (matter-time (encode-universal-time 43 23 14 15 10 2020 0)))))
  ;; Root01: Not Before Oct 15 14:23:43 2020 GMT, Not After Oct 15 14:23:42 2040 GMT
  (let ((root (sdk-certificate "root01")))
    (is (= (matter-time (encode-universal-time 43 23 14 15 10 2020 0)) (certificate-not-before root)))
    (is (= (matter-time (encode-universal-time 42 23 14 15 10 2040 0)) (certificate-not-after root)))
    (is (certificate-valid-at-p root (matter-time (encode-universal-time 0 0 0 1 1 2030 0))))
    (is (not (certificate-valid-at-p root (matter-time (encode-universal-time 0 0 0 1 1 2019 0)))))
    (is (not (certificate-valid-at-p root (matter-time (encode-universal-time 0 0 0 1 1 2041 0)))))
    (is (< (matter-time) (certificate-not-after root)))))

(defun der-contains-p (der string)
  (search (ascii string) der))

(test der-time-forms
  "Before 2050 UTCTime, from 2050 GeneralizedTime, 0 the no-expiry time."
  (let* ((keypair (generate-p256-keypair))
         (never (make-root-certificate :keypair keypair :not-before 0 :not-after 0))
         (far (make-root-certificate :keypair keypair
                                     :not-before (matter-time (encode-universal-time 0 0 0 1 1 2049 0))
                                     :not-after (matter-time (encode-universal-time 59 59 23 31 12 2050 0)))))
    (is (der-contains-p (certificate-tbs-der never) "99991231235959Z"))
    (is (der-contains-p (certificate-tbs-der far) "490101000000Z"))
    (is (der-contains-p (certificate-tbs-der far) "20501231235959Z"))
    (is (certificate-valid-at-p never (matter-time)))
    (is (certificate-valid-at-p never #xFFFFFFFF))))

;;; ------------------------------------------------------------------
;;; The SDK's certificates: TLV in, DER out, byte for byte

(test sdk-certificates-decode-encode-convert
  (dolist (name *sdk-cert-names*)
    (let ((c (sdk-certificate name)))
      (is (equalp (sdk name "chip") (certificate-octets c)) "~a octets" name)
      (is (equalp (sdk name "chip") (encode-certificate c)) "~a TLV round trip" name)
      (is (equalp (sdk name "der") (certificate-der c)) "~a DER" name)
      (is (equalp (sdk name "publickey") (certificate-public-key c)) "~a public key" name)
      (is (equalp (sdk name "subjectkeyid") (certificate-subject-key-id c)) "~a SKID" name)
      (is (equalp (sdk name "authoritykeyid") (certificate-authority-key-id c)) "~a AKID" name)
      (is (equalp (sdk name "subjectkeyid") (subject-key-identifier (certificate-public-key c)))
          "~a SKID is SHA-1 of the key" name)
      (is (= 1 (certificate-signature-algorithm c)))
      (is (= 1 (certificate-public-key-algorithm c)))
      (is (= 1 (certificate-curve c)))
      ;; the DER signature wraps the raw one
      (let ((tail (ecdsa-signature-der (certificate-signature c))))
        (is (search tail (certificate-der c)))))))

(test sdk-certificate-fields
  (let ((root (sdk-certificate "root01")) (ica (sdk-certificate "ica01")) (node (sdk-certificate "node01-01")))
    (is (equalp (hex "534c458273623514") (certificate-serial-number root)))
    (is (equal '((:matter-rcac-id #xCACACACA00000001)) (certificate-subject root)))
    (is (dn-equal (certificate-subject root) (certificate-issuer root)))
    (is (equal '((:basic-constraints :ca t) (:key-usage :key-cert-sign :crl-sign))
               (subseq (certificate-extensions root) 0 2)))
    (is (certificate-ca-p root))
    (is (null (certificate-path-length root)))
    (is (equal '((:matter-icac-id #xCACACACA00000003)) (certificate-subject ica)))
    (is (equal '((:matter-rcac-id #xCACACACA00000001)) (certificate-issuer ica)))
    (is (equal '((:matter-node-id #xDEDEDEDE00010001) (:matter-fabric-id #xFAB000000000001D))
               (certificate-subject node)))
    (is (not (certificate-ca-p node)))
    (is (equal '(:digital-signature) (certificate-key-usage node)))
    (is (equal '(:client-auth :server-auth) (certificate-extended-key-usage node)))
    (is (eq :root (certificate-type root)))
    (is (eq :ica (certificate-type ica)))
    (is (eq :node (certificate-type node)))
    (is (eq :firmware-signing (certificate-type (sdk-certificate "fwsign01"))))
    (is (equal '(#xABCD0010 #xABCE1008) (certificate-case-auth-tags (sdk-certificate "node02-05"))))
    (is (equal '(#xABCF00A0 #xABCD0020 #xABCE0100) (certificate-case-auth-tags (sdk-certificate "node02-08"))))
    (is (null (certificate-case-auth-tags node)))
    ;; Node02_05..07 carry future extensions, 07's is critical
    (is (find :future (certificate-extensions (sdk-certificate "node02-05")) :key #'first))
    (is (= 2 (count :future (certificate-extensions (sdk-certificate "node02-06")) :key #'first)))
    (is (null (find :future (certificate-extensions node) :key #'first)))))

(test sdk-node-and-fabric-ids
  (loop :for (name node-id) :in '(("node01-01" #xDEDEDEDE00010001) ("node01-02" #xDEDEDEDE00010002)
                                  ("node02-01" #xDEDEDEDE00020001) ("node02-02" #xDEDEDEDE00020002)
                                  ("node02-03" #xDEDEDEDE00020003) ("node02-04" #xDEDEDEDE00020004)
                                  ("node02-05" #xDEDEDEDE00020005) ("node02-06" #xDEDEDEDE00020006)
                                  ("node02-07" #xDEDEDEDE00020007) ("node02-08" #xDEDEDEDE00020008))
        :do (let ((c (sdk-certificate name)))
              (is (= node-id (certificate-node-id c)) "~a" name)
              (is (= #xFAB000000000001D (certificate-fabric-id c)) "~a" name))))

(test sdk-signatures
  (flet ((signed-by (name signer)
           (is (verify-certificate-signature (sdk-certificate name) (sdk-certificate signer)) "~a by ~a" name signer)
           (is (verify-certificate-signature (sdk-certificate name) (sdk signer "publickey")))))
    (signed-by "root01" "root01")
    (signed-by "root02" "root02")
    (signed-by "root03" "root03")
    (signed-by "ica01" "root01")
    (signed-by "ica02" "root02")
    (signed-by "node01-01" "ica01")
    (signed-by "node01-02" "root01")
    (dolist (name '("node02-01" "node02-02" "node02-03" "node02-04" "node02-05" "node02-06" "node02-07" "node02-08"))
      (signed-by name "ica02")))
  (is (not (verify-certificate-signature (sdk-certificate "node01-01") (sdk-certificate "root01"))))
  (is (not (verify-certificate-signature (sdk-certificate "ica01") (sdk-certificate "root02"))))
  ;; a flipped bit anywhere in the TBS breaks the signature
  (let ((c (sdk-certificate "node01-01")))
    (setf (certificate-not-after c) (1+ (certificate-not-after c)))
    (is (not (verify-certificate-signature c (sdk-certificate "ica01"))))))

(test sdk-malformed-certificate
  "Node01_01 with an extension under a common-profile tag."
  (signals certificate-error (decode-certificate (sdk "node01-01-err01" "chip"))))

(test decode-certificate-rejections
  (let ((good (sdk "node01-01" "chip")))
    (signals certificate-error (decode-certificate (subseq good 0 (1- (length good)))))
    (signals certificate-error (decode-certificate (cat good (hex "00"))))
    (signals certificate-error (decode-certificate (hex "16 18")))
    (signals certificate-error (decode-certificate "not octets"))
    (signals certificate-error (decode-certificate (hex "15 18")))))

(defun rebuild (name &rest changes)
  "The SDK certificate NAME with CHANGES (a plist of slot keyword and value) applied, re-encoded."
  (let ((c (sdk-certificate name)))
    (loop :for (slot value) :on changes :by #'cddr
          :do (ecase slot
                (:subject (setf (certificate-subject c) value))
                (:issuer (setf (certificate-issuer c) value))
                (:extensions (setf (certificate-extensions c) value))
                (:public-key (setf (certificate-public-key c) value))
                (:signature (setf (certificate-signature c) value))
                (:curve (setf (certificate-curve c) value))
                (:signature-algorithm (setf (certificate-signature-algorithm c) value))
                (:not-before (setf (certificate-not-before c) value))
                (:not-after (setf (certificate-not-after c) value))))
    (encode-certificate c)))

(test decode-certificate-field-checks
  (signals certificate-error (decode-certificate (rebuild "node01-01" :curve 2)))
  (signals certificate-error (decode-certificate (rebuild "node01-01" :signature-algorithm 2)))
  (signals certificate-error (decode-certificate (rebuild "node01-01" :not-before (ash 1 32))))
  (signals certificate-error (decode-certificate (rebuild "node01-01" :extensions '((:key-usage :digital-signature)
                                                                                      (:key-usage :digital-signature)))))
  (let ((off (copy-seq (sdk "node01-01" "publickey"))))
    (setf (aref off 64) (logxor (aref off 64) 1))
    (signals certificate-error (decode-certificate (rebuild "node01-01" :public-key off))))
  (signals certificate-error (rebuild "node01-01" :public-key (subseq (sdk "node01-01" "publickey") 1)))
  (signals certificate-error (rebuild "node01-01" :signature (octets-from 0 63)))
  (signals certificate-error (rebuild "node01-01" :subject '((:no-such-attribute 1))))
  (signals certificate-error (rebuild "node01-01" :subject '((:matter-node-id "string"))))
  (signals certificate-error (rebuild "node01-01" :subject '((:common-name 42))))
  (signals certificate-error (rebuild "node01-01" :subject '((:matter-node-id 1 :printable))))
  (signals certificate-error (rebuild "node01-01" :extensions '((:key-usage :no-such-usage))))
  (signals certificate-error (rebuild "node01-01" :extensions '((:extended-key-usage :no-such-purpose))))
  ;; a DER-level future extension travels untouched
  (let* ((future (hex "300c0603551d1104050403020100"))
         (c (decode-certificate (rebuild "node01-01" :extensions (list '(:basic-constraints :ca nil)
                                                                       (list :future future))))))
    (is (equalp future (second (certificate-extension c :future))))
    (is (search future (certificate-der c)))))

;;; ------------------------------------------------------------------
;;; Distinguished names

(test dn-helpers
  (let ((dn '((:matter-noc-cat #xABCD0010) (:matter-fabric-id 29) (:matter-noc-cat #xABCE1008) (:matter-node-id 5))))
    (is (= 29 (dn-attribute dn :matter-fabric-id)))
    (is (= #xABCD0010 (dn-attribute dn :matter-noc-cat)))
    (is (equal '(#xABCD0010 #xABCE1008) (dn-attributes dn :matter-noc-cat)))
    (is (null (dn-attribute dn :common-name)))
    (is (dn-equal dn (copy-tree dn)))
    (is (not (dn-equal dn (reverse dn))))
    (is (not (dn-equal '((:common-name "x")) '((:common-name "x" :printable)))))
    (is (dn-equal '((:common-name "x" :printable)) '((:common-name "x" :printable))))
    (is (not (dn-equal '((:common-name "x")) '((:common-name "y")))))))

(test dn-string-attributes-round-trip
  "UTF8String, PrintableString and IA5String attributes survive TLV and reach DER as their type."
  (let* ((keypair (generate-p256-keypair))
         (subject (list (list :matter-rcac-id 7)
                        (list :common-name "Matter Test" :printable)
                        (list :organization-name (coerce (list #\M (code-char 252) #\n) 'string))
                        (list :domain-component "example")))
         (root (make-root-certificate :keypair keypair :subject subject))
         (again (decode-certificate (certificate-octets root))))
    (is (dn-equal subject (certificate-subject again)))
    (is (dn-equal subject (certificate-issuer again)))
    (let ((der (certificate-der root)))
      (is (search (der-printable-string "Matter Test") der))
      (is (search (der-utf8-string (coerce (list #\M (code-char 252) #\n) 'string)) der))
      (is (search (der-ia5-string "example") der))
      (is (search (der-utf8-string "0000000000000007") der)))
    (is (eq :root (certificate-type again)))
    (is (verify-certificate-signature again root))))

;;; ------------------------------------------------------------------
;;; Certificate types

(defun subject-type (subject)
  (certificate-type (make-certificate :subject subject)))

(test certificate-types
  (is (eq :root (subject-type '((:matter-rcac-id 1)))))
  (is (eq :root (subject-type '((:matter-rcac-id 1) (:matter-fabric-id 1)))))
  (is (eq :ica (subject-type '((:matter-fabric-id 1) (:matter-icac-id 1)))))
  (is (eq :node (subject-type '((:matter-node-id 1) (:matter-fabric-id 1)))))
  (is (eq :node (subject-type '((:matter-noc-cat #x00010001) (:matter-node-id #xFFFFFFEFFFFFFFFF) (:matter-fabric-id 1)))))
  (is (eq :firmware-signing (subject-type '((:matter-firmware-signing-id 1)))))
  (is (null (subject-type '((:common-name "anything")))))
  (is (null (subject-type nil)))
  (signals certificate-error (subject-type '((:matter-rcac-id 1) (:matter-icac-id 1))))
  (signals certificate-error (subject-type '((:matter-node-id 1) (:matter-rcac-id 1) (:matter-fabric-id 1))))
  (signals certificate-error (subject-type '((:matter-node-id 1))))
  (signals certificate-error (subject-type '((:matter-node-id 0) (:matter-fabric-id 1))))
  (signals certificate-error (subject-type '((:matter-node-id #xFFFFFFF000000000) (:matter-fabric-id 1))))
  (signals certificate-error (subject-type '((:matter-node-id 1) (:matter-fabric-id 0))))
  (signals certificate-error (subject-type '((:matter-node-id 1) (:matter-fabric-id 1) (:matter-fabric-id 2))))
  (signals certificate-error (subject-type '((:matter-icac-id 1) (:matter-noc-cat #x00010001))))
  (signals certificate-error (subject-type '((:matter-node-id 1) (:matter-fabric-id 1) (:matter-noc-cat #x00010000)))))

(test identifier-predicates
  (is (operational-node-id-p 1))
  (is (operational-node-id-p #xFFFFFFEFFFFFFFFF))
  (is (not (operational-node-id-p 0)))
  (is (not (operational-node-id-p #xFFFFFFF000000000)))
  (is (not (operational-node-id-p #xFFFFFFFF00000001)))
  (is (not (operational-node-id-p "1")))
  (is (fabric-id-p 1))
  (is (fabric-id-p #xFFFFFFFFFFFFFFFF))
  (is (not (fabric-id-p 0)))
  (is (not (fabric-id-p (ash 1 64))))
  (is (case-auth-tag-p #xABCD0001))
  (is (not (case-auth-tag-p #xABCD0000)))
  (is (not (case-auth-tag-p (ash 1 32)))))

;;; ------------------------------------------------------------------
;;; Chain validation

(test sdk-chains-validate
  (multiple-value-bind (node-id fabric-id cats noc-key root-key)
      (validate-certificate-chain (sdk "node01-01" "chip") (sdk "ica01" "chip") (sdk "root01" "chip"))
    (is (= #xDEDEDEDE00010001 node-id))
    (is (= #xFAB000000000001D fabric-id))
    (is (null cats))
    (is (equalp (sdk "node01-01" "publickey") noc-key))
    (is (equalp (sdk "root01" "publickey") root-key)))
  ;; without an ICAC, certificates instead of octets
  (is (= #xDEDEDEDE00010002
         (validate-certificate-chain (sdk-certificate "node01-02") nil (sdk-certificate "root01"))))
  (dolist (name '("node02-01" "node02-02" "node02-03" "node02-04" "node02-05" "node02-06" "node02-08"))
    (finishes (validate-certificate-chain (sdk name "chip") (sdk "ica02" "chip") (sdk "root02" "chip"))))
  (is (equal '(#xABCD0010 #xABCE1008)
             (nth-value 2 (validate-certificate-chain (sdk "node02-05" "chip") (sdk "ica02" "chip") (sdk "root02" "chip")))))
  ;; with a time inside the validity period
  (finishes (validate-certificate-chain (sdk "node01-01" "chip") (sdk "ica01" "chip") (sdk "root01" "chip")
                                        :time (matter-time (encode-universal-time 0 0 0 1 1 2030 0)))))

(test sdk-chains-that-fail
  (flet ((fails (noc icac rcac &rest keys)
           (signals certificate-error
             (apply #'validate-certificate-chain (sdk noc "chip") (and icac (sdk icac "chip")) (sdk rcac "chip") keys))))
    ;; the critical future extension of Node02_07
    (fails "node02-07" "ica02" "root02")
    ;; the wrong root, a missing ICA, the wrong ICA
    (fails "node01-01" "ica01" "root02")
    (fails "node01-01" nil "root01")
    (fails "node01-01" "ica02" "root01")
    (fails "node02-01" "ica01" "root01")
    (fails "node01-02" "ica01" "root01")
    ;; the wrong kinds in the slots
    (fails "root01" "ica01" "root01")
    (fails "ica01" nil "root01")
    (fails "node01-01" "root01" "ica01")
    (fails "node01-01" "node01-02" "root01")
    (fails "fwsign01" "ica01" "root01")
    ;; outside the validity period
    (fails "node01-01" "ica01" "root01" :time (matter-time (encode-universal-time 0 0 0 1 1 2019 0)))
    (fails "node01-01" "ica01" "root01" :time (matter-time (encode-universal-time 0 0 0 1 1 2041 0)))))

(test validate-rcac
  (is (certificate-p (validate-rcac (sdk "root01" "chip"))))
  (is (certificate-p (validate-rcac (sdk-certificate "root02"))))
  (signals certificate-error (validate-rcac (sdk "ica01" "chip")))
  (signals certificate-error (validate-rcac (sdk "node01-01" "chip")))
  (let ((keypair (generate-p256-keypair)))
    (finishes (validate-rcac (make-root-certificate :keypair keypair)))
    ;; a root with a path length above 1 is refused; so is one that cannot sign
    (let ((c (make-root-certificate :keypair keypair)))
      (setf (certificate-extensions c)
            (list '(:basic-constraints :ca t :path-length 2) '(:key-usage :key-cert-sign)
                  (certificate-extension c :subject-key-id) (certificate-extension c :authority-key-id)))
      (signals certificate-error (validate-rcac (sign-certificate c keypair))))
    (let ((c (make-root-certificate :keypair keypair)))
      (setf (certificate-extensions c)
            (list '(:basic-constraints :ca t) '(:key-usage :digital-signature)
                  (certificate-extension c :subject-key-id) (certificate-extension c :authority-key-id)))
      (signals certificate-error (validate-rcac (sign-certificate c keypair))))
    ;; or whose signature is by another key
    (let ((c (make-root-certificate :keypair keypair)))
      (signals certificate-error (validate-rcac (sign-certificate c (generate-p256-keypair)))))))

;;; ------------------------------------------------------------------
;;; Making certificates

(test generated-chain
  (let* ((root-keypair (generate-p256-keypair))
         (ica-keypair (generate-p256-keypair))
         (node-keypair (generate-p256-keypair))
         (rcac (make-root-certificate :keypair root-keypair :rcac-id #xCAFE))
         (icac (make-ica-certificate :keypair ica-keypair :icac-id 3 :fabric-id #x1D
                                     :issuer rcac :issuer-keypair root-keypair))
         (noc (make-node-certificate :public-key node-keypair :node-id #x1234 :fabric-id #x1D
                                     :case-auth-tags '(#xABCD0001)
                                     :issuer icac :issuer-keypair ica-keypair)))
    (is (eq :root (certificate-type rcac)))
    (is (eq :ica (certificate-type icac)))
    (is (eq :node (certificate-type noc)))
    (is (equal '((:matter-rcac-id #xCAFE)) (certificate-subject rcac)))
    (is (equal '((:matter-icac-id 3) (:matter-fabric-id #x1D)) (certificate-subject icac)))
    (is (equal '((:matter-node-id #x1234) (:matter-fabric-id #x1D) (:matter-noc-cat #xABCD0001)) (certificate-subject noc)))
    (is (dn-equal (certificate-subject icac) (certificate-issuer noc)))
    (is (equalp (certificate-subject-key-id icac) (certificate-authority-key-id noc)))
    (is (equalp (subject-key-identifier (p256-keypair-public node-keypair)) (certificate-subject-key-id noc)))
    (is (= 0 (certificate-path-length icac)))
    (is (zerop (certificate-not-after noc)))
    (is (<= (certificate-not-before noc) (matter-time)))
    (is (= 8 (length (certificate-serial-number rcac))))
    (is (not (logbitp 7 (aref (certificate-serial-number rcac) 0))))
    (multiple-value-bind (node-id fabric-id cats)
        (validate-certificate-chain (certificate-octets noc) (certificate-octets icac) (certificate-octets rcac)
                                    :time (matter-time))
      (is (= #x1234 node-id))
      (is (= #x1D fabric-id))
      (is (equal '(#xABCD0001) cats)))
    ;; decoding our own encoding gives back the same certificate
    (let ((again (decode-certificate (certificate-octets noc))))
      (is (dn-equal (certificate-subject noc) (certificate-subject again)))
      (is (equalp (certificate-extensions noc) (certificate-extensions again)))
      (is (equalp (certificate-signature noc) (certificate-signature again)))
      (is (equalp (certificate-der noc) (certificate-der again))))
    ;; a NOC signed straight by the root
    (let ((direct (make-node-certificate :public-key node-keypair :node-id 2 :fabric-id #x1D
                                         :issuer rcac :issuer-keypair root-keypair)))
      (is (= 2 (validate-certificate-chain direct nil rcac))))
    ;; the wrong signer, a tampered NOC, an ICAC for another fabric
    (signals certificate-error
      (validate-certificate-chain (make-node-certificate :public-key node-keypair :node-id 2 :fabric-id #x1D
                                                         :issuer icac :issuer-keypair root-keypair)
                                  icac rcac))
    (let ((tampered (copy-seq (certificate-octets noc))))
      (setf (aref tampered 20) (logxor (aref tampered 20) 1))
      (signals certificate-error (validate-certificate-chain tampered icac rcac)))
    (signals certificate-error
      (validate-certificate-chain (make-node-certificate :public-key node-keypair :node-id 2 :fabric-id #x1E
                                                         :issuer icac :issuer-keypair ica-keypair)
                                  icac rcac))
    ;; a root whose path length forbids an ICA
    (let ((short (make-root-certificate :keypair root-keypair)))
      (setf (certificate-extensions short)
            (list '(:basic-constraints :ca t :path-length 0) '(:key-usage :key-cert-sign :crl-sign)
                  (certificate-extension short :subject-key-id) (certificate-extension short :authority-key-id)))
      (sign-certificate short root-keypair)
      (let ((icac (make-ica-certificate :keypair ica-keypair :issuer short :issuer-keypair root-keypair))
            (noc (make-node-certificate :public-key node-keypair :node-id 2 :fabric-id #x1D
                                        :issuer short :issuer-keypair root-keypair)))
        (is (= 2 (validate-certificate-chain noc nil short)))
        (signals certificate-error
          (validate-certificate-chain (make-node-certificate :public-key node-keypair :node-id 2 :fabric-id #x1D
                                                             :issuer icac :issuer-keypair ica-keypair)
                                      icac short))))
    ;; malformed subjects fail at construction
    (signals certificate-error (make-node-certificate :public-key node-keypair :node-id 0 :fabric-id #x1D
                                                      :issuer rcac :issuer-keypair root-keypair))
    (signals certificate-error (make-node-certificate :public-key node-keypair :node-id 1 :fabric-id #x1D
                                                      :case-auth-tags '(#xABCD0000)
                                                      :issuer rcac :issuer-keypair root-keypair))))

(test serial-numbers
  (let ((keypair (generate-p256-keypair)))
    (is (equalp (hex "01") (certificate-serial-number (make-root-certificate :keypair keypair :serial-number 1))))
    (is (equalp (hex "00ff") (certificate-serial-number (make-root-certificate :keypair keypair :serial-number 255))))
    (is (equalp (hex "0100") (certificate-serial-number (make-root-certificate :keypair keypair :serial-number 256))))
    (is (equalp (hex "00abcd") (certificate-serial-number (make-root-certificate :keypair keypair :serial-number (hex "abcd")))))
    (is (equalp (hex "12") (certificate-serial-number (make-root-certificate :keypair keypair :serial-number (hex "12")))))))

;;; ------------------------------------------------------------------
;;; Fabric identifiers (specification vectors via the SDK's tests)

(defparameter *spec-root-public-key*
  (hex "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"))

(test compressed-fabric-id-vector
  (multiple-value-bind (octets integer) (compressed-fabric-id *spec-root-public-key* #x2906C908D115D362)
    (is (equalp (hex "87e1b004e235a130") octets))
    (is (= #x87e1b004e235a130 integer)))
  (signals certificate-error (compressed-fabric-id (make-array 65 :element-type '(unsigned-byte 8) :initial-element 0) 1))
  (signals certificate-error (compressed-fabric-id *spec-root-public-key* (ash 1 64))))

(test operational-group-key-vectors
  (is (equalp (hex "1f19ed3cef8a211baf306faeeee7aac6")
              (operational-group-key (hex "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf") (hex "2906C908D115D362"))))
  (is (equalp (hex "aa979a48bd8cdf293a0709b9c1eb1930")
              (operational-group-key (hex "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf") (hex "2906C908D115D362"))))
  (is (equalp (hex "a6f5306baf6d050af23ba4bd6b9dd960")
              (operational-group-key (hex "235bf7e62823d358dca4ba50b1535f4b") (hex "87e1b004e235a130"))))
  (is (= #x6c80 (group-session-id (hex "1f19ed3cef8a211baf306faeeee7aac6"))))
  (is (= #x0c48 (group-session-id (hex "aa979a48bd8cdf293a0709b9c1eb1930"))))
  (signals certificate-error (operational-group-key (hex "a0a1") (hex "2906C908D115D362")))
  (signals certificate-error (operational-group-key (hex "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf") (hex "2906"))))

(test case-destination-id-vector
  (let ((ipk (hex "9bc61cd9c62a2df6d64dfcaa9dc472d4"))
        (random (hex "7e171231568dfa17206b3accf8faec2f4d21b5801131 96f47c7c4deb810a73dc")))
    (is (equalp (hex "dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53")
                (case-destination-id ipk random *spec-root-public-key* #x2906C908D115D362 #xCD5544AA7B13EF14)))
    (is (not (equalp (hex "dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53")
                     (case-destination-id ipk random *spec-root-public-key* #x2906C908D115D362 #xCD5544AA7B13EF15))))
    (signals certificate-error (case-destination-id ipk (subseq random 1) *spec-root-public-key* 1 1))
    (signals certificate-error (case-destination-id ipk random (subseq *spec-root-public-key* 1) 1 1))))

;;; ------------------------------------------------------------------
;;; Fabrics

(defun sdk-fabric (noc icac &key (epoch-key (octets-from 0 16)))
  (make-fabric :rcac (sdk "root01" "chip") :icac (and icac (sdk icac "chip")) :noc (sdk noc "chip")
               :operational-keypair (make-p256-keypair (sdk noc "privatekey"))
               :epoch-key epoch-key))

(test make-fabric-from-sdk-credentials
  (let ((f (sdk-fabric "node01-01" "ica01")))
    (is (= #xDEDEDEDE00010001 (fabric-node-id f)))
    (is (= #xFAB000000000001D (fabric-fabric-id f)))
    (is (null (fabric-case-auth-tags f)))
    (is (equalp (sdk "root01" "publickey") (fabric-root-public-key f)))
    (is (equalp (compressed-fabric-id (sdk "root01" "publickey") #xFAB000000000001D) (fabric-compressed-fabric-id f)))
    (is (equalp (operational-group-key (octets-from 0 16) (fabric-compressed-fabric-id f)) (fabric-ipk f)))
    (is (= 16 (length (fabric-ipk f))))
    (is (certificate-p (fabric-icac f)))
    (is (string= (format nil "~16,'0x-DEDEDEDE00010001" (nth-value 1 (compressed-fabric-id (sdk "root01" "publickey") #xFAB000000000001D)))
                 (fabric-operational-instance-name f)))
    (is (= 33 (length (fabric-operational-instance-name f))))
    (is (string= "-DEDEDEDE00010002" (subseq (fabric-operational-instance-name f #xDEDEDEDE00010002) 16)))
    (let ((random (octets-from 0 32)))
      (is (equalp (case-destination-id (fabric-ipk f) random (sdk "root01" "publickey") #xFAB000000000001D #xDEDEDEDE00010001)
                  (fabric-destination-id f random)))
      (is (equalp (case-destination-id (fabric-ipk f) random (sdk "root01" "publickey") #xFAB000000000001D 7)
                  (fabric-destination-id f random 7)))))
  (let ((f (sdk-fabric "node01-02" nil)))
    (is (= #xDEDEDEDE00010002 (fabric-node-id f)))
    (is (null (fabric-icac f))))
  ;; the NOC must certify the key pair given
  (signals certificate-error
    (make-fabric :rcac (sdk "root01" "chip") :icac (sdk "ica01" "chip") :noc (sdk "node01-01" "chip")
                 :operational-keypair (make-p256-keypair (sdk "node01-02" "privatekey"))
                 :epoch-key (octets-from 0 16)))
  (signals certificate-error
    (make-fabric :rcac (sdk "root01" "chip") :noc (sdk "node01-01" "chip")
                 :operational-keypair (make-p256-keypair (sdk "node01-01" "privatekey"))
                 :epoch-key (octets-from 0 16)))
  (signals certificate-error
    (make-fabric :rcac (sdk "root01" "chip") :icac (sdk "ica01" "chip") :noc (sdk "node01-01" "chip")
                 :operational-keypair (sdk "node01-01" "privatekey")
                 :epoch-key (octets-from 0 16))))

(test generated-fabrics
  (multiple-value-bind (f root-keypair ica-keypair) (make-test-fabric :fabric-id #x77 :node-id 5 :icac t
                                                                      :case-auth-tags '(#x00010001))
    (is (= #x77 (fabric-fabric-id f)))
    (is (= 5 (fabric-node-id f)))
    (is (equal '(#x00010001) (fabric-case-auth-tags f)))
    (is (certificate-p (fabric-icac f)))
    (is (equalp (p256-keypair-public root-keypair) (fabric-root-public-key f)))
    (is (= 16 (length (fabric-epoch-key f))))
    (let ((g (fabric-add-node f 6 :ica-keypair ica-keypair))
          (h (fabric-add-node f 7 :root-keypair root-keypair :case-auth-tags '(#xABCD0002))))
      (is (= 6 (fabric-node-id g)))
      (is (= 7 (fabric-node-id h)))
      (is (null (fabric-icac h)))
      (is (equalp (fabric-ipk f) (fabric-ipk g)))
      (is (equalp (fabric-ipk f) (fabric-ipk h)))
      (is (equalp (fabric-compressed-fabric-id f) (fabric-compressed-fabric-id h)))
      (is (equal '(#xABCD0002) (fabric-case-auth-tags h)))
      (is (equalp (fabric-destination-id f (octets-from 0 32) 6) (fabric-destination-id g (octets-from 0 32))))))
  (let ((plain (make-test-fabric)))
    (is (null (fabric-icac plain)))
    (is (= #x1D (fabric-fabric-id plain)))
    (is (= 1 (fabric-node-id plain)))))
