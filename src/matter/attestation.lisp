;;;; attestation.lisp -- device attestation (Matter Core Specification
;;;; section 6.2 and 6.3) and the certificate signing request of
;;;; commissioning (11.17.6): what a commissionee proves about itself
;;;; before it is given a fabric, and how a commissioner checks it.
;;;;
;;;; The device holds ATTESTATION-CREDENTIALS: its DAC and PAI as X.509
;;;; DER, the DAC's key pair, and the Certification Declaration (a CMS
;;;; SignedData envelope around a TLV structure, signed by the CSA).  On an
;;;; AttestationRequest it signs the attestation elements (CD, nonce,
;;;; timestamp, vendor reserved) together with the session's attestation
;;;; challenge; on a CSRRequest it makes a fresh key pair, a PKCS#10 CSR
;;;; for it, and signs the NOCSR elements the same way.
;;;;
;;;; The commissioner verifies with VERIFY-DEVICE-ATTESTATION: the DAC and
;;;; PAI chain to a PAA in the trust store, the vendor and product ids
;;;; agree across DAC, PAI, PAA and CD, the CD is signed by a known CSA
;;;; key, the nonce is ours, and the signature is the DAC's; then
;;;; VERIFY-NOCSR gives the public key to certify.  The trust store starts
;;;; with the SDK's two test PAAs, the CD keys with the test key and the
;;;; five official ones the SDK knows.

(in-package :cl-matter)

(define-condition attestation-error (error)
  ((reason :initarg :reason :reader attestation-error-reason)
   (message :initarg :message :reader attestation-error-message))
  (:report (lambda (c stream) (format stream "attestation ~a: ~a" (attestation-error-reason c) (attestation-error-message c))))
  (:documentation "A device attestation or CSR that does not verify; REASON is a keyword."))

(defun %attestation-fail (reason format &rest args)
  (error 'attestation-error :reason reason :message (apply #'format nil format args)))

(defconstant +attestation-nonce-length+ 32)
(defconstant +attestation-elements-max-length+ 900 "RESP_MAX of section 11.17.5.")
(defconstant +certificate-chain-dac+ 1)
(defconstant +certificate-chain-pai+ 2)

(defun %check-nonce (nonce what)
  (let ((nonce (handler-case (%check-octet-vector what nonce)
                 (crypto-error (e) (%attestation-fail :invalid-argument "~a" (crypto-error-message e))))))
    (unless (= (length nonce) +attestation-nonce-length+)
      (%attestation-fail :invalid-argument "~a must be ~d octets, got ~d" what +attestation-nonce-length+ (length nonce)))
    nonce))

;;; ------------------------------------------------------------------
;;; Attestation elements (6.2.3.1 / 11.17.5.4)

(defconstant +attestation-tag-certification-declaration+ 1)
(defconstant +attestation-tag-nonce+ 2)
(defconstant +attestation-tag-timestamp+ 3)
(defconstant +attestation-tag-firmware-info+ 4)

(defun encode-attestation-elements (&key certification-declaration nonce (timestamp 0) firmware-info vendor-reserved)
  "The attestation_elements_message: a TLV structure of the CD (CMS octets),
the 32-octet NONCE, the TIMESTAMP (Matter epoch seconds, 0 when the device
has no clock), optional FIRMWARE-INFO octets, and VENDOR-RESERVED, a list
of (vendor-id profile-number tag-number octets) in that order."
  (let ((cd (%check-octet-vector "the certification declaration" certification-declaration))
        (nonce (%check-nonce nonce "the attestation nonce")))
    (when (zerop (length cd)) (%attestation-fail :invalid-argument "the certification declaration is empty"))
    (unless (and (integerp timestamp) (<= 0 timestamp #xFFFFFFFF))
      (%attestation-fail :invalid-argument "the timestamp must be a 32-bit epoch, got ~s" timestamp))
    (let ((octets (tlv-encode
                   (make-tlv-element
                    nil :structure
                    (append (list (tlv +attestation-tag-certification-declaration+ :octets cd)
                                  (tlv +attestation-tag-nonce+ :octets nonce)
                                  (tlv +attestation-tag-timestamp+ :unsigned timestamp))
                            (when firmware-info
                              (list (tlv +attestation-tag-firmware-info+ :octets (%check-octet-vector "the firmware info" firmware-info))))
                            (loop :for (vendor-id profile tag-number data) :in vendor-reserved
                                  :collect (tlv (list :profile vendor-id profile tag-number) :octets
                                                (%check-octet-vector "a vendor reserved element" data))))))))
      (when (> (length octets) +attestation-elements-max-length+)
        (%attestation-fail :invalid-argument "the attestation elements are ~d octets, more than RESP_MAX ~d"
                           (length octets) +attestation-elements-max-length+))
      octets)))

(defun %decode-elements (octets what required tags)
  "The context-tagged members of the anonymous structure in OCTETS as a
plist by TAGS ((tag name type) ...), in ascending tag order as the SDK
demands, with the profile-tagged members after them collected under
:VENDOR-RESERVED as (vendor profile tag octets).  REQUIRED tags must be
present."
  (let ((element (handler-case (multiple-value-bind (element end) (tlv-decode octets)
                                 (unless (= end (length octets))
                                   (%attestation-fail :malformed "~a: ~d trailing octet~:p" what (- (length octets) end)))
                                 element)
                   (tlv-error (e) (%attestation-fail :malformed "~a: ~a" what e))))
        (plist '()) (reserved '()) (last-tag -1) (in-context t))
    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
      (%attestation-fail :malformed "~a must be an anonymous TLV structure" what))
    (dolist (item (tlv-element-value element))
      (let ((tag (tlv-element-tag item)))
        (cond ((integerp tag)
               (unless in-context (%attestation-fail :malformed "~a: a context tag after a vendor tag" what))
               (unless (> tag last-tag) (%attestation-fail :malformed "~a: context tags out of order at ~d" what tag))
               (when (and (= last-tag -1) (/= tag (first (first tags))))
                 (%attestation-fail :malformed "~a: the first element must have tag ~d" what (first (first tags))))
               (setf last-tag tag)
               (let ((spec (assoc tag tags)))
                 (when spec
                   (destructuring-bind (name type) (rest spec)
                     (unless (eq type (tlv-element-type item))
                       (%attestation-fail :malformed "~a: ~a must be ~a, got ~a" what name type (tlv-element-type item)))
                     (setf (getf plist name) (tlv-element-value item))))))
              ((and (consp tag) (eq :profile (first tag)))
               (setf in-context nil)
               (unless (eq :octets (tlv-element-type item))
                 (%attestation-fail :malformed "~a: vendor reserved elements are octet strings" what))
               (push (list (second tag) (third tag) (fourth tag) (tlv-element-value item)) reserved))
              (t (%attestation-fail :malformed "~a: unexpected tag ~s" what tag)))))
    (dolist (tag required)
      (unless (getf plist (second (assoc tag tags)))
        (%attestation-fail :malformed "~a: ~a (tag ~d) is missing" what (second (assoc tag tags)) tag)))
    (append plist (list :vendor-reserved (nreverse reserved)))))

(defun decode-attestation-elements (octets)
  "The plist (:certification-declaration :nonce :timestamp :firmware-info
:vendor-reserved) of an attestation_elements_message; ATTESTATION-ERROR
:MALFORMED when it is not one."
  (let ((plist (%decode-elements (%check-octet-vector "the attestation elements" octets) "attestation elements"
                                 (list +attestation-tag-certification-declaration+ +attestation-tag-nonce+ +attestation-tag-timestamp+)
                                 `((,+attestation-tag-certification-declaration+ :certification-declaration :octets)
                                   (,+attestation-tag-nonce+ :nonce :octets)
                                   (,+attestation-tag-timestamp+ :timestamp :unsigned)
                                   (,+attestation-tag-firmware-info+ :firmware-info :octets)))))
    (unless (= (length (getf plist :nonce)) +attestation-nonce-length+)
      (%attestation-fail :malformed "the attestation nonce is ~d octets" (length (getf plist :nonce))))
    plist))

;;; NOCSR elements (11.17.5.6)

(defconstant +nocsr-tag-csr+ 1)
(defconstant +nocsr-tag-nonce+ 2)

(defun encode-nocsr-elements (&key csr nonce vendor-reserved-1 vendor-reserved-2 vendor-reserved-3)
  "The nocsr_elements_message of the CSR (PKCS#10 DER) and the 32-octet NONCE."
  (let ((csr (%check-octet-vector "the CSR" csr))
        (nonce (%check-nonce nonce "the CSR nonce")))
    (when (zerop (length csr)) (%attestation-fail :invalid-argument "the CSR is empty"))
    (let ((octets (tlv-encode
                   (make-tlv-element
                    nil :structure
                    (append (list (tlv +nocsr-tag-csr+ :octets csr) (tlv +nocsr-tag-nonce+ :octets nonce))
                            (loop :for (tag data) :in (list (list 3 vendor-reserved-1) (list 4 vendor-reserved-2)
                                                            (list 5 vendor-reserved-3))
                                  :when data :collect (tlv tag :octets (%check-octet-vector "a vendor reserved element" data))))))))
      (when (> (length octets) +attestation-elements-max-length+)
        (%attestation-fail :invalid-argument "the NOCSR elements are ~d octets, more than RESP_MAX ~d"
                           (length octets) +attestation-elements-max-length+))
      octets)))

(defun decode-nocsr-elements (octets)
  "The plist (:csr :nonce :vendor-reserved-1 :vendor-reserved-2 :vendor-reserved-3) of a nocsr_elements_message."
  (let ((plist (%decode-elements (%check-octet-vector "the NOCSR elements" octets) "NOCSR elements"
                                 (list +nocsr-tag-csr+ +nocsr-tag-nonce+)
                                 `((,+nocsr-tag-csr+ :csr :octets) (,+nocsr-tag-nonce+ :nonce :octets)
                                   (3 :vendor-reserved-1 :octets) (4 :vendor-reserved-2 :octets) (5 :vendor-reserved-3 :octets)))))
    (unless (= (length (getf plist :nonce)) +attestation-nonce-length+)
      (%attestation-fail :malformed "the CSR nonce is ~d octets" (length (getf plist :nonce))))
    (remf plist :vendor-reserved)
    plist))

;;; The signature: ECDSA by the DAC key over elements || attestation challenge

(defun attestation-tbs (elements challenge)
  "The attestation_tbs: ELEMENTS followed by the 16-octet session CHALLENGE."
  (let ((challenge (%check-octet-vector "the attestation challenge" challenge)))
    (unless (= 16 (length challenge))
      (%attestation-fail :invalid-argument "the attestation challenge is 16 octets, got ~d" (length challenge)))
    (%concat-octets (%check-octet-vector "the elements" elements) challenge)))

(defun sign-attestation (keypair elements challenge)
  "The DAC's 64-octet signature over ELEMENTS and the session CHALLENGE."
  (p256-sign keypair (attestation-tbs elements challenge)))

(defun verify-attestation-signature (public-key elements challenge signature)
  "True when SIGNATURE is PUBLIC-KEY's (the DAC's) over ELEMENTS and CHALLENGE."
  (p256-verify public-key (attestation-tbs elements challenge) signature))

;;; ------------------------------------------------------------------
;;; Certificate signing requests (PKCS#10, RFC 2986)

(defparameter *csr-default-subject* '((:organization-name "CSA"))
  "The subject of the CSRs we make; a NOC's subject comes from the issuer, not from here.")

(defun make-certificate-signing-request (keypair &key (subject *csr-default-subject*))
  "A PKCS#10 CSR in DER for KEYPAIR, self-signed with it."
  (unless (p256-keypair-p keypair) (%attestation-fail :invalid-argument "a CSR needs a P256-KEYPAIR"))
  (%check-dn subject "the CSR subject")
  (let* ((info (der-sequence (der-integer 0)
                             (%dn-der subject)
                             (der-sequence (der-sequence (der-oid *oid-ec-public-key*) (der-oid *oid-prime256v1*))
                                           (der-bit-string (p256-keypair-public keypair)))
                             (der-context 0 nil)))
         (signature (p256-sign keypair info)))
    (der-sequence info
                  (der-sequence (der-oid *oid-ecdsa-with-sha256*))
                  (der-bit-string (ecdsa-signature-der signature)))))

(defun decode-certificate-signing-request (octets)
  "The PKCS#10 CSR in OCTETS, its signature verified: (values public-key
subject-dn).  ATTESTATION-ERROR :INVALID-CSR when it is malformed or the
signature is not the key's."
  (handler-case
      (let* ((octets (%check-octet-vector "the CSR" octets))
             (top (der-children (der-decode octets) +der-sequence+ "the CSR"))
             (info (first top))
             (members (der-children info +der-sequence+ "the CertificationRequestInfo")))
        (unless (= 3 (length top)) (%attestation-fail :invalid-csr "a CSR has three members, got ~d" (length top)))
        (unless (>= (length members) 3) (%attestation-fail :invalid-csr "a CertificationRequestInfo with ~d members" (length members)))
        (unless (= 0 (der-node-integer (first members))) (%attestation-fail :invalid-csr "unsupported CSR version"))
        (let ((algorithm (der-node-oid (der-child (second top) 0 +der-oid+ "the signature algorithm")))
              (public-key (%der-subject-public-key (third members) "the CSR's public key"))
              (subject (%der-dn (second members) "the CSR subject")))
          (unless (string= algorithm *oid-ecdsa-with-sha256*)
            (%attestation-fail :invalid-csr "unsupported CSR signature algorithm ~a" algorithm))
          (unless (p256-verify public-key (der-node-whole info)
                               (ecdsa-signature-from-der (der-node-bit-string (third top))))
            (%attestation-fail :invalid-csr "the CSR's signature does not verify with its public key"))
          (values public-key subject)))
    (der-error (e) (%attestation-fail :invalid-csr "malformed CSR: ~a" (der-error-message e)))
    (certificate-error (e) (%attestation-fail :invalid-csr "malformed CSR: ~a" (certificate-error-message e)))
    (crypto-error (e) (%attestation-fail :invalid-csr "~a" (crypto-error-message e)))))

;;; ------------------------------------------------------------------
;;; Certification declarations (6.3): a TLV structure in a CMS SignedData

(defconstant +cd-tag-format-version+ 0)
(defconstant +cd-tag-vendor-id+ 1)
(defconstant +cd-tag-product-ids+ 2)
(defconstant +cd-tag-device-type-id+ 3)
(defconstant +cd-tag-certificate-id+ 4)
(defconstant +cd-tag-security-level+ 5)
(defconstant +cd-tag-security-information+ 6)
(defconstant +cd-tag-version-number+ 7)
(defconstant +cd-tag-certification-type+ 8)
(defconstant +cd-tag-dac-origin-vendor-id+ 9)
(defconstant +cd-tag-dac-origin-product-id+ 10)
(defconstant +cd-tag-authorized-paa-list+ 11)

(defparameter *oid-cms-signed-data* "1.2.840.113549.1.7.2")
(defparameter *oid-cms-data* "1.2.840.113549.1.7.1")
(defparameter *oid-sha256* "2.16.840.1.101.3.4.2.1")

(defparameter *cd-signing-keys*
  (mapcar (lambda (entry) (cons (%hex-octets (first entry)) (%hex-octets (second entry))))
          '(;; the SDK's test CD signing key (credentials/test/certification-declaration)
            ("62fa823359acfaa9963e1cfa140addf504f37160"
             "043c398922452b55caf389c25bd1bca4656952ccb90e8869249ad8474653014cbf95d687965e036b521c51037e6b8cedefca1eb44046694fa08882eed6519decba")
            ;; CSA "Certification Declaration Signing Key 001" .. 005
            ("fe343f959947763b61ee4539131338494fe67d8e"
             "04cdeee93e44f8b72be3d1a9c07e21968b9afff3b403f05e1669d7b1e5caee6fc7714b42e7e23695e92cd7635473a280ae688f37bb9489e11629b9b94ff7b09929")
            ("dd04db585b214c1c581587e6568df487b6ddc701"
             "04031937e8f94251045df27457bb46253ee3754e8c12ae28557d8027b9d4c356d91b408cff32275017b25f8c8ba20516d5c83af2b724128013dfcc8f95d200a90b")
            ("471035e7c04eaaa8be7c4d4c13e3e4c20995a84b"
             "049f575cd5fdb7521f10a4df31f073912b614728f2d37f5b6b96bc2cbf7c0b119690577d555d21a09660a8b082a339ea530f7a812d8693b56fd764185fabcd32f5")
            ("f68603a3692e981072419ea1e1ab3854bd7795d3"
             "047cfc8d8810a89cf4fa191778f2afec78f8517a97a3e57fc213bad888e3611e74ffb684bdeba8a68b25234a5c358f373bab9b6d304e1306dd7620a528d1161c0b")
            ("637f2634ad62eafe6af662efb96f6fd2fcbffc2f"
             "04438a52c662a2a6d72647f95eb753136ee4ae0fdb3aa9c16931426b3d0867f9103ae7d7a1b887e9f813a6f26f76bbcda93593787c12778ca8f2975dc45a2042f9")))
  "The Certification Declaration signing keys a commissioner accepts, as
(subject-key-id . public-key): the SDK's test key and the CSA's five.")

(defun add-cd-signing-key (public-key &optional (key-id (subject-key-identifier public-key)))
  "Accept CDs signed by PUBLIC-KEY (65 octets), identified in CMS by KEY-ID."
  (push (cons key-id public-key) *cd-signing-keys*)
  public-key)

(defun encode-certification-declaration-tlv (cd)
  "The TLV of certification declaration CD, a plist of :FORMAT-VERSION
:VENDOR-ID :PRODUCT-IDS (a list) :DEVICE-TYPE-ID :CERTIFICATE-ID (19
characters) :SECURITY-LEVEL :SECURITY-INFORMATION :VERSION-NUMBER
:CERTIFICATION-TYPE, and optionally :DAC-ORIGIN-VENDOR-ID with
:DAC-ORIGIN-PRODUCT-ID and :AUTHORIZED-PAA-LIST (20-octet key ids)."
  (flet ((field (key) (multiple-value-bind (value present) (%plist-get cd key)
                        (unless present (%attestation-fail :invalid-argument "the certification declaration lacks ~s" key))
                        value)))
    (let ((ids (field :product-ids)) (certificate-id (field :certificate-id)))
      (unless (and (listp ids) (<= 1 (length ids) 100) (every (lambda (id) (and (integerp id) (<= 0 id #xFFFF))) ids))
        (%attestation-fail :invalid-argument "product ids must be 1..100 16-bit integers"))
      (unless (and (stringp certificate-id) (= 19 (length certificate-id)))
        (%attestation-fail :invalid-argument "the certificate id is 19 characters, got ~s" certificate-id))
      (when (and (getf cd :dac-origin-vendor-id) (not (getf cd :dac-origin-product-id)))
        (%attestation-fail :invalid-argument "a DAC origin vendor id needs the product id too"))
      (tlv-encode
       (make-tlv-element
        nil :structure
        (append (list (tlv +cd-tag-format-version+ :unsigned (field :format-version))
                      (tlv +cd-tag-vendor-id+ :unsigned (field :vendor-id))
                      (tlv +cd-tag-product-ids+ :array (mapcar (lambda (id) (tlv nil :unsigned id)) ids))
                      (tlv +cd-tag-device-type-id+ :unsigned (field :device-type-id))
                      (tlv +cd-tag-certificate-id+ :string certificate-id)
                      (tlv +cd-tag-security-level+ :unsigned (field :security-level))
                      (tlv +cd-tag-security-information+ :unsigned (field :security-information))
                      (tlv +cd-tag-version-number+ :unsigned (field :version-number))
                      (tlv +cd-tag-certification-type+ :unsigned (field :certification-type)))
                (when (getf cd :dac-origin-vendor-id)
                  (list (tlv +cd-tag-dac-origin-vendor-id+ :unsigned (getf cd :dac-origin-vendor-id))
                        (tlv +cd-tag-dac-origin-product-id+ :unsigned (getf cd :dac-origin-product-id))))
                (when (getf cd :authorized-paa-list)
                  (list (tlv +cd-tag-authorized-paa-list+ :array
                             (mapcar (lambda (id) (tlv nil :octets (%check-octet-vector "a PAA key id" id)))
                                     (getf cd :authorized-paa-list)))))))))))

(defun decode-certification-declaration-tlv (octets)
  "The plist of the certification declaration TLV OCTETS (see the encoder)."
  (let ((element (handler-case (multiple-value-bind (element end) (tlv-decode octets)
                                 (unless (= end (length octets))
                                   (%attestation-fail :malformed "the certification declaration has trailing octets"))
                                 element)
                   (tlv-error (e) (%attestation-fail :malformed "certification declaration: ~a" e)))))
    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
      (%attestation-fail :malformed "a certification declaration is an anonymous structure"))
    (flet ((field (tag name type &key optional)
             (let ((item (tlv-ref element tag)))
               (cond ((and (null item) optional) (values nil nil))
                     ((null item) (%attestation-fail :malformed "the certification declaration lacks ~a" name))
                     ((not (eq type (tlv-element-type item)))
                      (%attestation-fail :malformed "~a of the certification declaration must be ~a" name type))
                     (t (values (tlv-element-value item) t))))))
      (let ((cd (list :format-version (field +cd-tag-format-version+ "the format version" :unsigned)
                      :vendor-id (field +cd-tag-vendor-id+ "the vendor id" :unsigned)
                      :product-ids (mapcar (lambda (item)
                                             (unless (eq :unsigned (tlv-element-type item))
                                               (%attestation-fail :malformed "product ids are unsigned integers"))
                                             (tlv-element-value item))
                                           (field +cd-tag-product-ids+ "the product ids" :array))
                      :device-type-id (field +cd-tag-device-type-id+ "the device type id" :unsigned)
                      :certificate-id (field +cd-tag-certificate-id+ "the certificate id" :string)
                      :security-level (field +cd-tag-security-level+ "the security level" :unsigned)
                      :security-information (field +cd-tag-security-information+ "the security information" :unsigned)
                      :version-number (field +cd-tag-version-number+ "the version number" :unsigned)
                      :certification-type (field +cd-tag-certification-type+ "the certification type" :unsigned))))
        (multiple-value-bind (origin-vendor present) (field +cd-tag-dac-origin-vendor-id+ "the DAC origin vendor id" :unsigned :optional t)
          (when present
            (setf cd (append cd (list :dac-origin-vendor-id origin-vendor
                                      :dac-origin-product-id (field +cd-tag-dac-origin-product-id+ "the DAC origin product id" :unsigned))))))
        (when (and (tlv-ref element +cd-tag-dac-origin-product-id+) (null (getf cd :dac-origin-vendor-id)))
          (%attestation-fail :malformed "a DAC origin product id without the vendor id"))
        (multiple-value-bind (paas present) (field +cd-tag-authorized-paa-list+ "the authorized PAA list" :array :optional t)
          (when present
            (setf cd (append cd (list :authorized-paa-list
                                      (mapcar (lambda (item)
                                                (unless (and (eq :octets (tlv-element-type item))
                                                             (= 20 (length (tlv-element-value item))))
                                                  (%attestation-fail :malformed "authorized PAAs are 20-octet key ids"))
                                                (tlv-element-value item))
                                              paas))))))
        (dolist (item (tlv-element-value element))
          (unless (and (integerp (tlv-element-tag item)) (<= 0 (tlv-element-tag item) +cd-tag-authorized-paa-list+))
            (%attestation-fail :malformed "unknown certification declaration element ~s" (tlv-element-tag item))))
        cd))))

(defun encode-certification-declaration (cd keypair &key (key-id (subject-key-identifier (p256-keypair-public keypair))))
  "CD (a plist, see ENCODE-CERTIFICATION-DECLARATION-TLV) as the CMS
SignedData the device presents, signed by KEYPAIR and naming its KEY-ID."
  (let* ((content (encode-certification-declaration-tlv cd))
         (signature (p256-sign keypair content)))
    (der-sequence
     (der-oid *oid-cms-signed-data*)
     (der-context 0 t
                  (der-sequence
                   (der-integer 3)
                   (der-set (der-sequence (der-oid *oid-sha256*)))
                   (der-sequence (der-oid *oid-cms-data*) (der-context 0 t (der-octet-string content)))
                   (der-set (der-sequence (der-integer 3)
                                          (der-context 0 nil (%check-octet-vector "the key id" key-id))
                                          (der-sequence (der-oid *oid-sha256*))
                                          (der-sequence (der-oid *oid-ecdsa-with-sha256*))
                                          (der-octet-string (ecdsa-signature-der signature)))))))))

(defun decode-certification-declaration (octets &key (signing-keys *cd-signing-keys*))
  "The certification declaration in the CMS OCTETS: (values cd-plist
signer-key-id cd-tlv-octets).  The signature must be by one of SIGNING-KEYS
((key-id . public-key) ...); ATTESTATION-ERROR :CD-SIGNER-UNKNOWN or
:CD-SIGNATURE-INVALID otherwise, :MALFORMED for anything else."
  (handler-case
      (let* ((octets (%check-octet-vector "the certification declaration" octets))
             (info (der-children (der-decode octets) +der-sequence+ "the CMS ContentInfo")))
        (unless (and (= 2 (length info)) (string= *oid-cms-signed-data* (der-node-oid (first info))))
          (%attestation-fail :malformed "the certification declaration is not CMS SignedData"))
        (let* ((signed (der-children (der-child (der-expect (second info) (der-context-tag 0)) 0 +der-sequence+ "SignedData")
                                     +der-sequence+ "SignedData"))
               (content-info (der-children (third signed) +der-sequence+ "EncapsulatedContentInfo"))
               (signer-infos (der-children (car (last signed)) +der-set+ "SignerInfos")))
          (unless (= 3 (der-node-integer (first signed))) (%attestation-fail :malformed "SignedData version ~d" (der-node-integer (first signed))))
          (unless (string= *oid-cms-data* (der-node-oid (first content-info)))
            (%attestation-fail :malformed "the signed content is not id-data"))
          (unless (= 1 (length signer-infos)) (%attestation-fail :malformed "~d signers, one expected" (length signer-infos)))
          (let* ((content (der-node-octet-string (der-child (der-expect (second content-info) (der-context-tag 0)) 0
                                                            +der-octet-string+ "the content")))
                 (signer (der-children (first signer-infos) +der-sequence+ "SignerInfo"))
                 (sid (second signer))
                 (key-id (progn (der-expect sid (der-context-tag 0 nil) "the subject key identifier")
                                (der-node-content sid)))
                 (signature-node (find +der-octet-string+ (cddr signer) :key #'der-node-tag))
                 (key (cdr (find key-id signing-keys :key #'car :test #'equalp))))
            (unless (= 3 (der-node-integer (first signer))) (%attestation-fail :malformed "SignerInfo version ~d" (der-node-integer (first signer))))
            (unless (string= *oid-sha256* (der-node-oid (der-child (third signer) 0 +der-oid+ "the digest algorithm")))
              (%attestation-fail :malformed "the CD digest algorithm is not SHA-256"))
            (unless (find-if (lambda (node) (and (= +der-sequence+ (der-node-tag node))
                                                 (ignore-errors (string= *oid-ecdsa-with-sha256*
                                                                         (der-node-oid (der-child node 0 +der-oid+))))))
                             (cdddr signer))
              (%attestation-fail :malformed "the CD signature algorithm is not ecdsa-with-SHA256"))
            (unless signature-node (%attestation-fail :malformed "the CD has no signature"))
            (unless key (%attestation-fail :cd-signer-unknown "the CD is signed by an unknown key ~{~2,'0x~}" (coerce key-id 'list)))
            (unless (p256-verify key content (ecdsa-signature-from-der (der-node-octet-string signature-node)))
              (%attestation-fail :cd-signature-invalid "the CD's signature does not verify"))
            (values (decode-certification-declaration-tlv content) key-id content))))
    (der-error (e) (%attestation-fail :malformed "certification declaration: ~a" (der-error-message e)))
    (certificate-error (e) (%attestation-fail :malformed "certification declaration: ~a" (certificate-error-message e)))
    (crypto-error (e) (%attestation-fail :malformed "~a" (crypto-error-message e)))))

;;; ------------------------------------------------------------------
;;; The attestation certificate chain (6.2.2) and the PAA trust store

(defparameter *test-paa-pems*
  '("-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIHC4+6qN2G7jAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9N
YXR0ZXIgVGVzdCBQQUEwIBcNMjEwNjI4MTQyMzQzWhgPOTk5OTEyMzEyMzU5NTla
MBoxGDAWBgNVBAMMD01hdHRlciBUZXN0IFBBQTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABBDvAqgah7aBIfuo0xl4+AejF+UKqKgoRGgokUuTPejt1KXDnJ/3Gkzj
ZH/X9iZTt9JJX8ukwPR/h2iAA54HIEqjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR4XOcFuGuPTm/Hk6pgy0PqaWiC1TAf
BgNVHSMEGDAWgBR4XOcFuGuPTm/Hk6pgy0PqaWiC1TAKBggqhkjOPQQDAgNIADBF
AiEAue/bPqBqUuwL8B5h2u0sLRVt22zwFBAdq3mPrAX6R+UCIGAGHT411g2dSw1E
ja12EvfoXFguP8MS3Bh5TdNzcV5d
-----END CERTIFICATE-----"
    "-----BEGIN CERTIFICATE-----
MIIBvTCCAWSgAwIBAgIITqjoMYLUHBwwCgYIKoZIzj0EAwIwMDEYMBYGA1UEAwwP
TWF0dGVyIFRlc3QgUEFBMRQwEgYKKwYBBAGConwCAQwERkZGMTAgFw0yMTA2Mjgx
NDIzNDNaGA85OTk5MTIzMTIzNTk1OVowMDEYMBYGA1UEAwwPTWF0dGVyIFRlc3Qg
UEFBMRQwEgYKKwYBBAGConwCAQwERkZGMTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABLbLY3KIfyko9brIGqnZOuJDHK2p154kL2UXfvnO2TKijs0Duq9qj8oYShpQ
NUKWDUU/MD8fGUIddR6Pjxqam3WjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYD
VR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRq/SJ3H1Ef7L8WQZdnENzcMaFxfjAfBgNV
HSMEGDAWgBRq/SJ3H1Ef7L8WQZdnENzcMaFxfjAKBggqhkjOPQQDAgNHADBEAiBQ
qoAC9NkyqaAFOPZTaK0P/8jvu8m+t9pWmDXPmqdRDgIgI7rI/g8j51RFtlM5CBpH
mUkpxyqvChVI1A0DTVFLJd4=
-----END CERTIFICATE-----")
  "The SDK's test PAAs (credentials/test/attestation): Chip-Test-PAA-NoVID and Chip-Test-PAA-FFF1.")

(defparameter *paa-trust-store* (mapcar #'decode-certificate-pem *test-paa-pems*)
  "The Product Attestation Authorities a commissioner trusts, as
CERTIFICATEs.  Starts with the SDK's two test PAAs: replace it with the
CSA's Distributed Compliance Ledger roots for production devices.")

(defun add-trusted-paa (certificate)
  "Trust CERTIFICATE (a CERTIFICATE, DER octets or PEM text) as a PAA."
  (let ((c (cond ((certificate-p certificate) certificate)
                 ((stringp certificate) (decode-certificate-pem certificate))
                 (t (certificate-from-octets certificate)))))
    (validate-paa c)
    (push c *paa-trust-store*)
    c))

(defun find-trusted-paa (pai &optional (trust-store *paa-trust-store*))
  "The PAA of TRUST-STORE that PAI names as its issuer, by authority key
id and subject, or NIL."
  (find-if (lambda (paa)
             (and (equalp (certificate-authority-key-id pai) (certificate-subject-key-id paa))
                  (dn-equal (certificate-issuer pai) (certificate-subject paa))))
           trust-store))

(defun %attestation-cert (x what)
  (cond ((certificate-p x) x)
        ((stringp x) (handler-case (decode-certificate-pem x)
                       (certificate-error (e) (%attestation-fail :malformed "~a: ~a" what (certificate-error-message e)))))
        (t (handler-case (certificate-from-octets x)
             (certificate-error (e) (%attestation-fail :malformed "~a: ~a" what (certificate-error-message e)))))))

(defun validate-paa (paa &key time)
  "PAA is a well-formed, self-signed Product Attestation Authority
certificate (6.2.2.3): cA, keyCertSign, no product id."
  (let ((c (%attestation-cert paa "the PAA")))
    (unless (dn-equal (certificate-subject c) (certificate-issuer c))
      (%attestation-fail :paa-format-invalid "the PAA is not self-issued"))
    (unless (certificate-ca-p c) (%attestation-fail :paa-format-invalid "the PAA is not a CA certificate"))
    (unless (member :key-cert-sign (certificate-key-usage c))
      (%attestation-fail :paa-format-invalid "the PAA lacks the keyCertSign key usage"))
    (unless (and (certificate-subject-key-id c)
                 (or (null (certificate-authority-key-id c))
                     (equalp (certificate-subject-key-id c) (certificate-authority-key-id c))))
      (%attestation-fail :paa-format-invalid "the PAA's key identifiers do not match"))
    (when (certificate-product-id c) (%attestation-fail :paa-format-invalid "the PAA carries a product id"))
    (unless (verify-certificate-signature c c)
      (%attestation-fail :paa-signature-invalid "the PAA's signature does not verify"))
    (when (and time (not (certificate-valid-at-p c time)))
      (%attestation-fail :paa-expired "the PAA is not valid at this time"))
    c))

(defun validate-attestation-chain (dac pai paa &key time)
  "DAC, PAI and PAA (certificates, DER or PEM) form a valid attestation
chain (6.2.2 and the SDK's verifier): each is of the right profile, each
link names and signs the next, the vendor ids agree and the product ids
where present.  Returns (values dac pai paa) as certificates; failure is
ATTESTATION-ERROR with a reason naming the link."
  (let ((dac (%attestation-cert dac "the DAC"))
        (pai (%attestation-cert pai "the PAI"))
        (paa (validate-paa paa)))
    ;; the DAC (6.2.2.1)
    (when (certificate-ca-p dac) (%attestation-fail :dac-format-invalid "the DAC is a CA certificate"))
    (unless (member :digital-signature (certificate-key-usage dac))
      (%attestation-fail :dac-format-invalid "the DAC lacks the digitalSignature key usage"))
    (let ((dac-vid (certificate-vendor-id dac)) (dac-pid (certificate-product-id dac))
          (pai-vid (certificate-vendor-id pai)) (pai-pid (certificate-product-id pai))
          (paa-vid (certificate-vendor-id paa)))
      (unless dac-vid (%attestation-fail :dac-format-invalid "the DAC has no vendor id"))
      (unless dac-pid (%attestation-fail :dac-format-invalid "the DAC has no product id"))
      ;; the PAI (6.2.2.2)
      (unless (certificate-ca-p pai) (%attestation-fail :pai-format-invalid "the PAI is not a CA certificate"))
      (unless (member :key-cert-sign (certificate-key-usage pai))
        (%attestation-fail :pai-format-invalid "the PAI lacks the keyCertSign key usage"))
      (let ((path-length (certificate-path-length pai)))
        (when (and path-length (/= 0 path-length))
          (%attestation-fail :pai-format-invalid "the PAI's path length constraint must be 0")))
      (unless pai-vid (%attestation-fail :pai-format-invalid "the PAI has no vendor id"))
      (unless (= pai-vid dac-vid)
        (%attestation-fail :dac-vendor-id-mismatch "the DAC's vendor id ~4,'0x is not the PAI's ~4,'0x" dac-vid pai-vid))
      (when (and pai-pid (/= pai-pid dac-pid))
        (%attestation-fail :dac-product-id-mismatch "the DAC's product id ~4,'0x is not the PAI's ~4,'0x" dac-pid pai-pid))
      (when (and paa-vid (/= paa-vid pai-vid))
        (%attestation-fail :pai-vendor-id-mismatch "the PAI's vendor id ~4,'0x is not the PAA's ~4,'0x" pai-vid paa-vid)))
    ;; the links
    (flet ((issued-by (certificate issuer what reason)
             (unless (dn-equal (certificate-issuer certificate) (certificate-subject issuer))
               (%attestation-fail reason "~a's issuer is not its signer's subject" what))
             (unless (equalp (certificate-authority-key-id certificate) (certificate-subject-key-id issuer))
               (%attestation-fail reason "~a's authority key id is not its signer's subject key id" what))
             (unless (verify-certificate-signature certificate issuer)
               (%attestation-fail reason "~a's signature does not verify" what))))
      (issued-by pai paa "the PAI" :pai-signature-invalid)
      (issued-by dac pai "the DAC" :dac-signature-invalid))
    (when time
      (unless (certificate-valid-at-p dac time) (%attestation-fail :dac-expired "the DAC is not valid at this time"))
      (unless (certificate-valid-at-p pai time) (%attestation-fail :pai-expired "the PAI is not valid at this time"))
      (unless (certificate-valid-at-p paa time) (%attestation-fail :paa-expired "the PAA is not valid at this time")))
    (values dac pai paa)))

;;; ------------------------------------------------------------------
;;; The commissioner's checks (6.2.3)

(defun verify-device-attestation (&key dac pai elements signature challenge nonce vendor-id product-id
                                    (trust-store *paa-trust-store*) (cd-signing-keys *cd-signing-keys*) time)
  "Check what a commissionee answered to CertificateChainRequest (DAC, PAI)
and AttestationRequest (ELEMENTS, SIGNATURE) on the session with the
attestation CHALLENGE, against the NONCE we sent and the VENDOR-ID and
PRODUCT-ID its Basic Information cluster claims.  Returns a plist (:dac
:pai :paa :certification-declaration :elements :vendor-id :product-id)
with the certificates decoded; any failure is ATTESTATION-ERROR whose
reason names the check (6.2.3.1)."
  (let* ((dac (%attestation-cert dac "the DAC"))
         (pai (%attestation-cert pai "the PAI"))
         (paa (or (find-trusted-paa pai trust-store)
                  (%attestation-fail :paa-not-found "no trusted PAA issued the PAI ~s" (certificate-issuer pai)))))
    (validate-attestation-chain dac pai paa :time time)
    (let* ((plist (decode-attestation-elements elements))
           (nonce (%check-nonce nonce "the attestation nonce")))
      (unless (equalp nonce (getf plist :nonce))
        (%attestation-fail :nonce-mismatch "the attestation nonce is not the one we sent"))
      (unless (verify-attestation-signature (certificate-public-key dac) elements challenge signature)
        (%attestation-fail :attestation-signature-invalid "the attestation signature is not the DAC's"))
      (multiple-value-bind (cd) (decode-certification-declaration (getf plist :certification-declaration)
                                                                  :signing-keys cd-signing-keys)
        (let ((dac-vid (certificate-vendor-id dac)) (dac-pid (certificate-product-id dac))
              (pai-vid (certificate-vendor-id pai)) (pai-pid (certificate-product-id pai)))
          (unless (= 1 (getf cd :format-version))
            (%attestation-fail :cd-format-invalid "certification declaration format version ~d" (getf cd :format-version)))
          (when vendor-id
            (unless (= vendor-id (getf cd :vendor-id))
              (%attestation-fail :cd-vendor-id-mismatch "the device claims vendor ~4,'0x, the CD says ~4,'0x"
                                 vendor-id (getf cd :vendor-id))))
          (when product-id
            (unless (member product-id (getf cd :product-ids))
              (%attestation-fail :cd-product-id-mismatch "the device claims product ~4,'0x, not in the CD" product-id)))
          (cond ((getf cd :dac-origin-vendor-id)
                 (unless (and (= dac-vid (getf cd :dac-origin-vendor-id)) (= pai-vid (getf cd :dac-origin-vendor-id)))
                   (%attestation-fail :cd-vendor-id-mismatch "the DAC and PAI vendor id is not the CD's DAC origin vendor"))
                 (unless (= dac-pid (getf cd :dac-origin-product-id))
                   (%attestation-fail :cd-product-id-mismatch "the DAC product id is not the CD's DAC origin product"))
                 (when (and pai-pid (/= pai-pid (getf cd :dac-origin-product-id)))
                   (%attestation-fail :cd-product-id-mismatch "the PAI product id is not the CD's DAC origin product")))
                (t
                 (unless (and (= dac-vid (getf cd :vendor-id)) (= pai-vid (getf cd :vendor-id)))
                   (%attestation-fail :cd-vendor-id-mismatch "the DAC and PAI vendor id ~4,'0x is not the CD's ~4,'0x"
                                      dac-vid (getf cd :vendor-id)))
                 (unless (member dac-pid (getf cd :product-ids))
                   (%attestation-fail :cd-product-id-mismatch "the DAC product id ~4,'0x is not in the CD" dac-pid))
                 (when (and pai-pid (not (member pai-pid (getf cd :product-ids))))
                   (%attestation-fail :cd-product-id-mismatch "the PAI product id ~4,'0x is not in the CD" pai-pid))))
          (when (getf cd :authorized-paa-list)
            (unless (member (certificate-subject-key-id paa) (getf cd :authorized-paa-list) :test #'equalp)
              (%attestation-fail :paa-not-authorized "the PAA is not in the CD's authorized PAA list")))
          (list :dac dac :pai pai :paa paa :certification-declaration cd :elements plist
                :vendor-id dac-vid :product-id dac-pid))))))

(defun verify-nocsr (&key elements signature challenge nonce dac-public-key)
  "Check a CSRResponse: ELEMENTS and SIGNATURE on the session with the
attestation CHALLENGE, against the NONCE we sent, signed by the DAC's
public key.  Returns (values csr-public-key elements-plist csr-subject)."
  (let ((plist (decode-nocsr-elements elements))
        (nonce (%check-nonce nonce "the CSR nonce")))
    (unless (equalp nonce (getf plist :nonce))
      (%attestation-fail :nonce-mismatch "the CSR nonce is not the one we sent"))
    (unless (verify-attestation-signature dac-public-key elements challenge signature)
      (%attestation-fail :attestation-signature-invalid "the NOCSR signature is not the DAC's"))
    (multiple-value-bind (public-key subject) (decode-certificate-signing-request (getf plist :csr))
      (values public-key plist subject))))

;;; ------------------------------------------------------------------
;;; What a device holds

(defstruct (attestation-credentials (:constructor %make-attestation-credentials))
  "A device's attestation material: DAC and PAI as X.509 DER, the DAC's
key pair, and the certification declaration as CMS octets."
  (dac nil :read-only t)
  (pai nil :read-only t)
  (keypair nil :read-only t)
  (certification-declaration nil :read-only t)
  (firmware-info nil :read-only t))

(defmethod print-object ((c attestation-credentials) stream)
  (print-unreadable-object (c stream :type t)
    (let ((dac (ignore-errors (decode-certificate-der (attestation-credentials-dac c)))))
      (format stream "~@[vendor ~4,'0x ~]~@[product ~4,'0x~]"
              (and dac (certificate-vendor-id dac)) (and dac (certificate-product-id dac))))))

(defun make-attestation-credentials (&key dac pai keypair certification-declaration firmware-info)
  "Credentials from the DAC and PAI (certificates, DER or PEM), the DAC's
KEYPAIR (a P256-KEYPAIR, or PEM / DER of its private key) and the
CERTIFICATION-DECLARATION (CMS octets).  The DAC must certify the key pair."
  (let* ((dac (%attestation-cert dac "the DAC"))
         (pai (%attestation-cert pai "the PAI"))
         (keypair (cond ((p256-keypair-p keypair) keypair)
                        ((stringp keypair) (decode-ec-private-key-pem keypair))
                        (t (decode-ec-private-key keypair))))
         (cd (%check-octet-vector "the certification declaration" certification-declaration)))
    (unless (equalp (certificate-public-key dac) (p256-keypair-public keypair))
      (%attestation-fail :invalid-argument "the DAC does not certify the key pair's public key"))
    (unless (dn-equal (certificate-issuer dac) (certificate-subject pai))
      (%attestation-fail :invalid-argument "the PAI is not the DAC's issuer"))
    (decode-certification-declaration-tlv (nth-value 2 (decode-certification-declaration cd :signing-keys *cd-signing-keys*)))
    (%make-attestation-credentials :dac (certificate-der dac) :pai (certificate-der pai) :keypair keypair
                                   :certification-declaration cd :firmware-info firmware-info)))

(defun attestation-credentials-vendor-id (credentials)
  (certificate-vendor-id (decode-certificate-der (attestation-credentials-dac credentials))))

(defun attestation-credentials-product-id (credentials)
  (certificate-product-id (decode-certificate-der (attestation-credentials-dac credentials))))

;;; The SDK's example device credentials: Chip-Test-DAC-FFF1-8000-0000 under
;;; Chip-Test-PAI-FFF1-8000 under Chip-Test-PAA-FFF1, and the example CD
;;; for vendor FFF1, products 8000..8063, signed by CSA key 001.

(defparameter *test-dac-pem* "-----BEGIN CERTIFICATE-----
MIIB6TCCAY+gAwIBAgIIG9Y4GPFEp5cwCgYIKoZIzj0EAwIwRjEYMBYGA1UEAwwP
TWF0dGVyIFRlc3QgUEFJMRQwEgYKKwYBBAGConwCAQwERkZGMTEUMBIGCisGAQQB
gqJ8AgIMBDgwMDAwIBcNMjEwNjI4MTQyMzQzWhgPOTk5OTEyMzEyMzU5NTlaMEsx
HTAbBgNVBAMMFE1hdHRlciBUZXN0IERBQyAwMDAwMRQwEgYKKwYBBAGConwCAQwE
RkZGMTEUMBIGCisGAQQBgqJ8AgIMBDgwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAT8oTjJK3bhzROHPBnqGXKYSFV4wV230pjRhCX8aEPNUIAo72N0uwvdCTwq
DUPG1tLGexArzyBwMdpswOMWT+A1o2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB
/wQEAwIHgDAdBgNVHQ4EFgQU5XCI9Ejm/5/iAJdEUov57AgvwR8wHwYDVR0jBBgw
FoAUr0K3CU3r1RXsbs8zuBEVIl8yUogwCgYIKoZIzj0EAwIDSAAwRQIgBW7jMFwb
LoDiJguE1FKOUtrvC4Ab1JLoPveGT8USjEwCIQDph/Qb+Pq+SBBV253a+Kd1VSQs
OLXNjr7WcwaNdVKy/Q==
-----END CERTIFICATE-----")

(defparameter *test-dac-key-pem* "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICHy4+QgwHAXNIEEaba60VzzBngiyaSllsGG+pvvFT+hoAoGCCqGSM49
AwEHoUQDQgAE/KE4ySt24c0ThzwZ6hlymEhVeMFdt9KY0YQl/GhDzVCAKO9jdLsL
3Qk8Kg1DxtbSxnsQK88gcDHabMDjFk/gNQ==
-----END EC PRIVATE KEY-----")

(defparameter *test-pai-pem* "-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIIPmzmUJrYQM0wCgYIKoZIzj0EAwIwMDEYMBYGA1UEAwwP
TWF0dGVyIFRlc3QgUEFBMRQwEgYKKwYBBAGConwCAQwERkZGMTAgFw0yMTA2Mjgx
NDIzNDNaGA85OTk5MTIzMTIzNTk1OVowRjEYMBYGA1UEAwwPTWF0dGVyIFRlc3Qg
UEFJMRQwEgYKKwYBBAGConwCAQwERkZGMTEUMBIGCisGAQQBgqJ8AgIMBDgwMDAw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASA3fEbIo8+MfY7z1eY2hRiOuu96C7z
eO6tv7GP4avOMdCO1LIGBLbMxtm1+rZOfeEMt0vgF8nsFRYFbXDyzQsio2YwZDAS
BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUr0K3
CU3r1RXsbs8zuBEVIl8yUogwHwYDVR0jBBgwFoAUav0idx9RH+y/FkGXZxDc3DGh
cX4wCgYIKoZIzj0EAwIDSAAwRQIhAJbJyM8uAYhgBdj1vHLAe3X9mldpWsSRETET
i+oDPOUDAiAlVJQ75X1T1sR199I+v8/CA2zSm6Y5PsfvrYcUq3GCGQ==
-----END CERTIFICATE-----")

(defparameter *test-certification-declaration*
  (%hex-octets "3082021706092a864886f70d010702a082020830820204020103310d300b06096086480165030402013082017006092a864886f70d010701a08201610482015d152400012501f1ff3602050080050180050280050380050480050580050680050780050880050980050a80050b80050c80050d80050e80050f80051080051180051280051380051480051580051680051780051880051980051a80051b80051c80051d80051e80051f80052080052180052280052380052480052580052680052780052880052980052a80052b80052c80052d80052e80052f80053080053180053280053380053480053580053680053780053880053980053a80053b80053c80053d80053e80053f80054080054180054280054380054480054580054680054780054880054980054a80054b80054c80054d80054e80054f80055080055180055280055380055480055580055680055780055880055980055a80055b80055c80055d80055e80055f80056080056180056280056380182403162c0413435341303030303053574330303030302d303024050024060024070124080018317c307a0201038014fe343f959947763b61ee4539131338494fe67d8e300b0609608648016503040201300a06082a8648ce3d0403020446304402204a12f8d42f90235c05a77121cbebae15d590146558e9c9b47a1a38f7a36a7dc5022020a4742897c30aeda0a56b36e14ebbc85bbdb74493f993581eb0444ed6ca940b")
  "The SDK example CD for vendor FFF1, products 8000..8063 (DeviceAttestationCredsExample.cpp), signed by CSA key 001.")

(defun test-attestation-credentials ()
  "The SDK's example device credentials (vendor FFF1, product 8000): what
every SDK example app presents, accepted by chip-tool's default verifier."
  (make-attestation-credentials :dac *test-dac-pem* :pai *test-pai-pem* :keypair *test-dac-key-pem*
                                :certification-declaration *test-certification-declaration*))
