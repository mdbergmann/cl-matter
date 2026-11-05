;;;; certificate.lisp -- Matter operational certificates (Matter Core
;;;; Specification section 6.5): the TLV encoding a node stores and sends,
;;;; its mapping to the X.509 DER the signature is actually over, the
;;;; validation of an RCAC -> ICAC -> NOC chain, and the generation of
;;;; such a chain for a fabric of our own.
;;;;
;;;; A certificate is a CERTIFICATE struct.  Distinguished names are lists
;;;; of attributes, each (TYPE VALUE) or (TYPE VALUE :PRINTABLE):
;;;;
;;;;   ((:matter-node-id #xDEDEDEDE00010001) (:matter-fabric-id #xFAB000000000001D))
;;;;   ((:common-name "Lamp" :printable) (:organization-name "ACME"))
;;;;
;;;; the Matter ids as integers, the X.509 attributes as strings (UTF8String,
;;;; or PrintableString when flagged).  Extensions are a list in wire order:
;;;;
;;;;   (:basic-constraints :ca T :path-length 0)
;;;;   (:key-usage :digital-signature :key-cert-sign ...)
;;;;   (:extended-key-usage :server-auth :client-auth ...)
;;;;   (:subject-key-id OCTETS) (:authority-key-id OCTETS)
;;;;   (:future OCTETS)                 a DER Extension kept as is
;;;;
;;;; Times are Matter epoch seconds (since 2000-01-01 00:00:00 UTC); a
;;;; not-after of 0 means no expiry (99991231235959Z in X.509).

(in-package :cl-matter)

(define-condition certificate-error (error)
  ((message :initarg :message :reader certificate-error-message))
  (:report (lambda (c stream) (format stream "certificate: ~a" (certificate-error-message c))))
  (:documentation "A malformed certificate, or a chain that does not validate."))

(defun %cert-fail (format &rest args)
  (error 'certificate-error :message (apply #'format nil format args)))

;;; ------------------------------------------------------------------
;;; Constants

(defconstant +cert-tag-serial-number+ 1)
(defconstant +cert-tag-signature-algorithm+ 2)
(defconstant +cert-tag-issuer+ 3)
(defconstant +cert-tag-not-before+ 4)
(defconstant +cert-tag-not-after+ 5)
(defconstant +cert-tag-subject+ 6)
(defconstant +cert-tag-public-key-algorithm+ 7)
(defconstant +cert-tag-curve+ 8)
(defconstant +cert-tag-public-key+ 9)
(defconstant +cert-tag-extensions+ 10)
(defconstant +cert-tag-signature+ 11)

(defconstant +ext-tag-basic-constraints+ 1)
(defconstant +ext-tag-key-usage+ 2)
(defconstant +ext-tag-extended-key-usage+ 3)
(defconstant +ext-tag-subject-key-id+ 4)
(defconstant +ext-tag-authority-key-id+ 5)
(defconstant +ext-tag-future+ 6)
(defconstant +basic-constraints-tag-ca+ 1)
(defconstant +basic-constraints-tag-path-length+ 2)

(defconstant +signature-algorithm-ecdsa-sha256+ 1)
(defconstant +public-key-algorithm-ec+ 1)
(defconstant +curve-p256+ 1)
(defconstant +key-identifier-length+ 20)
(defconstant +dn-printable-flag+ #x80 "Set in a DN attribute's TLV tag for a PrintableString.")

(defparameter *oid-ecdsa-with-sha256* "1.2.840.10045.4.3.2")
(defparameter *oid-ec-public-key* "1.2.840.10045.2.1")
(defparameter *oid-prime256v1* "1.2.840.10045.3.1.7")
(defparameter *oid-basic-constraints* "2.5.29.19")
(defparameter *oid-key-usage* "2.5.29.15")
(defparameter *oid-extended-key-usage* "2.5.29.37")
(defparameter *oid-subject-key-id* "2.5.29.14")
(defparameter *oid-authority-key-id* "2.5.29.35")

(defparameter *dn-attribute-types*
  ;; TLV tag (low 7 bits), keyword, OID, value kind
  '((1 :common-name "2.5.4.3" :string)
    (2 :surname "2.5.4.4" :string)
    (3 :serial-number "2.5.4.5" :string)
    (4 :country-name "2.5.4.6" :string)
    (5 :locality-name "2.5.4.7" :string)
    (6 :state-or-province-name "2.5.4.8" :string)
    (7 :organization-name "2.5.4.10" :string)
    (8 :organizational-unit-name "2.5.4.11" :string)
    (9 :title "2.5.4.12" :string)
    (10 :name "2.5.4.41" :string)
    (11 :given-name "2.5.4.42" :string)
    (12 :initials "2.5.4.43" :string)
    (13 :generation-qualifier "2.5.4.44" :string)
    (14 :dn-qualifier "2.5.4.46" :string)
    (15 :pseudonym "2.5.4.65" :string)
    (16 :domain-component "0.9.2342.19200300.100.1.25" :ia5)
    (17 :matter-node-id "1.3.6.1.4.1.37244.1.1" :u64)
    (18 :matter-firmware-signing-id "1.3.6.1.4.1.37244.1.2" :u64)
    (19 :matter-icac-id "1.3.6.1.4.1.37244.1.3" :u64)
    (20 :matter-rcac-id "1.3.6.1.4.1.37244.1.4" :u64)
    (21 :matter-fabric-id "1.3.6.1.4.1.37244.1.5" :u64)
    (22 :matter-noc-cat "1.3.6.1.4.1.37244.1.6" :u32)
    ;; the attestation attributes of section 6.2.2.2 have no TLV form: X.509 only
    (nil :matter-vid "1.3.6.1.4.1.37244.2.1" :string)
    (nil :matter-pid "1.3.6.1.4.1.37244.2.2" :string))
  "The DN attribute types of section 6.5.6.1, by TLV tag number, and the
two of the attestation certificates (X.509 only, TLV tag NIL).")

(defparameter *key-usage-bits*
  '((:digital-signature . 0) (:non-repudiation . 1) (:key-encipherment . 2)
    (:data-encipherment . 3) (:key-agreement . 4) (:key-cert-sign . 5)
    (:crl-sign . 6) (:encipher-only . 7) (:decipher-only . 8))
  "RFC 5280 KeyUsage bit numbers.")

(defparameter *key-purposes*
  '((1 :server-auth "1.3.6.1.5.5.7.3.1")
    (2 :client-auth "1.3.6.1.5.5.7.3.2")
    (3 :code-signing "1.3.6.1.5.5.7.3.3")
    (4 :email-protection "1.3.6.1.5.5.7.3.4")
    (5 :time-stamping "1.3.6.1.5.5.7.3.8")
    (6 :ocsp-signing "1.3.6.1.5.5.7.3.9"))
  "ExtendedKeyUsage purposes by their Matter TLV id.")

;;; ------------------------------------------------------------------
;;; Matter identifiers

(defconstant +max-operational-node-id+ #xFFFFFFEFFFFFFFFF)

(defun operational-node-id-p (id)
  "True for an operational node id: 1 .. #xFFFFFFEFFFFFFFFF."
  (and (integerp id) (<= 1 id +max-operational-node-id+)))

(defun fabric-id-p (id)
  "True for a fabric id: a non-zero 64-bit value."
  (and (integerp id) (<= 1 id #xFFFFFFFFFFFFFFFF)))

(defun case-auth-tag-p (cat)
  "True for a CASE Authenticated Tag: 32 bits whose low 16, the version, are not 0."
  (and (integerp cat) (<= 0 cat #xFFFFFFFF) (/= 0 (logand cat #xFFFF))))

;;; ------------------------------------------------------------------
;;; Time

(defparameter *matter-epoch-universal-time* (encode-universal-time 0 0 0 1 1 2000 0)
  "2000-01-01 00:00:00 UTC as a universal time.")

(defun matter-time (&optional (universal-time (get-universal-time)))
  "UNIVERSAL-TIME (default now) as Matter epoch seconds."
  (- universal-time *matter-epoch-universal-time*))

(defun matter-time-universal (seconds)
  "Matter epoch SECONDS as a universal time."
  (+ seconds *matter-epoch-universal-time*))

(defun %matter-time-der (seconds)
  "The X.509 Time of Matter epoch SECONDS: 0 is the no-expiry time
99991231235959Z; UTCTime before 2050, GeneralizedTime from then on."
  (if (zerop seconds)
      (der-generalized-time "99991231235959Z")
      (multiple-value-bind (sec min hour day month year)
          (decode-universal-time (matter-time-universal seconds) 0)
        (if (< year 2050)
            (der-utc-time (format nil "~2,'0d~2,'0d~2,'0d~2,'0d~2,'0d~2,'0dZ"
                                  (mod year 100) month day hour min sec))
            (der-generalized-time (format nil "~4,'0d~2,'0d~2,'0d~2,'0d~2,'0d~2,'0dZ"
                                          year month day hour min sec))))))

;;; ------------------------------------------------------------------
;;; Distinguished names

(defun %dn-type-entry (type)
  (or (find type *dn-attribute-types* :key #'second)
      (%cert-fail "~s is not a DN attribute type" type)))

(defun dn-attribute (dn type)
  "The value of the first TYPE attribute of DN, or NIL."
  (second (find type dn :key #'first)))

(defun dn-attributes (dn type)
  "All values of the TYPE attributes of DN, in order."
  (loop :for attribute :in dn :when (eq (first attribute) type) :collect (second attribute)))

(defun dn-equal (a b)
  "True when the two DNs hold the same attributes in the same order."
  (and (= (length a) (length b))
       (every (lambda (x y)
                (and (eq (first x) (first y))
                     (equal (second x) (second y))
                     (eq (and (member :printable x) t) (and (member :printable y) t))))
              a b)))

(defun %check-dn (dn what)
  "Signal when DN is not a well-formed list of attributes; return it."
  (unless (listp dn) (%cert-fail "~a must be a list of attributes, got ~s" what dn))
  (dolist (attribute dn dn)
    (unless (and (consp attribute) (keywordp (first attribute)) (consp (rest attribute)))
      (%cert-fail "~a has a malformed attribute ~s" what attribute))
    (destructuring-bind (type value &rest flags) attribute
      (let ((kind (fourth (%dn-type-entry type))))
        (unless (subsetp flags '(:printable))
          (%cert-fail "~a: ~s has unknown flags ~s" what type flags))
        (ecase kind
          (:u64 (unless (and (integerp value) (<= 0 value #xFFFFFFFFFFFFFFFF))
                  (%cert-fail "~a: ~s must be a 64-bit integer, got ~s" what type value))
                (when (member :printable flags)
                  (%cert-fail "~a: ~s cannot be a PrintableString" what type)))
          (:u32 (unless (and (integerp value) (<= 0 value #xFFFFFFFF))
                  (%cert-fail "~a: ~s must be a 32-bit integer, got ~s" what type value))
                (when (member :printable flags)
                  (%cert-fail "~a: ~s cannot be a PrintableString" what type)))
          ((:string :ia5) (unless (stringp value)
                            (%cert-fail "~a: ~s must be a string, got ~s" what type value))))))))

(defun %dn-tlv (tag dn)
  (make-tlv-element
   tag :list
   (loop :for (type value . flags) :in dn
         :for entry := (%dn-type-entry type)
         :do (unless (first entry) (%cert-fail "~s has no Matter TLV encoding" type))
         :collect (make-tlv-element (logior (first entry) (if (member :printable flags) +dn-printable-flag+ 0))
                                    (if (member (fourth entry) '(:u64 :u32)) :unsigned :string)
                                    value))))

(defun %tlv-dn (element what)
  (unless (eq :list (tlv-element-type element))
    (%cert-fail "~a must be a TLV list, got ~a" what (tlv-element-type element)))
  (loop :for item :in (tlv-element-value element)
        :for tag := (tlv-element-tag item)
        :collect (progn
                   (unless (integerp tag)
                     (%cert-fail "~a: attribute tags must be context tags, got ~s" what tag))
                   (let ((entry (find (logand tag (lognot +dn-printable-flag+)) *dn-attribute-types* :key #'first))
                         (printable (logtest tag +dn-printable-flag+)))
                     (unless entry (%cert-fail "~a: unknown DN attribute tag ~d" what tag))
                     (ecase (fourth entry)
                       ((:u64 :u32)
                        (when printable
                          (%cert-fail "~a: ~s cannot be a PrintableString" what (second entry)))
                        (unless (eq :unsigned (tlv-element-type item))
                          (%cert-fail "~a: ~s must be an unsigned integer, got ~a"
                                      what (second entry) (tlv-element-type item)))
                        (list (second entry) (tlv-element-value item)))
                       ((:string :ia5)
                        (unless (eq :string (tlv-element-type item))
                          (%cert-fail "~a: ~s must be a string, got ~a"
                                      what (second entry) (tlv-element-type item)))
                        (if printable
                            (list (second entry) (tlv-element-value item) :printable)
                            (list (second entry) (tlv-element-value item)))))))))

(defun %dn-der (dn)
  "Name ::= SEQUENCE OF RelativeDistinguishedName, one single-attribute RDN
per attribute, the Matter ids as 16 (CATs 8) uppercase hex digits."
  (apply #'der-sequence
         (loop :for (type value . flags) :in dn
               :for entry := (%dn-type-entry type)
               :collect (der-set
                         (der-sequence
                          (der-oid (third entry))
                          (ecase (fourth entry)
                            (:u64 (der-utf8-string (format nil "~16,'0x" value)))
                            (:u32 (der-utf8-string (format nil "~8,'0x" value)))
                            (:ia5 (der-ia5-string value))
                            (:string (if (member :printable flags)
                                         (der-printable-string value)
                                         (der-utf8-string value)))))))))

;;; ------------------------------------------------------------------
;;; The certificate

(defstruct certificate
  (serial-number nil)                   ; octets, a BER INTEGER's content
  (signature-algorithm +signature-algorithm-ecdsa-sha256+)
  (issuer nil)                          ; a DN
  (not-before 0)                        ; Matter epoch seconds
  (not-after 0)                         ; 0: never expires
  (subject nil)
  (public-key-algorithm +public-key-algorithm-ec+)
  (curve +curve-p256+)
  (public-key nil)                      ; 65 octets
  (extensions nil)                      ; in wire order, see the file header
  (signature nil)                       ; 64 octets r || s
  (octets nil)                          ; the TLV encoding, once known
  (x509-der nil)                        ; the X.509 DER it was decoded from, if it was
  (x509-tbs-der nil))                   ; that DER's TBSCertificate: what its signature is over

(defmethod print-object ((c certificate) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a ~s" (ignore-errors (certificate-type c)) (certificate-subject c))))

(defun certificate-extension (certificate kind)
  "The KIND extension of CERTIFICATE as (KIND . DATA), or NIL."
  (find kind (certificate-extensions certificate) :key #'first))

(defun certificate-ca-p (certificate)
  "True when the basic constraints say cA."
  (getf (rest (certificate-extension certificate :basic-constraints)) :ca))

(defun certificate-path-length (certificate)
  "The pathLenConstraint, or NIL when there is none."
  (getf (rest (certificate-extension certificate :basic-constraints)) :path-length))

(defun certificate-key-usage (certificate)
  "The key usage keywords; second value NIL when the extension is absent."
  (let ((extension (certificate-extension certificate :key-usage)))
    (values (rest extension) (and extension t))))

(defun certificate-extended-key-usage (certificate)
  (let ((extension (certificate-extension certificate :extended-key-usage)))
    (values (rest extension) (and extension t))))

(defun certificate-subject-key-id (certificate)
  (second (certificate-extension certificate :subject-key-id)))

(defun certificate-authority-key-id (certificate)
  (second (certificate-extension certificate :authority-key-id)))

(defun certificate-node-id (certificate)
  (dn-attribute (certificate-subject certificate) :matter-node-id))

(defun certificate-fabric-id (certificate)
  (dn-attribute (certificate-subject certificate) :matter-fabric-id))

(defun certificate-case-auth-tags (certificate)
  "The CATs of a NOC's subject, in order."
  (dn-attributes (certificate-subject certificate) :matter-noc-cat))

(defun certificate-type (certificate)
  "What the subject DN says the certificate is: :ROOT, :ICA, :NODE,
:FIRMWARE-SIGNING, or NIL for an application-defined subject.  A subject
that claims two types, a node without a fabric id, or CATs on anything but
a node is CERTIFICATE-ERROR (section 6.5.11 and the SDK's GetCertType)."
  (let ((type nil) (fabric-id nil) (cats nil))
    (flet ((claim (new)
             (when type (%cert-fail "the subject claims to be both ~a and ~a" type new))
             (setf type new)))
      (dolist (attribute (certificate-subject certificate))
        (destructuring-bind (attribute-type value &rest flags) attribute
          (declare (ignore flags))
          (case attribute-type
            (:matter-rcac-id (claim :root))
            (:matter-icac-id (claim :ica))
            (:matter-firmware-signing-id (claim :firmware-signing))
            (:matter-node-id
             (claim :node)
             (unless (operational-node-id-p value)
               (%cert-fail "~16,'0x is not an operational node id" value)))
            (:matter-fabric-id
             (when fabric-id (%cert-fail "the subject has two fabric ids"))
             (unless (fabric-id-p value) (%cert-fail "~16,'0x is not a fabric id" value))
             (setf fabric-id value))
            (:matter-noc-cat
             (unless (case-auth-tag-p value) (%cert-fail "~8,'0x is not a CASE authenticated tag" value))
             (setf cats t))))))
    (when (and (eq type :node) (null fabric-id))
      (%cert-fail "a node certificate's subject must carry the fabric id"))
    (when (and cats (not (eq type :node)))
      (%cert-fail "only a node certificate's subject carries CASE authenticated tags"))
    type))

(defun certificate-valid-at-p (certificate time)
  "True when Matter epoch TIME is within the validity period."
  (and (<= (certificate-not-before certificate) time)
       (or (zerop (certificate-not-after certificate))
           (<= time (certificate-not-after certificate)))))

;;; ------------------------------------------------------------------
;;; TLV

(defun %key-usage-bits (keywords)
  (reduce #'logior keywords
          :key (lambda (k) (ash 1 (or (cdr (assoc k *key-usage-bits*))
                                      (%cert-fail "~s is not a key usage" k))))
          :initial-value 0))

(defun %key-usage-keywords (bits)
  (unless (<= 0 bits #x1FF) (%cert-fail "key usage bits ~b are out of range" bits))
  (loop :for (keyword . bit) :in *key-usage-bits* :when (logbitp bit bits) :collect keyword))

(defun %extension-tlv (extension)
  (destructuring-bind (kind &rest data) extension
    (ecase kind
      (:basic-constraints
       (make-tlv-element +ext-tag-basic-constraints+ :structure
                         (append (list (make-tlv-element +basic-constraints-tag-ca+ :boolean
                                                         (and (getf data :ca) t)))
                                 (when (getf data :path-length)
                                   (list (make-tlv-element +basic-constraints-tag-path-length+ :unsigned
                                                           (getf data :path-length)))))))
      (:key-usage (make-tlv-element +ext-tag-key-usage+ :unsigned (%key-usage-bits data)))
      (:extended-key-usage
       (make-tlv-element +ext-tag-extended-key-usage+ :array
                         (mapcar (lambda (purpose)
                                   (make-tlv-element nil :unsigned
                                                     (or (first (find purpose *key-purposes* :key #'second))
                                                         (%cert-fail "~s is not a key purpose" purpose))))
                                 data)))
      (:subject-key-id (make-tlv-element +ext-tag-subject-key-id+ :octets (first data)))
      (:authority-key-id (make-tlv-element +ext-tag-authority-key-id+ :octets (first data)))
      (:future (make-tlv-element +ext-tag-future+ :octets (first data))))))

(defun %tlv-extension (element)
  (let ((tag (tlv-element-tag element)) (type (tlv-element-type element)) (value (tlv-element-value element)))
    (flet ((need (expected what)
             (unless (eq type expected) (%cert-fail "the ~a extension must be ~a, got ~a" what expected type))))
      (cond ((eql tag +ext-tag-basic-constraints+)
             (need :structure "basic constraints")
             (let ((ca (tlv-ref element +basic-constraints-tag-ca+))
                   (path (tlv-ref element +basic-constraints-tag-path-length+)))
               (unless (and ca (eq :boolean (tlv-element-type ca)))
                 (%cert-fail "basic constraints need the boolean cA"))
               (when (and path (not (eq :unsigned (tlv-element-type path))))
                 (%cert-fail "the path length constraint must be an unsigned integer"))
               (unless (<= (length value) (if path 2 1))
                 (%cert-fail "basic constraints hold unknown elements"))
               (append (list :basic-constraints :ca (tlv-element-value ca))
                       (when path (list :path-length (tlv-element-value path))))))
            ((eql tag +ext-tag-key-usage+)
             (need :unsigned "key usage")
             (cons :key-usage (%key-usage-keywords value)))
            ((eql tag +ext-tag-extended-key-usage+)
             (need :array "extended key usage")
             (cons :extended-key-usage
                   (mapcar (lambda (item)
                             (unless (eq :unsigned (tlv-element-type item))
                               (%cert-fail "key purposes must be unsigned integers"))
                             (or (second (find (tlv-element-value item) *key-purposes* :key #'first))
                                 (%cert-fail "~d is not a key purpose" (tlv-element-value item))))
                           value)))
            ((eql tag +ext-tag-subject-key-id+)
             (need :octets "subject key id")
             (list :subject-key-id value))
            ((eql tag +ext-tag-authority-key-id+)
             (need :octets "authority key id")
             (list :authority-key-id value))
            ((eql tag +ext-tag-future+)
             (need :octets "future")
             (list :future value))
            (t (%cert-fail "unknown extension tag ~s" tag))))))

(defun encode-certificate (certificate)
  "The TLV octets of CERTIFICATE (also stored in its OCTETS slot)."
  (let ((c certificate))
    (%check-dn (certificate-issuer c) "the issuer")
    (%check-dn (certificate-subject c) "the subject")
    (unless (= (length (certificate-public-key c)) +p256-point-length+)
      (%cert-fail "the public key must be ~d octets" +p256-point-length+))
    (unless (= (length (certificate-signature c)) +p256-signature-length+)
      (%cert-fail "the signature must be ~d octets; sign the certificate first" +p256-signature-length+))
    (setf (certificate-octets c)
          (tlv-encode
           (make-tlv-element
            nil :structure
            (list (make-tlv-element +cert-tag-serial-number+ :octets (certificate-serial-number c))
                  (make-tlv-element +cert-tag-signature-algorithm+ :unsigned (certificate-signature-algorithm c))
                  (%dn-tlv +cert-tag-issuer+ (certificate-issuer c))
                  (make-tlv-element +cert-tag-not-before+ :unsigned (certificate-not-before c))
                  (make-tlv-element +cert-tag-not-after+ :unsigned (certificate-not-after c))
                  (%dn-tlv +cert-tag-subject+ (certificate-subject c))
                  (make-tlv-element +cert-tag-public-key-algorithm+ :unsigned (certificate-public-key-algorithm c))
                  (make-tlv-element +cert-tag-curve+ :unsigned (certificate-curve c))
                  (make-tlv-element +cert-tag-public-key+ :octets (certificate-public-key c))
                  (make-tlv-element +cert-tag-extensions+ :list
                                    (mapcar #'%extension-tlv (certificate-extensions c)))
                  (make-tlv-element +cert-tag-signature+ :octets (certificate-signature c))))))))

(defun %cert-field (structure tag type what &key length)
  (let ((field (tlv-ref structure tag)))
    (cond ((null field) (%cert-fail "~a is missing (tag ~d)" what tag))
          ((not (eq type (tlv-element-type field)))
           (%cert-fail "~a must be ~a, got ~a" what type (tlv-element-type field)))
          ((and length (/= length (length (tlv-element-value field))))
           (%cert-fail "~a must be ~d octets, got ~d" what length (length (tlv-element-value field))))
          (t (tlv-element-value field)))))

(defun decode-certificate (octets)
  "The CERTIFICATE in the TLV OCTETS; every field is checked for presence,
type and range, and OCTETS are kept in the struct."
  (let* ((octets (handler-case (%check-octet-vector "the certificate" octets)
                   (crypto-error (e) (%cert-fail "~a" (crypto-error-message e)))))
         (element (multiple-value-bind (element end)
                      (handler-case (tlv-decode octets)
                        (tlv-error (e) (%cert-fail "malformed TLV: ~a" e)))
                    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
                      (%cert-fail "a certificate is an anonymous TLV structure, got ~a" element))
                    (unless (= end (length octets))
                      (%cert-fail "~d trailing octet~:p after the certificate" (- (length octets) end)))
                    element)))
    (let ((known (list +cert-tag-serial-number+ +cert-tag-signature-algorithm+ +cert-tag-issuer+
                       +cert-tag-not-before+ +cert-tag-not-after+ +cert-tag-subject+
                       +cert-tag-public-key-algorithm+ +cert-tag-curve+ +cert-tag-public-key+
                       +cert-tag-extensions+ +cert-tag-signature+)))
      (dolist (item (tlv-element-value element))
        (unless (member (tlv-element-tag item) known)
          (%cert-fail "unknown certificate element with tag ~s" (tlv-element-tag item)))))
    (let ((c (make-certificate
              :serial-number (%cert-field element +cert-tag-serial-number+ :octets "the serial number")
              :signature-algorithm (%cert-field element +cert-tag-signature-algorithm+ :unsigned "the signature algorithm")
              :issuer (%tlv-dn (or (tlv-ref element +cert-tag-issuer+) (%cert-fail "the issuer is missing")) "the issuer")
              :not-before (%cert-field element +cert-tag-not-before+ :unsigned "notBefore")
              :not-after (%cert-field element +cert-tag-not-after+ :unsigned "notAfter")
              :subject (%tlv-dn (or (tlv-ref element +cert-tag-subject+) (%cert-fail "the subject is missing")) "the subject")
              :public-key-algorithm (%cert-field element +cert-tag-public-key-algorithm+ :unsigned "the public key algorithm")
              :curve (%cert-field element +cert-tag-curve+ :unsigned "the curve id")
              :public-key (%cert-field element +cert-tag-public-key+ :octets "the public key" :length +p256-point-length+)
              :signature (%cert-field element +cert-tag-signature+ :octets "the signature" :length +p256-signature-length+)
              :octets octets)))
      (let ((extensions (tlv-ref element +cert-tag-extensions+)))
        (unless extensions (%cert-fail "the extensions list is missing"))
        (unless (eq :list (tlv-element-type extensions))
          (%cert-fail "the extensions must be a TLV list, got ~a" (tlv-element-type extensions)))
        (setf (certificate-extensions c) (mapcar #'%tlv-extension (tlv-element-value extensions))))
      (unless (plusp (length (certificate-serial-number c)))
        (%cert-fail "the serial number is empty"))
      (unless (= (certificate-signature-algorithm c) +signature-algorithm-ecdsa-sha256+)
        (%cert-fail "unsupported signature algorithm ~d" (certificate-signature-algorithm c)))
      (unless (= (certificate-public-key-algorithm c) +public-key-algorithm-ec+)
        (%cert-fail "unsupported public key algorithm ~d" (certificate-public-key-algorithm c)))
      (unless (= (certificate-curve c) +curve-p256+)
        (%cert-fail "unsupported curve ~d" (certificate-curve c)))
      (unless (<= (certificate-not-before c) #xFFFFFFFF)
        (%cert-fail "notBefore is not a 32-bit time"))
      (unless (<= (certificate-not-after c) #xFFFFFFFF)
        (%cert-fail "notAfter is not a 32-bit time"))
      (unless (p256-point-p (certificate-public-key c))
        (%cert-fail "the public key is not a point on P-256"))
      (let ((kinds (mapcar #'first (certificate-extensions c))))
        (unless (= (length (remove :future kinds)) (length (remove-duplicates (remove :future kinds))))
          (%cert-fail "an extension appears twice")))
      c)))

(defun certificate (x)
  "X as a CERTIFICATE: itself, or decoded from octets."
  (if (certificate-p x) x (decode-certificate x)))

(defun certificate-octets* (certificate)
  "The TLV octets of CERTIFICATE, encoding it if they are not stored yet."
  (or (certificate-octets certificate) (encode-certificate certificate)))

;;; ------------------------------------------------------------------
;;; DER

(defun %extension-der (extension)
  (destructuring-bind (kind &rest data) extension
    (flet ((extension (oid critical value)
             (der-sequence (der-oid oid)
                           (if critical (der-boolean t) (vector))
                           (der-octet-string value))))
      (ecase kind
        (:basic-constraints
         (extension *oid-basic-constraints* t
                    (der-sequence (if (getf data :ca) (der-boolean t) (vector))
                                  (if (getf data :path-length) (der-integer (getf data :path-length)) (vector)))))
        (:key-usage
         (extension *oid-key-usage* t (der-bit-string-flags (%key-usage-bits data))))
        (:extended-key-usage
         (extension *oid-extended-key-usage* t
                    (apply #'der-sequence
                           (mapcar (lambda (purpose)
                                     (der-oid (or (third (find purpose *key-purposes* :key #'second))
                                                  (%cert-fail "~s is not a key purpose" purpose))))
                                   data))))
        (:subject-key-id
         (extension *oid-subject-key-id* nil (der-octet-string (first data))))
        (:authority-key-id
         (extension *oid-authority-key-id* nil (der-sequence (der-context 0 nil (first data)))))
        (:future (first data))))))

(defun certificate-tbs-der (certificate)
  "The DER TBSCertificate: what the signature is over.  A certificate
decoded from X.509 keeps the octets it came with; one made or decoded
from TLV is re-encoded exactly as its signer did."
  (when (certificate-x509-tbs-der certificate)
    (return-from certificate-tbs-der (certificate-x509-tbs-der certificate)))
  (let ((c certificate))
    (%check-dn (certificate-issuer c) "the issuer")
    (%check-dn (certificate-subject c) "the subject")
    (unless (= (length (certificate-public-key c)) +p256-point-length+)
      (%cert-fail "the public key must be ~d octets" +p256-point-length+))
    (unless (or (zerop (certificate-not-after c)) (< (certificate-not-before c) (certificate-not-after c)))
      (%cert-fail "notBefore must precede notAfter"))
    (der-sequence
     (der-context 0 t (der-integer 2))
     (der-integer-octets (certificate-serial-number c))
     (der-sequence (der-oid *oid-ecdsa-with-sha256*))
     (%dn-der (certificate-issuer c))
     (der-sequence (%matter-time-der (certificate-not-before c))
                   (%matter-time-der (certificate-not-after c)))
     (%dn-der (certificate-subject c))
     (der-sequence (der-sequence (der-oid *oid-ec-public-key*) (der-oid *oid-prime256v1*))
                   (der-bit-string (certificate-public-key c)))
     (der-context 3 t (apply #'der-sequence (mapcar #'%extension-der (certificate-extensions c)))))))

(defun ecdsa-signature-der (signature)
  "The 64-octet r || s as the DER Ecdsa-Sig-Value X.509 carries."
  (unless (= (length signature) +p256-signature-length+)
    (%cert-fail "an ECDSA signature is ~d octets, got ~d" +p256-signature-length+ (length signature)))
  (der-sequence (der-unsigned-octets (subseq signature 0 +p256-scalar-length+))
                (der-unsigned-octets (subseq signature +p256-scalar-length+))))

(defun certificate-der (certificate)
  "The whole X.509 certificate in DER, as openssl or a TLS stack would
read it: the octets it was decoded from, or the encoding of its fields."
  (when (certificate-x509-der certificate)
    (return-from certificate-der (certificate-x509-der certificate)))
  (der-sequence (certificate-tbs-der certificate)
                (der-sequence (der-oid *oid-ecdsa-with-sha256*))
                (der-bit-string (ecdsa-signature-der (certificate-signature certificate)))))

;;; ------------------------------------------------------------------
;;; Signing and verifying

(defun certificate-tbs-digest (certificate)
  (sha256 (certificate-tbs-der certificate)))

(defun verify-certificate-signature (certificate signer)
  "True when CERTIFICATE's signature is by SIGNER's public key (a certificate
or 65 octets)."
  (let ((public (if (certificate-p signer) (certificate-public-key signer) signer)))
    (and (certificate-signature certificate)
         (p256-verify-digest public (certificate-tbs-digest certificate) (certificate-signature certificate)))))

(defun sign-certificate (certificate private &key (encode t))
  "Sign CERTIFICATE with PRIVATE (a P256-KEYPAIR, an integer or 32 octets):
sets its signature, encodes it as TLV, and returns it.  With ENCODE NIL
the certificate is X.509-only (an attestation certificate, whose subject
has no TLV form): its DER is stored instead."
  (setf (certificate-x509-der certificate) nil ; a stored X.509 form would carry the old signature
        (certificate-x509-tbs-der certificate) nil)
  (setf (certificate-signature certificate) (p256-sign-digest private (certificate-tbs-digest certificate)))
  (if encode
      (encode-certificate certificate)
      (setf (certificate-x509-tbs-der certificate) (certificate-tbs-der certificate)
            (certificate-x509-der certificate) (certificate-der certificate)))
  certificate)

(defun subject-key-identifier (public-key)
  "The RFC 5280 method-1 key identifier: SHA-1 of the public key octets."
  (ironclad:digest-sequence :sha1 (%check-octet-vector "the public key" public-key)))

;;; ------------------------------------------------------------------
;;; Chain validation (section 6.5.11, the SDK's ValidateCert and
;;; VerifyCredentials)

(defun %check-issued-by (certificate issuer what)
  "CERTIFICATE names ISSUER's subject and key id as its issuer, and ISSUER signed it."
  (unless (dn-equal (certificate-issuer certificate) (certificate-subject issuer))
    (%cert-fail "~a's issuer is not the subject of its signer" what))
  (unless (equalp (certificate-authority-key-id certificate) (certificate-subject-key-id issuer))
    (%cert-fail "~a's authority key id is not its signer's subject key id" what))
  (unless (verify-certificate-signature certificate issuer)
    (%cert-fail "~a's signature does not verify" what)))

(defun %check-ca-certificate (certificate depth what)
  "A certificate that signs others: cA, keyCertSign, path length allowing DEPTH - 1 below."
  (unless (certificate-ca-p certificate) (%cert-fail "~a is not a CA certificate" what))
  (unless (member :key-cert-sign (certificate-key-usage certificate))
    (%cert-fail "~a lacks the keyCertSign key usage" what))
  (let ((path-length (certificate-path-length certificate)))
    (when (and path-length (> (1- depth) path-length))
      (%cert-fail "~a's path length constraint ~d does not allow this chain" what path-length))))

(defun %check-future-extensions (certificate what)
  "A future extension marked critical makes the certificate unusable."
  (dolist (extension (certificate-extensions certificate))
    (when (and (eq :future (first extension))
               (%der-extension-critical-p (second extension)))
      (%cert-fail "~a has a critical extension we do not understand" what))))

(defun %der-extension-critical-p (octets)
  "True when the DER Extension OCTETS carry critical TRUE: SEQUENCE { OID,
BOOLEAN, OCTET STRING }; anything unparseable counts as critical."
  (handler-case
      (let ((i 0))
        (flet ((tlv ()                  ; -> (values tag content-start content-end)
                 (let ((tag (aref octets i)) (len (aref octets (1+ i))) (start (+ i 2)))
                   (when (logbitp 7 len)
                     (let ((n (logand len #x7F)))
                       (setf len (%octets-integer (subseq octets start (+ start n)))
                             start (+ start n))))
                   (values tag start (+ start len)))))
          (multiple-value-bind (tag start end) (tlv)
            (unless (= tag #x30) (return-from %der-extension-critical-p t))
            (setf i start)
            (multiple-value-bind (tag oid-start oid-end) (tlv)
              (declare (ignore oid-start))
              (unless (= tag #x06) (return-from %der-extension-critical-p t))
              (setf i oid-end)
              (when (< i end)
                (multiple-value-bind (tag start2 end2) (tlv)
                  (and (= tag #x01) (plusp (aref octets start2)) (< start2 end2))))))))
    (error () t)))

(defun validate-rcac (rcac)
  "RCAC (a certificate or octets) is a well-formed, self-signed root:
returns the certificate.  Its validity period is not checked."
  (let ((c (certificate rcac)))
    (unless (eq :root (certificate-type c)) (%cert-fail "the RCAC's subject is not a root"))
    (unless (dn-equal (certificate-subject c) (certificate-issuer c))
      (%cert-fail "the RCAC is not self-issued"))
    (unless (and (certificate-subject-key-id c)
                 (equalp (certificate-subject-key-id c) (certificate-authority-key-id c)))
      (%cert-fail "the RCAC's authority key id is not its subject key id"))
    (unless (certificate-ca-p c) (%cert-fail "the RCAC is not a CA certificate"))
    (let ((path-length (certificate-path-length c)))
      (when (and path-length (> path-length 1))
        (%cert-fail "the RCAC's path length constraint must be at most 1")))
    (unless (member :key-cert-sign (certificate-key-usage c))
      (%cert-fail "the RCAC lacks the keyCertSign key usage"))
    (%check-future-extensions c "the RCAC")
    (unless (verify-certificate-signature c c)
      (%cert-fail "the RCAC's signature does not verify"))
    c))

(defun validate-certificate-chain (noc icac rcac &key time)
  "The operational credentials NOC, ICAC (or NIL) and RCAC, certificates or
octets, form a valid chain: each is well formed and of the right type, the
NOC is for digital signatures with the serverAuth and clientAuth purposes,
the CAs may sign, every link names and signs the next, the fabric ids
agree, and each certificate is within its validity period at Matter epoch
TIME when one is given.  Returns (values node-id fabric-id cats
noc-public-key root-public-key); a failure is CERTIFICATE-ERROR."
  (let* ((rcac (validate-rcac rcac))
         (icac (and icac (certificate icac)))
         (noc (certificate noc))
         (signer rcac))
    (when time
      (unless (certificate-valid-at-p rcac time) (%cert-fail "the RCAC is not valid at this time")))
    (when icac
      (unless (eq :ica (certificate-type icac)) (%cert-fail "the ICAC's subject is not an intermediate CA"))
      (%check-future-extensions icac "the ICAC")
      (%check-ca-certificate rcac 2 "the RCAC")
      (%check-ca-certificate icac 1 "the ICAC")
      (%check-issued-by icac rcac "the ICAC")
      (when time
        (unless (certificate-valid-at-p icac time) (%cert-fail "the ICAC is not valid at this time")))
      (setf signer icac))
    (unless (eq :node (certificate-type noc)) (%cert-fail "the NOC's subject is not a node"))
    (%check-future-extensions noc "the NOC")
    (when (certificate-ca-p noc) (%cert-fail "the NOC must not be a CA certificate"))
    (unless (member :digital-signature (certificate-key-usage noc))
      (%cert-fail "the NOC lacks the digitalSignature key usage"))
    (unless (subsetp '(:server-auth :client-auth) (certificate-extended-key-usage noc))
      (%cert-fail "the NOC lacks the serverAuth and clientAuth key purposes"))
    (%check-issued-by noc signer "the NOC")
    (when time
      (unless (certificate-valid-at-p noc time) (%cert-fail "the NOC is not valid at this time")))
    (let ((fabric-id (certificate-fabric-id noc)))
      (when (and icac (certificate-fabric-id icac) (/= (certificate-fabric-id icac) fabric-id))
        (%cert-fail "the ICAC's fabric id differs from the NOC's"))
      (when (and (certificate-fabric-id rcac) (/= (certificate-fabric-id rcac) fabric-id))
        (%cert-fail "the RCAC's fabric id differs from the NOC's"))
      (values (certificate-node-id noc) fabric-id (certificate-case-auth-tags noc)
              (certificate-public-key noc) (certificate-public-key rcac)))))

;;; ------------------------------------------------------------------
;;; Making certificates of our own

(defun %serial-number (serial)
  "SERIAL, an integer or octets, as the content of a positive BER INTEGER."
  (cond ((null serial)
         ;; 8 random octets, the top bit clear so the INTEGER stays 8 octets
         (let ((octets (random-octets 8)))
           (setf (aref octets 0) (logand (aref octets 0) #x7F))
           octets))
        ((integerp serial) (%serial-number (%integer-octets serial (max 1 (ceiling (integer-length serial) 8)))))
        (t (let ((octets (%check-octet-vector "the serial number" serial)))
             (if (logbitp 7 (aref octets 0)) (%concat-octets (vector 0) octets) octets)))))

(defun %make-signed-certificate (&key subject issuer public-key signer serial-number not-before not-after
                                   extensions x509)
  (let ((c (make-certificate :serial-number (%serial-number serial-number)
                             :issuer issuer :subject subject
                             :not-before not-before :not-after not-after
                             :public-key public-key
                             :extensions extensions)))
    (certificate-type c)                ; a malformed subject fails here, not at the peer
    (sign-certificate c signer :encode (not x509))))

(defun make-root-certificate (&key keypair rcac-id fabric-id serial-number
                                (not-before (matter-time)) (not-after 0) subject x509)
  "A self-signed RCAC for KEYPAIR with subject matter-rcac-id RCAC-ID (default
1) and, if given, matter-fabric-id FABRIC-ID; SUBJECT replaces that default
subject.  NOT-AFTER 0 means never.  X509 makes an X.509-only certificate
(a PAA: its subject has no TLV form)."
  (let* ((subject (or subject
                      (append (list (list :matter-rcac-id (or rcac-id 1)))
                              (when fabric-id (list (list :matter-fabric-id fabric-id))))))
         (key-id (subject-key-identifier (p256-keypair-public keypair))))
    (%make-signed-certificate
     :x509 x509
     :subject subject :issuer subject
     :public-key (p256-keypair-public keypair) :signer keypair
     :serial-number serial-number :not-before not-before :not-after not-after
     :extensions (list '(:basic-constraints :ca t)
                       '(:key-usage :key-cert-sign :crl-sign)
                       (list :subject-key-id key-id)
                       (list :authority-key-id key-id)))))

(defun make-ica-certificate (&key keypair icac-id fabric-id issuer issuer-keypair serial-number
                               (not-before (matter-time)) (not-after 0) subject x509)
  "An ICAC for KEYPAIR signed by the ISSUER certificate's ISSUER-KEYPAIR."
  (let ((subject (or subject
                     (append (list (list :matter-icac-id (or icac-id 1)))
                             (when fabric-id (list (list :matter-fabric-id fabric-id)))))))
    (%make-signed-certificate
     :x509 x509
     :subject subject :issuer (certificate-subject issuer)
     :public-key (p256-keypair-public keypair) :signer issuer-keypair
     :serial-number serial-number :not-before not-before :not-after not-after
     :extensions (list '(:basic-constraints :ca t :path-length 0)
                       '(:key-usage :key-cert-sign :crl-sign)
                       (list :subject-key-id (subject-key-identifier (p256-keypair-public keypair)))
                       (list :authority-key-id (certificate-subject-key-id issuer))))))

(defun make-node-certificate (&key public-key node-id fabric-id case-auth-tags issuer issuer-keypair
                                serial-number (not-before (matter-time)) (not-after 0) subject x509)
  "A NOC for PUBLIC-KEY (65 octets, or a P256-KEYPAIR) and NODE-ID on
FABRIC-ID, with the CASE-AUTH-TAGS, signed by the ISSUER certificate's
ISSUER-KEYPAIR (an RCAC or ICAC)."
  (let ((public-key (if (p256-keypair-p public-key) (p256-keypair-public public-key) public-key))
        (subject (or subject
                     (append (list (list :matter-node-id node-id) (list :matter-fabric-id fabric-id))
                             (mapcar (lambda (cat) (list :matter-noc-cat cat)) case-auth-tags)))))
    (%make-signed-certificate
     :x509 x509
     :subject subject :issuer (certificate-subject issuer)
     :public-key public-key :signer issuer-keypair
     :serial-number serial-number :not-before not-before :not-after not-after
     :extensions (list '(:basic-constraints :ca nil)
                       '(:key-usage :digital-signature)
                       '(:extended-key-usage :client-auth :server-auth)
                       (list :subject-key-id (subject-key-identifier public-key))
                       (list :authority-key-id (certificate-subject-key-id issuer))))))

;;; ------------------------------------------------------------------
;;; X.509 import (RFC 5280 over der.lisp): the attestation certificates
;;; of section 6.2.2, PAA roots, and anything else that arrives as DER
;;; rather than Matter TLV.  The decoded certificate keeps its DER and its
;;; TBSCertificate, so its signature verifies over the original octets
;;; and CERTIFICATE-DER gives them back unchanged.

(defparameter *oid-dn-types*
  (loop :for entry :in *dn-attribute-types* :collect (cons (third entry) entry))
  "DN attribute entries by OID, for the X.509 direction.")

(defun %der-dn (node what)
  "An X.509 Name NODE as our DN list.  An attribute whose type we do not
know becomes ((:OID \"1.2...\") VALUE) and cannot be re-encoded."
  (loop :for rdn :in (der-children node +der-sequence+ what)
        :append (loop :for attribute :in (der-children rdn +der-set+ (format nil "~a's RDN" what))
                      :collect (let* ((parts (der-children attribute +der-sequence+ (format nil "~a's attribute" what)))
                                      (oid (der-node-oid (first parts)))
                                      (value (second parts))
                                      (entry (cdr (assoc oid *oid-dn-types* :test #'string=))))
                                 (unless value (%cert-fail "~a: an attribute without a value" what))
                                 (cond ((null entry)
                                        (list (list :oid oid)
                                              (if (member (der-node-tag value)
                                                          (list +der-utf8-string+ +der-printable-string+ +der-ia5-string+))
                                                  (der-node-string value)
                                                  (der-node-content value))))
                                       ((member (fourth entry) '(:u64 :u32))
                                        (multiple-value-bind (string kind) (der-node-string value)
                                          (declare (ignore kind))
                                          (let ((digits (if (eq :u64 (fourth entry)) 16 8)))
                                            (unless (and (= (length string) digits)
                                                         (every (lambda (c) (digit-char-p c 16)) string))
                                              (%cert-fail "~a: ~s is not ~d hex digits: ~s" what (second entry) digits string))
                                            (list (second entry) (parse-integer string :radix 16)))))
                                       (t (multiple-value-bind (string kind) (der-node-string value)
                                            (if (eq kind :printable)
                                                (list (second entry) string :printable)
                                                (list (second entry) string)))))))))

(defun %der-extension (node)
  "An X.509 Extension NODE as our extension form; unknown ones are kept as (:future DER)."
  (let* ((parts (der-children node +der-sequence+ "an extension"))
         (oid (der-node-oid (first parts)))
         (value (der-node-octet-string (car (last parts)))))
    (unless (<= 2 (length parts) 3) (%cert-fail "an extension with ~d members" (length parts)))
    (cond ((string= oid *oid-basic-constraints*)
           (let* ((members (der-children (der-decode value) +der-sequence+ "basic constraints"))
                  (ca-node (and (first members) (= +der-boolean+ (der-node-tag (first members))) (first members)))
                  (path-node (find +der-integer+ members :key #'der-node-tag)))
             (append (list :basic-constraints :ca (and ca-node (der-node-boolean ca-node)))
                     (when path-node (list :path-length (der-node-integer path-node))))))
          ((string= oid *oid-key-usage*)
           (cons :key-usage (%key-usage-keywords (der-node-bit-string-flags (der-decode value)))))
          ((string= oid *oid-extended-key-usage*)
           (cons :extended-key-usage
                 (mapcar (lambda (purpose)
                           (let ((oid (der-node-oid purpose)))
                             (or (second (find oid *key-purposes* :key #'third :test #'string=))
                                 (%cert-fail "unknown key purpose ~a" oid))))
                         (der-children (der-decode value) +der-sequence+ "extended key usage"))))
          ((string= oid *oid-subject-key-id*)
           (list :subject-key-id (der-node-octet-string (der-decode value))))
          ((string= oid *oid-authority-key-id*)
           (let* ((members (der-children (der-decode value) +der-sequence+ "authority key id"))
                  (key-id (find (der-context-tag 0 nil) members :key #'der-node-tag)))
             (unless key-id (%cert-fail "an authority key id without the key identifier"))
             (list :authority-key-id (der-node-content key-id))))
          (t (list :future (der-node-whole node))))))

(defun ecdsa-signature-from-der (octets)
  "The 64-octet r || s of a DER Ecdsa-Sig-Value."
  (let ((parts (der-children (der-decode octets) +der-sequence+ "the ECDSA signature")))
    (unless (= 2 (length parts)) (%cert-fail "an ECDSA signature with ~d integers" (length parts)))
    (flet ((scalar (node)
             (let ((n (der-node-integer node)))
               (unless (<= 0 n (1- (ash 1 256))) (%cert-fail "an ECDSA signature integer out of range"))
               (%integer-octets n +p256-scalar-length+))))
      (%concat-octets (scalar (first parts)) (scalar (second parts))))))

(defun %der-subject-public-key (node what)
  "The 65 octets of an id-ecPublicKey / prime256v1 SubjectPublicKeyInfo."
  (let* ((parts (der-children node +der-sequence+ what))
         (algorithm (der-children (first parts) +der-sequence+ (format nil "~a's algorithm" what))))
    (unless (and (= 2 (length parts)) (= 2 (length algorithm)))
      (%cert-fail "~a is not an EC SubjectPublicKeyInfo" what))
    (unless (string= *oid-ec-public-key* (der-node-oid (first algorithm)))
      (%cert-fail "~a: unsupported public key algorithm ~a" what (der-node-oid (first algorithm))))
    (unless (string= *oid-prime256v1* (der-node-oid (second algorithm)))
      (%cert-fail "~a: unsupported curve ~a" what (der-node-oid (second algorithm))))
    (let ((key (der-node-bit-string (second parts))))
      (unless (= (length key) +p256-point-length+)
        (%cert-fail "~a: a public key of ~d octets" what (length key)))
      (unless (p256-point-p key) (%cert-fail "~a: the public key is not a point on P-256" what))
      key)))

(defun decode-certificate-der (octets)
  "The CERTIFICATE in the X.509 DER OCTETS.  Only the Matter profile is
accepted: version 3, ecdsa-with-SHA256, a P-256 key.  The DER and its
TBSCertificate stay with the certificate."
  (handler-case
      (let* ((octets (%check-octet-vector "the certificate" octets))
             (top (der-children (der-decode octets) +der-sequence+ "the certificate"))
             (tbs (first top))
             (members (der-children tbs +der-sequence+ "the TBSCertificate"))
             (version (der-optional-child tbs 0 (der-context-tag 0))))
        (unless (= 3 (length top)) (%cert-fail "a certificate has three members, got ~d" (length top)))
        (unless version (%cert-fail "the certificate is not version 3 (no version member)"))
        (unless (= 2 (der-node-integer (der-child version 0 +der-integer+ "the version")))
          (%cert-fail "unsupported certificate version ~d" (1+ (der-node-integer (der-child version 0)))))
        (pop members)
        (when (< (length members) 7) (%cert-fail "a TBSCertificate with ~d members" (1+ (length members))))
        (destructuring-bind (serial algorithm issuer validity subject spki &rest rest) members
          (let ((algorithm-oid (der-node-oid (der-child algorithm 0 +der-oid+ "the signature algorithm")))
                (outer-algorithm (der-node-oid (der-child (second top) 0 +der-oid+ "the signature algorithm")))
                (extensions (find (der-context-tag 3) rest :key #'der-node-tag)))
            (unless (string= algorithm-oid *oid-ecdsa-with-sha256*)
              (%cert-fail "unsupported signature algorithm ~a" algorithm-oid))
            (unless (string= outer-algorithm algorithm-oid)
              (%cert-fail "the signature algorithms inside and outside the TBSCertificate differ"))
            (let* ((times (der-children validity +der-sequence+ "the validity"))
                   (c (make-certificate
                       :serial-number (der-node-unsigned-octets serial)
                       :issuer (%der-dn issuer "the issuer")
                       :not-before (der-node-time (first times))
                       :not-after (der-node-time (second times))
                       :subject (%der-dn subject "the subject")
                       :public-key (%der-subject-public-key spki "the subject public key")
                       :extensions (and extensions
                                        (mapcar #'%der-extension
                                                (der-children (der-child extensions 0 +der-sequence+ "the extensions")
                                                              +der-sequence+ "the extensions")))
                       :signature (ecdsa-signature-from-der (der-node-bit-string (third top)))
                       :x509-der octets
                       :x509-tbs-der (der-node-whole tbs))))
              (unless (= 2 (length times)) (%cert-fail "a validity with ~d times" (length times)))
              (unless (plusp (length (certificate-serial-number c))) (%cert-fail "the serial number is empty"))
              (unless (or (zerop (certificate-not-after c)) (<= (certificate-not-before c) (certificate-not-after c)))
                (%cert-fail "notBefore is after notAfter"))
              (let ((kinds (mapcar #'first (certificate-extensions c))))
                (unless (= (length (remove :future kinds)) (length (remove-duplicates (remove :future kinds))))
                  (%cert-fail "an extension appears twice")))
              c))))
    (der-error (e) (%cert-fail "malformed X.509: ~a" (der-error-message e)))
    (crypto-error (e) (%cert-fail "~a" (crypto-error-message e)))))

(defun decode-certificate-pem (string)
  "The CERTIFICATE in the first CERTIFICATE block of PEM STRING."
  (decode-certificate-der (handler-case (pem-block string "CERTIFICATE")
                            (der-error (e) (%cert-fail "~a" (der-error-message e))))))

(defun certificate-from-octets (octets)
  "A CERTIFICATE from OCTETS in either form: Matter TLV (an anonymous
structure, first octet #x15) or X.509 DER (a SEQUENCE, #x30)."
  (let ((octets (%check-octet-vector "the certificate" octets)))
    (cond ((zerop (length octets)) (%cert-fail "the certificate is empty"))
          ((= #x30 (aref octets 0)) (decode-certificate-der octets))
          (t (decode-certificate octets)))))

;;; The vendor and product id of an attestation certificate (section
;;; 6.2.2.2): the Matter DN attributes, or the fallback "Mvid:FFF1" /
;;; "Mpid:8000" inside a string attribute.

(defun %dn-hex-id (dn type marker what)
  (let ((values (dn-attributes dn type)))
    (when (> (length values) 1) (%cert-fail "~a appears ~d times in the subject" what (length values)))
    (if values
        (let ((string (first values)))
          (unless (and (= 4 (length string)) (every (lambda (c) (digit-char-p c 16)) string))
            (%cert-fail "~a ~s is not 4 hex digits" what string))
          (parse-integer string :radix 16))
        (loop :for attribute :in dn
              :for value := (second attribute)
              :for start := (and (stringp value) (search marker value))
              :when (and start (<= (+ start (length marker) 4) (length value))
                         (every (lambda (c) (digit-char-p c 16))
                                (subseq value (+ start (length marker)) (+ start (length marker) 4))))
                :return (parse-integer value :start (+ start (length marker)) :end (+ start (length marker) 4) :radix 16)))))

(defun certificate-vendor-id (certificate)
  "The vendor id of an attestation certificate's subject, or NIL."
  (%dn-hex-id (certificate-subject certificate) :matter-vid "Mvid:" "the vendor id"))

(defun certificate-product-id (certificate)
  "The product id of an attestation certificate's subject, or NIL."
  (%dn-hex-id (certificate-subject certificate) :matter-pid "Mpid:" "the product id"))

;;; EC private keys as openssl writes them

(defparameter *oid-pkcs8-ec-key* *oid-ec-public-key*)

(defun decode-ec-private-key (octets)
  "The P256-KEYPAIR in OCTETS: a SEC 1 ECPrivateKey (an \"EC PRIVATE KEY\"
PEM block) or a PKCS#8 PrivateKeyInfo wrapping one (\"PRIVATE KEY\")."
  (handler-case
      (let* ((octets (%check-octet-vector "the private key" octets))
             (members (der-children (der-decode octets) +der-sequence+ "the private key")))
        (when (and (>= (length members) 3) (= +der-sequence+ (der-node-tag (second members))))
          ;; PKCS#8: version, algorithm, OCTET STRING holding the SEC 1 key
          (let ((algorithm (der-children (second members) +der-sequence+ "the key algorithm")))
            (unless (string= *oid-pkcs8-ec-key* (der-node-oid (first algorithm)))
              (%cert-fail "unsupported private key algorithm ~a" (der-node-oid (first algorithm))))
            (when (and (second algorithm) (= +der-oid+ (der-node-tag (second algorithm)))
                       (not (string= *oid-prime256v1* (der-node-oid (second algorithm)))))
              (%cert-fail "unsupported curve ~a" (der-node-oid (second algorithm)))))
          (setf members (der-children (der-decode (der-node-octet-string (third members)))
                                      +der-sequence+ "the EC private key")))
        (unless (and (>= (length members) 2) (= 1 (der-node-integer (first members))))
          (%cert-fail "not a version 1 ECPrivateKey"))
        (let ((private (der-node-octet-string (second members)))
              (parameters (find (der-context-tag 0) members :key #'der-node-tag))
              (public (find (der-context-tag 1) members :key #'der-node-tag)))
          (when parameters
            (let ((curve (der-node-oid (der-child parameters 0 +der-oid+ "the curve"))))
              (unless (string= curve *oid-prime256v1*) (%cert-fail "unsupported curve ~a" curve))))
          (let ((keypair (make-p256-keypair private)))
            (when public
              (unless (equalp (p256-keypair-public keypair)
                              (der-node-bit-string (der-child public 0 +der-bit-string+ "the public key")))
                (%cert-fail "the public key in the file is not the private key's")))
            keypair)))
    (der-error (e) (%cert-fail "malformed private key: ~a" (der-error-message e)))
    (crypto-error (e) (%cert-fail "~a" (crypto-error-message e)))))

(defun decode-ec-private-key-pem (string)
  "The P256-KEYPAIR of the first EC PRIVATE KEY or PRIVATE KEY block of PEM STRING."
  (let ((blocks (handler-case (pem-decode string) (der-error (e) (%cert-fail "~a" (der-error-message e))))))
    (let ((block (or (assoc "EC PRIVATE KEY" blocks :test #'string=)
                     (assoc "PRIVATE KEY" blocks :test #'string=))))
      (unless block (%cert-fail "no private key block in the PEM text"))
      (decode-ec-private-key (cdr block)))))

(defun encode-ec-private-key (keypair)
  "KEYPAIR as a SEC 1 ECPrivateKey in DER, as openssl's EC PRIVATE KEY."
  (der-sequence (der-integer 1)
                (der-octet-string (p256-keypair-private keypair))
                (der-context 0 t (der-oid *oid-prime256v1*))
                (der-context 1 t (der-bit-string (p256-keypair-public keypair)))))
