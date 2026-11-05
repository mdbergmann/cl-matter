;;;; discovery.lisp -- Matter discovery (Core Specification sections 4.3
;;;; and 5.1): the DNS-SD advertisements a node makes and the onboarding
;;;; payload a commissioner starts from.
;;;;
;;;; A commissionable node advertises _matterc._udp while its commissioning
;;;; window is open, with the discriminator, vendor and product ids and
;;;; commissioning mode in subtypes and TXT keys (4.3.1); an operational
;;;; node advertises _matter._tcp -- the name is historic, the transport
;;;; is UDP -- once per fabric it belongs to, the instance named after the
;;;; compressed fabric id and the node id (4.3.2).  START-DEVICE-ADVERTISING
;;;; keeps a DEVICE's advertisements in step with its window and its fabric
;;;; table through the device's ON-ADVERTISING-CHANGE hook.
;;;;
;;;; The onboarding payload (5.1) is what the user hands the commissioner:
;;;; the 11- or 21-digit manual pairing code (5.1.4) carries the passcode
;;;; and the short discriminator, the QR code (5.1.3, "MT:" + base-38) the
;;;; whole payload.  DISCOVER-COMMISSIONABLE-NODES is the commissioner's
;;;; side: browse for _matterc._udp and read the TXT keys back.

(in-package :cl-matter)

(defparameter *commissionable-service-type* "_matterc._udp")
(defparameter *operational-service-type* "_matter._tcp")
(defparameter *commissioner-service-type* "_matterd._udp")

(defconstant +commissioning-mode-none+ 0 "Not in commissioning mode (extended discovery).")
(defconstant +commissioning-mode-basic+ 1 "The initial commissioning window.")
(defconstant +commissioning-mode-enhanced+ 2 "A window an administrator opened (Administrator Commissioning).")

(defconstant +discovery-soft-ap+ 1 "Onboarding payload discovery capability: SoftAP.")
(defconstant +discovery-ble+ 2 "Onboarding payload discovery capability: BLE.")
(defconstant +discovery-on-network+ 4 "Onboarding payload discovery capability: already on the IP network.")

(defconstant +commissioning-flow-standard+ 0)
(defconstant +commissioning-flow-user-intent+ 1)
(defconstant +commissioning-flow-custom+ 2)

(define-condition discovery-error (error)
  ((message :initarg :message :reader discovery-error-message))
  (:report (lambda (c stream) (format stream "~a" (discovery-error-message c))))
  (:documentation "A malformed onboarding payload or advertisement."))

(defun %discovery-fail (format &rest args)
  (error 'discovery-error :message (apply #'format nil format args)))

(defun %hex-string (octets)
  "OCTETS as uppercase hex."
  (string-upcase (with-output-to-string (out)
                   (loop :for b :across octets :do (format out "~2,'0x" b)))))

(defun %utf8-octet-length (string)
  (%utf8-length string))

(defun %milliseconds (seconds)
  (round (* 1000 seconds)))

;;; ------------------------------------------------------------------
;;; Names

(defun random-instance-name ()
  "A commissionable node's instance name: 64 random bits as 16 uppercase
hex digits (4.3.1.3)."
  (%hex-string (random-octets 8)))

(defun random-host-name (&optional (domain "local"))
  "A host name in the shape the specification asks for (4.3.1.1, an EUI-64
as 16 uppercase hex digits) under DOMAIN; random, since the hardware's
address is not ours to know."
  (concatenate 'string (%hex-string (random-octets 8)) "." domain))

;;; ------------------------------------------------------------------
;;; TXT keys

(defun %common-txt (idle-interval active-interval active-threshold tcp icd)
  "The keys common to commissionable and operational advertisements (4.3.4):
the MRP intervals in milliseconds, TCP support, ICD mode."
  (list (format nil "SII=~d" (%milliseconds idle-interval))
        (format nil "SAI=~d" (%milliseconds active-interval))
        (format nil "SAT=~d" (%milliseconds active-threshold))
        (format nil "T=~d" tcp)
        (format nil "ICD=~d" icd)))

(defun %check-text (value max what)
  (when value
    (unless (stringp value) (%discovery-fail "~a must be a string, got ~s" what value))
    (when (> (%utf8-octet-length value) max)
      (%discovery-fail "~a is at most ~d UTF-8 octets, got ~d" what max (%utf8-octet-length value))))
  value)

(defun commissionable-service (&key discriminator port (instance (random-instance-name))
                                 vendor-id product-id (commissioning-mode +commissioning-mode-basic+)
                                 device-type device-name rotating-id pairing-hint pairing-instruction
                                 (idle-interval *mrp-default-idle-interval*)
                                 (active-interval *mrp-default-active-interval*)
                                 (active-threshold *mrp-default-active-threshold*)
                                 (tcp 0) (icd 0))
  "The _matterc._udp service of a commissionable node (4.3.1) listening on
PORT with the 12-bit DISCRIMINATOR: a DNS-SD:SERVICE with the subtypes
_L<long> _S<short> [_V<vendor>] [_T<device type>] [_CM] and the TXT keys
D, VP, CM, DT, DN, RI, PH, PI and the common SII/SAI/SAT/T/ICD.
ROTATING-ID is an octet vector of at most 50; DEVICE-NAME at most 32
UTF-8 octets; PAIRING-INSTRUCTION at most 128."
  (%check-id discriminator 12 "the discriminator")
  (unless (and (integerp port) (<= 1 port 65535)) (%discovery-fail "the port must be 1..65535, got ~s" port))
  (unless (member commissioning-mode '(0 1 2)) (%discovery-fail "the commissioning mode is 0, 1 or 2, got ~s" commissioning-mode))
  (when vendor-id (%check-id vendor-id 16 "the vendor id"))
  (when product-id (%check-id product-id 16 "the product id"))
  (when device-type (%check-id device-type 32 "the device type"))
  (when pairing-hint (%check-id pairing-hint 32 "the pairing hint"))
  (when (and product-id (null vendor-id)) (%discovery-fail "a product id needs a vendor id"))
  (when (and rotating-id (> (length rotating-id) 50)) (%discovery-fail "the rotating id is at most 50 octets, got ~d" (length rotating-id)))
  (%check-text device-name 32 "the device name")
  (%check-text pairing-instruction 128 "the pairing instruction")
  (let ((txt (list (format nil "D=~d" discriminator)))
        (subtypes (list (format nil "_S~d" (ash discriminator -8))      ; reversed below
                        (format nil "_L~d" discriminator))))
    (when vendor-id
      (push (if product-id (format nil "VP=~d+~d" vendor-id product-id) (format nil "VP=~d" vendor-id)) txt)
      (push (format nil "_V~d" vendor-id) subtypes))
    (push (format nil "CM=~d" commissioning-mode) txt)
    (unless (zerop commissioning-mode) (push "_CM" subtypes))
    (when device-type
      (push (format nil "DT=~d" device-type) txt)
      (push (format nil "_T~d" device-type) subtypes))
    (when device-name (push (format nil "DN=~a" device-name) txt))
    (when rotating-id (push (format nil "RI=~a" (%hex-string rotating-id)) txt))
    (when pairing-hint (push (format nil "PH=~d" pairing-hint) txt))
    (when pairing-instruction (push (format nil "PI=~a" pairing-instruction) txt))
    (dns-sd:make-service :instance instance :type *commissionable-service-type* :port port
                         :txt (append (nreverse txt) (%common-txt idle-interval active-interval active-threshold tcp icd))
                         :subtypes (nreverse subtypes))))

(defun operational-service (fabric &key (node-id (fabric-node-id fabric)) port
                                     (idle-interval *mrp-default-idle-interval*)
                                     (active-interval *mrp-default-active-interval*)
                                     (active-threshold *mrp-default-active-threshold*)
                                     (tcp 0) (icd 0))
  "The _matter._tcp service of NODE-ID on FABRIC listening on PORT (4.3.2):
instance <compressed fabric id>-<node id>, subtype _I<compressed fabric
id>, the common TXT keys."
  (unless (and (integerp port) (<= 1 port 65535)) (%discovery-fail "the port must be 1..65535, got ~s" port))
  (dns-sd:make-service :instance (fabric-operational-instance-name fabric node-id)
                       :type *operational-service-type* :port port
                       :txt (%common-txt idle-interval active-interval active-threshold tcp icd)
                       :subtypes (list (format nil "_I~a" (%hex-string (fabric-compressed-fabric-id fabric))))))

(defun commissioner-service (&key port (instance (random-instance-name)) vendor-id product-id device-type device-name
                               (idle-interval *mrp-default-idle-interval*)
                               (active-interval *mrp-default-active-interval*)
                               (active-threshold *mrp-default-active-threshold*)
                               (tcp 0) (icd 0))
  "The _matterd._udp service of a commissioner that devices may find
(4.3.3): VP, DT, DN and the common keys."
  (unless (and (integerp port) (<= 1 port 65535)) (%discovery-fail "the port must be 1..65535, got ~s" port))
  (when (and product-id (null vendor-id)) (%discovery-fail "a product id needs a vendor id"))
  (%check-text device-name 32 "the device name")
  (let ((txt '()) (subtypes '()))
    (when vendor-id
      (push (if product-id (format nil "VP=~d+~d" vendor-id product-id) (format nil "VP=~d" vendor-id)) txt)
      (push (format nil "_V~d" vendor-id) subtypes))
    (when device-type
      (push (format nil "DT=~d" device-type) txt)
      (push (format nil "_T~d" device-type) subtypes))
    (when device-name (push (format nil "DN=~a" device-name) txt))
    (dns-sd:make-service :instance instance :type *commissioner-service-type* :port port
                         :txt (append (nreverse txt) (%common-txt idle-interval active-interval active-threshold tcp icd))
                         :subtypes (nreverse subtypes))))

(defun %txt-integer (value)
  (and value (every #'digit-char-p value) (plusp (length value)) (parse-integer value)))

(defun parse-matter-txt (txt)
  "The Matter keys of a TXT record -- TXT the record's strings, or the
alist DNS-SD:PARSE-TXT-RECORD makes of them -- as a plist: :DISCRIMINATOR
:VENDOR-ID :PRODUCT-ID :COMMISSIONING-MODE :DEVICE-TYPE :DEVICE-NAME
:ROTATING-ID (octets) :PAIRING-HINT :PAIRING-INSTRUCTION :IDLE-INTERVAL
:ACTIVE-INTERVAL :ACTIVE-THRESHOLD (seconds) :TCP :ICD.  A key that is
absent or does not parse is left out."
  (let ((alist (if (and txt (stringp (first txt))) (dns-sd:parse-txt-record txt) txt))
        (plist '()))
    (flet ((value (key) (dns-sd:txt-value alist key))
           (put (indicator value) (when value (setf plist (list* value indicator plist)))))
      (put :discriminator (%txt-integer (value "D")))
      (let* ((vp (value "VP"))
             (plus (and vp (position #\+ vp))))
        (when vp
          (put :vendor-id (%txt-integer (subseq vp 0 plus)))
          (when plus (put :product-id (%txt-integer (subseq vp (1+ plus)))))))
      (put :commissioning-mode (%txt-integer (value "CM")))
      (put :device-type (%txt-integer (value "DT")))
      (put :device-name (value "DN"))
      (let ((ri (value "RI")))
        (when (and ri (evenp (length ri)) (every (lambda (c) (digit-char-p c 16)) ri))
          (put :rotating-id (%hex-octets ri))))
      (put :pairing-hint (%txt-integer (value "PH")))
      (put :pairing-instruction (value "PI"))
      (flet ((seconds (key) (let ((ms (%txt-integer (value key)))) (and ms (/ ms 1000d0)))))
        (put :idle-interval (seconds "SII"))
        (put :active-interval (seconds "SAI"))
        (put :active-threshold (seconds "SAT")))
      (put :tcp (%txt-integer (value "T")))
      (put :icd (%txt-integer (value "ICD"))))
    (nreverse plist)))

;;; ------------------------------------------------------------------
;;; The onboarding payload (5.1)

(defparameter *forbidden-passcodes*
  '(0 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 99999999 12345678 87654321)
  "Passcodes a device must not use (5.1.7.1).")

(defun passcode-valid-p (passcode)
  "1..99999998 and not one of the trivial values (5.1.7.1)."
  (and (integerp passcode) (<= 1 passcode 99999998) (not (member passcode *forbidden-passcodes*))))

(defun random-passcode ()
  "A setup passcode that PASSCODE-VALID-P accepts."
  (loop
    (let* ((octets (random-octets 4))
           (value (logand (logior (ash (aref octets 0) 24) (ash (aref octets 1) 16) (ash (aref octets 2) 8) (aref octets 3))
                          #x7FFFFFF)))
      (when (passcode-valid-p value) (return value)))))

(defstruct (onboarding-payload (:constructor %make-onboarding-payload))
  "What a QR or manual pairing code carries (5.1.1).  DISCRIMINATOR is the
12-bit one, or the 4-bit short one shifted into place when it came from a
manual code (SHORT-DISCRIMINATOR-P).  TLV-DATA is the optional TLV of a QR
code, raw octets or NIL."
  (version 0 :type (unsigned-byte 3))
  (vendor-id 0 :type (unsigned-byte 16))
  (product-id 0 :type (unsigned-byte 16))
  (commissioning-flow 0 :type (unsigned-byte 2))
  (discovery-capabilities 0 :type (unsigned-byte 8))
  (discriminator 0 :type (unsigned-byte 12))
  (short-discriminator-p nil)
  (passcode 0 :type (unsigned-byte 27))
  (tlv-data nil))

(defmethod print-object ((p onboarding-payload) stream)
  (print-unreadable-object (p stream :type t)
    (format stream "vendor ~4,'0x product ~4,'0x discriminator ~d~:[~; (short)~] passcode ~d"
            (onboarding-payload-vendor-id p) (onboarding-payload-product-id p)
            (onboarding-payload-discriminator p) (onboarding-payload-short-discriminator-p p)
            (onboarding-payload-passcode p))))

(defun make-onboarding-payload (&key (version 0) (vendor-id 0) (product-id 0) (commissioning-flow +commissioning-flow-standard+)
                                  (discovery-capabilities +discovery-on-network+) discriminator passcode tlv-data)
  (%check-id version 3 "the payload version")
  (%check-id vendor-id 16 "the vendor id")
  (%check-id product-id 16 "the product id")
  (%check-id commissioning-flow 2 "the commissioning flow")
  (%check-id discovery-capabilities 8 "the discovery capabilities")
  (%check-id discriminator 12 "the discriminator")
  (unless (passcode-valid-p passcode) (%discovery-fail "~s is not a valid passcode (5.1.7.1)" passcode))
  (%make-onboarding-payload :version version :vendor-id vendor-id :product-id product-id
                            :commissioning-flow commissioning-flow :discovery-capabilities discovery-capabilities
                            :discriminator discriminator :passcode passcode :tlv-data tlv-data))

(defun onboarding-payload-short-discriminator (payload)
  "The upper 4 bits of the discriminator, what a manual code carries."
  (ash (onboarding-payload-discriminator payload) -8))

;;; Verhoeff check digit (5.1.4.2)

(defparameter *verhoeff-d*
  #2A((0 1 2 3 4 5 6 7 8 9) (1 2 3 4 0 6 7 8 9 5) (2 3 4 0 1 7 8 9 5 6) (3 4 0 1 2 8 9 5 6 7) (4 0 1 2 3 9 5 6 7 8)
      (5 9 8 7 6 0 4 3 2 1) (6 5 9 8 7 1 0 4 3 2) (7 6 5 9 8 2 1 0 4 3) (8 7 6 5 9 3 2 1 0 4) (9 8 7 6 5 4 3 2 1 0)))
(defparameter *verhoeff-p*
  #2A((0 1 2 3 4 5 6 7 8 9) (1 5 7 6 2 8 3 0 9 4) (5 8 0 3 7 9 6 1 4 2) (8 9 1 6 0 4 3 5 2 7)
      (9 4 5 3 1 2 6 8 7 0) (4 2 8 6 5 7 3 9 0 1) (2 7 9 3 8 0 6 4 1 5) (7 0 4 6 9 1 3 2 5 8)))
(defparameter *verhoeff-inverse* #(0 4 3 2 1 5 6 7 8 9))

(defun verhoeff-check-digit (digits)
  "The Verhoeff check digit of the string DIGITS."
  (let ((c 0))
    (loop :for i :from 0
          :for ch :across (reverse digits)
          :do (setf c (aref *verhoeff-d* c (aref *verhoeff-p* (mod (1+ i) 8) (digit-char-p ch)))))
    (aref *verhoeff-inverse* c)))

(defun verhoeff-valid-p (digits)
  "True when the last character of DIGITS is the check digit of the rest."
  (and (> (length digits) 1)
       (= (digit-char-p (char digits (1- (length digits))))
          (verhoeff-check-digit (subseq digits 0 (1- (length digits)))))))

;;; The manual pairing code (5.1.4.1)

(defun encode-manual-pairing-code (payload &key (with-vendor-product (/= (onboarding-payload-commissioning-flow payload)
                                                                        +commissioning-flow-standard+)))
  "PAYLOAD's manual pairing code: 11 digits, or 21 with the vendor and
product ids (WITH-VENDOR-PRODUCT; the default when the commissioning flow
is not the standard one), the Verhoeff check digit last."
  (let* ((discriminator (onboarding-payload-discriminator payload))
         (passcode (onboarding-payload-passcode payload))
         (digits (with-output-to-string (out)
                   (format out "~d" (logior (if with-vendor-product 4 0) (ash discriminator -10)))
                   (format out "~5,'0d" (logior (ash (logand discriminator #x300) 6) (logand passcode #x3FFF)))
                   (format out "~4,'0d" (ash passcode -14))
                   (when with-vendor-product
                     (format out "~5,'0d~5,'0d" (onboarding-payload-vendor-id payload) (onboarding-payload-product-id payload))))))
    (format nil "~a~d" digits (verhoeff-check-digit digits))))

(defun decode-manual-pairing-code (string)
  "The ONBOARDING-PAYLOAD of a manual pairing code; characters other than
digits (dashes, spaces) are ignored.  Its discriminator is the short one
in place (SHORT-DISCRIMINATOR-P).  Signals DISCOVERY-ERROR when the length
or the check digit is wrong."
  (let ((digits (remove-if-not #'digit-char-p string)))
    (unless (member (length digits) '(11 21))
      (%discovery-fail "a manual pairing code has 11 or 21 digits, ~s has ~d" string (length digits)))
    (unless (verhoeff-valid-p digits)
      (%discovery-fail "the check digit of manual pairing code ~s is wrong" string))
    (flet ((field (start end) (parse-integer digits :start start :end end)))
      (let* ((first (field 0 1))
             (chunk2 (field 1 6))
             (chunk3 (field 6 10))
             (with-vendor-product (logbitp 2 first))
             (discriminator (logior (ash (logand first 3) 10) (ash (ash chunk2 -14) 8)))
             (passcode (logior (ash chunk3 14) (logand chunk2 #x3FFF))))
        (when (logbitp 3 first) (%discovery-fail "manual pairing code ~s has a version this decoder does not know" string))
        (when (and with-vendor-product (/= (length digits) 21))
          (%discovery-fail "manual pairing code ~s says it carries vendor and product ids but has 11 digits" string))
        (when (and (not with-vendor-product) (/= (length digits) 11))
          (%discovery-fail "manual pairing code ~s has 21 digits but does not carry vendor and product ids" string))
        (when (> chunk3 8191) (%discovery-fail "manual pairing code ~s: the passcode field is out of range" string))
        (unless (passcode-valid-p passcode) (%discovery-fail "manual pairing code ~s carries the invalid passcode ~d" string passcode))
        (%make-onboarding-payload :discriminator discriminator :short-discriminator-p t :passcode passcode
                                  :commissioning-flow (if with-vendor-product +commissioning-flow-custom+ +commissioning-flow-standard+)
                                  :vendor-id (if with-vendor-product (field 10 15) 0)
                                  :product-id (if with-vendor-product (field 15 20) 0))))))

;;; The QR code (5.1.3)

(defparameter *base38-alphabet* "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.")
(defparameter *qr-code-prefix* "MT:")

(defun base38-encode (octets)
  "Octets to base-38 (5.1.3.1): groups of three little-endian octets become
five characters, a trailing two become four, a trailing one two."
  (with-output-to-string (out)
    (loop :for start :from 0 :below (length octets) :by 3
          :do (let* ((n (min 3 (- (length octets) start)))
                     (value (loop :for i :from 0 :below n :sum (ash (aref octets (+ start i)) (* 8 i)))))
                (loop :repeat (ecase n (3 5) (2 4) (1 2))
                      :do (write-char (char *base38-alphabet* (mod value 38)) out)
                          (setf value (floor value 38)))))))

(defun base38-decode (string)
  "The inverse of BASE38-ENCODE; DISCOVERY-ERROR on a character outside the
alphabet or a group length that cannot occur."
  (let ((octets (make-array (* 3 (ceiling (length string) 5)) :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (loop :for start :from 0 :below (length string) :by 5
          :do (let* ((end (min (length string) (+ start 5)))
                     (n (ecase (- end start)
                          (5 3) (4 2) (2 1)
                          ((1 3) (%discovery-fail "base-38 text ~s has a trailing group of ~d characters" string (- end start)))))
                     (value 0))
                (loop :for i :from (1- end) :downto start
                      :do (let ((digit (position (char-upcase (char string i)) *base38-alphabet*)))
                            (unless digit (%discovery-fail "~s is not a base-38 character" (char string i)))
                            (setf value (+ (* value 38) digit))))
                (when (>= value (ash 1 (* 8 n)))
                  (%discovery-fail "base-38 group ~s does not fit ~d octets" (subseq string start end) n))
                (dotimes (i n) (vector-push (ldb (byte 8 (* 8 i)) value) octets))))
    (coerce octets '(simple-array (unsigned-byte 8) (*)))))

(defparameter *qr-payload-fields*
  '((version 3) (vendor-id 16) (product-id 16) (commissioning-flow 2) (discovery-capabilities 8)
    (discriminator 12) (passcode 27) (padding 4))
  "The packed binary data of a QR code (5.1.3.1), least significant first: 88 bits.")

(defun encode-qr-code (payload)
  "PAYLOAD as the text of its QR code: \"MT:\" and the base-38 of the 11
packed octets, with the TLV data after them when there is any."
  (let ((bits 0) (shift 0))
    (dolist (field *qr-payload-fields*)
      (destructuring-bind (name width) field
        (let ((value (case name
                       (version (onboarding-payload-version payload))
                       (vendor-id (onboarding-payload-vendor-id payload))
                       (product-id (onboarding-payload-product-id payload))
                       (commissioning-flow (onboarding-payload-commissioning-flow payload))
                       (discovery-capabilities (onboarding-payload-discovery-capabilities payload))
                       (discriminator (onboarding-payload-discriminator payload))
                       (passcode (onboarding-payload-passcode payload))
                       (padding 0))))
          (setf bits (dpb value (byte width shift) bits))
          (incf shift width))))
    (let ((octets (make-array (+ 11 (length (onboarding-payload-tlv-data payload))) :element-type '(unsigned-byte 8))))
      (dotimes (i 11) (setf (aref octets i) (ldb (byte 8 (* 8 i)) bits)))
      (when (onboarding-payload-tlv-data payload)
        (replace octets (onboarding-payload-tlv-data payload) :start1 11))
      (concatenate 'string *qr-code-prefix* (base38-encode octets)))))

(defun decode-qr-code (string)
  "The ONBOARDING-PAYLOAD of a QR code's text (\"MT:...\"); DISCOVERY-ERROR
when it is not one."
  (let ((prefix (length *qr-code-prefix*)))
    (unless (and (> (length string) prefix) (string-equal *qr-code-prefix* string :end2 prefix))
      (%discovery-fail "a QR code payload starts with ~s, ~s does not" *qr-code-prefix* string))
    (let ((octets (base38-decode (subseq string prefix))))
      (when (< (length octets) 11) (%discovery-fail "QR code ~s is too short: ~d octets, 11 needed" string (length octets)))
      (let ((bits 0) (shift 0) (fields '()))
        (dotimes (i 11) (setf bits (dpb (aref octets i) (byte 8 (* 8 i)) bits)))
        (dolist (field *qr-payload-fields*)
          (destructuring-bind (name width) field
            (push (cons name (ldb (byte width shift) bits)) fields)
            (incf shift width)))
        (flet ((field (name) (cdr (assoc name fields))))
          (unless (zerop (field 'version)) (%discovery-fail "QR code ~s has payload version ~d; only 0 is known" string (field 'version)))
          (unless (zerop (field 'padding)) (%discovery-fail "QR code ~s has non-zero padding" string))
          (unless (passcode-valid-p (field 'passcode)) (%discovery-fail "QR code ~s carries the invalid passcode ~d" string (field 'passcode)))
          (%make-onboarding-payload :version (field 'version) :vendor-id (field 'vendor-id) :product-id (field 'product-id)
                                    :commissioning-flow (field 'commissioning-flow)
                                    :discovery-capabilities (field 'discovery-capabilities)
                                    :discriminator (field 'discriminator) :passcode (field 'passcode)
                                    :tlv-data (and (> (length octets) 11) (subseq octets 11))))))))

;;; ------------------------------------------------------------------
;;; A device's advertisements

(defstruct (device-advertiser (:constructor %make-device-advertiser))
  "What START-DEVICE-ADVERTISING keeps on a DEVICE: the RESPONDER, whether
it is ours to stop, the INSTANCE name of the commissionable service and
the OPTIONS the services are built with."
  device responder owns-responder-p instance options (services '()))

(defun %device-port (device)
  (nth-value 1 (transport-local-endpoint (exchange-manager-transport (device-manager device)))))

(defun device-services (device &key (port (%device-port device)) (instance (random-instance-name))
                                 (commissioning-mode +commissioning-mode-basic+) device-type device-name
                                 rotating-id pairing-hint pairing-instruction (tcp 0) (icd 0))
  "The DNS-SD services DEVICE should advertise now: a commissionable one
while its window is open (with INSTANCE and COMMISSIONING-MODE), an
operational one per fabric.  The MRP intervals are the manager's session
parameters."
  (let* ((parameters (session-manager-session-parameters (exchange-manager-session-manager (device-manager device))))
         (mrp (list :idle-interval (%session-parameters-seconds parameters #'session-parameters-idle-interval
                                                               *mrp-default-idle-interval*)
                    :active-interval (%session-parameters-seconds parameters #'session-parameters-active-interval
                                                                 *mrp-default-active-interval*)
                    :active-threshold (%session-parameters-seconds parameters #'session-parameters-active-threshold
                                                                  *mrp-default-active-threshold*)
                    :tcp tcp :icd icd))
         (services '()))
    (when (commissioning-window-open-p device)
      (push (apply #'commissionable-service :discriminator (device-discriminator device) :port port :instance instance
                   :vendor-id (device-vendor-id device) :product-id (device-product-id device)
                   :commissioning-mode commissioning-mode :device-type device-type :device-name device-name
                   :rotating-id rotating-id :pairing-hint pairing-hint :pairing-instruction pairing-instruction
                   mrp)
            services))
    (dolist (fabric (device-fabrics device))
      (push (apply #'operational-service fabric :port port mrp) services))
    (nreverse services)))

(defun %refresh-device-advertising (device)
  "The device's services on the responder follow its state; services the
application put on a shared responder stay as they are."
  (let ((advertiser (device-advertiser device)))
    (when advertiser
      (let* ((responder (device-advertiser-responder advertiser))
             (services (apply #'device-services device :instance (device-advertiser-instance advertiser)
                              (device-advertiser-options advertiser)))
             (others (set-difference (dns-sd:responder-services responder) (device-advertiser-services advertiser))))
        (setf (device-advertiser-services advertiser) services)
        (dns-sd:responder-set-services responder (append others services))))))

(defun start-device-advertising (device &key responder host addresses interface socket (probe t) (thread t)
                                          port (instance (random-instance-name))
                                          (commissioning-mode +commissioning-mode-basic+) device-type device-name
                                          rotating-id pairing-hint pairing-instruction (tcp 0) (icd 0))
  "Advertise DEVICE over mDNS and keep the advertisement in step with its
commissioning window and fabric table.  RESPONDER is a running DNS-SD
responder to add the services to; without one, a responder is started with
HOST (default: a random EUI-64 name, as the specification asks), ADDRESSES,
INTERFACE, SOCKET, PROBE and THREAD as DNS-SD:START-RESPONDER takes them.
PORT defaults to the one the device's transport is bound to.  The other
keys are COMMISSIONABLE-SERVICE's.  Returns the DEVICE-ADVERTISER; see
DEVICE-ADVERTISED-SERVICES for what is on the air."
  (when (device-advertiser device) (error "~a is already advertising" device))
  (let* ((options (list :port (or port (%device-port device)) :commissioning-mode commissioning-mode
                        :device-type device-type :device-name device-name :rotating-id rotating-id
                        :pairing-hint pairing-hint :pairing-instruction pairing-instruction :tcp tcp :icd icd))
         (services (apply #'device-services device :instance instance options))
         (advertiser (%make-device-advertiser :device device :instance instance :options options
                                              :owns-responder-p (null responder) :services services)))
    (setf (device-advertiser-responder advertiser)
          (if responder
              (progn (dns-sd:responder-set-services responder (append (dns-sd:responder-services responder) services))
                     responder)
              (dns-sd:start-responder :services services :host (or host (random-host-name)) :addresses addresses
                                      :interface interface :socket socket :probe probe :thread thread)))
    (setf (device-advertiser device) advertiser
          (device-on-advertising-change device) #'%refresh-device-advertising)
    advertiser))

(defun stop-device-advertising (device)
  "Withdraw DEVICE's advertisements: stop the responder START-DEVICE-ADVERTISING
started, or take the device's services out of the one it was given."
  (let ((advertiser (device-advertiser device)))
    (when advertiser
      (setf (device-advertiser device) nil
            (device-on-advertising-change device) nil)
      (let ((responder (device-advertiser-responder advertiser)))
        (if (device-advertiser-owns-responder-p advertiser)
            (dns-sd:stop-responder responder)
            (dns-sd:responder-set-services responder (set-difference (dns-sd:responder-services responder)
                                                                     (device-advertiser-services advertiser)))))
      t)))

(defun device-advertised-services (device)
  "The DNS-SD services DEVICE advertises at the moment, NIL when it does not advertise."
  (let ((advertiser (device-advertiser device)))
    (and advertiser (device-advertiser-services advertiser))))

(defun device-onboarding-payload (device passcode &key (discovery-capabilities +discovery-on-network+)
                                                     (commissioning-flow +commissioning-flow-standard+))
  "The onboarding payload a commissioner needs for DEVICE, whose window
PASSCODE opens: ENCODE-QR-CODE and ENCODE-MANUAL-PAIRING-CODE print it."
  (make-onboarding-payload :vendor-id (device-vendor-id device) :product-id (device-product-id device)
                           :discriminator (device-discriminator device) :passcode passcode
                           :discovery-capabilities discovery-capabilities :commissioning-flow commissioning-flow))

;;; ------------------------------------------------------------------
;;; The commissioner's search

(defun %resolved-node (service)
  (append (list :instance (getf service :name) :host (getf service :host) :port (getf service :port)
                :addresses (getf service :addresses))
          (parse-matter-txt (getf service :txt))))

(defun discover-commissionable-nodes (&key discriminator short-discriminator vendor-id (timeout 3) socket interface)
  "Browse for commissionable nodes (4.3.1): all of them, or those with the
long DISCRIMINATOR, the SHORT-DISCRIMINATOR or the VENDOR-ID (through the
_L, _S and _V subtypes).  Returns a list of plists: :INSTANCE :HOST :PORT
:ADDRESSES and the keys PARSE-MATTER-TXT reads.  SOCKET is a DNS-SD:MDNS-SOCKET
to use; INTERFACE restricts a socket opened here."
  (let* ((subtype (cond (discriminator (format nil "_L~d" (%check-id discriminator 12 "the discriminator")))
                        (short-discriminator (format nil "_S~d" (%check-id short-discriminator 4 "the short discriminator")))
                        (vendor-id (format nil "_V~d" (%check-id vendor-id 16 "the vendor id")))))
         (type (if subtype (format nil "~a._sub.~a" subtype *commissionable-service-type*) *commissionable-service-type*))
         (owns-socket-p (null socket))
         (socket (or socket (dns-sd:open-mdns-socket :interface interface))))
    (unwind-protect
         (multiple-value-bind (instances records) (dns-sd:browse type :socket socket :timeout timeout)
           (loop :for instance :in instances
                 :for service := (dns-sd:resolve instance :socket socket :records records :timeout timeout)
                 :when service :collect (%resolved-node service)))
      (when owns-socket-p (dns-sd:close-mdns-socket socket)))))

(defun discover-operational-node (fabric node-id &key (timeout 3) socket interface)
  "Resolve NODE-ID on FABRIC (4.3.2): a plist like DISCOVER-COMMISSIONABLE-NODES
makes, or NIL when nothing answered within TIMEOUT seconds."
  (let* ((owns-socket-p (null socket))
         (socket (or socket (dns-sd:open-mdns-socket :interface interface))))
    (unwind-protect
         (let ((service (dns-sd:resolve (format nil "~a.~a.local" (fabric-operational-instance-name fabric node-id)
                                                *operational-service-type*)
                                        :socket socket :timeout timeout)))
           (and service (%resolved-node service)))
      (when owns-socket-p (dns-sd:close-mdns-socket socket)))))
