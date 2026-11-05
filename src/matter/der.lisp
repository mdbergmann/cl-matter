;;;; der.lisp -- the DER decoder (X.690) behind the certificates that
;;;; arrive in X.509 form: device attestation certificates, PAA roots,
;;;; certificate signing requests and the CMS envelope of a certification
;;;; declaration.  Plus base64 and PEM, the way those files are stored.
;;;;
;;;; DER-DECODE turns octets into a tree of DER-NODEs.  A node keeps its
;;;; place in the original octets, so the exact bytes a signature covers
;;;; (a TBSCertificate, a CertificationRequestInfo) can be taken from it
;;;; without re-encoding.  Only what RFC 5280, PKCS#10 and CMS need is
;;;; interpreted: INTEGER, BOOLEAN, BIT STRING, OCTET STRING, OBJECT
;;;; IDENTIFIER, the string types, UTCTime and GeneralizedTime.

(in-package :cl-matter)

(define-condition der-error (error)
  ((message :initarg :message :reader der-error-message))
  (:report (lambda (c stream) (format stream "DER: ~a" (der-error-message c))))
  (:documentation "Malformed DER, or DER that is not what the caller expected."))

(defun %der-fail (format &rest args)
  (error 'der-error :message (apply #'format nil format args)))

;;; ------------------------------------------------------------------
;;; Tags

(defconstant +der-boolean+ #x01)
(defconstant +der-integer+ #x02)
(defconstant +der-bit-string+ #x03)
(defconstant +der-octet-string+ #x04)
(defconstant +der-null+ #x05)
(defconstant +der-oid+ #x06)
(defconstant +der-utf8-string+ #x0C)
(defconstant +der-printable-string+ #x13)
(defconstant +der-ia5-string+ #x16)
(defconstant +der-utc-time+ #x17)
(defconstant +der-generalized-time+ #x18)
(defconstant +der-sequence+ #x30)
(defconstant +der-set+ #x31)

(defun der-context-tag (number &optional (constructed t))
  "The tag octet of a context-specific [NUMBER], EXPLICIT (constructed) by default."
  (logior #x80 (if constructed #x20 0) number))

;;; ------------------------------------------------------------------
;;; Nodes

(defstruct (der-node (:constructor %make-der-node))
  "One TLV of a DER document.  TAG is the identifier octet; START..END
delimit the whole TLV in OCTETS, CONTENT-START..END its content.  A
constructed node has CHILDREN, a primitive one its content octets."
  (tag 0) octets (start 0) (content-start 0) (end 0) (children '()))

(defmethod print-object ((n der-node) stream)
  (print-unreadable-object (n stream :type t)
    (format stream "#x~2,'0x ~d octet~:p~@[ ~d children~]" (der-node-tag n)
            (- (der-node-end n) (der-node-content-start n))
            (and (der-node-constructed-p n) (length (der-node-children n))))))

(defun der-node-constructed-p (node) (logbitp 5 (der-node-tag node)))
(defun der-node-class (node) (ash (der-node-tag node) -6))
(defun der-node-number (node) (logand #x1F (der-node-tag node)))

(defun der-node-content (node)
  "The content octets of NODE, a fresh vector."
  (subseq (der-node-octets node) (der-node-content-start node) (der-node-end node)))

(defun der-node-whole (node)
  "The whole TLV of NODE, tag and length included: what a signature is over."
  (subseq (der-node-octets node) (der-node-start node) (der-node-end node)))

(defun der-node-length (node)
  (- (der-node-end node) (der-node-content-start node)))

(defun der-decode (octets &key (start 0) end (whole t))
  "The DER-NODE at START of OCTETS: (values node end-of-node).  With WHOLE
(the default) the node must extend exactly to END (default: the end of
OCTETS); trailing octets are an error."
  (let* ((octets (handler-case (%check-octet-vector "the DER document" octets)
                   (crypto-error (e) (%der-fail "~a" (crypto-error-message e)))))
         (end (or end (length octets))))
    (multiple-value-bind (node next) (%der-decode-at octets start end 0)
      (when (and whole (/= next end))
        (%der-fail "~d trailing octet~:p after the ~a" (- end next) (%der-tag-name (der-node-tag node))))
      (values node next))))

(defparameter *der-max-depth* 32)

(defun %der-decode-at (octets start end depth)
  (when (> depth *der-max-depth*) (%der-fail "nesting deeper than ~d" *der-max-depth*))
  (when (>= start end) (%der-fail "truncated: no tag at offset ~d" start))
  (let ((tag (aref octets start)) (i (1+ start)))
    (when (= #x1F (logand tag #x1F))
      (%der-fail "multi-octet tag numbers are not supported (offset ~d)" start))
    (when (>= i end) (%der-fail "truncated: no length at offset ~d" i))
    (let ((length (aref octets i)))
      (incf i)
      (cond ((= length #x80) (%der-fail "indefinite length at offset ~d is not DER" (1- i)))
            ((logbitp 7 length)
             (let ((n (logand length #x7F)))
               (when (> n 4) (%der-fail "a ~d-octet length at offset ~d" n (1- i)))
               (when (> (+ i n) end) (%der-fail "truncated length at offset ~d" i))
               (setf length (%octets-integer (subseq octets i (+ i n))))
               (when (or (zerop n) (and (= n 1) (< length 128)) (zerop (aref octets i)))
                 (%der-fail "a length that is not minimal at offset ~d" (1- i)))
               (incf i n))))
      (let ((content-end (+ i length)))
        (when (> content-end end) (%der-fail "the ~a at offset ~d runs past the end" (%der-tag-name tag) start))
        (let ((node (%make-der-node :tag tag :octets octets :start start :content-start i :end content-end)))
          (when (logbitp 5 tag)
            (setf (der-node-children node)
                  (loop :with j := i
                        :while (< j content-end)
                        :collect (multiple-value-bind (child next) (%der-decode-at octets j content-end (1+ depth))
                                   (setf j next)
                                   child))))
          (values node content-end))))))

(defun %der-tag-name (tag)
  (case tag
    (#x01 "BOOLEAN") (#x02 "INTEGER") (#x03 "BIT STRING") (#x04 "OCTET STRING") (#x05 "NULL")
    (#x06 "OBJECT IDENTIFIER") (#x0C "UTF8String") (#x13 "PrintableString") (#x16 "IA5String")
    (#x17 "UTCTime") (#x18 "GeneralizedTime") (#x30 "SEQUENCE") (#x31 "SET")
    (t (if (= #x80 (logand tag #xC0))
           (format nil "[~d]" (logand tag #x1F))
           (format nil "tag #x~2,'0x" tag)))))

;;; ------------------------------------------------------------------
;;; Expectations

(defun der-expect (node tag &optional (what (%der-tag-name tag)))
  "NODE, when its tag is TAG; else DER-ERROR naming WHAT."
  (unless (der-node-p node) (%der-fail "~a is missing" what))
  (unless (= tag (der-node-tag node))
    (%der-fail "~a expected, got ~a at offset ~d" what (%der-tag-name (der-node-tag node)) (der-node-start node)))
  node)

(defun der-children (node tag &optional what)
  "The children of the constructed NODE (tag TAG)."
  (der-node-children (der-expect node tag what)))

(defun der-child (node index &optional (tag nil) what)
  "Child INDEX of NODE, checked against TAG when given; NIL when absent."
  (let ((child (nth index (der-node-children node))))
    (if tag (der-expect child tag what) child)))

(defun der-optional-child (node index tag)
  "Child INDEX of NODE when it has tag TAG, else NIL (an OPTIONAL member)."
  (let ((child (nth index (der-node-children node))))
    (and child (= tag (der-node-tag child)) child)))

;;; ------------------------------------------------------------------
;;; Values

(defun der-node-integer (node)
  "The INTEGER (two's complement) value of NODE."
  (der-expect node +der-integer+)
  (let ((content (der-node-content node)))
    (when (zerop (length content)) (%der-fail "an empty INTEGER at offset ~d" (der-node-start node)))
    (let ((n (%octets-integer content)))
      (if (logbitp 7 (aref content 0))
          (- n (ash 1 (* 8 (length content))))
          n))))

(defun der-node-unsigned-octets (node)
  "The INTEGER content of NODE as big-endian unsigned octets, the sign
octet dropped (a serial number as a certificate stores it)."
  (der-expect node +der-integer+)
  (let ((content (der-node-content node)))
    (if (and (> (length content) 1) (zerop (aref content 0)) (logbitp 7 (aref content 1)))
        (subseq content 1)
        content)))

(defun der-node-boolean (node)
  (der-expect node +der-boolean+)
  (unless (= 1 (der-node-length node)) (%der-fail "a BOOLEAN of ~d octets" (der-node-length node)))
  (/= 0 (aref (der-node-octets node) (der-node-content-start node))))

(defun der-node-oid (node)
  "The OBJECT IDENTIFIER of NODE in dotted form."
  (der-expect node +der-oid+)
  (let ((content (der-node-content node)) (arcs '()) (value 0))
    (when (zerop (length content)) (%der-fail "an empty OBJECT IDENTIFIER"))
    (loop :for octet :across content
          :do (setf value (logior (ash value 7) (logand octet #x7F)))
              (unless (logbitp 7 octet)
                (push value arcs)
                (setf value 0)))
    (unless (zerop value) (%der-fail "a truncated OBJECT IDENTIFIER"))
    (setf arcs (nreverse arcs))
    (let* ((first (first arcs))
           (head (cond ((< first 40) (list 0 first))
                       ((< first 80) (list 1 (- first 40)))
                       (t (list 2 (- first 80))))))
      (format nil "~{~d~^.~}" (append head (rest arcs))))))

(defun der-node-string (node)
  "The string of a UTF8String, PrintableString or IA5String NODE; the
second value is :PRINTABLE, :IA5 or :UTF8."
  (let ((tag (der-node-tag node)))
    (cond ((= tag +der-utf8-string+)
           (values (or (%utf8-decode (der-node-octets node) (der-node-content-start node) (der-node-end node))
                       (%der-fail "a UTF8String that is not UTF-8"))
                   :utf8))
          ((member tag (list +der-printable-string+ +der-ia5-string+))
           (let ((content (der-node-content node)))
             (unless (every (lambda (o) (< o 128)) content)
               (%der-fail "a ~a with non-ASCII octets" (%der-tag-name tag)))
             (values (map 'string #'code-char content) (if (= tag +der-ia5-string+) :ia5 :printable))))
          (t (%der-fail "a string expected, got ~a at offset ~d" (%der-tag-name tag) (der-node-start node))))))

(defun der-node-bit-string (node)
  "The octets of a BIT STRING NODE; second value the count of unused bits."
  (der-expect node +der-bit-string+)
  (let ((content (der-node-content node)))
    (when (zerop (length content)) (%der-fail "an empty BIT STRING"))
    (when (> (aref content 0) 7) (%der-fail "a BIT STRING with ~d unused bits" (aref content 0)))
    (values (subseq content 1) (aref content 0))))

(defun der-node-bit-string-flags (node)
  "A named-bit-list BIT STRING as an integer, bit 0 the first bit (X.509 KeyUsage)."
  (multiple-value-bind (octets unused) (der-node-bit-string node)
    (let ((bits 0) (count (- (* 8 (length octets)) unused)))
      (dotimes (i count bits)
        (when (logbitp (- 7 (mod i 8)) (aref octets (floor i 8)))
          (setf bits (logior bits (ash 1 i))))))))

(defun der-node-octet-string (node)
  (der-node-content (der-expect node +der-octet-string+)))

(defun der-node-time (node)
  "The UTCTime or GeneralizedTime of NODE as Matter epoch seconds;
99991231235959Z, X.509's no-expiry time, is 0."
  (let* ((tag (der-node-tag node))
         (text (map 'string #'code-char (der-node-content node)))
         (generalized (cond ((= tag +der-generalized-time+) t)
                            ((= tag +der-utc-time+) nil)
                            (t (%der-fail "a time expected, got ~a" (%der-tag-name tag)))))
         (digits (if generalized 14 12)))
    (unless (and (= (length text) (1+ digits))
                 (char= #\Z (char text digits))
                 (every #'digit-char-p (subseq text 0 digits)))
      (%der-fail "malformed ~a ~s" (%der-tag-name tag) text))
    (flet ((field (start length) (parse-integer text :start start :end (+ start length))))
      (let* ((year (if generalized (field 0 4) (let ((yy (field 0 2))) (if (< yy 50) (+ 2000 yy) (+ 1900 yy)))))
             (offset (if generalized 4 2))
             (month (field offset 2)) (day (field (+ offset 2) 2))
             (hour (field (+ offset 4) 2)) (minute (field (+ offset 6) 2)) (second (field (+ offset 8) 2)))
        (if (and (= year 9999) (= month 12) (= day 31) (= hour 23) (= minute 59) (= second 59))
            0
            (handler-case (matter-time (encode-universal-time second minute hour day month year 0))
              (error () (%der-fail "impossible time ~s" text))))))))

;;; ------------------------------------------------------------------
;;; Base64 and PEM

(defparameter *base64-alphabet* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (octets &key (line-length nil))
  "OCTETS as base64; LINE-LENGTH breaks it into lines (PEM uses 64)."
  (let ((octets (%check-octet-vector "the data" octets))
        (out (make-string-output-stream))
        (column 0))
    (flet ((emit (char)
             (write-char char out)
             (when (and line-length (= (incf column) line-length))
               (terpri out)
               (setf column 0))))
      (loop :for i :from 0 :below (length octets) :by 3
            :for n := (min 3 (- (length octets) i))
            :for group := (loop :with v := 0 :for j :from 0 :below 3
                                :do (setf v (logior (ash v 8) (if (< j n) (aref octets (+ i j)) 0)))
                                :finally (return v))
            :do (emit (char *base64-alphabet* (ldb (byte 6 18) group)))
                (emit (char *base64-alphabet* (ldb (byte 6 12) group)))
                (emit (if (> n 1) (char *base64-alphabet* (ldb (byte 6 6) group)) #\=))
                (emit (if (> n 2) (char *base64-alphabet* (ldb (byte 6 0) group)) #\=)))
      (when (and line-length (plusp column)) (terpri out)))
    (get-output-stream-string out)))

(defun base64-decode (string)
  "The octets of base64 STRING; whitespace is skipped, padding checked."
  (let ((out (make-array (* 3 (ceiling (length string) 4)) :element-type '(unsigned-byte 8) :fill-pointer 0))
        (bits 0) (count 0) (padding 0))
    (loop :for char :across string
          :do (cond ((member char '(#\Space #\Newline #\Return #\Tab #\Linefeed)) nil)
                    ((char= char #\=) (incf padding))
                    ((plusp padding) (%der-fail "base64 data after padding"))
                    (t (let ((value (position char *base64-alphabet*)))
                         (unless value (%der-fail "~s is not a base64 character" char))
                         (setf bits (logior (ash bits 6) value))
                         (incf count)
                         (when (= count 4)
                           (vector-push (ldb (byte 8 16) bits) out)
                           (vector-push (ldb (byte 8 8) bits) out)
                           (vector-push (ldb (byte 8 0) bits) out)
                           (setf bits 0 count 0))))))
    (case count
      (0 (unless (zerop padding) (%der-fail "base64 padding without data")))
      (2 (unless (= padding 2) (%der-fail "base64: two characters need two padding characters"))
       (vector-push (ldb (byte 8 4) bits) out))
      (3 (unless (= padding 1) (%der-fail "base64: three characters need one padding character"))
       (vector-push (ldb (byte 8 10) bits) out)
       (vector-push (ldb (byte 8 2) bits) out))
      (t (%der-fail "base64 data of ~d characters is truncated" (+ count (* 4 (floor (length out) 3))))))
    (%octets out)))

(defun pem-encode (label octets)
  "OCTETS as a PEM block: -----BEGIN LABEL----- ... -----END LABEL-----."
  (format nil "-----BEGIN ~a-----~%~a-----END ~a-----~%" label (base64-encode octets :line-length 64) label))

(defun pem-decode (string)
  "The blocks of PEM text STRING as a list of (LABEL . OCTETS), in order."
  (let ((blocks '()) (start 0))
    (loop
      (let ((begin (search "-----BEGIN " string :start2 start)))
        (unless begin (return))
        (let* ((label-end (or (search "-----" string :start2 (+ begin 11))
                              (%der-fail "PEM: an unterminated BEGIN line")))
               (label (subseq string (+ begin 11) label-end))
               (footer (format nil "-----END ~a-----" label))
               (end (or (search footer string :start2 label-end)
                        (%der-fail "PEM: no END line for ~a" label))))
          (push (cons label (base64-decode (subseq string (+ label-end 5) end))) blocks)
          (setf start (+ end (length footer))))))
    (nreverse blocks)))

(defun pem-block (string label)
  "The octets of the first LABEL block of PEM STRING, or DER-ERROR."
  (or (cdr (assoc label (pem-decode string) :test #'string=))
      (%der-fail "PEM: no ~a block" label)))

(defun read-pem-file (path &optional label)
  "The blocks of the PEM file at PATH (PEM-DECODE), or the octets of its
first LABEL block when one is named."
  (let ((text (with-open-file (in path :external-format :utf-8)
                (let ((s (make-string (file-length in))))
                  (subseq s 0 (read-sequence s in))))))
    (if label (pem-block text label) (pem-decode text))))
