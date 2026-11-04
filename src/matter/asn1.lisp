;;;; asn1.lisp -- the DER encoder behind Matter certificates (X.690).
;;;;
;;;; A Matter operational certificate travels as TLV, but its signature
;;;; is over the DER TBSCertificate of the equivalent X.509 certificate,
;;;; so verifying one means re-encoding it to DER exactly as the signer
;;;; did.  Only the encoder is needed; the types below are the ones
;;;; RFC 5280 and the Matter certificate profile use.  Every function
;;;; returns a fresh octet vector of the whole TLV (tag, length, value).

(in-package :cl-matter)

(defun %der-length-octets (n)
  (if (< n 128)
      (vector n)
      (let ((octets (loop :with v := n :while (plusp v)
                          :collect (ldb (byte 8 0) v) :do (setf v (ash v -8)))))
        (coerce (cons (logior #x80 (length octets)) (nreverse octets)) 'vector))))

(defun der (tag &rest contents)
  "A TLV with the TAG octet and the concatenated CONTENTS (octet vectors)."
  (let ((value (apply #'%concat-octets contents)))
    (%concat-octets (vector tag) (%der-length-octets (length value)) value)))

(defun der-sequence (&rest items) (apply #'der #x30 items))
(defun der-set (&rest items) (apply #'der #x31 items))

(defun der-integer (n)
  "INTEGER from the integer N (two's complement, minimal)."
  (let ((octets (loop :with v := n
                      :collect (ldb (byte 8 0) v)
                      :do (setf v (ash v -8))
                      :until (if (minusp n) (= v -1) (zerop v)))))
    (setf octets (nreverse octets))
    ;; a positive number whose top bit is set needs a leading zero; a negative
    ;; one whose top bit is clear a leading #xFF
    (cond ((and (>= n 0) (logbitp 7 (first octets))) (push 0 octets))
          ((and (< n 0) (not (logbitp 7 (first octets)))) (push #xFF octets)))
    (der #x02 (coerce octets 'vector))))

(defun der-integer-octets (octets)
  "INTEGER from OCTETS already in two's complement, as a certificate serial
number is stored in its TLV form."
  (der #x02 octets))

(defun der-unsigned-octets (octets)
  "INTEGER from big-endian unsigned OCTETS: leading zeros dropped, a zero
added when the top bit is set (the r and s of an ECDSA signature)."
  (let ((start (or (position-if #'plusp octets) (1- (length octets)))))
    (der #x02 (if (logbitp 7 (aref octets start))
                  (%concat-octets (vector 0) (subseq octets start))
                  (subseq octets start)))))

(defun der-boolean (value) (der #x01 (vector (if value #xFF 0))))
(defun der-null () (der #x05))
(defun der-octet-string (octets) (der #x04 octets))

(defun der-bit-string (octets &optional (unused-bits 0))
  (der #x03 (vector unused-bits) octets))

(defun der-bit-string-flags (bits)
  "A named-bit-list BIT STRING from the integer BITS, bit 0 first as in
X.509 KeyUsage, trailing zero bits dropped as DER requires."
  (if (zerop bits)
      (der #x03 (vector 0))
      (let* ((count (integer-length bits))
             (octets (make-array (ceiling count 8) :element-type '(unsigned-byte 8) :initial-element 0)))
        (dotimes (i count)
          (when (logbitp i bits)
            (setf (aref octets (floor i 8)) (logior (aref octets (floor i 8)) (ash #x80 (- (mod i 8)))))))
        (der #x03 (vector (- (* 8 (length octets)) count)) octets))))

(defun der-oid (string)
  "OBJECT IDENTIFIER from its dotted form, \"1.2.840.10045.4.3.2\"."
  (let* ((arcs (loop :for start := 0 :then (1+ end)
                     :for end := (position #\. string :start start)
                     :collect (parse-integer string :start start :end end)
                     :while end))
         (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (flet ((base128 (n)
             (let ((groups (loop :with v := n :collect (ldb (byte 7 0) v) :do (setf v (ash v -7)) :until (zerop v))))
               (setf groups (nreverse groups))
               (loop :for (g . more) :on groups
                     :do (vector-push-extend (if more (logior #x80 g) g) out)))))
      (base128 (+ (* 40 (first arcs)) (second arcs)))
      (dolist (arc (cddr arcs)) (base128 arc)))
    (der #x06 out)))

(defun der-utf8-string (string) (der #x0C (%utf8-octets string)))
(defun der-printable-string (string) (der #x13 (%ascii-octets string)))
(defun der-ia5-string (string) (der #x16 (%ascii-octets string)))
(defun der-utc-time (string) (der #x17 (%ascii-octets string)))
(defun der-generalized-time (string) (der #x18 (%ascii-octets string)))

(defun der-context (number constructed-p &rest contents)
  "A context-specific [NUMBER] tag, constructed (EXPLICIT) or primitive."
  (apply #'der (logior #x80 (if constructed-p #x20 0) number) contents))

(defun %utf8-octets (string)
  (let ((out (make-array (%utf8-length string) :element-type '(unsigned-byte 8)
                                               :adjustable t :fill-pointer 0)))
    (%utf8-encode-into string out)
    (%octets out)))
