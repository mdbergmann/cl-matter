(defpackage :cl-matter.tlv.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.tlv.tests)

(def-suite tlv-tests :description "Matter TLV codec" :in cl-matter.tests:test-suite)
(in-suite tlv-tests)

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun hex (string)
  (let* ((digits (remove #\Space string))
         (out (make-array (floor (length digits) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer digits :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun round-trip (element)
  (tlv-decode (tlv-encode element)))

(defmacro encodes-as (element hex-string)
  "ELEMENT encodes to the octets of HEX-STRING and decodes back to itself."
  `(let ((element ,element)
         (expected (hex ,hex-string)))
     (is (equalp expected (tlv-encode element)))
     (multiple-value-bind (back end) (tlv-decode expected)
       (is (equalp element back))
       (is (= (length expected) end)))))

;;; ------------------------------------------------------------------
;;; Appendix A of the Matter Core Specification: the worked examples

(test spec-primitives
  (encodes-as (tlv nil :boolean nil) "08")
  (encodes-as (tlv nil :boolean t) "09")
  (encodes-as (tlv nil :signed 42) "00 2a")
  (encodes-as (tlv nil :signed -17) "00 ef")
  (encodes-as (tlv nil :unsigned 42) "04 2a")
  (encodes-as (tlv nil :signed -170000) "02 f0 67 fd ff")
  (encodes-as (tlv nil :signed 40000000000) "03 00 90 2f 50 09 00 00 00")
  (encodes-as (tlv nil :string "Hello!") "0c 06 48 65 6c 6c 6f 21")
  (encodes-as (tlv nil :string (format nil "Tsch~cs" (code-char 252))) "0c 07 54 73 63 68 c3 bc 73")
  (encodes-as (tlv nil :octets (octets 0 1 2 3 4)) "10 05 00 01 02 03 04")
  (encodes-as (tlv nil :null) "14"))

(test spec-floats
  (encodes-as (tlv nil :float 0.0) "0a 00 00 00 00")
  (encodes-as (tlv nil :float (float 1/3 1.0f0)) "0a ab aa aa 3e")
  (encodes-as (tlv nil :float 17.9f0) "0a 33 33 8f 41")
  (encodes-as (tlv nil :float :infinity) "0a 00 00 80 7f")
  (encodes-as (tlv nil :float :-infinity) "0a 00 00 80 ff")
  (encodes-as (tlv nil :double 0.0d0) "0b 00 00 00 00 00 00 00 00")
  (encodes-as (tlv nil :double (float 1/3 1.0d0)) "0b 55 55 55 55 55 55 d5 3f")
  (encodes-as (tlv nil :double 17.9d0) "0b 66 66 66 66 66 e6 31 40")
  (encodes-as (tlv nil :double :infinity) "0b 00 00 00 00 00 00 f0 7f")
  (encodes-as (tlv nil :double :-infinity) "0b 00 00 00 00 00 00 f0 ff"))

(test spec-containers
  (encodes-as (tlv-structure nil) "15 18")
  (encodes-as (tlv-array nil) "16 18")
  (encodes-as (tlv-list nil) "17 18")
  (encodes-as (tlv-structure nil (tlv 0 :signed 42) (tlv 1 :signed -17))
              "15 20 00 2a 20 01 ef 18")
  (encodes-as (apply #'tlv-array nil (loop :for i :below 5 :collect (tlv nil :signed i)))
              "16 00 00 00 01 00 02 00 03 00 04 18")
  (encodes-as (tlv-list nil (tlv nil :signed 1) (tlv 0 :signed 42) (tlv nil :signed 2)
                        (tlv nil :signed 3) (tlv 0 :signed -17))
              "17 00 01 20 00 2a 00 02 00 03 20 00 ef 18")
  (encodes-as (tlv-array nil (tlv nil :signed 42) (tlv nil :signed -170000) (tlv-structure nil)
                         (tlv nil :float 17.9f0) (tlv nil :string "Hello!"))
              "16 00 2a 02 f0 67 fd ff 15 18 0a 33 33 8f 41 0c 06 48 65 6c 6c 6f 21 18"))

(test spec-tags
  (encodes-as (tlv nil :unsigned 42) "04 2a")
  (encodes-as (tlv 1 :unsigned 42) "24 01 2a")
  (encodes-as (tlv '(:common 1) :unsigned 42) "44 01 00 2a")
  (encodes-as (tlv '(:common 100000) :unsigned 42) "64 a0 86 01 00 2a")
  (encodes-as (tlv '(:profile #xFFF1 #xDEED 1) :unsigned 42) "c4 f1 ff ed de 01 00 2a")
  (encodes-as (tlv '(:profile #xFFF1 #xDEED #xAA55FEED) :unsigned 42) "e4 f1 ff ed de ed fe 55 aa 2a")
  (encodes-as (tlv-structure '(:profile #xFFF1 #xDEED 1)
                             (tlv '(:profile #xFFF1 #xDEED #xAA55) :unsigned 42))
              "d5 f1 ff ed de 01 00 c4 f1 ff ed de 55 aa 2a 18")
  (encodes-as (tlv '(:implicit 7) :unsigned 1) "84 07 00 01")
  (encodes-as (tlv '(:implicit #x10000) :unsigned 1) "a4 00 00 01 00 01"))

;;; ------------------------------------------------------------------
;;; Widths, limits and representation

(test decoder-accepts-any-width
  "The spec's \"Signed Integer, 2-octet, value 42\" and friends."
  (is (= 42 (tlv-element-value (tlv-decode (hex "01 2a 00")))))
  (is (= 42 (tlv-element-value (tlv-decode (hex "02 2a 00 00 00")))))
  (is (= -1 (tlv-element-value (tlv-decode (hex "03 ff ff ff ff ff ff ff ff")))))
  (is (= #xFFFFFFFFFFFFFFFF (tlv-element-value (tlv-decode (hex "07 ff ff ff ff ff ff ff ff")))))
  (is (string= "ab" (tlv-element-value (tlv-decode (hex "0d 02 00 61 62")))))
  (is (equalp (octets 9) (tlv-element-value (tlv-decode (hex "12 01 00 00 00 09"))))))

(test integer-widths
  (encodes-as (tlv nil :signed 127) "00 7f")
  (encodes-as (tlv nil :signed 128) "01 80 00")
  (encodes-as (tlv nil :signed -128) "00 80")
  (encodes-as (tlv nil :signed -129) "01 7f ff")
  (encodes-as (tlv nil :signed 32767) "01 ff 7f")
  (encodes-as (tlv nil :signed 32768) "02 00 80 00 00")
  (encodes-as (tlv nil :signed (1- (ash 1 31))) "02 ff ff ff 7f")
  (encodes-as (tlv nil :signed (ash 1 31)) "03 00 00 00 80 00 00 00 00")
  (encodes-as (tlv nil :signed (- (ash 1 63))) "03 00 00 00 00 00 00 00 80")
  (encodes-as (tlv nil :signed (1- (ash 1 63))) "03 ff ff ff ff ff ff ff 7f")
  (encodes-as (tlv nil :unsigned 255) "04 ff")
  (encodes-as (tlv nil :unsigned 256) "05 00 01")
  (encodes-as (tlv nil :unsigned 65536) "06 00 00 01 00")
  (encodes-as (tlv nil :unsigned (ash 1 32)) "07 00 00 00 00 01 00 00 00")
  (encodes-as (tlv nil :unsigned (1- (ash 1 64))) "07 ff ff ff ff ff ff ff ff"))

(test string-length-widths
  (let ((s256 (make-string 256 :initial-element #\a))
        (o300 (make-array 300 :element-type '(unsigned-byte 8) :initial-element 7)))
    (let ((bytes (tlv-encode (tlv nil :string s256))))
      (is (= #x0d (aref bytes 0)))
      (is (equalp (octets 0 1) (subseq bytes 1 3)))
      (is (string= s256 (tlv-element-value (tlv-decode bytes)))))
    (let ((bytes (tlv-encode (tlv nil :octets o300))))
      (is (= #x11 (aref bytes 0)))
      (is (equalp o300 (tlv-element-value (tlv-decode bytes)))))))

(test utf8-strings
  (let ((s (format nil "~c~c~c" (code-char #x20AC) (code-char #x1F600) #\z)))
    (is (string= s (tlv-element-value (round-trip (tlv nil :string s)))))
    (is (= 8 (aref (tlv-encode (tlv nil :string s)) 1))))
  (signals tlv-decode-error (tlv-decode (hex "0c 02 c3 28")))        ; bad continuation
  (signals tlv-decode-error (tlv-decode (hex "0c 02 c0 80")))        ; overlong
  (signals tlv-decode-error (tlv-decode (hex "0c 03 ed a0 80")))     ; surrogate
  (signals tlv-decode-error (tlv-decode (hex "0c 01 e2"))))          ; truncated sequence

(test float-conversions
  "Exact round trips, rounding to nearest even, subnormals, NaN."
  (encodes-as (tlv nil :float 1.0) "0a 00 00 80 3f")
  (encodes-as (tlv nil :float -2.5) "0a 00 00 20 c0")
  (encodes-as (tlv nil :float 3.4028235e38) "0a ff ff 7f 7f")        ; largest float
  (flet ((encodes-to (element hex-string)
           (is (equalp (hex hex-string) (tlv-encode element)))))
    ;; integers and rationals are converted exactly and decode as floats
    (encodes-to (tlv nil :float 1) "0a 00 00 80 3f")
    (encodes-to (tlv nil :double 1/3) "0b 55 55 55 55 55 55 d5 3f")
    (encodes-to (tlv nil :float (expt 2 -149)) "0a 01 00 00 00")       ; smallest subnormal
    (encodes-to (tlv nil :float (expt 2 -126)) "0a 00 00 80 00")       ; smallest normal
    (encodes-to (tlv nil :double (expt 2 -1074)) "0b 01 00 00 00 00 00 00 00")
    ;; too large for float32 becomes infinity
    (encodes-to (tlv nil :float 1d39) "0a 00 00 80 7f")
    ;; round to nearest, ties to even: 1 + 2^-24 -> 1.0, 1 + 3*2^-24 -> m = 2, 1 + 5*2^-25 -> m = 1
    (encodes-to (tlv nil :float (+ 1 (expt 2 -24))) "0a 00 00 80 3f")
    (encodes-to (tlv nil :float (+ 1 (* 3 (expt 2 -24)))) "0a 02 00 80 3f")
    (encodes-to (tlv nil :float (+ 1 (* 5 (expt 2 -25)))) "0a 01 00 80 3f"))
  ;; subnormals decode to the exact value
  (is (= (expt 2 -149) (rational (tlv-element-value (tlv-decode (hex "0a 01 00 00 00"))))))
  (is (= (expt 2 -1074) (rational (tlv-element-value (tlv-decode (hex "0b 01 00 00 00 00 00 00 00"))))))
  (is (= (expt 2 -1022) (rational (tlv-element-value (tlv-decode (hex "0b 00 00 00 00 00 00 10 00"))))))
  (is (eq :nan (tlv-element-value (tlv-decode (hex "0a 00 00 c0 7f")))))
  (is (eq :nan (tlv-element-value (round-trip (tlv nil :double :nan)))))
  (is (typep (tlv-element-value (tlv-decode (hex "0a 00 00 80 3f"))) 'single-float))
  (is (typep (tlv-element-value (tlv-decode (hex "0b 00 00 00 00 00 00 f0 3f"))) 'double-float))
  (is (= 17.9d0 (tlv-element-value (tlv-decode (hex "0b 66 66 66 66 66 e6 31 40"))))))

(test nested-and-accessors
  (let* ((element (tlv-structure nil
                                 (tlv 1 :octets (octets 1 2 3))
                                 (tlv 2 :unsigned 1234)
                                 (tlv-array 3 (tlv nil :string "a") (tlv nil :string "b"))
                                 (tlv-structure 4 (tlv 1 :boolean t) (tlv 2 :null))
                                 (tlv '(:common 5) :signed -1)))
         (back (round-trip element)))
    (is (equalp element back))
    (is (tlv-container-p back))
    (is (not (tlv-container-p (tlv-ref back 2))))
    (is (= 1234 (tlv-get back 2)))
    (is (equal '("a" "b") (mapcar #'tlv-element-value (tlv-get back 3))))
    (is (eq t (tlv-get (tlv-ref back 4) 1)))
    (multiple-value-bind (v present) (tlv-get (tlv-ref back 4) 2)
      (is (null v))
      (is-true present))
    (multiple-value-bind (v present) (tlv-get back 9)
      (is (null v))
      (is-false present))
    (is (= -1 (tlv-get back '(:common 5))))
    (is (null (tlv-ref back '(:common 6))))))

(test decode-start-end-and-trailing
  (let* ((inner (tlv-encode (tlv 1 :unsigned 5)))
         (buffer (make-array (+ 2 (length inner) 3) :element-type '(unsigned-byte 8)
                                                    :initial-element #xFF)))
    (replace buffer inner :start1 2)
    (multiple-value-bind (element end) (tlv-decode buffer :start 2 :end (+ 2 (length inner)))
      (is (equalp (tlv 1 :unsigned 5) element))
      (is (= (+ 2 (length inner)) end)))
    ;; one element is read; what follows is for the caller
    (multiple-value-bind (element end) (tlv-decode buffer :start 2)
      (is (= 5 (tlv-element-value element)))
      (is (= (+ 2 (length inner)) end)))))

(test print-representation
  (is (search "TLV 1=UNSIGNED 42" (princ-to-string (tlv 1 :unsigned 42))))
  (is (search "STRUCTURE (2 elements)" (princ-to-string (tlv-structure nil (tlv 1 :null) (tlv 2 :null)))))
  (is (search "TLV NULL" (princ-to-string (tlv nil :null)))))

;;; ------------------------------------------------------------------
;;; Errors

(defmacro rejects (hex-string)
  `(handler-case (progn (tlv-decode (hex ,hex-string)) (fail "~a was accepted" ,hex-string))
     (tlv-decode-error (e)
       (is (integerp (tlv-decode-error-offset e)))
       (is (search "byte" (princ-to-string e))))))

(test rejects-malformed
  (rejects "")                              ; nothing
  (rejects "00")                            ; value missing
  (rejects "01 2a")                         ; value short
  (rejects "24")                            ; tag missing
  (rejects "0c 05 61 62")                   ; string short
  (rejects "0d 01")                         ; length short
  (rejects "0a 00 00 00")                   ; float short
  (rejects "19")                            ; reserved type
  (rejects "1f")
  (rejects "18")                            ; end of container at top level
  (rejects "15")                            ; structure never closed
  (rejects "15 20 00 2a")
  (rejects "16 20 00 2a 18")                ; array element with a tag
  (rejects "15 00 2a 18")                   ; structure member without a tag
  (rejects "38")                            ; end of container with a tag
  (rejects "c4 f1 ff ed de 01"))            ; fully qualified tag short

(test rejects-deep-nesting
  (let ((*tlv-max-depth* 4))
    (is (tlv-decode (hex "15 35 01 35 01 35 01 18 18 18 18")))             ; depth 4 ok
    (signals tlv-decode-error (tlv-decode (hex "15 35 01 35 01 35 01 35 01 18 18 18 18 18")))))

(test error-offset
  (handler-case (progn (tlv-decode (hex "15 20 00 2a 19 18")) (fail "accepted"))
    (tlv-decode-error (e) (is (= 4 (tlv-decode-error-offset e))))))

(test rejects-unencodable
  (macrolet ((bad (element) `(signals tlv-encode-error (tlv-encode ,element))))
    (bad (tlv nil :unsigned -1))
    (bad (tlv nil :unsigned (ash 1 64)))
    (bad (tlv nil :signed (ash 1 63)))
    (bad (tlv nil :signed (- (1+ (ash 1 63)))))
    (bad (tlv nil :signed "1"))
    (bad (tlv nil :string 5))
    (bad (tlv nil :octets "abc"))
    (bad (tlv nil :float "x"))
    (bad (tlv 256 :null))
    (bad (tlv -1 :null))
    (bad (tlv '(:common -1) :null))
    (bad (tlv '(:profile 1 2) :null))
    (bad (tlv '(:profile #x10000 0 0) :null))
    (bad (tlv '(:bogus 1) :null))
    (bad (tlv-array nil (tlv 1 :null)))          ; tagged array element
    (bad (tlv-structure nil (tlv nil :null)))    ; untagged member
    (bad (tlv-list nil 42))                      ; not an element
    (bad 42)))
