(in-package :cl-matter)

;;; Matter TLV (Matter Core Specification, Appendix A): a self-describing
;;; binary encoding.  Every element is a control octet -- tag control in
;;; the top three bits, element type in the low five -- then the tag, then
;;; the value; containers hold elements up to an end-of-container octet.
;;; All multi-octet fields are little endian.
;;;
;;; In Lisp an element is a TLV-ELEMENT of TAG, TYPE and VALUE:
;;;
;;;   TAG    NIL                                anonymous
;;;          0..255                             context-specific
;;;          (:common N) (:implicit N)          common / implicit profile
;;;          (:profile VENDOR-ID PROFILE-ID N)  fully qualified
;;;   TYPE   VALUE
;;;   :signed :unsigned   an integer, 8 octets at most on the wire
;;;   :boolean            T or NIL
;;;   :float :double      a real, or :infinity :-infinity :nan
;;;   :string             a string (UTF-8 on the wire)
;;;   :octets             an (unsigned-byte 8) vector
;;;   :null               ignored
;;;   :structure :array :list   a list of TLV-ELEMENTs
;;;
;;; The encoder uses the smallest width that holds an integer or a length;
;;; the decoder takes any width.  Floats are converted exactly, from and to
;;; the rational value, so the Lisp float format does not matter.

(define-condition tlv-error (error)
  ((message :initarg :message :reader tlv-error-message))
  (:report (lambda (c stream)
             (format stream "TLV: ~a" (tlv-error-message c)))))

(define-condition tlv-encode-error (tlv-error) ())

(define-condition tlv-decode-error (tlv-error)
  ((offset :initarg :offset :initform nil :reader tlv-decode-error-offset))
  (:report (lambda (c stream)
             (format stream "malformed TLV~@[ at byte ~d~]: ~a"
                     (tlv-decode-error-offset c) (tlv-error-message c)))))

(defparameter *tlv-max-depth* 32
  "Deepest container nesting the decoder follows; a datagram cannot make
it recurse further than this.")

(defstruct (tlv-element (:constructor make-tlv-element (tag type value)))
  (tag nil)
  (type :null :type keyword)
  (value nil))

(defmethod print-object ((element tlv-element) stream)
  (print-unreadable-object (element stream)
    (format stream "TLV ~@[~s=~]~a" (tlv-element-tag element) (tlv-element-type element))
    (cond ((tlv-container-p element)
           (format stream " (~d element~:p)" (length (tlv-element-value element))))
          ((not (eq :null (tlv-element-type element)))
           (format stream " ~s" (tlv-element-value element))))))

(defun tlv (tag type &optional value)
  "Make a TLV-ELEMENT: (tlv 1 :unsigned 42), (tlv nil :structure (list ...))."
  (make-tlv-element tag type value))

(defun tlv-structure (tag &rest elements) (make-tlv-element tag :structure elements))
(defun tlv-array (tag &rest elements) (make-tlv-element tag :array elements))
(defun tlv-list (tag &rest elements) (make-tlv-element tag :list elements))

(defun tlv-container-p (element)
  (member (tlv-element-type element) '(:structure :array :list)))

(defun tlv-ref (container tag)
  "The element tagged TAG in CONTAINER, or NIL."
  (find tag (tlv-element-value container) :key #'tlv-element-tag :test #'equal))

(defun tlv-get (container tag)
  "The value of the element tagged TAG in CONTAINER; the second value says
whether it was there."
  (let ((element (tlv-ref container tag)))
    (if element
        (values (tlv-element-value element) t)
        (values nil nil))))

;;; ------------------------------------------------------------------
;;; Wire constants

(defconstant +tag-anonymous+          #x00)
(defconstant +tag-context+            #x20)
(defconstant +tag-common-2+           #x40)
(defconstant +tag-common-4+           #x60)
(defconstant +tag-implicit-2+         #x80)
(defconstant +tag-implicit-4+         #xA0)
(defconstant +tag-fully-qualified-6+  #xC0)
(defconstant +tag-fully-qualified-8+  #xE0)

(defconstant +type-signed+       #x00)  ; +0..3: 1, 2, 4, 8 octets
(defconstant +type-unsigned+     #x04)  ; +0..3
(defconstant +type-false+        #x08)
(defconstant +type-true+         #x09)
(defconstant +type-float+        #x0A)
(defconstant +type-double+       #x0B)
(defconstant +type-string+       #x0C)  ; +0..3: length in 1, 2, 4, 8 octets
(defconstant +type-octets+       #x10)  ; +0..3
(defconstant +type-null+         #x14)
(defconstant +type-structure+    #x15)
(defconstant +type-array+        #x16)
(defconstant +type-list+         #x17)
(defconstant +type-end+          #x18)

;;; ------------------------------------------------------------------
;;; IEEE 754 from and to the exact rational value

(defun %float-bits (x mantissa-bits exponent-bits)
  "The IEEE 754 bit pattern of the real X, rounded to nearest even."
  (let* ((width (+ 1 exponent-bits mantissa-bits))
         (bias (1- (ash 1 (1- exponent-bits))))
         (max-field (1- (ash 1 exponent-bits)))
         (sign-bit (ash 1 (1- width))))
    (case x
      (:infinity (ash max-field mantissa-bits))
      (:-infinity (logior sign-bit (ash max-field mantissa-bits)))
      (:nan (logior (ash max-field mantissa-bits) (ash 1 (1- mantissa-bits))))
      (t
       (let* ((r (rational x))
              (negative (or (minusp r) (and (floatp x) (zerop r) (minusp (float-sign x)))))
              (a (abs r))
              (sign (if negative sign-bit 0)))
         (if (zerop a)
             sign
             ;; e with 2^e <= a < 2^(e+1)
             (let ((e (- (integer-length (numerator a)) (integer-length (denominator a)))))
               (when (< a (expt 2 e)) (decf e))
               (if (< e (- 1 bias))
                   ;; subnormal: fixed scale, the mantissa may carry into exponent 1
                   (let ((m (round (* a (expt 2 (+ mantissa-bits bias -1))))))
                     (logior sign m))
                   (let ((m (- (round (* a (expt 2 (- mantissa-bits e)))) (ash 1 mantissa-bits))))
                     (when (= m (ash 1 mantissa-bits)) ; rounded up to the next power of two
                       (setf m 0) (incf e))
                     (let ((field (+ e bias)))
                       (if (>= field max-field)
                           (logior sign (ash max-field mantissa-bits))
                           (logior sign (ash field mantissa-bits) m))))))))))))

(defun %bits-float (bits mantissa-bits exponent-bits prototype)
  "The real of an IEEE 754 bit pattern, as a float like PROTOTYPE, or
:INFINITY :-INFINITY :NAN."
  (let* ((bias (1- (ash 1 (1- exponent-bits))))
         (max-field (1- (ash 1 exponent-bits)))
         (negative (logbitp (+ exponent-bits mantissa-bits) bits))
         (field (ldb (byte exponent-bits mantissa-bits) bits))
         (m (ldb (byte mantissa-bits 0) bits)))
    (cond ((= field max-field)
           (cond ((/= m 0) :nan) (negative :-infinity) (t :infinity)))
          (t
           ;; the integer significand is exact in the target format, and
           ;; SCALE-FLOAT reaches the subnormals, where FLOAT of the
           ;; rational may not (AmiLisp 0.12 returns NaN for 2^-1074)
           (let ((f (if (zerop field)
                        (scale-float (float m prototype) (- 1 bias mantissa-bits))
                        (scale-float (float (+ m (ash 1 mantissa-bits)) prototype)
                                     (- field bias mantissa-bits)))))
             (if negative (- f) f))))))

;;; ------------------------------------------------------------------
;;; UTF-8 (strict: a TLV string must be valid UTF-8)

(defun %utf8-length (string)
  (loop :for ch :across string
        :for c := (char-code ch)
        :sum (cond ((< c #x80) 1) ((< c #x800) 2) ((< c #x10000) 3) (t 4))))

(defun %utf8-encode-into (string out)
  (loop :for ch :across string
        :for c := (char-code ch)
        :do (cond ((< c #x80) (vector-push-extend c out))
                  ((< c #x800)
                   (vector-push-extend (logior #xC0 (ash c -6)) out)
                   (vector-push-extend (logior #x80 (logand c #x3F)) out))
                  ((< c #x10000)
                   (vector-push-extend (logior #xE0 (ash c -12)) out)
                   (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                   (vector-push-extend (logior #x80 (logand c #x3F)) out))
                  (t
                   (vector-push-extend (logior #xF0 (ash c -18)) out)
                   (vector-push-extend (logior #x80 (logand (ash c -12) #x3F)) out)
                   (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                   (vector-push-extend (logior #x80 (logand c #x3F)) out)))))

(defun %utf8-decode (octets start end)
  "OCTETS[START,END) as a string, or NIL when it is not valid UTF-8."
  (with-output-to-string (out)
    (let ((i start))
      (flet ((cont (k)
               (let ((j (+ i k)))
                 (and (< j end)
                      (= (logand (aref octets j) #xC0) #x80)
                      (logand (aref octets j) #x3F)))))
        (loop :while (< i end)
              :do (let ((b (aref octets i)) (code nil) (len 1))
                    (cond ((< b #x80) (setf code b))
                          ((= (logand b #xE0) #xC0)
                           (let ((c1 (cont 1)))
                             (when c1 (setf code (logior (ash (logand b #x1F) 6) c1) len 2))
                             (when (and code (< code #x80)) (setf code nil))))
                          ((= (logand b #xF0) #xE0)
                           (let ((c1 (cont 1)) (c2 (cont 2)))
                             (when (and c1 c2)
                               (setf code (logior (ash (logand b #x0F) 12) (ash c1 6) c2) len 3))
                             (when (and code (or (< code #x800) (<= #xD800 code #xDFFF)))
                               (setf code nil))))
                          ((= (logand b #xF8) #xF0)
                           (let ((c1 (cont 1)) (c2 (cont 2)) (c3 (cont 3)))
                             (when (and c1 c2 c3)
                               (setf code (logior (ash (logand b #x07) 18) (ash c1 12) (ash c2 6) c3)
                                     len 4))
                             (when (and code (or (< code #x10000) (> code #x10FFFF)))
                               (setf code nil)))))
                    (unless (and code (< code char-code-limit))
                      (return-from %utf8-decode nil))
                    (write-char (code-char code) out)
                    (incf i len)))))))

;;; ------------------------------------------------------------------
;;; Encoder

(defun %encode-fail (format &rest args)
  (error 'tlv-encode-error :message (apply #'format nil format args)))

(defun %put-le (out value octets)
  (dotimes (i octets)
    (vector-push-extend (ldb (byte 8 (* 8 i)) value) out)))

(defun %width-code (n)
  "0..3 for a 1, 2, 4 or 8 octet field holding the unsigned N."
  (cond ((< n #x100) 0) ((< n #x10000) 1) ((< n #x100000000) 2)
        ((< n #x10000000000000000) 3)
        (t (%encode-fail "~d does not fit in 8 octets" n))))

(defun %signed-width-code (n)
  (cond ((<= -128 n 127) 0) ((<= -32768 n 32767) 1)
        ((<= (- (ash 1 31)) n (1- (ash 1 31))) 2)
        ((<= (- (ash 1 63)) n (1- (ash 1 63))) 3)
        (t (%encode-fail "~d does not fit in a signed 8 octet integer" n))))

(defun %put-tag (out tag type-code)
  "The control octet and the tag."
  (flet ((control (tag-control) (vector-push-extend (logior tag-control type-code) out)))
    (cond ((null tag) (control +tag-anonymous+))
          ((integerp tag)
           (unless (<= 0 tag 255)
             (%encode-fail "context tag ~d is not in 0..255" tag))
           (control +tag-context+)
           (vector-push-extend tag out))
          ((and (consp tag) (member (first tag) '(:common :implicit))
                (integerp (second tag)) (null (cddr tag)))
           (let ((n (second tag))
                 (common (eq (first tag) :common)))
             (unless (<= 0 n #xFFFFFFFF)
               (%encode-fail "profile tag number ~d is not in 0..2^32-1" n))
             (cond ((< n #x10000)
                    (control (if common +tag-common-2+ +tag-implicit-2+))
                    (%put-le out n 2))
                   (t
                    (control (if common +tag-common-4+ +tag-implicit-4+))
                    (%put-le out n 4)))))
          ((and (consp tag) (eq (first tag) :profile) (= (length tag) 4)
                (every #'integerp (rest tag)))
           (destructuring-bind (vendor profile n) (rest tag)
             (unless (and (<= 0 vendor #xFFFF) (<= 0 profile #xFFFF) (<= 0 n #xFFFFFFFF))
               (%encode-fail "fully qualified tag ~s out of range" tag))
             (control (if (< n #x10000) +tag-fully-qualified-6+ +tag-fully-qualified-8+))
             (%put-le out vendor 2)
             (%put-le out profile 2)
             (%put-le out n (if (< n #x10000) 2 4))))
          (t (%encode-fail "~s is not a TLV tag" tag)))))

(defun %encode-element (element out)
  (unless (tlv-element-p element)
    (%encode-fail "~s is not a TLV-ELEMENT" element))
  (let ((tag (tlv-element-tag element))
        (type (tlv-element-type element))
        (value (tlv-element-value element)))
    (ecase type
      (:signed
       (unless (integerp value) (%encode-fail "~s is not an integer" value))
       (let ((w (%signed-width-code value)))
         (%put-tag out tag (+ +type-signed+ w))
         (%put-le out (ldb (byte (ash 8 w) 0) value) (ash 1 w))))
      (:unsigned
       (unless (and (integerp value) (>= value 0))
         (%encode-fail "~s is not a non-negative integer" value))
       (let ((w (%width-code value)))
         (%put-tag out tag (+ +type-unsigned+ w))
         (%put-le out value (ash 1 w))))
      (:boolean
       (%put-tag out tag (if value +type-true+ +type-false+)))
      (:float
       (unless (or (realp value) (member value '(:infinity :-infinity :nan)))
         (%encode-fail "~s is not a real" value))
       (%put-tag out tag +type-float+)
       (%put-le out (%float-bits value 23 8) 4))
      (:double
       (unless (or (realp value) (member value '(:infinity :-infinity :nan)))
         (%encode-fail "~s is not a real" value))
       (%put-tag out tag +type-double+)
       (%put-le out (%float-bits value 52 11) 8))
      (:string
       (unless (stringp value) (%encode-fail "~s is not a string" value))
       (let* ((length (%utf8-length value))
              (w (%width-code length)))
         (%put-tag out tag (+ +type-string+ w))
         (%put-le out length (ash 1 w))
         (%utf8-encode-into value out)))
      (:octets
       (unless (and (vectorp value) (not (stringp value)))
         (%encode-fail "~s is not an octet vector" value))
       (let ((w (%width-code (length value))))
         (%put-tag out tag (+ +type-octets+ w))
         (%put-le out (length value) (ash 1 w))
         (loop :for b :across value :do (vector-push-extend b out))))
      (:null
       (%put-tag out tag +type-null+))
      ((:structure :array :list)
       (unless (listp value) (%encode-fail "the value of a ~a must be a list" type))
       (%put-tag out tag (ecase type
                           (:structure +type-structure+)
                           (:array +type-array+)
                           (:list +type-list+)))
       (dolist (child value)
         (unless (tlv-element-p child)
           (%encode-fail "~s inside a ~a is not a TLV-ELEMENT" child type))
         (case type
           (:array (when (tlv-element-tag child)
                     (%encode-fail "array elements must be anonymous, ~s is tagged ~s"
                                   child (tlv-element-tag child))))
           (:structure (unless (tlv-element-tag child)
                         (%encode-fail "structure members need a tag: ~s" child))))
         (%encode-element child out))
       (vector-push-extend +type-end+ out)))))

(defun tlv-encode (element)
  "ELEMENT (a TLV-ELEMENT) -> a fresh (unsigned-byte 8) vector.  Signals
TLV-ENCODE-ERROR for a value that does not fit its type or a container
that breaks the tagging rules."
  (let ((out (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (%encode-element element out)
    (let ((result (make-array (length out) :element-type '(unsigned-byte 8))))
      (replace result out)
      result)))

;;; ------------------------------------------------------------------
;;; Decoder

(defstruct (%in (:constructor %make-in (octets pos end)))
  octets pos end)

(defun %decode-fail (in format &rest args)
  (error 'tlv-decode-error :offset (%in-pos in) :message (apply #'format nil format args)))

(defun %need (in n what)
  (when (> (+ (%in-pos in) n) (%in-end in))
    (%decode-fail in "~a needs ~d octet~:p, ~d left" what n (- (%in-end in) (%in-pos in)))))

(defun %get8 (in what)
  (%need in 1 what)
  (prog1 (aref (%in-octets in) (%in-pos in))
    (incf (%in-pos in))))

(defun %get-le (in octets what)
  (%need in octets what)
  (let ((value 0)
        (base (%in-pos in))
        (data (%in-octets in)))
    (dotimes (i octets)
      (setf value (logior value (ash (aref data (+ base i)) (* 8 i)))))
    (incf (%in-pos in) octets)
    value))

(defun %get-tag (in control)
  (let ((tag-control (logand control #xE0)))
    (cond ((= tag-control +tag-anonymous+) nil)
          ((= tag-control +tag-context+) (%get8 in "context tag"))
          ((= tag-control +tag-common-2+) (list :common (%get-le in 2 "common profile tag")))
          ((= tag-control +tag-common-4+) (list :common (%get-le in 4 "common profile tag")))
          ((= tag-control +tag-implicit-2+) (list :implicit (%get-le in 2 "implicit profile tag")))
          ((= tag-control +tag-implicit-4+) (list :implicit (%get-le in 4 "implicit profile tag")))
          (t (let* ((vendor (%get-le in 2 "vendor id"))
                    (profile (%get-le in 2 "profile number"))
                    (n (%get-le in (if (= tag-control +tag-fully-qualified-6+) 2 4) "tag number")))
               (list :profile vendor profile n))))))

(defun %decode-element (in depth)
  "The element at the reader's position, or :END for an end-of-container."
  (let* ((control (%get8 in "element control octet"))
         (type-code (logand control #x1F)))
    (when (= type-code +type-end+)
      (unless (= (logand control #xE0) +tag-anonymous+)
        (%decode-fail in "end of container carries a tag"))
      (return-from %decode-element :end))
    (when (> type-code +type-end+)
      (decf (%in-pos in))
      (%decode-fail in "reserved element type #x~2,'0x" type-code))
    (let ((tag (%get-tag in control)))
      (flet ((element (type value) (make-tlv-element tag type value)))
        (cond ((< type-code +type-unsigned+)
               (let* ((octets (ash 1 (- type-code +type-signed+)))
                      (raw (%get-le in octets "signed integer"))
                      (bits (* 8 octets)))
                 (element :signed (if (logbitp (1- bits) raw) (- raw (ash 1 bits)) raw))))
              ((< type-code +type-false+)
               (element :unsigned (%get-le in (ash 1 (- type-code +type-unsigned+)) "unsigned integer")))
              ((= type-code +type-false+) (element :boolean nil))
              ((= type-code +type-true+) (element :boolean t))
              ((= type-code +type-float+)
               (element :float (%bits-float (%get-le in 4 "float") 23 8 1.0f0)))
              ((= type-code +type-double+)
               (element :double (%bits-float (%get-le in 8 "double") 52 11 1.0d0)))
              ((< type-code +type-null+)
               (let* ((string-p (< type-code +type-octets+))
                      (w (- type-code (if string-p +type-string+ +type-octets+)))
                      (length (%get-le in (ash 1 w) "string length"))
                      (start (%in-pos in)))
                 (%need in length (if string-p "UTF-8 string" "octet string"))
                 (incf (%in-pos in) length)
                 (if string-p
                     (let ((string (%utf8-decode (%in-octets in) start (+ start length))))
                       (unless string
                         (setf (%in-pos in) start)
                         (%decode-fail in "string is not valid UTF-8"))
                       (element :string string))
                     (let ((octets (make-array length :element-type '(unsigned-byte 8))))
                       (replace octets (%in-octets in) :start2 start :end2 (+ start length))
                       (element :octets octets)))))
              ((= type-code +type-null+) (element :null nil))
              (t
               (let ((type (cond ((= type-code +type-structure+) :structure)
                                 ((= type-code +type-array+) :array)
                                 (t :list)))
                     (container-start (1- (%in-pos in))))
                 (when (>= depth *tlv-max-depth*)
                   (%decode-fail in "containers nested deeper than ~d" *tlv-max-depth*))
                 (let ((children
                         (loop :for child := (progn
                                               (when (>= (%in-pos in) (%in-end in))
                                                 (setf (%in-pos in) container-start)
                                                 (%decode-fail in "~a is not closed" type))
                                               (%decode-element in (1+ depth)))
                               :until (eq child :end)
                               :do (case type
                                     (:array (when (tlv-element-tag child)
                                               (%decode-fail in "array element with tag ~s"
                                                             (tlv-element-tag child))))
                                     (:structure (unless (tlv-element-tag child)
                                                   (%decode-fail in "structure member without a tag"))))
                               :collect child)))
                   (element type children)))))))))

(defun tlv-decode (octets &key (start 0) end)
  "One TLV element from OCTETS[START,END) -> the TLV-ELEMENT and, second,
the offset just past it.  Signals TLV-DECODE-ERROR, with the offset, for
anything malformed: truncation, a reserved type, an unclosed container, a
stray end-of-container, a tagged array element, an untagged structure
member, invalid UTF-8, nesting past *TLV-MAX-DEPTH*."
  (let* ((end (or end (length octets)))
         (in (%make-in octets start end))
         (element (%decode-element in 0)))
    (when (eq element :end)
      (setf (%in-pos in) start)
      (%decode-fail in "end of container outside any container"))
    (values element (%in-pos in))))
