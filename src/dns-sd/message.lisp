(in-package :cl-matter.dns-sd)

;;; DNS message codec: the RFC 1035 wire format as mDNS uses it (RFC 6762
;;; section 18) -- header, questions, resource records, name compression,
;;; and the record types discovery needs: PTR, SRV, TXT, A, AAAA, NSEC
;;; (CNAME for completeness; anything else is carried as raw octets).
;;;
;;; Names are strings in presentation form: labels joined by ".", with a
;;; "." or "\" inside a label escaped by a backslash ("Printer v2\.0._ipp"),
;;; and UTF-8 on the wire (RFC 6762 section 16).  Record data is decoded per
;;; type -- see DNS-RECORD -- and the decoder trusts nothing: every length
;;; is checked, compression pointers must point strictly backwards, and a
;;; defect is reported as DNS-DECODE-ERROR with the byte offset.

(defconstant +type-a+     1)
(defconstant +type-cname+ 5)
(defconstant +type-ptr+   12)
(defconstant +type-txt+   16)
(defconstant +type-aaaa+  28)
(defconstant +type-srv+   33)
(defconstant +type-nsec+  47)
(defconstant +type-any+   255)
(defconstant +class-in+   1)

;; header flag bits, for DNS-MESSAGE-FLAGS
(defconstant +flag-response+      #x8000 "QR: the message is a response.")
(defconstant +flag-authoritative+ #x0400 "AA: set on every mDNS response.")
(defconstant +flag-truncated+     #x0200 "TC: more known answers follow.")
(defconstant +flag-rcode-mask+    #x000F)

(defvar *compress-srv-target* t
  "Bound to NIL by ENCODE-MESSAGE for a legacy unicast response: RFC 6762
section 18.14 forbids compressing the SRV target there.")

(defconstant +max-name-octets+  255)
(defconstant +max-label-octets+ 63)
(defconstant +max-txt-string+   255)

(define-condition dns-decode-error (error)
  ((message :initarg :message :reader dns-decode-error-message)
   (offset :initarg :offset :initform nil :reader dns-decode-error-offset))
  (:report (lambda (c stream)
             (format stream "malformed DNS message~@[ at byte ~d~]: ~a"
                     (dns-decode-error-offset c) (dns-decode-error-message c)))))

(define-condition dns-encode-error (error)
  ((message :initarg :message :reader dns-encode-error-message))
  (:report (lambda (c stream)
             (format stream "cannot encode DNS message: ~a" (dns-encode-error-message c)))))

(defstruct dns-question
  (name "" :type string)
  (type +type-any+ :type (unsigned-byte 16))
  (class +class-in+ :type (unsigned-byte 16))
  ;; mDNS: the top bit of the class field asks for a unicast response (QU)
  (unicast-response-p nil :type boolean))

(defstruct dns-record
  (name "" :type string)
  (type 0 :type (unsigned-byte 16))
  (class +class-in+ :type (unsigned-byte 16))
  ;; mDNS: the top bit of the class field is the cache-flush bit
  (cache-flush-p nil :type boolean)
  (ttl 0 :type (unsigned-byte 32))
  ;; decoded per TYPE:
  ;;   PTR, CNAME  a name string
  ;;   SRV         (:priority n :weight n :port n :target "host.local")
  ;;   TXT         a list of strings, NIL for the empty record
  ;;   A, AAAA     the address as a string ("192.168.1.5", "fe80::1")
  ;;   NSEC        (:next-name "host.local" :types (1 28))
  ;;   other       the raw octets
  (data nil))

(defstruct dns-message
  (id 0 :type (unsigned-byte 16))
  (flags 0 :type (unsigned-byte 16))
  (questions nil :type list)
  (answers nil :type list)
  (authorities nil :type list)
  (additionals nil :type list))

(defun dns-message-response-p (message)
  (logtest +flag-response+ (dns-message-flags message)))

(defun dns-message-truncated-p (message)
  (logtest +flag-truncated+ (dns-message-flags message)))

;;; ------------------------------------------------------------------
;;; UTF-8

(defun %utf8-length (string)
  (loop :for ch :across string
        :for c := (char-code ch)
        :sum (cond ((< c #x80) 1) ((< c #x800) 2) ((< c #x10000) 3) (t 4))))

(defun %utf8-decode (octets start end)
  "Decode OCTETS[START,END) as UTF-8.  A malformed sequence, or a code
point this Lisp cannot represent, becomes a question mark."
  (with-output-to-string (out)
    (let ((i start))
      (flet ((cont (k)
               ;; the K-th continuation byte after I, or NIL
               (let ((j (+ i k)))
                 (and (< j end)
                      (= (logand (aref octets j) #xC0) #x80)
                      (logand (aref octets j) #x3F)))))
        (loop :while (< i end)
              :do (let* ((b (aref octets i))
                         (code nil)
                         (len 1))
                    (cond ((< b #x80) (setf code b))
                          ((= (logand b #xE0) #xC0)
                           (let ((c1 (cont 1)))
                             (when c1
                               (setf code (logior (ash (logand b #x1F) 6) c1) len 2))))
                          ((= (logand b #xF0) #xE0)
                           (let ((c1 (cont 1)) (c2 (cont 2)))
                             (when (and c1 c2)
                               (setf code (logior (ash (logand b #x0F) 12) (ash c1 6) c2) len 3))))
                          ((= (logand b #xF8) #xF0)
                           (let ((c1 (cont 1)) (c2 (cont 2)) (c3 (cont 3)))
                             (when (and c1 c2 c3)
                               (setf code (logior (ash (logand b #x07) 18) (ash c1 12) (ash c2 6) c3)
                                     len 4)))))
                    (let ((ch (and code (< code char-code-limit) (code-char code))))
                      (write-char (or ch #\?) out))
                    (incf i len)))))))

;;; ------------------------------------------------------------------
;;; Names in presentation form <-> label lists

(defun %name-labels (name)
  "\"a.b\\.c.local\" -> (\"a\" \"b.c\" \"local\").  A trailing dot is allowed,
the root is NIL."
  (let ((labels '())
        (label (make-string-output-stream))
        (any nil)
        (i 0)
        (n (length name)))
    (flet ((finish ()
             (let ((s (get-output-stream-string label)))
               (when (zerop (length s))
                 (error 'dns-encode-error
                        :message (format nil "empty label in name ~s" name)))
               (push s labels))))
      (loop :while (< i n)
            :do (let ((ch (char name i)))
                  (cond ((char= ch #\\)
                         (when (>= (1+ i) n)
                           (error 'dns-encode-error
                                  :message (format nil "name ~s ends in a backslash" name)))
                         (write-char (char name (1+ i)) label)
                         (setf any t)
                         (incf i 2))
                        ((char= ch #\.)
                         (finish)
                         (setf any nil)
                         (incf i))
                        (t (write-char ch label)
                           (setf any t)
                           (incf i)))))
      (when any (finish))
      (nreverse labels))))

(defun %labels-name (labels)
  (with-output-to-string (out)
    (loop :for (label . more) :on labels
          :do (loop :for ch :across label
                    :do (when (or (char= ch #\.) (char= ch #\\))
                          (write-char #\\ out))
                        (write-char ch out))
              (when more (write-char #\. out)))))

;;; ------------------------------------------------------------------
;;; Addresses

(defun %parse-ipv4 (string)
  (let ((parts (loop :with start := 0
                     :for dot := (position #\. string :start start)
                     :collect (handler-case (parse-integer string :start start :end dot)
                                (error () nil))
                     :while dot
                     :do (setf start (1+ dot)))))
    (unless (and (= (length parts) 4)
                 (every (lambda (p) (and p (<= 0 p 255))) parts))
      (error 'dns-encode-error :message (format nil "not an IPv4 address: ~s" string)))
    (coerce parts '(vector (unsigned-byte 8)))))

(defun %format-ipv4 (octets start)
  (format nil "~d.~d.~d.~d"
          (aref octets start) (aref octets (+ start 1))
          (aref octets (+ start 2)) (aref octets (+ start 3))))

(defun %parse-ipv6 (string)
  "RFC 4291 text form -> 16 octets.  Handles \"::\" compression."
  (flet ((groups (s)
           ;; "1:2:3" -> (1 2 3); "" -> NIL
           (if (zerop (length s))
               '()
               (loop :with start := 0
                     :for colon := (position #\: s :start start)
                     :collect (let ((g (and (< start (or colon (length s)))
                                            (<= (- (or colon (length s)) start) 4)
                                            (handler-case
                                                (parse-integer s :start start :end colon :radix 16)
                                              (error () nil)))))
                                (unless g
                                  (error 'dns-encode-error
                                         :message (format nil "not an IPv6 address: ~s" string)))
                                g)
                     :while colon
                     :do (setf start (1+ colon))))))
    (let* ((gap (search "::" string))
           (left (groups (if gap (subseq string 0 gap) string)))
           (right (if gap (groups (subseq string (+ gap 2))) '()))
           (fill (- 8 (length left) (length right))))
      (when (or (if gap (< fill 1) (/= fill 0))
                (and gap (search "::" string :start2 (1+ gap))))
        (error 'dns-encode-error :message (format nil "not an IPv6 address: ~s" string)))
      (let ((words (append left (if gap (make-list fill :initial-element 0) '()) right))
            (octets (make-array 16 :element-type '(unsigned-byte 8))))
        (loop :for w :in words
              :for i :from 0 :by 2
              :do (setf (aref octets i) (ldb (byte 8 8) w)
                        (aref octets (1+ i)) (ldb (byte 8 0) w)))
        octets))))

(defun %format-ipv6 (octets start)
  "16 octets -> RFC 5952 text: lowercase hex, the longest run of two or
more zero groups (the first when tied) written as \"::\"."
  (let ((words (loop :for i :from start :below (+ start 16) :by 2
                     :collect (logior (ash (aref octets i) 8) (aref octets (1+ i)))))
        (best-start nil) (best-len 0))
    (let ((run-start nil) (run-len 0))
      (loop :for w :in words
            :for i :from 0
            :do (if (zerop w)
                    (progn (unless run-start (setf run-start i run-len 0))
                           (incf run-len)
                           (when (> run-len best-len)
                             (setf best-start run-start best-len run-len)))
                    (setf run-start nil))))
    (when (< best-len 2) (setf best-start nil))
    (with-output-to-string (out)
      (loop :for w :in words
            :for i :from 0
            :with skipping := nil
            :do (cond ((and best-start (= i best-start))
                       (write-string "::" out)
                       (setf skipping t))
                      ((and skipping (< i (+ best-start best-len))))
                      (t (setf skipping nil)
                         (when (and (> i 0)
                                    (not (and best-start (= i (+ best-start best-len)))))
                           (write-char #\: out))
                         (format out "~(~x~)" w)))))))

;;; ------------------------------------------------------------------
;;; Encoder

(defstruct (%out (:constructor %make-out ()))
  (bytes (make-array 512 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  ;; label list (a name suffix) -> offset of its first occurrence
  (names (make-hash-table :test 'equal)))

(declaim (inline %put8))
(defun %put8 (out byte)
  (vector-push-extend byte (%out-bytes out)))

(defun %put16 (out value)
  (%put8 out (ldb (byte 8 8) value))
  (%put8 out (ldb (byte 8 0) value)))

(defun %put32 (out value)
  (%put16 out (ldb (byte 16 16) value))
  (%put16 out (ldb (byte 16 0) value)))

(defun %put-octets (out octets)
  (loop :for b :across octets :do (%put8 out b)))

(defun %put-utf8 (out string)
  (loop :for ch :across string
        :for c := (char-code ch)
        :do (cond ((< c #x80) (%put8 out c))
                  ((< c #x800)
                   (%put8 out (logior #xC0 (ash c -6)))
                   (%put8 out (logior #x80 (logand c #x3F))))
                  ((< c #x10000)
                   (%put8 out (logior #xE0 (ash c -12)))
                   (%put8 out (logior #x80 (logand (ash c -6) #x3F)))
                   (%put8 out (logior #x80 (logand c #x3F))))
                  (t
                   (%put8 out (logior #xF0 (ash c -18)))
                   (%put8 out (logior #x80 (logand (ash c -12) #x3F)))
                   (%put8 out (logior #x80 (logand (ash c -6) #x3F)))
                   (%put8 out (logior #x80 (logand c #x3F)))))))

(defun %position (out)
  (fill-pointer (%out-bytes out)))

(defun %patch16 (out offset value)
  (setf (aref (%out-bytes out) offset) (ldb (byte 8 8) value)
        (aref (%out-bytes out) (1+ offset)) (ldb (byte 8 0) value)))

(defun %put-name (out name &key (compress t))
  "Write NAME, replacing any suffix already in the message by a pointer
when COMPRESS; every suffix written is remembered for later names."
  (let ((labels (%name-labels name))
        (total 1))
    (dolist (label labels)
      (let ((len (%utf8-length label)))
        (when (> len +max-label-octets+)
          (error 'dns-encode-error
                 :message (format nil "label ~s of ~s is longer than ~d octets"
                                  label name +max-label-octets+)))
        (incf total (1+ len))))
    (when (> total +max-name-octets+)
      (error 'dns-encode-error
             :message (format nil "name ~s is longer than ~d octets" name +max-name-octets+)))
    (loop
      (when (null labels)
        (%put8 out 0)
        (return))
      (let ((known (and compress (gethash labels (%out-names out)))))
        (when known
          (%put16 out (logior #xC000 known))
          (return)))
      (let ((pos (%position out)))
        (when (< pos #x4000)
          (setf (gethash labels (%out-names out)) pos)))
      (%put8 out (%utf8-length (car labels)))
      (%put-utf8 out (car labels))
      (setf labels (cdr labels)))))

(defun %put-nsec-bitmap (out types)
  "RFC 4034 section 4.1.2 type bitmaps: one window per 256 types."
  (let ((types (sort (remove-duplicates (copy-list types)) #'<)))
    (loop :while types
          :do (let* ((window (ash (car types) -8))
                     (bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                     (last 0))
                (loop :while (and types (= (ash (car types) -8) window))
                      :do (let* ((low (logand (car types) #xFF))
                                 (index (ash low -3)))
                            (setf (aref bytes index)
                                  (logior (aref bytes index) (ash #x80 (- (logand low 7)))))
                            (setf last (max last (1+ index)))
                            (pop types)))
                (%put8 out window)
                (%put8 out last)
                (dotimes (i last) (%put8 out (aref bytes i)))))))

(defun %put-rdata (out type data)
  (cond ((or (= type +type-ptr+) (= type +type-cname+))
         (%put-name out data))
        ((= type +type-srv+)
         (%put16 out (or (getf data :priority) 0))
         (%put16 out (or (getf data :weight) 0))
         (%put16 out (or (getf data :port) 0))
         (%put-name out (or (getf data :target)
                            (error 'dns-encode-error :message "SRV record without :target"))
                    :compress *compress-srv-target*))
        ((= type +type-txt+)
         (if (null data)
             (%put8 out 0)
             (dolist (s data)
               (let ((len (if (stringp s) (%utf8-length s) (length s))))
                 (when (> len +max-txt-string+)
                   (error 'dns-encode-error
                          :message (format nil "TXT string longer than ~d octets: ~s"
                                           +max-txt-string+ s)))
                 (%put8 out len)
                 (if (stringp s) (%put-utf8 out s) (%put-octets out s))))))
        ((= type +type-a+)
         (%put-octets out (%parse-ipv4 data)))
        ((= type +type-aaaa+)
         (%put-octets out (%parse-ipv6 data)))
        ((= type +type-nsec+)
         ;; RFC 6762 section 18.14: unlike DNSSEC, mDNS compresses this name
         (%put-name out (getf data :next-name))
         (%put-nsec-bitmap out (getf data :types)))
        (t
         (unless (and (vectorp data) (not (stringp data)))
           (error 'dns-encode-error
                  :message (format nil "data of a type ~d record must be an octet vector, got ~s"
                                   type data)))
         (%put-octets out data))))

(defun %put-record (out record)
  (%put-name out (dns-record-name record))
  (%put16 out (dns-record-type record))
  (%put16 out (logior (logand (dns-record-class record) #x7FFF)
                      (if (dns-record-cache-flush-p record) #x8000 0)))
  (%put32 out (dns-record-ttl record))
  (let ((length-at (%position out)))
    (%put16 out 0)
    (%put-rdata out (dns-record-type record) (dns-record-data record))
    (let ((rdlength (- (%position out) length-at 2)))
      (when (> rdlength #xFFFF)
        (error 'dns-encode-error :message "record data longer than 65535 octets"))
      (%patch16 out length-at rdlength))))

(defun encode-message (message &key (compress-srv-target t))
  "MESSAGE -> a fresh (unsigned-byte 8) vector in DNS wire format, names
compressed.  COMPRESS-SRV-TARGET NIL leaves SRV targets uncompressed, as a
legacy unicast response must (RFC 6762 section 18.14).  Signals
DNS-ENCODE-ERROR for a name, label or TXT string too long for the wire, or
record data that does not fit the record's type."
  (let ((out (%make-out))
        (*compress-srv-target* compress-srv-target))
    (%put16 out (dns-message-id message))
    (%put16 out (dns-message-flags message))
    (%put16 out (length (dns-message-questions message)))
    (%put16 out (length (dns-message-answers message)))
    (%put16 out (length (dns-message-authorities message)))
    (%put16 out (length (dns-message-additionals message)))
    (dolist (q (dns-message-questions message))
      (%put-name out (dns-question-name q))
      (%put16 out (dns-question-type q))
      (%put16 out (logior (logand (dns-question-class q) #x7FFF)
                          (if (dns-question-unicast-response-p q) #x8000 0))))
    (dolist (r (dns-message-answers message)) (%put-record out r))
    (dolist (r (dns-message-authorities message)) (%put-record out r))
    (dolist (r (dns-message-additionals message)) (%put-record out r))
    (let* ((bytes (%out-bytes out))
           (result (make-array (length bytes) :element-type '(unsigned-byte 8))))
      (replace result bytes)
      result)))

;;; ------------------------------------------------------------------
;;; Decoder

(defstruct (%in (:constructor %make-in (octets start end &optional (pos start))))
  octets
  start   ; offset of the message header: compression pointers count from here
  end     ; one past the last octet this reader may touch
  pos)

(defun %fail (in format &rest args)
  (error 'dns-decode-error
         :offset (- (%in-pos in) (%in-start in))
         :message (apply #'format nil format args)))

(defun %need (in n what)
  (when (> (+ (%in-pos in) n) (%in-end in))
    (%fail in "~a needs ~d octet~:p, ~d left" what n (- (%in-end in) (%in-pos in)))))

(defun %get8 (in what)
  (%need in 1 what)
  (prog1 (aref (%in-octets in) (%in-pos in))
    (incf (%in-pos in))))

(defun %get16 (in what)
  (%need in 2 what)
  (let ((octets (%in-octets in)) (pos (%in-pos in)))
    (incf (%in-pos in) 2)
    (logior (ash (aref octets pos) 8) (aref octets (1+ pos)))))

(defun %get32 (in what)
  (let ((high (%get16 in what)))
    (logior (ash high 16) (%get16 in what))))

(defun %get-name (in)
  "Read a possibly compressed name at the reader's position.  Pointers may
only lead backwards, each further than the one before, so a loop or a
forward reference is an error rather than a hang."
  (let* ((octets (%in-octets in))
         (start (%in-start in))
         (end (%in-end in))
         (pos (%in-pos in))
         (bound pos)          ; a pointer must land before this
         (jumped nil)
         (total 0)
         (labels '()))
    (loop
      (when (>= pos end)
        (setf (%in-pos in) pos)
        (%fail in "name runs past the end of the message"))
      (let ((len (aref octets pos)))
        (cond ((zerop len)
               (incf pos)
               (unless jumped (setf (%in-pos in) pos))
               (return))
              ((= (logand len #xC0) #xC0)
               (when (>= (1+ pos) end)
                 (setf (%in-pos in) pos)
                 (%fail in "compression pointer cut off"))
               (let ((target (+ start (logior (ash (logand len #x3F) 8) (aref octets (1+ pos))))))
                 (unless (< target bound)
                   (setf (%in-pos in) pos)
                   (%fail in "compression pointer to offset ~d does not point backwards"
                          (- target start)))
                 (unless jumped
                   (setf (%in-pos in) (+ pos 2)
                         jumped t))
                 (setf bound target
                       pos target)))
              ((/= (logand len #xC0) 0)
               (setf (%in-pos in) pos)
               (%fail in "unsupported label type #x~2,'0x" (logand len #xC0)))
              (t
               (incf total (1+ len))
               (when (> total +max-name-octets+)
                 (setf (%in-pos in) pos)
                 (%fail in "name longer than ~d octets" +max-name-octets+))
               (when (> (+ pos 1 len) end)
                 (setf (%in-pos in) pos)
                 (%fail in "label of ~d octets runs past the end of the message" len))
               (push (%utf8-decode octets (1+ pos) (+ pos 1 len)) labels)
               (incf pos (1+ len))))))
    (%labels-name (nreverse labels))))

(defun %get-question (in)
  (let* ((name (%get-name in))
         (type (%get16 in "question type"))
         (class (%get16 in "question class")))
    (make-dns-question :name name :type type
                       :class (logand class #x7FFF)
                       :unicast-response-p (logbitp 15 class))))

(defun %get-nsec-types (in)
  (let ((types '()))
    (loop :while (< (%in-pos in) (%in-end in))
          :do (let ((window (%get8 in "NSEC window"))
                    (len (%get8 in "NSEC bitmap length")))
                (unless (<= 1 len 32)
                  (%fail in "NSEC bitmap length ~d is not 1..32" len))
                (dotimes (i len)
                  (let ((byte (%get8 in "NSEC bitmap")))
                    (dotimes (bit 8)
                      (when (logbitp (- 7 bit) byte)
                        (push (logior (ash window 8) (* i 8) bit) types)))))))
    (nreverse types)))

(defun %get-rdata (in type rdlength)
  "Decode RDLENGTH octets of TYPE data at the reader's position, with a
reader of its own so the data cannot run into the next record."
  (let* ((rstart (%in-pos in))
         (rend (+ rstart rdlength))
         (sub (%make-in (%in-octets in) (%in-start in) rend rstart))
         (data
           (cond ((or (= type +type-ptr+) (= type +type-cname+))
                  (%get-name sub))
                 ((= type +type-srv+)
                  (let* ((priority (%get16 sub "SRV priority"))
                         (weight (%get16 sub "SRV weight"))
                         (port (%get16 sub "SRV port"))
                         (target (%get-name sub)))
                    (list :priority priority :weight weight :port port :target target)))
                 ((= type +type-txt+)
                  (let ((strings
                          (loop :while (< (%in-pos sub) rend)
                                :collect (let ((len (%get8 sub "TXT string length")))
                                           (%need sub len "TXT string")
                                           (prog1 (%utf8-decode (%in-octets sub) (%in-pos sub)
                                                                (+ (%in-pos sub) len))
                                             (incf (%in-pos sub) len))))))
                    (if (equal strings '("")) nil strings)))
                 ((= type +type-a+)
                  (unless (= rdlength 4)
                    (%fail sub "A record data is ~d octets, not 4" rdlength))
                  (setf (%in-pos sub) rend)
                  (%format-ipv4 (%in-octets sub) rstart))
                 ((= type +type-aaaa+)
                  (unless (= rdlength 16)
                    (%fail sub "AAAA record data is ~d octets, not 16" rdlength))
                  (setf (%in-pos sub) rend)
                  (%format-ipv6 (%in-octets sub) rstart))
                 ((= type +type-nsec+)
                  (let ((next (%get-name sub)))
                    (list :next-name next :types (%get-nsec-types sub))))
                 (t
                  (let ((raw (make-array rdlength :element-type '(unsigned-byte 8))))
                    (replace raw (%in-octets sub) :start2 rstart :end2 rend)
                    (setf (%in-pos sub) rend)
                    raw)))))
    (unless (= (%in-pos sub) rend)
      (%fail sub "~d octet~:p of type ~d record data left over" (- rend (%in-pos sub)) type))
    (setf (%in-pos in) rend)
    data))

(defun %get-record (in)
  (let* ((name (%get-name in))
         (type (%get16 in "record type"))
         (class (%get16 in "record class"))
         (ttl (%get32 in "record TTL"))
         (rdlength (%get16 in "record data length")))
    (%need in rdlength "record data")
    (make-dns-record :name name :type type
                     :class (logand class #x7FFF)
                     :cache-flush-p (logbitp 15 class)
                     :ttl ttl
                     :data (%get-rdata in type rdlength))))

(defun decode-message (octets &key (start 0) end)
  "OCTETS[START,END) in DNS wire format -> DNS-MESSAGE, and as a second
value the offset just past the message.  Signals DNS-DECODE-ERROR on
malformed input: a datagram off the network is never trusted."
  (let* ((end (or end (length octets)))
         (in (%make-in octets start end)))
    (when (< (- end start) 12)
      (%fail in "a DNS message has a 12 octet header, this one has ~d octets" (- end start)))
    (let* ((id (%get16 in "id"))
           (flags (%get16 in "flags"))
           (qdcount (%get16 in "question count"))
           (ancount (%get16 in "answer count"))
           (nscount (%get16 in "authority count"))
           (arcount (%get16 in "additional count")))
      (flet ((collect (count reader)
               (loop :repeat count :collect (funcall reader in))))
        (let ((message
                (make-dns-message
                 :id id :flags flags
                 :questions (collect qdcount #'%get-question)
                 :answers (collect ancount #'%get-record)
                 :authorities (collect nscount #'%get-record)
                 :additionals (collect arcount #'%get-record))))
          (values message (%in-pos in)))))))
