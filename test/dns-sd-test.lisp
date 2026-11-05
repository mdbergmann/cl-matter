(defpackage :cl-matter.dns-sd.tests
  (:use :cl :fiveam :cl-matter.dns-sd))
(in-package :cl-matter.dns-sd.tests)

(def-suite dns-sd-tests :description "cl-matter/dns-sd" :in cl-matter.tests:test-suite)
(in-suite dns-sd-tests)

(test constants
  (is (= 5353 +mdns-port+))
  (is (string= "224.0.0.251" +mdns-ipv4-group+))
  (is (string= "ff02::fb" +mdns-ipv6-group+)))

(test structures
  (let ((q (make-dns-question :name "_http._tcp.local" :type 12)))
    (is (string= "_http._tcp.local" (dns-question-name q)))
    (is (= 12 (dns-question-type q))))
  (let ((m (make-dns-message :questions (list (make-dns-question :name "a.local")))))
    (is (= 1 (length (dns-message-questions m))))))

;;; ------------------------------------------------------------------
;;; Helpers and captured packets

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun hex (string)
  "\"c00c\" -> #(192 12); spaces are ignored."
  (let* ((digits (remove #\Space string))
         (out (make-array (floor (length digits) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer digits :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun round-trip (message)
  (decode-message (encode-message message)))

(defun record (name type data &key (ttl 120) cache-flush)
  (make-dns-record :name name :type type :data data :ttl ttl :cache-flush-p cache-flush))

;;; Captured 2026-11-03 from macOS mDNSResponder with a service registered
;;; as: dns-sd -R "cl-matter test" _cl-matter-test._udp local 12345 txtvers=1 path=/x

;; the query that produced *legacy-response*: PTR _cl-matter-test._udp.local, id #x1234
(defparameter *query*
  (hex "1234 0000 0001 0000 0000 0000 0f5f636c2d6d61747465722d74657374 045f756470 056c6f63616c 00 000c 0001"))

;; unicast answer to a legacy (non-5353 source port) query: question echoed,
;; PTR answer, SRV + TXT + 2 AAAA + A additionals, TTL 10, no cache-flush bits
(defparameter *legacy-response*
  (hex "1234840000010001000000050f5f636c2d6d61747465722d74657374045f756470056c6f63616c00000c0001c00c000c00010000000a00110e636c2d6d61747465722074657374c00cc038002100010000000a000e000000003039056d6270726fc021c038001000010000000a001209747874766572733d3107706174683d2f78c05b001c00010000000a0010fe800000000000000c3026503c2c3ceac05b001c00010000000a0010fd9912e5c44144360c46ea5500d61a48c05b000100010000000a0004c0a87b84"))

;; the multicast announcement of the same service: TXT, two PTRs, SRV as
;; answers; AAAA, AAAA, A and two NSECs (with compressed next names) as
;; additionals; cache-flush set on the unique records, TTL 4500
(defparameter *announcement*
  (hex "0000840000000004000000050e636c2d6d617474657220746573740f5f636c2d6d61747465722d74657374045f756470056c6f63616c000010800100001194001209747874766572733d3107706174683d2f78095f7365727669636573075f646e732d7364c02b000c0001000011940002c01bc01b000c0001000011940002c00cc00c0021800100001194000e000000003039056d6270726fc030c093001c8001000011940010fe800000000000000c3026503c2c3ceac093001c8001000011940010fd9912e5c44144360c46ea5500d61a48c09300018001000011940004c0a87b84c093002f8001000011940008c093000440000008c00c002f8001000011940009c00c00050000800040"))

;; a response to _services._dns-sd._udp.local: four PTR answers, no question
(defparameter *services-response*
  (hex "000084000000000400000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001000011940010085f616972706c6179045f746370c023c00c000c0001000011940008055f72616f70c03dc00c000c00010000119400120f5f636f6d70616e696f6e2d6c696e6bc03dc00c000c000100001194000a075f617371756963c01e"))

;;; ------------------------------------------------------------------
;;; Captured packets

(test encode-query-byte-exact
  "Our encoding of the PTR query is byte for byte what was sent."
  (is (equalp *query*
              (encode-message
               (make-dns-message :id #x1234
                                 :questions (list (make-dns-question
                                                   :name "_cl-matter-test._udp.local"
                                                   :type +type-ptr+)))))))

(test decode-query
  (multiple-value-bind (m end) (decode-message *query*)
    (is (= (length *query*) end))
    (is (= #x1234 (dns-message-id m)))
    (is (not (dns-message-response-p m)))
    (is (= 1 (length (dns-message-questions m))))
    (let ((q (first (dns-message-questions m))))
      (is (string= "_cl-matter-test._udp.local" (dns-question-name q)))
      (is (= +type-ptr+ (dns-question-type q)))
      (is (= +class-in+ (dns-question-class q)))
      (is (not (dns-question-unicast-response-p q))))
    (is (null (dns-message-answers m)))))

(test decode-legacy-response
  (let ((m (decode-message *legacy-response*)))
    (is (= #x1234 (dns-message-id m)))
    (is (dns-message-response-p m))
    (is (logtest +flag-authoritative+ (dns-message-flags m)))
    (is (not (dns-message-truncated-p m)))
    (is (= 1 (length (dns-message-questions m))))
    (is (= 1 (length (dns-message-answers m))))
    (is (= 0 (length (dns-message-authorities m))))
    (is (= 5 (length (dns-message-additionals m))))
    (let ((ptr (first (dns-message-answers m))))
      (is (string= "_cl-matter-test._udp.local" (dns-record-name ptr)))
      (is (= +type-ptr+ (dns-record-type ptr)))
      (is (= 10 (dns-record-ttl ptr)))
      (is (not (dns-record-cache-flush-p ptr)))
      (is (string= "cl-matter test._cl-matter-test._udp.local" (dns-record-data ptr))))
    (destructuring-bind (srv txt aaaa1 aaaa2 a) (dns-message-additionals m)
      (is (= +type-srv+ (dns-record-type srv)))
      (is (string= "cl-matter test._cl-matter-test._udp.local" (dns-record-name srv)))
      (is (equal '(:priority 0 :weight 0 :port 12345 :target "mbpro.local")
                 (dns-record-data srv)))
      (is (= +type-txt+ (dns-record-type txt)))
      (is (equal '("txtvers=1" "path=/x") (dns-record-data txt)))
      (is (= +type-aaaa+ (dns-record-type aaaa1)))
      (is (string= "mbpro.local" (dns-record-name aaaa1)))
      (is (string= "fe80::c30:2650:3c2c:3cea" (dns-record-data aaaa1)))
      (is (string= "fd99:12e5:c441:4436:c46:ea55:d6:1a48" (dns-record-data aaaa2)))
      (is (= +type-a+ (dns-record-type a)))
      (is (string= "192.168.123.132" (dns-record-data a))))))

(test decode-announcement
  "Cache-flush bits, compressed SRV targets and NSEC next names."
  (let ((m (decode-message *announcement*)))
    (is (= 0 (dns-message-id m)))
    (is (= #x8400 (dns-message-flags m)))
    (is (null (dns-message-questions m)))
    (is (= 4 (length (dns-message-answers m))))
    (is (= 5 (length (dns-message-additionals m))))
    (destructuring-bind (txt ptr-services ptr srv) (dns-message-answers m)
      (is (= +type-txt+ (dns-record-type txt)))
      (is (dns-record-cache-flush-p txt))
      (is (= +class-in+ (dns-record-class txt)))
      (is (= 4500 (dns-record-ttl txt)))
      (is (equal '("txtvers=1" "path=/x") (dns-record-data txt)))
      (is (string= "_services._dns-sd._udp.local" (dns-record-name ptr-services)))
      (is (not (dns-record-cache-flush-p ptr-services)))
      (is (string= "_cl-matter-test._udp.local" (dns-record-data ptr-services)))
      (is (string= "_cl-matter-test._udp.local" (dns-record-name ptr)))
      (is (string= "cl-matter test._cl-matter-test._udp.local" (dns-record-data ptr)))
      (is (dns-record-cache-flush-p srv))
      (is (equal '(:priority 0 :weight 0 :port 12345 :target "mbpro.local")
                 (dns-record-data srv))))
    (destructuring-bind (aaaa1 aaaa2 a nsec-host nsec-service) (dns-message-additionals m)
      (is (string= "fe80::c30:2650:3c2c:3cea" (dns-record-data aaaa1)))
      (is (string= "fd99:12e5:c441:4436:c46:ea55:d6:1a48" (dns-record-data aaaa2)))
      (is (string= "192.168.123.132" (dns-record-data a)))
      (is (every #'dns-record-cache-flush-p (list aaaa1 aaaa2 a nsec-host nsec-service)))
      (is (= +type-nsec+ (dns-record-type nsec-host)))
      (is (string= "mbpro.local" (dns-record-name nsec-host)))
      (is (equal '(:next-name "mbpro.local" :types (1 28)) (dns-record-data nsec-host)))
      (is (equal (list :next-name "cl-matter test._cl-matter-test._udp.local"
                       :types (list +type-txt+ +type-srv+))
                 (dns-record-data nsec-service))))))

(test decode-services-response
  (let ((m (decode-message *services-response*)))
    (is (= 4 (length (dns-message-answers m))))
    (is (every (lambda (r) (string= "_services._dns-sd._udp.local" (dns-record-name r)))
               (dns-message-answers m)))
    (is (equal '("_airplay._tcp.local" "_raop._tcp.local"
                 "_companion-link._tcp.local" "_asquic._udp.local")
               (mapcar #'dns-record-data (dns-message-answers m))))))

(test re-encode-captured
  "Decoding and encoding gives the responder's packets back byte for byte:
the same compression choices, NSEC next names included."
  (dolist (packet (list *query* *legacy-response* *announcement* *services-response*))
    (let* ((m (decode-message packet))
           (bytes (encode-message m)))
      (is (equalp packet bytes))
      (is (equalp m (decode-message bytes))))))

;;; ------------------------------------------------------------------
;;; Hand-built messages

(test header-and-flags
  (let* ((m (make-dns-message :id 7 :flags (logior +flag-response+ +flag-authoritative+)))
         (bytes (encode-message m)))
    (is (= 12 (length bytes)))
    (is (equalp (octets 0 7 #x84 0 0 0 0 0 0 0 0 0) bytes))
    (is (dns-message-response-p (decode-message bytes)))
    (is (equalp m (decode-message bytes)))))

(test qu-and-cache-flush-bits
  (let* ((m (make-dns-message
             :questions (list (make-dns-question :name "a.local" :type +type-any+
                                                 :unicast-response-p t))
             :answers (list (record "a.local" +type-a+ "10.0.0.1" :cache-flush t))))
         (bytes (encode-message m))
         (back (decode-message bytes)))
    ;; question: 1 a 5 local 0 | type FF | class 80 01
    (is (equalp (octets 1 97 5 108 111 99 97 108 0 0 255 #x80 1) (subseq bytes 12 25)))
    (is (dns-question-unicast-response-p (first (dns-message-questions back))))
    (is (= +class-in+ (dns-question-class (first (dns-message-questions back)))))
    (is (dns-record-cache-flush-p (first (dns-message-answers back))))
    (is (= +class-in+ (dns-record-class (first (dns-message-answers back)))))
    (is (equalp m back))))

(test all-sections-round-trip
  (let ((m (make-dns-message
            :id 1 :flags +flag-response+
            :questions (list (make-dns-question :name "_http._tcp.local" :type +type-ptr+))
            :answers (list (record "_http._tcp.local" +type-ptr+ "Web._http._tcp.local"))
            :authorities (list (record "Web._http._tcp.local" +type-srv+
                                       '(:priority 0 :weight 0 :port 80 :target "box.local")))
            :additionals (list (record "box.local" +type-a+ "192.168.0.9")
                               (record "box.local" +type-aaaa+ "fe80::1")
                               (record "Web._http._tcp.local" +type-txt+ '("path=/" "v=1"))
                               (record "box.local" +type-nsec+
                                       '(:next-name "box.local" :types (1 28)))
                               (record "box.local" +type-cname+ "other.local")
                               (record "box.local" 99 #(1 2 3))))))
    (let ((back (round-trip m)))
      (is (equalp m back))
      (is (= 1 (length (dns-message-authorities back))))
      (is (equalp (octets 1 2 3) (dns-record-data (car (last (dns-message-additionals back)))))))))

(test name-compression
  "Repeated suffixes become pointers; the pointer is two bytes."
  (let* ((one (encode-message
               (make-dns-message
                :answers (list (record "_a._tcp.local" +type-ptr+ "x._a._tcp.local")))))
         (two (encode-message
               (make-dns-message
                :answers (list (record "_a._tcp.local" +type-ptr+ "x._a._tcp.local")
                               (record "_a._tcp.local" +type-ptr+ "y._a._tcp.local"))))))
    ;; the second record: pointer (2) + type/class/ttl/rdlength (10) + "y" (2) + pointer (2)
    (is (= (+ (length one) 16) (length two)))
    ;; the first PTR's data is "x" then a pointer back to the record name at 12
    (is (equalp (octets 1 120 #xC0 12) (subseq one (- (length one) 4))))))

(test escaped-dots-in-labels
  "A dot inside an instance name travels as part of one label."
  (let* ((name "Printer v2\\.0._ipp._tcp.local")
         (bytes (encode-message
                 (make-dns-message :questions (list (make-dns-question :name name)))))
         (back (decode-message bytes)))
    (is (= 12 (aref bytes 12)))                ; label "Printer v2.0" is 12 octets
    (is (= (char-code #\.) (aref bytes 23)))   ; and the dot is inside it
    (is (string= name (dns-question-name (first (dns-message-questions back))))))
  (let* ((name "back\\\\slash.local")
         (back (round-trip (make-dns-message :questions (list (make-dns-question :name name))))))
    (is (string= name (dns-question-name (first (dns-message-questions back)))))))

(test utf8-labels
  (let* ((name (format nil "K~cche._http._tcp.local" (code-char 252)))
         (bytes (encode-message
                 (make-dns-message :questions (list (make-dns-question :name name)))))
         (back (decode-message bytes)))
    (is (= 6 (aref bytes 12)))                       ; "Küche" is 6 octets
    (is (equalp (octets #xC3 #xBC) (subseq bytes 14 16)))
    (is (string= name (dns-question-name (first (dns-message-questions back))))))
  ;; three and four byte sequences, and an invalid one, in TXT strings
  (let* ((s (format nil "~c~c" (code-char #x20AC) (code-char #x1F600)))
         (back (round-trip (make-dns-message
                            :answers (list (record "a.local" +type-txt+ (list s)))))))
    (is (string= s (first (dns-record-data (first (dns-message-answers back)))))))
  (let ((m (decode-message
            (octets 0 0 0 0 0 0 0 1 0 0 0 0
                    1 #xFF 0  0 16 0 1  0 0 0 1  0 3  2 #xC3 #x28))))
    (is (string= "?" (dns-record-name (first (dns-message-answers m)))))
    (is (equal '("?(") (dns-record-data (first (dns-message-answers m)))))))

(test root-and-trailing-dot
  (let ((back (round-trip (make-dns-message
                           :questions (list (make-dns-question :name "local.")
                                            (make-dns-question :name ""))))))
    (is (string= "local" (dns-question-name (first (dns-message-questions back)))))
    (is (string= "" (dns-question-name (second (dns-message-questions back)))))))

(test txt-records
  ;; the empty TXT record is a single zero octet (RFC 6763 section 6.1)
  (let ((bytes (encode-message (make-dns-message :answers (list (record "a.local" +type-txt+ nil))))))
    (is (equalp (octets 0 1 0) (subseq bytes (- (length bytes) 3))))
    (is (null (dns-record-data (first (dns-message-answers (decode-message bytes)))))))
  ;; an octet vector element goes out raw
  (let ((back (round-trip (make-dns-message
                           :answers (list (record "a.local" +type-txt+
                                                  (list "k=v" (octets 255 0 1))))))))
    (is (= 2 (length (dns-record-data (first (dns-message-answers back))))))))

(test nsec-bitmaps
  (let* ((types (list 300 1 +type-nsec+ +type-srv+ 28 +type-txt+ 261 1))
         (back (round-trip (make-dns-message
                            :answers (list (record "a.local" +type-nsec+
                                                   (list :next-name "a.local" :types types)))))))
    (is (equal '(1 16 28 33 47 261 300)
               (getf (dns-record-data (first (dns-message-answers back))) :types))))
  ;; the announcement's bitmap for A + AAAA, byte exact
  (let ((bytes (encode-message (make-dns-message
                                :answers (list (record "mbpro.local" +type-nsec+
                                                       '(:next-name "mbpro.local" :types (1 28))))))))
    (is (equalp (octets 0 4 #x40 0 0 8) (subseq bytes (- (length bytes) 6))))))

(test ipv6-text-form
  (flet ((both (text expected)
           (is (string= expected
                        (cl-matter.dns-sd::%format-ipv6 (cl-matter.dns-sd::%parse-ipv6 text) 0)))))
    (both "::1" "::1")
    (both "::" "::")
    (both "fe80::" "fe80::")
    (both "2001:DB8::1" "2001:db8::1")
    (both "2001:db8:0:0:0:0:2:1" "2001:db8::2:1")
    (both "1:0:0:1:0:0:0:1" "1:0:0:1::1")          ; the longer run wins
    (both "2001:db8:0:0:1:0:0:1" "2001:db8::1:0:0:1") ; the first run wins a tie
    (both "1:2:3:4:5:6:7:0" "1:2:3:4:5:6:7:0")       ; a single zero is not compressed
    (both "ff02::fb" "ff02::fb")))

(test address-round-trip
  (let ((back (round-trip (make-dns-message
                           :answers (list (record "a.local" +type-a+ "0.0.0.0")
                                          (record "a.local" +type-a+ "255.255.255.255")
                                          (record "a.local" +type-aaaa+ "ff02::fb"))))))
    (is (equal '("0.0.0.0" "255.255.255.255" "ff02::fb")
               (mapcar #'dns-record-data (dns-message-answers back))))))

(test decode-with-start-and-end
  "A message inside a larger buffer; the second value says where it ends."
  (let* ((buffer (make-array (+ 3 (length *query*) 5) :element-type '(unsigned-byte 8)
                                                         :initial-element 170)))
    (replace buffer *query* :start1 3)
    (multiple-value-bind (m end) (decode-message buffer :start 3 :end (+ 3 (length *query*)))
      (is (= (+ 3 (length *query*)) end))
      (is (string= "_cl-matter-test._udp.local"
                   (dns-question-name (first (dns-message-questions m))))))
    ;; trailing octets after the counted sections are left alone
    (multiple-value-bind (m end) (decode-message buffer :start 3)
      (is (= (+ 3 (length *query*)) end))
      (is (= 1 (length (dns-message-questions m)))))))

;;; ------------------------------------------------------------------
;;; Errors

(defmacro rejects (form)
  "FORM signals DNS-DECODE-ERROR with an offset."
  `(handler-case (progn ,form (fail "~s was accepted" ',form))
     (dns-decode-error (e)
       (is (integerp (dns-decode-error-offset e)))
       (is (stringp (dns-decode-error-message e))))))

(defun with-question (&rest bytes)
  "A header announcing one question, followed by BYTES."
  (apply #'octets 0 0 0 0 0 1 0 0 0 0 0 0 bytes))

(defun with-answer (&rest bytes)
  (apply #'octets 0 0 0 0 0 0 0 1 0 0 0 0 bytes))

(test rejects-malformed
  (rejects (decode-message (octets 0 0 0 0 0)))                      ; short header
  (rejects (decode-message (with-question)))                          ; question missing
  (rejects (decode-message (with-question 5 108 111)))                ; label cut off
  (rejects (decode-message (with-question 1 97 0 0 12)))              ; class cut off
  (rejects (decode-message (with-question #xC0 12 0 12 0 1)))         ; pointer to itself
  (rejects (decode-message (with-question 1 97 #xC0 12 0 12 0 1)))    ; pointer into own name
  (rejects (decode-message (with-question #xC0 40 0 12 0 1)))         ; pointer forward
  (rejects (decode-message (with-question #x40 97 0 0 12 0 1)))       ; label type 01
  (rejects (decode-message (with-question #xC0)))                     ; pointer cut off
  (rejects (decode-message (with-answer 1 97 0 0 1 0 1 0 0 0 0 0 4 1 2 3)))     ; rdata short
  (rejects (decode-message (with-answer 1 97 0 0 1 0 1 0 0 0 0 0 3 1 2 3)))     ; A of 3 octets
  (rejects (decode-message (with-answer 1 97 0 0 28 0 1 0 0 0 0 0 4 1 2 3 4)))  ; AAAA of 4
  (rejects (decode-message (with-answer 1 97 0 0 12 0 1 0 0 0 0 0 4 1 98 0 0))) ; PTR with leftover
  (rejects (decode-message (with-answer 1 97 0 0 33 0 1 0 0 0 0 0 4 0 0 0 0)))  ; SRV too short
  (rejects (decode-message (with-answer 1 97 0 0 16 0 1 0 0 0 0 0 2 5 97)))     ; TXT string cut
  (rejects (decode-message (with-answer 1 97 0 0 47 0 1 0 0 0 0 0 4 0 0 33 0))) ; NSEC bitmap len
  ;; a name over 255 octets built from four 63-octet labels and one more
  (let ((label (cons 63 (make-list 63 :initial-element 97))))
    (rejects (decode-message
              (apply #'with-question (append label label label label '(1 97 0 0 1 0 1)))))))

(test rejects-unencodable
  (flet ((bad (message) (signals dns-encode-error (encode-message message)))
         (q (name) (make-dns-message :questions (list (make-dns-question :name name)))))
    (bad (q (make-string 64 :initial-element #\a)))                        ; label too long
    (bad (q (format nil "~{~a~^.~}" (make-list 5 :initial-element           ; name too long
                                              (make-string 60 :initial-element #\a)))))
    (bad (q "a..b"))                                                        ; empty label
    (bad (q "a\\"))                                                         ; dangling escape
    (bad (make-dns-message :answers (list (record "a" +type-a+ "1.2.3"))))
    (bad (make-dns-message :answers (list (record "a" +type-a+ "1.2.3.256"))))
    (bad (make-dns-message :answers (list (record "a" +type-aaaa+ "1::2::3"))))
    (bad (make-dns-message :answers (list (record "a" +type-aaaa+ "1:2:3:4:5:6:7"))))
    (bad (make-dns-message :answers (list (record "a" +type-aaaa+ "12345::"))))
    (bad (make-dns-message :answers (list (record "a" +type-srv+ '(:port 1)))))
    (bad (make-dns-message :answers (list (record "a" +type-txt+
                                                  (list (make-string 256 :initial-element #\x))))))
    (bad (make-dns-message :answers (list (record "a" 99 "not octets"))))))

(test error-reports-offset
  (handler-case (progn (decode-message (with-question #xC0 40 0 12 0 1)) (fail "accepted"))
    (dns-decode-error (e)
      (is (= 12 (dns-decode-error-offset e)))
      (is (search "byte 12" (princ-to-string e))))))

;;; ------------------------------------------------------------------
;;; Querier
;;;
;;; No LAN involved: a plain socket on 127.0.0.1 plays the responder, the
;;; MDNS-SOCKET under test is a legacy querier aimed at it, and the answers
;;; are queued in its receive buffer before the call, since nothing reads
;;; the fake responder's socket while BROWSE runs.

(defparameter *instance* "cl-matter test._cl-matter-test._udp.local")

(defmacro with-fake-responder ((responder querier) &body body)
  `(cl-matter.net:with-udp-socket (,responder :address "127.0.0.1")
     (setf (cl-matter.net:socket-timeout ,responder) 0.3)
     (with-mdns-socket (,querier :address "127.0.0.1" :multicast nil
                                 :group "127.0.0.1"
                                 :port (nth-value 1 (cl-matter.net:socket-local-endpoint ,responder)))
       ,@body)))

(defun queue-reply (responder querier packet)
  (multiple-value-bind (address port)
      (cl-matter.net:socket-local-endpoint (mdns-socket-socket querier))
    (cl-matter.net:send-to responder packet address port)))

(defun received-query (responder)
  "The next datagram at the fake responder, decoded, or NIL."
  (let* ((buf (make-array 1500 :element-type '(unsigned-byte 8)))
         (len (cl-matter.net:receive-from responder buf)))
    (and len (decode-message buf :end len))))

(defun question-list (message)
  (mapcar (lambda (q) (list (dns-question-name q) (dns-question-type q)))
          (dns-message-questions message)))

(test parse-txt
  (let ((alist (parse-txt-record '("txtvers=1" "path=/x" "flag" "empty=" "k=a=b" "" "PATH=dup"))))
    (is (equal '(("txtvers" . "1") ("path" . "/x") ("flag") ("empty" . "") ("k" . "a=b"))
               alist))
    (is (string= "/x" (txt-value alist "Path")))
    (multiple-value-bind (v present) (txt-value alist "flag")
      (is (null v))
      (is-true present))
    (multiple-value-bind (v present) (txt-value alist "nope")
      (is (null v))
      (is (not present))))
  (is (null (parse-txt-record nil))))

(test open-mdns-socket-modes
  "On the real group the socket is a multicast listener or a legacy querier,
and it says which; a forced legacy socket has an ephemeral port."
  (with-mdns-socket (s)
    (is (mdns-socket-p s))
    (is (member (mdns-socket-multicast-p s) '(t nil)))
    (when (mdns-socket-multicast-p s)
      (is (= +mdns-port+ (nth-value 1 (cl-matter.net:socket-local-endpoint
                                        (mdns-socket-socket s)))))))
  (with-mdns-socket (s :multicast nil)
    (is (not (mdns-socket-multicast-p s)))
    (is (/= +mdns-port+ (nth-value 1 (cl-matter.net:socket-local-endpoint
                                       (mdns-socket-socket s)))))))

(test browse-collects-instances
  "PTR answers from several responses, junk and queries skipped, no duplicates."
  (with-fake-responder (responder querier)
    (queue-reply responder querier *announcement*)
    (queue-reply responder querier (octets 1 2 3))           ; malformed
    (queue-reply responder querier *query*)                  ; a query, not a response
    (queue-reply responder querier *legacy-response*)        ; the same PTR again
    (queue-reply responder querier *services-response*)      ; another name
    (multiple-value-bind (instances records)
        (browse "_cl-matter-test._udp" :socket querier :timeout 0.4)
      (is (equal (list *instance*) instances))
      (is (= 1 (length (%records-of-type records +type-ptr+ "_cl-matter-test._udp.local"))))
      (is (find +type-srv+ records :key #'dns-record-type))
      (is (find +type-nsec+ records :key #'dns-record-type)))
    ;; what went out: one PTR question, id 0, a query
    (let ((q (received-query responder)))
      (is (= 0 (dns-message-id q)))
      (is (not (dns-message-response-p q)))
      (is (equal (list (list "_cl-matter-test._udp.local" +type-ptr+)) (question-list q))))))

(defun %records-of-type (records type name)
  (mapcar #'dns-record-type
          (remove-if-not (lambda (r) (and (= type (dns-record-type r))
                                          (string-equal name (dns-record-name r))))
                         records)))

(test browse-domain-and-case
  (with-fake-responder (responder querier)
    (queue-reply responder querier *announcement*)
    (is (equal (list *instance*)
               (browse "_CL-MATTER-TEST._UDP" :domain "LOCAL" :socket querier :timeout 0.3)))
    (is (equal '(("_CL-MATTER-TEST._UDP.LOCAL" 12)) (question-list (received-query responder)))))
  (with-fake-responder (responder querier)
    (browse "_x._tcp" :domain nil :socket querier :timeout 0.2)
    (is (equal '(("_x._tcp" 12)) (question-list (received-query responder))))))

(test goodbye-removes-instance
  "A PTR with TTL 0 retracts the instance an earlier response announced."
  (let ((goodbye (encode-message
                  (make-dns-message
                   :flags +flag-response+
                   :answers (list (record "_cl-matter-test._udp.local" +type-ptr+ *instance* :ttl 0))))))
    (with-fake-responder (responder querier)
      (queue-reply responder querier *announcement*)
      (queue-reply responder querier goodbye)
      (is (null (browse "_cl-matter-test._udp" :socket querier :timeout 0.3))))))

(test query-retransmits
  "A query lasting longer than a second goes out twice."
  (with-fake-responder (responder querier)
    (query querier (list (make-dns-question :name "a.local" :type +type-a+)) :timeout 1.2)
    (is (received-query responder))
    (is (received-query responder))
    (is (null (received-query responder)))))

(test resolve-from-browse-records
  "With BROWSE's records in hand RESOLVE sends nothing."
  (with-fake-responder (responder querier)
    (let ((service (resolve *instance* :socket querier :timeout 0.3
                            :records (cl-matter.dns-sd::%message-records (decode-message *announcement*)))))
      (is (equal (list :name *instance*
                       :host "mbpro.local"
                       :port 12345
                       :addresses '("fe80::c30:2650:3c2c:3cea" "fd99:12e5:c441:4436:c46:ea55:d6:1a48"
                                    "192.168.123.132")
                       :txt '(("txtvers" . "1") ("path" . "/x")))
                 service)))
    (is (null (received-query responder)))))

(test resolve-asks-then-stops-early
  "SRV and TXT are asked together; the answer ends the wait before the timeout."
  (with-fake-responder (responder querier)
    (queue-reply responder querier *legacy-response*)
    (let* ((t0 (get-internal-real-time))
           (service (resolve *instance* :socket querier :timeout 2))
           (elapsed (/ (- (get-internal-real-time) t0) internal-time-units-per-second)))
      (is (< elapsed 1))
      (is (= 12345 (getf service :port)))
      (is (string= "mbpro.local" (getf service :host)))
      (is (= 3 (length (getf service :addresses)))))
    (is (equal (list (list *instance* +type-srv+) (list *instance* +type-txt+))
               (question-list (received-query responder))))
    (is (null (received-query responder)))))

(test resolve-asks-for-addresses
  "When the responder adds no address records a second query asks for A and AAAA."
  (let ((srv-only (encode-message
                   (make-dns-message
                    :flags +flag-response+
                    :answers (list (record *instance* +type-srv+
                                           '(:priority 0 :weight 0 :port 7 :target "box.local"))
                                   (record *instance* +type-txt+ '("a=1")))))))
    (with-fake-responder (responder querier)
      (queue-reply responder querier srv-only)
      (let ((service (resolve *instance* :socket querier :timeout 0.6)))
        (is (= 7 (getf service :port)))
        (is (string= "box.local" (getf service :host)))
        (is (null (getf service :addresses)))
        (is (equal '(("a" . "1")) (getf service :txt))))
      (is (equal (list (list *instance* +type-srv+) (list *instance* +type-txt+))
                 (question-list (received-query responder))))
      (is (equal (list (list "box.local" +type-a+) (list "box.local" +type-aaaa+))
                 (question-list (received-query responder)))))))

(test resolve-unknown-is-nil
  (with-fake-responder (responder querier)
    (is (null (resolve "nobody._x._tcp.local" :socket querier :timeout 0.2)))))

;;; ------------------------------------------------------------------
;;; Responder
;;;
;;; Again on 127.0.0.1 without threads: PEER plays the multicast group and
;;; a full mDNS querier at once (the responder's "group" is PEER's port, so
;;; queries from PEER arrive from the mDNS port and answers go back to it);
;;; LEGACY is a querier on another port.  RESPONDER-POLL takes one turn.

(defparameter *lamp-instance* "Lamp._matterc._udp.local")

(defun lamp-service ()
  (make-service :instance "Lamp" :type "_matterc._udp" :port 5540
                :txt '(("D" . "840") ("CM" . "1") ("flag"))
                :subtypes '("_L840" "_S12")))

(defmacro with-responder-rig ((responder peer legacy &rest start-args) &body body)
  `(cl-matter.net:with-udp-socket (,peer :address "127.0.0.1")
     (cl-matter.net:with-udp-socket (,legacy :address "127.0.0.1")
       (setf (cl-matter.net:socket-timeout ,peer) 0.4
             (cl-matter.net:socket-timeout ,legacy) 0.4)
       (with-mdns-socket (rs :address "127.0.0.1" :multicast nil :group "127.0.0.1"
                             :port (nth-value 1 (cl-matter.net:socket-local-endpoint ,peer)))
         (let ((,responder (start-responder :socket rs :probe nil :thread nil
                                            :host "box.local"
                                            :addresses '("10.0.0.9" "fd00::9")
                                            :services (list (lamp-service))
                                            ,@start-args)))
           (unwind-protect (progn ,@body)
             (stop-responder ,responder)))))))

(defun responder-port (responder)
  (nth-value 1 (cl-matter.net:socket-local-endpoint
                (mdns-socket-socket (responder-socket responder)))))

(defun send-query (socket responder message)
  (cl-matter.net:send-to socket (encode-message message) "127.0.0.1" (responder-port responder)))

(defun receive-message (socket)
  "The next datagram at SOCKET decoded, and the raw packet; NIL on timeout."
  (let* ((buf (make-array 9000 :element-type '(unsigned-byte 8)))
         (len (cl-matter.net:receive-from socket buf)))
    (and len (values (decode-message buf :end len) (subseq buf 0 len)))))

(defun records-like (records type &optional name)
  (remove-if-not (lambda (r) (and (= type (dns-record-type r))
                                  (or (null name) (string-equal name (dns-record-name r)))))
                 records))

(defun ptr-query (name &key (id 0) known)
  (make-dns-message :id id
                    :questions (list (make-dns-question :name name :type +type-ptr+))
                    :answers known))

(test service-names
  (let ((s (make-service :instance "Printer v2.0" :type "_ipp._tcp" :port 631
                         :txt '("a=1" ("b" . 2) ("c")))))
    (is (string= "_ipp._tcp.local" (service-type-name s)))
    (is (string= "Printer v2\\.0._ipp._tcp.local" (service-instance-name s)))
    (is (equal '("a=1" "b=2" "c") (service-txt s)))))

(test responder-record-set
  (with-responder-rig (r peer legacy)
    (let ((records (responder-records r)))
      (is (= 10 (length records)))
      (is (equal '("_matterc._udp.local")
                 (mapcar #'dns-record-data (records-like records +type-ptr+ "_services._dns-sd._udp.local"))))
      (is (equal (list *lamp-instance*)
                 (mapcar #'dns-record-data (records-like records +type-ptr+ "_matterc._udp.local"))))
      (is (equal (list *lamp-instance*)
                 (mapcar #'dns-record-data (records-like records +type-ptr+ "_L840._sub._matterc._udp.local"))))
      (is (= 1 (length (records-like records +type-ptr+ "_S12._sub._matterc._udp.local"))))
      (let ((srv (first (records-like records +type-srv+))))
        (is (string= *lamp-instance* (dns-record-name srv)))
        (is (equal '(:priority 0 :weight 0 :port 5540 :target "box.local") (dns-record-data srv)))
        (is (= 4500 (dns-record-ttl srv))))
      (is (equal '("D=840" "CM=1" "flag") (dns-record-data (first (records-like records +type-txt+)))))
      (is (equal '(:next-name "Lamp._matterc._udp.local" :types (16 33))
                 (dns-record-data (first (records-like records +type-nsec+ *lamp-instance*)))))
      (is (equal '("10.0.0.9") (mapcar #'dns-record-data (records-like records +type-a+ "box.local"))))
      (is (equal '("fd00::9") (mapcar #'dns-record-data (records-like records +type-aaaa+ "box.local"))))
      (let ((nsec (first (records-like records +type-nsec+ "box.local"))))
        (is (equal '(:next-name "box.local" :types (1 28)) (dns-record-data nsec)))
        (is (= 120 (dns-record-ttl nsec)))))))

(test announces-twice
  (with-responder-rig (r peer legacy)
    (let ((first (receive-message peer)))
      (is (dns-message-response-p first))
      (is (= #x8400 (dns-message-flags first)))
      (is (= 0 (dns-message-id first)))
      (is (null (dns-message-questions first)))
      (is (= 10 (length (dns-message-answers first))))
      (is (every #'dns-record-cache-flush-p (remove +type-ptr+ (dns-message-answers first)
                                                    :key #'dns-record-type)))
      (is (notany #'dns-record-cache-flush-p (records-like (dns-message-answers first) +type-ptr+))))
    (is (null (receive-message peer)))          ; not yet
    (sleep 1.05)
    (responder-poll r :timeout 0.05)
    (let ((second (receive-message peer)))
      (is (= 10 (length (dns-message-answers second)))))
    (is (null (receive-message peer)))))

(test answers-ptr-with-additionals
  (with-responder-rig (r peer legacy)
    (receive-message peer)                      ; the announcement
    (send-query peer r (ptr-query "_matterc._udp.local" :id 7))
    (is (responder-poll r))
    (let ((m (receive-message peer)))
      (is (= 0 (dns-message-id m)))             ; multicast format, no echo
      (is (null (dns-message-questions m)))
      (is (= 1 (length (dns-message-answers m))))
      (let ((ptr (first (dns-message-answers m))))
        (is (string= *lamp-instance* (dns-record-data ptr)))
        (is (not (dns-record-cache-flush-p ptr))))
      (is (equal (list +type-srv+ +type-txt+ +type-nsec+ +type-a+ +type-aaaa+ +type-nsec+)
                 (mapcar #'dns-record-type (dns-message-additionals m))))
      (is (every #'dns-record-cache-flush-p (dns-message-additionals m)))
      (is (= 4500 (dns-record-ttl (first (dns-message-additionals m))))))
    (is (null (receive-message peer)))))

(test subtype-and-enumeration
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query peer r (ptr-query "_L840._sub._matterc._udp.local"))
    (responder-poll r)
    (let ((m (receive-message peer)))
      (is (string= *lamp-instance* (dns-record-data (first (dns-message-answers m)))))
      (is (= 6 (length (dns-message-additionals m)))))
    (send-query peer r (ptr-query "_services._dns-sd._udp.local"))
    (responder-poll r)
    (let ((m (receive-message peer)))
      (is (equal '("_matterc._udp.local") (mapcar #'dns-record-data (dns-message-answers m))))
      (is (null (dns-message-additionals m))))))

(test any-and-several-questions
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query peer r (make-dns-message
                        :questions (list (make-dns-question :name *lamp-instance* :type +type-any+)
                                         (make-dns-question :name "box.local" :type +type-a+))))
    (responder-poll r)
    (let ((m (receive-message peer)))
      (is (equal (list +type-srv+ +type-txt+ +type-nsec+ +type-a+)
                 (mapcar #'dns-record-type (dns-message-answers m))))
      ;; the host records not already answered
      (is (equal (list +type-aaaa+ +type-nsec+)
                 (mapcar #'dns-record-type (dns-message-additionals m)))))))

(test legacy-unicast-format
  "A query from another port: id and question echoed, TTL at most 10, no
cache-flush, the SRV target uncompressed."
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query legacy r (make-dns-message
                          :id 99
                          :questions (list (make-dns-question :name "box.local" :type +type-a+)
                                           (make-dns-question :name *lamp-instance* :type +type-srv+))))
    (responder-poll r)
    (is (null (receive-message peer)))          ; nothing multicast
    (multiple-value-bind (m packet) (receive-message legacy)
      (is (= 99 (dns-message-id m)))
      (is (= 2 (length (dns-message-questions m))))
      (is (every (lambda (rec) (<= (dns-record-ttl rec) 10))
                 (append (dns-message-answers m) (dns-message-additionals m))))
      (is (notany #'dns-record-cache-flush-p
                  (append (dns-message-answers m) (dns-message-additionals m))))
      ;; "box.local" in full twice: the echoed question and the SRV target
      (let ((box (octets 3 98 111 120 5 108 111 99 97 108 0)))
        (is (= 2 (loop :for i := (search box packet) :then (search box packet :start2 (1+ i))
                       :while i :count t)))))))

(test known-answer-suppression
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query peer r (ptr-query "_matterc._udp.local"
                                  :known (list (record "_matterc._udp.local" +type-ptr+
                                                       *lamp-instance* :ttl 4000))))
    (responder-poll r)
    (is (null (receive-message peer)))
    (send-query peer r (ptr-query "_matterc._udp.local"
                                  :known (list (record "_matterc._udp.local" +type-ptr+
                                                       *lamp-instance* :ttl 100))))
    (responder-poll r)
    (is (receive-message peer))))

(test negative-answer-is-nsec
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query peer r (make-dns-message
                        :questions (list (make-dns-question :name "box.local" :type +type-txt+))))
    (responder-poll r)
    (let ((m (receive-message peer)))
      (is (= 1 (length (dns-message-answers m))))
      (is (= +type-nsec+ (dns-record-type (first (dns-message-answers m)))))
      (is (equal '(:next-name "box.local" :types (1 28))
                 (dns-record-data (first (dns-message-answers m))))))))

(test ignores-what-is-not-ours
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (send-query peer r (make-dns-message
                        :questions (list (make-dns-question :name "other.local" :type +type-a+)
                                         (make-dns-question :name "_http._tcp.local" :type +type-ptr+))))
    (responder-poll r)
    (is (null (receive-message peer)))
    ;; responses and junk are ignored too
    (send-query peer r (make-dns-message :flags +flag-response+
                                         :answers (list (record "box.local" +type-a+ "1.2.3.4"))))
    (cl-matter.net:send-to peer (octets 1 2 3) "127.0.0.1" (responder-port r))
    (responder-poll r)
    (responder-poll r)
    (is (null (receive-message peer)))))

(test goodbye-on-stop
  (with-responder-rig (r peer legacy)
    (receive-message peer)
    (stop-responder r)
    (is (not (responder-running-p r)))
    (let ((m (receive-message peer)))
      (is (= 10 (length (dns-message-answers m))))
      (is (every (lambda (rec) (zerop (dns-record-ttl rec))) (dns-message-answers m)))
      (is (notany #'dns-record-cache-flush-p (dns-message-answers m))))
    (is (stop-responder r))                     ; twice is harmless
    (is (null (receive-message peer)))))

(test probe-then-announce
  "Three probes with QU questions of type ANY and the unique records in
the authority section, then the announcement."
  (cl-matter.net:with-udp-socket (peer :address "127.0.0.1")
    (setf (cl-matter.net:socket-timeout peer) 0.4)
    (with-mdns-socket (rs :address "127.0.0.1" :multicast nil :group "127.0.0.1"
                          :port (nth-value 1 (cl-matter.net:socket-local-endpoint peer)))
      (let ((r (start-responder :socket rs :thread nil :host "box.local" :addresses '("10.0.0.9")
                                :services (list (lamp-service)))))
        (unwind-protect
             (progn
               (dotimes (i 3)
                 (let ((probe (receive-message peer)))
                   (is (not (dns-message-response-p probe)))
                   (is (equal (list (list "box.local" +type-any+) (list *lamp-instance* +type-any+))
                              (question-list probe)))
                   (is (every #'dns-question-unicast-response-p (dns-message-questions probe)))
                   (is (equal (list +type-a+ +type-nsec+ +type-srv+ +type-txt+ +type-nsec+)
                              (mapcar #'dns-record-type (dns-message-authorities probe))))))
               (let ((announcement (receive-message peer)))
                 (is (dns-message-response-p announcement))
                 (is (= 9 (length (dns-message-answers announcement))))))
          (stop-responder r))))))

(test probe-conflict-renames
  "A response claiming our instance name with other data renames the
instance; one claiming the host name renames the host."
  (cl-matter.net:with-udp-socket (peer :address "127.0.0.1")
    (setf (cl-matter.net:socket-timeout peer) 0.4)
    (with-mdns-socket (rs :address "127.0.0.1" :multicast nil :group "127.0.0.1"
                          :port (nth-value 1 (cl-matter.net:socket-local-endpoint peer)))
      (multiple-value-bind (address port)
          (cl-matter.net:socket-local-endpoint (mdns-socket-socket rs))
        (flet ((claim (&rest records)
                 (cl-matter.net:send-to
                  peer (encode-message (make-dns-message :flags +flag-response+ :answers records))
                  address port)))
          (claim (record *lamp-instance* +type-srv+ '(:priority 0 :weight 0 :port 1 :target "x.local")))
          (claim (record "box.local" +type-a+ "10.0.0.1"))
          ;; identical data is not a conflict (RFC 6762 section 8.1)
          (claim (record "box.local" +type-aaaa+ "fd00::9"))
          (let ((r (start-responder :socket rs :thread nil :host "box.local"
                                    :addresses '("10.0.0.9" "fd00::9")
                                    :services (list (lamp-service)))))
            (unwind-protect
                 (progn
                   (is (string= "Lamp (2)" (service-instance (first (responder-services r)))))
                   (is (string= "box-2.local" (responder-host r)))
                   (is (string= "Lamp (2)._matterc._udp.local"
                                (service-instance-name (first (responder-services r)))))
                   (is (equal '(:priority 0 :weight 0 :port 5540 :target "box-2.local")
                              (dns-record-data (first (records-like (responder-records r) +type-srv+))))))
              (stop-responder r))))))))

(test next-name
  (is (string= "Lamp (2)" (cl-matter.dns-sd::%next-name "Lamp" " (")))
  (is (string= "Lamp (3)" (cl-matter.dns-sd::%next-name "Lamp (2)" " (")))
  (is (string= "Lamp (10)" (cl-matter.dns-sd::%next-name "Lamp (9)" " (")))
  (is (string= "Lamp (x) (2)" (cl-matter.dns-sd::%next-name "Lamp (x)" " (")))
  (is (string= "box-2" (cl-matter.dns-sd::%next-name "box" "-")))
  (is (string= "box-3" (cl-matter.dns-sd::%next-name "box-2" "-")))
  (is (string= "my-box-2" (cl-matter.dns-sd::%next-name "my-box" "-"))))

(test responder-thread
  "With a thread the responder answers on its own."
  (cl-matter.net:with-udp-socket (peer :address "127.0.0.1")
    (setf (cl-matter.net:socket-timeout peer) 1)
    (with-mdns-socket (rs :address "127.0.0.1" :multicast nil :group "127.0.0.1"
                          :port (nth-value 1 (cl-matter.net:socket-local-endpoint peer)))
      (let ((r (start-responder :socket rs :probe nil :host "box.local" :addresses '("10.0.0.9")
                                :services (list (lamp-service)))))
        (is (responder-thread r))
        (receive-message peer)                  ; announcement
        (send-query peer r (ptr-query "_matterc._udp.local"))
        (let ((m (receive-message peer)))
          (is (and m (string= *lamp-instance* (dns-record-data (first (dns-message-answers m)))))))
        (stop-responder r)
        (is (null (responder-thread r)))
        (is (null (responder-last-error r)))
        (is (receive-message peer))))))        ; the goodbye

(test default-addresses
  "No zone identifiers, no link-local IPv6; without any address the
responder refuses to start."
  (let ((addresses (cl-matter.dns-sd::%default-addresses)))
    (is (listp addresses))
    (is (every #'stringp addresses))
    (is (notany (lambda (a) (find #\% a)) addresses))
    (is (notany #'cl-matter.dns-sd::%link-local-p addresses))
    (when (null addresses)
      (with-mdns-socket (rs :address "127.0.0.1" :multicast nil)
        (signals cl-matter.net:net-error
          (start-responder :socket rs :probe nil :thread nil :host "box.local")))))
  (is (cl-matter.dns-sd::%link-local-p "fe80::1%en0"))
  (is (cl-matter.dns-sd::%link-local-p "FEBF::1"))
  (is (not (cl-matter.dns-sd::%link-local-p "fec0::1")))
  (is (not (cl-matter.dns-sd::%link-local-p "::1")))
  (is (not (cl-matter.dns-sd::%link-local-p "192.168.1.1"))))

;;; ------------------------------------------------------------------
;;; Changing the services while running

(test responder-set-services-announces-and-withdraws
  "A new service is announced (twice, a second apart), a removed one gets
goodbyes; the host's records and the other service's stay."
  (with-responder-rig (r peer legacy)
    (receive-message peer)                                    ; the start announcement ...
    (sleep 1.05)
    (responder-poll r :timeout 0)
    (receive-message peer)                                    ; ... and its repeat
    (let* ((before (responder-records r))
           (printer (make-service :instance "Printer" :type "_ipp._tcp" :port 631 :txt '("rp=/")))
           (printer-name "Printer._ipp._tcp.local"))
      ;; add one
      (let ((after (responder-set-services r (list (lamp-service) printer))))
        (is (eq after (responder-records r)))
        (is (= (+ (length before) 5) (length after)))         ; enumeration PTR, type PTR, SRV, TXT, NSEC
        (is (every (lambda (old) (find old after :test #'dns-sd::%same-record-p)) before))
        (let ((announcement (receive-message peer)))
          (is (dns-message-response-p announcement))
          (is (= 5 (length (dns-message-answers announcement))))
          (is (every (lambda (a) (or (string-equal printer-name (dns-record-name a))
                                     (equal printer-name (dns-record-data a))
                                     (equal "_ipp._tcp.local" (dns-record-data a))))
                     (dns-message-answers announcement)))
          (is (every (lambda (a) (plusp (dns-record-ttl a))) (dns-message-answers announcement)))
          (is (equal '(:priority 0 :weight 0 :port 631 :target "box.local")
                     (dns-record-data (first (records-like (dns-message-answers announcement) +type-srv+ printer-name))))))
        (is (null (receive-message peer)))                    ; the repeat is not due yet
        (sleep 1.05)
        (responder-poll r :timeout 0)
        (let ((again (receive-message peer)))
          (is (and again (= 5 (length (dns-message-answers again)))))))
      ;; it answers for the new name
      (send-query peer r (ptr-query "_ipp._tcp.local"))
      (responder-poll r)
      (let ((response (receive-message peer)))
        (is (equal (list printer-name) (mapcar #'dns-record-data (records-like (dns-message-answers response) +type-ptr+)))))
      ;; take the lamp away
      (let ((after (responder-set-services r (list printer))))
        (is (= 8 (length after)))                             ; 3 host + 5 printer (incl. its enumeration PTR)
        (is (null (records-like after +type-ptr+ "_matterc._udp.local")))
        (let ((goodbye (receive-message peer)))
          (is (= (- (length before) 3) (length (dns-message-answers goodbye))))
          (is (every (lambda (a) (zerop (dns-record-ttl a))) (dns-message-answers goodbye)))
          (is (notany (lambda (a) (string-equal "box.local" (dns-record-name a))) (dns-message-answers goodbye))))
        (is (null (receive-message peer))))
      ;; the lamp is no longer answered for
      (send-query peer r (ptr-query "_matterc._udp.local"))
      (responder-poll r)
      (is (null (receive-message peer)))
      ;; the same set again changes nothing on the wire
      (responder-set-services r (list printer))
      (is (null (receive-message peer))))))
