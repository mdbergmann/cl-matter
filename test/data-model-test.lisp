(defpackage :cl-matter.data-model.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.data-model.tests)

(def-suite data-model-tests :description "Interaction Model codec, data model types, clusters and nodes"
  :in cl-matter.tests:test-suite)
(in-suite data-model-tests)

(defun octets (&rest values)
  (coerce values '(vector (unsigned-byte 8))))

(defun roundtrip (message)
  "Encode MESSAGE and decode it again; the decoded struct."
  (multiple-value-bind (opcode payload) (encode-interaction-message message)
    (multiple-value-bind (back revision) (decode-interaction-message opcode payload)
      (is (= *interaction-model-revision* revision))
      back)))

;;; ------------------------------------------------------------------
;;; Types

(test type-roundtrips
  (flet ((rt (type value &optional (expected value))
           (let ((element (value-tlv type 7 value)))
             (is (= 7 (tlv-element-tag element)))
             (is (equalp expected (tlv-value type (tlv-decode (tlv-encode element))))))))
    (rt :bool t) (rt :bool nil)
    (rt :uint8 255) (rt :uint16 65535) (rt :uint32 #xFFFFFFFF) (rt :uint64 (1- (ash 1 64)))
    (rt :int8 -128) (rt :int16 -1) (rt :int32 (- (ash 1 31))) (rt :int64 (1- (ash 1 63)))
    (rt :uint24 #xFFFFFF) (rt :int40 (- (ash 1 39)))
    (rt :enum8 3) (rt :bitmap32 #x80000001) (rt :vendor-id #xFFF1) (rt :node-id #x1122334455667788)
    (rt :temperature -2750) (rt :single 1.5) (rt :double 2.5d0)
    (rt :string "Lamp") (rt '(:string 4) "Lamp")
    (rt :octets (octets 1 2 3)) (rt '(:octets 3) (octets 1 2 3))
    (rt '(:nullable :uint8) :null) (rt '(:nullable :uint8) 7)
    (rt '(:list :uint16) '(1 2 3)) (rt '(:list :uint16) '())
    (rt '(:list (:nullable :bool)) '(t :null nil))
    (rt '(:struct (0 :a :uint8) (1 :b (:string 8))) '(:a 1 :b "x"))
    (rt '(:struct (0 :a :uint8) (1 :b :uint8 :optional)) '(:a 1))
    (rt '(:list (:struct (0 :device-type :devtype-id) (1 :revision :uint16)))
        '((:device-type #x100 :revision 2) (:device-type 22 :revision 1)))))

(test type-aliases
  (is (eq :uint16 (resolve-type :vendor-id)))
  (is (eq :uint8 (resolve-type :enum8)))
  (is (eq :float (resolve-type :single)))
  (is (eq :uint8 (resolve-type :uint8)))
  (is (equal '(:list :uint8) (resolve-type '(:list :uint8)))))

(defun status-of (thunk)
  (handler-case (progn (funcall thunk) nil)
    (interaction-error (e) (im-status-name (interaction-error-status e)))))

(test type-constraints
  ;; out of range: CONSTRAINT_ERROR
  (is (eq :constraint-error (status-of (lambda () (value-tlv :uint8 nil 256)))))
  (is (eq :constraint-error (status-of (lambda () (value-tlv :uint8 nil -1)))))
  (is (eq :constraint-error (status-of (lambda () (value-tlv :int8 nil 128)))))
  (is (eq :constraint-error (status-of (lambda () (value-tlv '(:string 2) nil "abc")))))
  (is (eq :constraint-error (status-of (lambda () (value-tlv '(:octets 1) nil (octets 1 2))))))
  (is (eq :constraint-error (status-of (lambda () (value-tlv '(:struct (0 :a :uint8)) nil '())))))
  ;; wrong kind of value: INVALID_DATA_TYPE
  (is (eq :invalid-data-type (status-of (lambda () (value-tlv :uint8 nil "1")))))
  (is (eq :invalid-data-type (status-of (lambda () (value-tlv :bool nil 1)))))
  (is (eq :invalid-data-type (status-of (lambda () (value-tlv :string nil 1)))))
  (is (eq :invalid-data-type (status-of (lambda () (value-tlv '(:list :uint8) nil 1)))))
  ;; the same from the wire
  (is (eq :constraint-error (status-of (lambda () (tlv-value :uint8 (tlv nil :unsigned 256))))))
  (is (eq :invalid-data-type (status-of (lambda () (tlv-value :uint8 (tlv nil :string "1"))))))
  (is (eq :invalid-data-type (status-of (lambda () (tlv-value :bool (tlv nil :unsigned 1))))))
  (is (eq :constraint-error (status-of (lambda () (tlv-value :uint8 (tlv nil :null))))))
  (is (eq :invalid-data-type (status-of (lambda () (tlv-value '(:nullable :uint8) (tlv nil :string "x"))))))
  (is (eq :constraint-error (status-of (lambda () (tlv-value '(:string 2) (tlv nil :string "abc"))))))
  (is (eq :constraint-error (status-of (lambda () (tlv-value '(:struct (0 :a :uint8)) (tlv nil :structure '()))))))
  ;; a signed type takes an unsigned element of the right value
  (is (= 5 (tlv-value :int16 (tlv nil :unsigned 5))))
  (is (eq :constraint-error (status-of (lambda () (tlv-value :int8 (tlv nil :unsigned 200))))))
  ;; unknown fields in a structure are ignored
  (is (equal '(:a 1) (tlv-value '(:struct (0 :a :uint8)) (tlv nil :structure (list (tlv 0 :unsigned 1) (tlv 9 :string "?")))))))

;;; ------------------------------------------------------------------
;;; Codec

(test im-status-names
  (is (eq :unsupported-attribute (im-status-name #x86)))
  (is (= #x86 (im-status-code :unsupported-attribute)))
  (is (= #x86 (im-status-code #x86)))
  (is (= 250 (im-status-name 250)))
  (signals error (im-status-code :no-such-status))
  (is (im-status-success-p (im-status :success)))
  (is (not (im-status-success-p (im-status :failure 7))))
  (is (= 7 (im-status-cluster-status (im-status :failure 7)))))

(test read-request-bytes
  "A read of Basic Information's NodeLabel, octet by octet."
  (multiple-value-bind (opcode payload)
      (encode-interaction-message (make-read-request :attribute-requests (list (attribute-path 0 #x28 5))))
    (is (= +opcode-im-read-request+ opcode))
    (is (equalp (octets #x15 #x36 #x00 #x17 #x24 #x02 #x00 #x24 #x03 #x28 #x24 #x04 #x05 #x18 #x18
                        #x28 #x03 #x24 #xFF #x0B #x18)
                payload))))

(test attribute-paths
  (let ((p (attribute-path 1 6 0)))
    (is (attribute-path-concrete-p p))
    (is (not (attribute-path-concrete-p (attribute-path nil 6 0))))
    (is (attribute-path-matches-p (attribute-path nil nil nil) p))
    (is (attribute-path-matches-p (attribute-path 1 nil nil) p))
    (is (attribute-path-matches-p (attribute-path nil 6 0) p))
    (is (not (attribute-path-matches-p (attribute-path 2 nil nil) p)))
    (is (not (attribute-path-matches-p (attribute-path 1 6 1) p)))
    (is (equalp p (tlv-attribute-path (tlv-decode (tlv-encode (attribute-path-tlv nil p))))))
    (let ((w (make-attribute-path :node #x1234 :endpoint 1 :cluster 6 :attribute 2 :list-index :null :tag-compression t)))
      (is (equalp w (tlv-attribute-path (tlv-decode (tlv-encode (attribute-path-tlv nil w)))))))
    (let ((w (attribute-path 1 6 2 :list-index 3)))
      (is (equalp w (tlv-attribute-path (tlv-decode (tlv-encode (attribute-path-tlv nil w))))))))
  (let ((c (command-path 1 6 2)))
    (is (equalp c (tlv-command-path (tlv-decode (tlv-encode (command-path-tlv nil c))))))
    ;; the command path needs cluster and command
    (signals interaction-error (tlv-command-path (tlv nil :list (list (tlv 0 :unsigned 1))))))
  ;; a path that is not a list
  (signals interaction-error (tlv-attribute-path (tlv nil :structure (list (tlv 2 :unsigned 1)))))
  ;; too wide
  (signals interaction-error (tlv-attribute-path (tlv nil :list (list (tlv 2 :unsigned 70000))))))

(test message-roundtrips
  (let ((paths (list (attribute-path 0 #x1D 1) (attribute-path nil nil nil) (attribute-path 1 6 0 :node 99))))
    (let ((m (roundtrip (make-read-request :attribute-requests paths :fabric-filtered t
                                           :event-requests (list (make-event-path :endpoint 1 :cluster 6 :urgent t))
                                           :event-filters (list (make-event-filter :event-min 12))
                                           :data-version-filters
                                           (list (make-data-version-filter :path (make-cluster-path :endpoint 0 :cluster #x1D)
                                                                           :data-version 77))))))
      (is (equalp paths (read-request-attribute-requests m)))
      (is (read-request-fabric-filtered m))
      (is (= 6 (event-path-cluster (first (read-request-event-requests m)))))
      (is (event-path-urgent (first (read-request-event-requests m))))
      (is (= 12 (event-filter-event-min (first (read-request-event-filters m)))))
      (is (= 77 (data-version-filter-data-version (first (read-request-data-version-filters m)))))
      (is (= #x1D (cluster-path-cluster (data-version-filter-path (first (read-request-data-version-filters m)))))))
    (let ((m (roundtrip (make-report-data
                         :subscription-id #xDEADBEEF
                         :attribute-reports
                         (list (make-attribute-report
                                :data (make-attribute-data :data-version 5 :path (attribute-path 1 6 0)
                                                           :data (tlv 99 :boolean t)))
                               (make-attribute-report
                                :status (make-attribute-status :path (attribute-path 1 6 9)
                                                               :status (im-status :unsupported-attribute))))
                         :event-reports (list (make-event-report
                                               :data (make-event-data :path (make-event-path :endpoint 1 :cluster 6 :event 0)
                                                                      :event-number 3 :priority 1 :epoch-timestamp 1700000000000
                                                                      :data (tlv nil :structure (list (tlv 0 :unsigned 1)))))
                                              (make-event-report
                                               :status (make-event-status :path (make-event-path :endpoint 2)
                                                                          :status (im-status :unsupported-endpoint))))
                         :more-chunked-messages t))))
      (is (= #xDEADBEEF (report-data-subscription-id m)))
      (is (report-data-more-chunked-messages m))
      (is (not (report-data-suppress-response m)))
      (let ((data (attribute-report-data (first (report-data-attribute-reports m)))))
        (is (= 5 (attribute-data-data-version data)))
        (is (equalp (attribute-path 1 6 0) (attribute-data-path data)))
        (is (eq t (tlv-element-value (attribute-data-data data))))
        (is (= 2 (tlv-element-tag (attribute-data-data data)))))  ; retagged on the wire
      (is (eq :unsupported-attribute
              (im-status-name (im-status-status (attribute-status-status (attribute-report-status (second (report-data-attribute-reports m))))))))
      (let ((event (event-report-data (first (report-data-event-reports m)))))
        (is (= 3 (event-data-event-number event)))
        (is (= 1700000000000 (event-data-epoch-timestamp event)))
        (is (null (event-data-system-timestamp event)))
        (is (= 1 (tlv-get (event-data-data event) 0))))
      (is (= 2 (event-path-endpoint (event-status-path (event-report-status (second (report-data-event-reports m))))))))
    (let ((m (roundtrip (make-subscribe-request :keep-subscriptions t :min-interval-floor 2 :max-interval-ceiling 60
                                                :attribute-requests paths :fabric-filtered nil))))
      (is (subscribe-request-keep-subscriptions m))
      (is (= 2 (subscribe-request-min-interval-floor m)))
      (is (= 60 (subscribe-request-max-interval-ceiling m)))
      (is (equalp paths (subscribe-request-attribute-requests m)))
      (is (not (subscribe-request-fabric-filtered m))))
    (let ((m (roundtrip (make-subscribe-response :subscription-id 7 :max-interval 50))))
      (is (= 7 (subscribe-response-subscription-id m)))
      (is (= 50 (subscribe-response-max-interval m))))
    (let ((m (roundtrip (make-write-request :timed-request t
                                            :write-requests (list (make-attribute-data :path (attribute-path 0 #x28 5)
                                                                                       :data (tlv nil :string "Lamp"))
                                                                  (make-attribute-data :path (attribute-path 0 #x1F 0 :list-index :null)
                                                                                       :data-version 3
                                                                                       :data (tlv nil :structure '())))))))
      (is (write-request-timed-request m))
      (is (not (write-request-suppress-response m)))
      (is (= 2 (length (write-request-write-requests m))))
      (is (string= "Lamp" (tlv-element-value (attribute-data-data (first (write-request-write-requests m))))))
      (is (eq :null (attribute-path-list-index (attribute-data-path (second (write-request-write-requests m))))))
      (is (= 3 (attribute-data-data-version (second (write-request-write-requests m))))))
    (let ((m (roundtrip (make-write-response :write-responses (list (make-attribute-status :path (attribute-path 0 #x28 5)
                                                                                           :status (im-status :success)))))))
      (is (im-status-success-p (attribute-status-status (first (write-response-write-responses m))))))
    (let ((m (roundtrip (make-invoke-request :suppress-response t
                                             :invoke-requests (list (make-command-data :path (command-path 1 6 2) :ref 4)
                                                                    (make-command-data :path (command-path 1 3 0)
                                                                                       :fields (tlv nil :structure (list (tlv 0 :unsigned 10)))))))))
      (is (invoke-request-suppress-response m))
      (is (not (invoke-request-timed-request m)))
      (is (= 4 (command-data-ref (first (invoke-request-invoke-requests m)))))
      (is (null (command-data-fields (first (invoke-request-invoke-requests m)))))
      (is (= 10 (tlv-get (command-data-fields (second (invoke-request-invoke-requests m))) 0))))
    (let ((m (roundtrip (make-invoke-response-message
                         :invoke-responses (list (make-invoke-response
                                                  :command (make-command-data :path (command-path 1 3 1)
                                                                              :fields (tlv nil :structure (list (tlv 0 :unsigned 1)))))
                                                 (make-invoke-response
                                                  :status (make-command-status :path (command-path 1 6 9)
                                                                               :status (im-status :unsupported-command) :ref 2)))))))
      (is (= 1 (command-path-command (invoke-response-path (first (invoke-response-message-invoke-responses m))))))
      (is (= 9 (command-path-command (invoke-response-path (second (invoke-response-message-invoke-responses m))))))
      (is (= 2 (command-status-ref (invoke-response-status (second (invoke-response-message-invoke-responses m)))))))
    (let ((m (roundtrip (make-timed-request :timeout 5000))))
      (is (= 5000 (timed-request-timeout m))))
    (let ((m (roundtrip (make-status-response :status :busy))))
      (is (= +im-status-busy+ (status-response-status m))))))

(test codec-rejects
  (flet ((bad (opcode payload) (status-of (lambda () (decode-interaction-message opcode payload)))))
    ;; not a structure, trailing octets, unknown opcode
    (is (eq :invalid-action (bad +opcode-im-status-response+ (tlv-encode (tlv nil :unsigned 1)))))
    (is (eq :invalid-action (bad +opcode-im-status-response+
                                 (concatenate '(vector (unsigned-byte 8))
                                              (nth-value 1 (encode-interaction-message (make-status-response))) (octets 0)))))
    (is (eq :invalid-action (bad #x7F (nth-value 1 (encode-interaction-message (make-status-response))))))
    ;; a mandatory field missing
    (is (eq :invalid-action (bad +opcode-im-status-response+ (tlv-encode (tlv nil :structure '())))))
    (is (eq :invalid-action (bad +opcode-im-write-request+ (tlv-encode (tlv nil :structure (list (tlv 1 :boolean nil)))))))
    ;; a report with both or neither of status and data
    (is (eq :invalid-action (bad +opcode-im-report-data+
                                 (tlv-encode (tlv nil :structure (list (tlv 1 :array (list (tlv nil :structure '())))))))))
    ;; the revision is optional
    (is (null (nth-value 1 (decode-interaction-message +opcode-im-status-response+
                                                       (tlv-encode (tlv nil :structure (list (tlv 0 :unsigned 0))))))))
    ;; encoding checks widths
    (signals interaction-error (encode-interaction-message (make-timed-request :timeout 70000)))
    (signals interaction-error (encode-interaction-message (make-subscribe-response :subscription-id (ash 1 32))))
    (signals error (encode-interaction-message (make-status-response :status :not-a-status)))))

;;; ------------------------------------------------------------------
;;; Clusters

(define-cluster test-echo (#xFC01 :revision 1)
  (:attributes
   (counter 0 :uint32 :default 0)
   (names 1 (:list (:string 16)) :default '() :writable t)
   (big 2 (:list (:string 100)) :default '() :writable t)
   (maybe 3 (:nullable :int16) :default :null :writable t :optional t))
  (:commands
   (echo 0 :fields ((0 :text (:string 32)) (1 :times :uint8 :optional)) :response echo-response)
   (echo-response 1 :generated t :fields ((0 :text (:string 64)) (1 :length :uint16)))
   (fail 2)
   (timed-only 3 :timed t)))

(defun echo-handler (cluster fields)
  (declare (ignore cluster))
  (let ((text (apply #'concatenate 'string
                     (loop :repeat (or (getf fields :times) 1) :collect (getf fields :text)))))
    (list :text text :length (length text))))

(defun make-echo-cluster ()
  (make-cluster 'test-echo :names '("a" "b")
                           :handlers (list (cons 'echo #'echo-handler)
                                           (cons 'fail (lambda (c f) (declare (ignore c f)) (im-status :failure 42)))
                                           (cons 'timed-only (lambda (c f) (declare (ignore c f)) nil)))))

(test cluster-definitions
  (let ((d (find-cluster-definition 'on-off)))
    (is (eq d (find-cluster-definition +cluster-on-off+)))
    (is (eq d (find-cluster-definition "ON-OFF")))
    (is (= 6 (cluster-definition-revision d)))
    (is (= 0 (attribute-definition-id (find-attribute-definition d 'on-off))))
    (is (eq :bool (attribute-definition-type (find-attribute-definition d 0))))
    (is (attribute-definition-writable (find-attribute-definition d 'on-time)))
    (is (not (attribute-definition-writable (find-attribute-definition d 'on-off))))
    (is (= 2 (command-definition-id (find-command-definition d 'toggle))))
    (is (null (find-command-definition d 'no-such))))
  (is (null (find-cluster-definition #xFFFF nil)))
  (signals error (find-cluster-definition #xFFFF))
  (let ((d (find-cluster-definition 'test-echo)))
    (is (command-definition-generated (find-command-definition d 'echo-response)))
    (is (eq 'echo-response (command-definition-response (find-command-definition d 'echo))))
    (is (command-definition-timed (find-command-definition d 'timed-only)))))

(test cluster-instances
  (let ((c (make-on-off-cluster)))
    (is (= +cluster-on-off+ (cluster-id c)))
    (is (string= "ON-OFF" (symbol-name (cluster-name c))))
    (is (= 6 (cluster-revision c)))
    (is (eq nil (attribute-value c 'on-off)))
    (is (eq nil (attribute-value c 0)))
    (is (= 6 (attribute-value c 'cluster-revision)))
    (is (= 0 (attribute-value c 'feature-map)))
    ;; the optional attributes are not there
    (is (not (attribute-present-p c 'on-time)))
    (is (eq :unsupported-attribute (status-of (lambda () (attribute-value c 'on-time)))))
    (is (eq :unsupported-attribute (status-of (lambda () (attribute-value c 'no-such)))))
    (is (equal (list 0 #xFFF8 #xFFF9 #xFFFB #xFFFC #xFFFD) (cluster-attribute-ids c)))
    (is (equal '(0 1 2) (cluster-accepted-command-ids c)))
    (is (equal '() (cluster-generated-command-ids c)))
    ;; setting bumps the data version and checks the type
    (let ((v (cluster-data-version c)))
      (setf (attribute-value c 'on-off) t)
      (is (eq t (attribute-value c 'on-off)))
      (is (= (logand #xFFFFFFFF (1+ v)) (cluster-data-version c)))
      (is (eq :invalid-data-type (status-of (lambda () (setf (attribute-value c 'on-off) 1)))))
      (is (eq t (attribute-value c 'on-off)))
      (is (eq :unsupported-write (status-of (lambda () (setf (attribute-value c 'feature-map) 1))))))
    ;; an optional attribute given a value is present
    (let ((c2 (make-cluster 'on-off :on-time 5 :feature-map 1)))
      (is (attribute-present-p c2 'on-time))
      (is (= 5 (attribute-value c2 'on-time)))
      (is (= 1 (attribute-value c2 'feature-map)))
      (is (member #x4001 (cluster-attribute-ids c2)))
      (is (equal '() (cluster-accepted-command-ids c2))))
    (signals error (make-cluster 'on-off :no-such 1))
    (signals error (make-cluster 'no-such-cluster)))
  (let ((c (make-echo-cluster)))
    (is (equal '(0 2 3) (cluster-accepted-command-ids c)))
    (is (equal '(1) (cluster-generated-command-ids c)))
    (signals error (setf (command-handler c 'echo-response) #'echo-handler))
    (signals error (setf (command-handler c 'no-such) #'echo-handler))
    (setf (command-handler c 'fail) nil)
    (is (equal '(0 3) (cluster-accepted-command-ids c)))))

(test cluster-read-write
  (let ((c (make-cluster 'basic-information :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp"
                                            :serial-number "0001")))
    (is (equalp (tlv nil :string "ACME") (read-attribute c 1)))
    (is (equalp (tlv nil :unsigned 17) (read-attribute c 0)))
    (is (equalp (tlv nil :string "0001") (read-attribute c 15)))
    (is (eq :unsupported-attribute (status-of (lambda () (read-attribute c 11)))))
    (is (eq :unsupported-attribute (status-of (lambda () (read-attribute c 200)))))
    ;; the capability minima structure
    (let ((minima (read-attribute c 19)))
      (is (eq :structure (tlv-element-type minima)))
      (is (= 3 (tlv-get minima 0))))
    ;; peer writes
    (is (string= "Lamp 1" (write-attribute c 5 (tlv nil :string "Lamp 1"))))
    (is (string= "Lamp 1" (attribute-value c 'node-label)))
    (is (eq :constraint-error (status-of (lambda () (write-attribute c 6 (tlv nil :string "DEU"))))))
    (is (eq :invalid-data-type (status-of (lambda () (write-attribute c 5 (tlv nil :unsigned 1))))))
    (is (eq :unsupported-write (status-of (lambda () (write-attribute c 1 (tlv nil :string "x"))))))
    (is (eq :unsupported-write (status-of (lambda () (write-attribute c +attribute-feature-map+ (tlv nil :unsigned 1))))))
    (is (eq :unsupported-attribute (status-of (lambda () (write-attribute c 16 (tlv nil :boolean t))))))
    (is (eq :unsupported-attribute (status-of (lambda () (write-attribute c 200 (tlv nil :boolean t)))))))
  (let ((c (make-echo-cluster)))
    ;; whole list, append, replace one, index out of range, not a list
    (is (equal '("x") (write-attribute c 1 (tlv nil :array (list (tlv nil :string "x"))))))
    (is (equal '("x" "y") (write-attribute c 1 (tlv nil :string "y") :list-index :null)))
    (is (equal '("z" "y") (write-attribute c 1 (tlv nil :string "z") :list-index 0)))
    (is (eq :constraint-error (status-of (lambda () (write-attribute c 1 (tlv nil :string "w") :list-index 5)))))
    (is (eq :constraint-error (status-of (lambda () (write-attribute c 1 (tlv nil :string "a-string-too-long") :list-index :null)))))
    (is (eq :unsupported-write (status-of (lambda () (write-attribute c 0 (tlv nil :unsigned 1) :list-index :null)))))
    (is (equal '("z" "y") (attribute-value c 'names)))))

(test cluster-commands
  (let* ((changes '())
         (c (make-on-off-cluster :on-change (lambda (cluster state) (declare (ignore cluster)) (push state changes)))))
    (multiple-value-bind (response status) (invoke-cluster-command c 1 nil)
      (is (null response))
      (is (im-status-success-p status)))
    (is (eq t (attribute-value c 'on-off)))
    (invoke-cluster-command c 1 nil)             ; already on: no change reported
    (invoke-cluster-command c 2 nil)
    (is (eq nil (attribute-value c 'on-off)))
    (invoke-cluster-command c 2 (tlv nil :structure '()))  ; empty fields are fine
    (is (equal '(t nil t) (reverse changes)))
    (is (eq :invalid-command (status-of (lambda () (invoke-cluster-command c 2 (tlv nil :structure (list (tlv 0 :unsigned 1))))))))
    (is (eq :unsupported-command (status-of (lambda () (invoke-cluster-command c 9 nil)))))
    (is (eq :unsupported-command (status-of (lambda () (invoke-cluster-command c #x40 nil))))))
  (let ((c (make-echo-cluster)))
    (multiple-value-bind (response fields)
        (invoke-cluster-command c 0 (tlv nil :structure (list (tlv 0 :string "ab") (tlv 1 :unsigned 3))))
      (is (= 1 response))
      (is (string= "ababab" (tlv-get fields 0)))
      (is (= 6 (tlv-get fields 1))))
    (multiple-value-bind (response fields) (invoke-cluster-command c 0 (tlv nil :structure (list (tlv 0 :string "x"))))
      (is (= 1 response))
      (is (= 1 (tlv-get fields 1))))
    (is (eq :invalid-command (status-of (lambda () (invoke-cluster-command c 0 nil)))))
    (is (eq :invalid-command (status-of (lambda () (invoke-cluster-command c 0 (tlv nil :structure (list (tlv 0 :unsigned 1))))))))
    (is (eq :unsupported-command (status-of (lambda () (invoke-cluster-command c 1 nil)))))  ; the response itself
    (multiple-value-bind (response status) (invoke-cluster-command c 2 nil)
      (is (null response))
      (is (= +im-status-failure+ (im-status-status status)))
      (is (= 42 (im-status-cluster-status status))))
    (is (eq nil (invoke-cluster-command c 3 nil))))
  (let ((c (make-identify-cluster :identify-type 2)))
    (is (= 2 (attribute-value c 'identify-type)))
    (invoke-cluster-command c 0 (tlv nil :structure (list (tlv 0 :unsigned 15))))
    (is (= 15 (attribute-value c 'identify-time)))))

(test nodes-and-endpoints
  (let* ((light (make-on-off-cluster))
         (node (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id 1
                                :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                                  :clusters (list (make-identify-cluster) light)))))
         (root (find-endpoint node 0))
         (ep1 (find-endpoint node 1)))
    (is (= 2 (length (node-endpoints node))))
    (is (eq node (endpoint-node ep1)))
    (is (eq ep1 (cluster-endpoint light)))
    (is (eq light (find-cluster ep1 'on-off)))
    (is (eq light (node-cluster node 1 +cluster-on-off+)))
    (is (null (node-cluster node 2 +cluster-on-off+)))
    (is (null (find-cluster ep1 'basic-information)))
    (is (string= "ACME" (attribute-value (find-cluster root 'basic-information) 'vendor-name)))
    ;; descriptors
    (let ((d0 (find-cluster root 'descriptor)) (d1 (find-cluster ep1 'descriptor)))
      (is (equal (list (list :device-type +device-type-root-node+ :revision 3)) (attribute-value d0 'device-type-list)))
      (is (equal (list +cluster-descriptor+ +cluster-basic-information+) (attribute-value d0 'server-list)))
      (is (equal '(1) (attribute-value d0 'parts-list)))
      (is (equal '() (attribute-value d0 'client-list)))
      (is (equal (list (list :device-type +device-type-on-off-light+ :revision 3)) (attribute-value d1 'device-type-list)))
      (is (equal (list +cluster-descriptor+ +cluster-identify+ +cluster-on-off+) (attribute-value d1 'server-list)))
      (is (equal '() (attribute-value d1 'parts-list)))
      (is (equal '(0 1 2 3 #xFFF8 #xFFF9 #xFFFB #xFFFC #xFFFD) (cluster-attribute-ids d1)))
      (is (eq :unsupported-write (status-of (lambda () (write-attribute d1 3 (tlv nil :array '())))))))
    ;; listeners hear every change
    (let ((heard '()))
      (add-node-listener node (lambda (e c a) (push (list e c a) heard)))
      (setf (attribute-value light 'on-off) t)
      (invoke-cluster-command light 0 nil)
      (write-attribute (find-cluster root 'basic-information) 5 (tlv nil :string "x"))
      (is (equal (list (list 1 6 0) (list 1 6 0) (list 0 #x28 5)) (reverse heard))))
    (signals error (add-endpoint node (make-endpoint 1)))
    (signals error (add-cluster ep1 (make-on-off-cluster)))
    (add-endpoint node (make-endpoint 2 :descriptor nil))
    (is (equal '(1 2) (attribute-value (find-cluster root 'descriptor) 'parts-list)))
    (is (null (endpoint-clusters (find-endpoint node 2))))))
