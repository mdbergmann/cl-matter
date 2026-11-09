(defpackage :cl-matter.interaction.tests
  (:use :cl :fiveam :cl-matter)
  (:import-from :cl-matter.exchange.tests
                #:make-rig #:rig-a #:rig-b #:rig-clock #:rig-network #:rig-a-port #:rig-b-port
                #:pump #:run-rig #:advance #:clock-now #:secured-pair #:network-drop #:network-sent
                #:recorder #:events #:ascii #:with-udp-rig #:*salt* #:*passcode*)
  (:import-from :cl-matter.data-model.tests #:make-echo-cluster #:status-of))
(in-package :cl-matter.interaction.tests)

(def-suite interaction-tests :description "Read, Write, Invoke and Subscribe over exchanges"
  :in cl-matter.tests:test-suite)
(in-suite interaction-tests)

(defconstant +echo+ #xFC01)

;;; ------------------------------------------------------------------
;;; A light on B, a client on A

(defun light-node ()
  "(values node on-off-cluster): a root endpoint and an On/Off light with Identify and the test cluster."
  (let ((light (make-on-off-cluster)))
    (values (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id 1
                             :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                               :clusters (list (make-identify-cluster) light
                                                                               (make-echo-cluster)))))
            light)))

(defstruct (nr (:constructor %make-nr))
  "A node rig: RIG with the models A (client) and B (serving NODE)."
  rig a b node light sa sb)

(defun make-node-rig (&key trace (node-on-a nil))
  (let ((rig (make-rig :trace trace)))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (multiple-value-bind (node light) (light-node)
        (%make-nr :rig rig :node node :light light :sa sa :sb sb
                  :a (make-interaction-model (rig-a rig) :node (and node-on-a (light-node)))
                  :b (make-interaction-model (rig-b rig) :node node))))))

(defun complete (nr interaction &key (max-rounds 2000))
  "Run the rig until INTERACTION is done; its result, or its error signalled."
  (run-rig (nr-rig nr) (lambda () (not (interaction-running-p interaction))) :max-rounds max-rounds)
  (pump (nr-rig nr) :rounds 6)
  (cond ((interaction-running-p interaction) (error "~a did not finish" interaction))
        ((interaction-failed-p interaction) (error (interaction-condition interaction)))
        (t (interaction-result interaction))))

(defun read-one (nr path)
  (first (complete nr (start-read (nr-a nr) (nr-sa nr) (list path)))))

(defun report-status (report)
  (im-status-name (im-status-status (attribute-status-status (attribute-report-status report)))))

(defun light-on (nr) (attribute-value (nr-light nr) 'on-off))
(defun basic (nr) (node-cluster (nr-node nr) 0 +cluster-basic-information+))
(defun echo (nr) (node-cluster (nr-node nr) 1 +echo+))
(defun sent (nr) (network-sent (rig-network (nr-rig nr))))
(defun now (nr) (clock-now (rig-clock (nr-rig nr))))

(defun settle (nr &key (seconds 0.5d0))
  "Let SECONDS pass in small steps so acks go out and closing exchanges finish."
  (run-rig (nr-rig nr) (lambda () nil) :max-rounds (round seconds 0.05d0))
  (pump (nr-rig nr) :rounds 4))

(defun raw-exchange (nr opcode message-or-octets)
  "Send one Interaction Model message by hand on a new exchange from A;
returns the recorder's events cell."
  (multiple-value-bind (handler cell) (recorder)
    (let ((exchange (open-exchange (rig-a (nr-rig nr)) (nr-sa nr) +protocol-interaction-model+ :handler handler)))
      (exchange-send exchange opcode (if (%octets-p message-or-octets)
                                         message-or-octets
                                         (nth-value 1 (encode-interaction-message message-or-octets))))
      (values cell exchange))))

(defun %octets-p (x) (and (vectorp x) (not (stringp x))))

(defun received-status (cell)
  "The status name of the StatusResponse in the recorded events, or the message type."
  (let ((event (find :message (events cell) :key #'first)))
    (and event
         (let ((message (decode-interaction-message (second event) (third event))))
           (if (status-response-p message)
               (im-status-name (status-response-status message))
               (type-of message))))))

;;; ------------------------------------------------------------------
;;; Read

(test read-attributes-basic
  (let ((nr (make-node-rig)))
    (let* ((before (sent nr))
           (report (read-one nr (attribute-path 1 +cluster-on-off+ 0))))
      (is (equalp (attribute-path 1 6 0) (attribute-report-path report)))
      (multiple-value-bind (value known) (attribute-report-value report)
        (is (eq nil value))
        (is (eq t known)))
      (is (= (cluster-data-version (nr-light nr)) (attribute-data-data-version (attribute-report-data report))))
      ;; request, report (acking it), standalone ack of the report
      (is (= 3 (- (sent nr) before))))
    (setf (attribute-value (nr-light nr) 'on-off) t)
    (is (eq t (attribute-report-value (read-one nr (attribute-path 1 +cluster-on-off+ 0)))))
    ;; several paths, mixed clusters, in one read
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr)
                                            (list (attribute-path 0 +cluster-basic-information+ 1)
                                                  (attribute-path 0 +cluster-basic-information+ 2)
                                                  (attribute-path 1 +cluster-on-off+ +attribute-cluster-revision+)
                                                  (attribute-path 0 +cluster-descriptor+ 3))))))
      (is (= 4 (length reports)))
      (is (string= "ACME" (attribute-report-value (first reports))))
      (is (= #xFFF1 (attribute-report-value (second reports))))
      (is (= 6 (attribute-report-value (third reports))))
      (is (equal '(1) (attribute-report-value (fourth reports)))))
    ;; the test cluster is defined here too, so its values decode
    (is (= 0 (attribute-report-value (read-one nr (attribute-path 1 +echo+ 0)))))
    ;; an attribute of a cluster we do not define stays a TLV element
    (multiple-value-bind (value known)
        (attribute-report-value (make-attribute-report
                                 :data (make-attribute-data :path (attribute-path 1 #x9999 0) :data (tlv nil :unsigned 3))))
      (is (eq nil known))
      (is (tlv-element-p value))
      (is (= 3 (tlv-element-value value))))
    (is (null (interaction-model-subscriptions (nr-b nr))))
    (is (null (exchange-manager-exchanges (rig-a (nr-rig nr)))))
    (is (null (exchange-manager-exchanges (rig-b (nr-rig nr)))))))

(test read-wildcards
  (let* ((nr (make-node-rig))
         (expected (loop :for endpoint :in (node-endpoints (nr-node nr))
                         :sum (loop :for cluster :in (endpoint-clusters endpoint)
                                    :sum (length (cluster-attribute-ids cluster))))))
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil nil nil))))))
      (is (= expected (length reports)))
      (is (every #'attribute-report-data reports))
      (is (every (lambda (r) (attribute-path-concrete-p (attribute-report-path r))) reports)))
    (is (= 6 (length (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil +cluster-on-off+ nil)))))))
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil +cluster-descriptor+ 3))))))
      (is (= 2 (length reports)))
      (is (equal '(1) (attribute-report-value (first reports))))
      (is (equal '() (attribute-report-value (second reports)))))
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 1 nil +attribute-cluster-revision+))))))
      (is (= 4 (length reports))))
    ;; a wildcard that matches nothing is not an error
    (is (null (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 5 nil nil))))))
    (is (null (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil #x9999 nil))))))))

(test read-misses
  (let ((nr (make-node-rig)))
    (is (eq :unsupported-endpoint (report-status (read-one nr (attribute-path 5 +cluster-on-off+ 0)))))
    (is (eq :unsupported-cluster (report-status (read-one nr (attribute-path 1 #x9999 0)))))
    (is (eq :unsupported-attribute (report-status (read-one nr (attribute-path 1 +cluster-on-off+ 200)))))
    ;; an optional attribute the instance lacks
    (is (eq :unsupported-attribute (report-status (read-one nr (attribute-path 1 +cluster-on-off+ #x4001)))))
    (multiple-value-bind (value kind) (attribute-report-value (read-one nr (attribute-path 5 +cluster-on-off+ 0)))
      (is (eq :status kind))
      (is (= +im-status-unsupported-endpoint+ (im-status-status value))))
    ;; mixed hits and misses keep their order
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 9 1 1)
                                                                       (attribute-path 1 +cluster-on-off+ 0)
                                                                       (attribute-path 1 +cluster-on-off+ 9))))))
      (is (eq :unsupported-endpoint (report-status (first reports))))
      (is (attribute-report-data (second reports)))
      (is (eq :unsupported-attribute (report-status (third reports)))))
    ;; an empty read gets an empty report
    (is (null (complete nr (start-read (nr-a nr) (nr-sa nr) '()))))))

(test read-chunked
  (let* ((nr (make-node-rig))
         (whole (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil nil nil))))))
    (let ((*max-report-payload* 150))
      (let* ((before (sent nr))
             (reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path nil nil nil)))))
             (datagrams (- (sent nr) before)))
        (is (= (length whole) (length reports)))
        (is (equalp (mapcar #'attribute-report-path whole) (mapcar #'attribute-report-path reports)))
        (is (every (lambda (a b) (equalp (attribute-data-data (attribute-report-data a))
                                         (attribute-data-data (attribute-report-data b))))
                   whole reports))
        ;; several ReportData, each answered with a StatusResponse (and acks)
        (is (> datagrams 8))))
    ;; one attribute that does not fit a message at all
    (setf (attribute-value (echo nr) 'big) (loop :repeat 15 :collect (make-string 100 :initial-element #\x)))
    (is (eq :resource-exhausted (report-status (read-one nr (attribute-path 1 +echo+ 2)))))
    ;; the others around it still arrive
    (let ((reports (complete nr (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 1 +echo+ nil))))))
      (is (= 8 (length reports)))
      (is (= 1 (count-if #'attribute-report-status reports))))))

;;; A list that arrives in pieces (8.7.3.3), as real devices send their
;;; AttributeList, PartsList or Fabrics: the list, then one report per
;;; element with a list index.

(defun data-report (path element)
  (make-attribute-report :data (make-attribute-data :path path :data element)))

(test merge-chunked-reports-basics
  (let* ((parts (lambda (&optional index) (attribute-path 0 +cluster-descriptor+ 3 :list-index index)))
         (types (lambda (&optional index) (attribute-path 1 +cluster-descriptor+ 0 :list-index index)))
         (reports (list (data-report (funcall parts) (tlv-array nil (tlv nil :unsigned 1)))
                        (data-report (attribute-path 0 +cluster-basic-information+ 1) (tlv nil :string "ACME"))
                        (data-report (funcall parts :null) (tlv nil :unsigned 2))
                        (data-report (funcall types) (tlv-array nil))
                        (data-report (funcall parts :null) (tlv nil :unsigned 3))
                        (data-report (funcall types :null) (tlv-structure nil (tlv 0 :unsigned #x10A) (tlv 1 :unsigned 2)))
                        (data-report (funcall parts 0) (tlv nil :unsigned 9))))
         (merged (merge-chunked-reports reports)))
    (is (= 3 (length merged)))
    (is (equalp (list (funcall parts) (attribute-path 0 +cluster-basic-information+ 1) (funcall types))
                (mapcar #'attribute-report-path merged)))
    (is (equal '(9 2 3) (attribute-report-value (first merged))))
    (is (string= "ACME" (attribute-report-value (second merged))))
    (is (equal '((:device-type #x10A :revision 2)) (attribute-report-value (third merged))))
    ;; an element report decodes as one element, with or without a list to join
    (is (= 2 (attribute-report-value (data-report (funcall parts :null) (tlv nil :unsigned 2)))))
    (let ((orphan (merge-chunked-reports (list (data-report (funcall parts :null) (tlv nil :unsigned 2))))))
      (is (= 1 (length orphan)))
      (is (= 2 (attribute-report-value (first orphan)))))
    ;; a status report of the attribute is not a list to join
    (let ((status (make-attribute-report :status (make-attribute-status :path (funcall parts)
                                                                        :status (im-status :unsupported-access)))))
      (is (= 2 (length (merge-chunked-reports (list status (data-report (funcall parts :null) (tlv nil :unsigned 2))))))))
    ;; an index past the end is the server's error
    (signals interaction-error
      (merge-chunked-reports (list (data-report (funcall parts) (tlv-array nil))
                                   (data-report (funcall parts 3) (tlv nil :unsigned 9)))))
    (is (null (merge-chunked-reports '())))))

(test find-attribute-report-by-path
  (let ((reports (list (data-report (attribute-path 0 +cluster-basic-information+ 4) (tlv nil :unsigned 80))
                       (data-report (attribute-path 0 +cluster-basic-information+ 2) (tlv nil :unsigned #x130A)))))
    (is (= #x130A (attribute-report-value (find-attribute-report reports 0 +cluster-basic-information+ 2))))
    (is (= 80 (attribute-report-value (find-attribute-report reports 0 +cluster-basic-information+ 4))))
    (is (null (find-attribute-report reports 1 +cluster-basic-information+ 2)))))

(test read-chunked-list
  "A server that sends its PartsList in pieces over two ReportData messages."
  (let* ((rig (make-rig))
         (a (make-interaction-model (rig-a rig)))
         (parts (lambda (&optional index) (attribute-path 0 +cluster-descriptor+ 3 :list-index index)))
         (messages 0))
    (multiple-value-bind (sa sb) (secured-pair rig)
      (declare (ignore sb))
      (register-protocol-handler
       (rig-b rig) +protocol-interaction-model+
       (lambda (exchange event &rest data)
         (declare (ignore data))
         (when (eq event :message)
           (incf messages)
           (multiple-value-bind (opcode octets)
               (encode-interaction-message
                (if (= messages 1)      ; the ReadRequest: the list and its first extra element
                    (make-report-data :attribute-reports (list (data-report (funcall parts) (tlv-array nil (tlv nil :unsigned 1)))
                                                               (data-report (funcall parts :null) (tlv nil :unsigned 2)))
                                      :more-chunked-messages t)
                    ;; the StatusResponse to the first chunk: the rest
                    (make-report-data :attribute-reports (list (data-report (funcall parts :null) (tlv nil :unsigned 3))
                                                               (data-report (attribute-path 1 +cluster-on-off+ 0) (tlv nil :boolean t))))))
             (exchange-send exchange opcode octets))
           (when (= messages 2) (exchange-close exchange)))))
      (let ((interaction (start-read a sa (list (funcall parts) (attribute-path 1 +cluster-on-off+ 0)))))
        (run-rig rig (lambda () (not (interaction-running-p interaction))))
        (is (interaction-complete-p interaction))
        (let ((reports (interaction-result interaction)))
          (is (= 2 (length reports)))
          (is (equal '(1 2 3) (attribute-report-value (first reports))))
          (is (eq t (attribute-report-value (second reports)))))))))

(test read-data-version-filters
  (let* ((nr (make-node-rig))
         (version (cluster-data-version (nr-light nr)))
         (path (attribute-path 1 +cluster-on-off+ 0)))
    (flet ((filtered (version &optional (cluster +cluster-on-off+))
             (complete nr (start-read (nr-a nr) (nr-sa nr) (list path)
                                      :data-version-filters
                                      (list (make-data-version-filter :path (make-cluster-path :endpoint 1 :cluster cluster)
                                                                      :data-version version))))))
      (is (null (filtered version)))
      (is (= 1 (length (filtered (1+ version)))))
      (is (= 1 (length (filtered version +cluster-identify+))))
      (setf (attribute-value (nr-light nr) 'on-off) t)
      (is (= 1 (length (filtered version))))
      (is (null (filtered (cluster-data-version (nr-light nr))))))))

;;; ------------------------------------------------------------------
;;; Write

(test write-attributes-basic
  (let ((nr (make-node-rig)))
    (let ((statuses (complete nr (start-write (nr-a nr) (nr-sa nr)
                                              (list (attribute-write 0 +cluster-basic-information+ 5 "Lamp 1"))))))
      (is (= 1 (length statuses)))
      (is (im-status-success-p (attribute-status-status (first statuses))))
      (is (equalp (attribute-path 0 #x28 5) (attribute-status-path (first statuses))))
      (is (string= "Lamp 1" (attribute-value (basic nr) 'node-label))))
    ;; a TLV element instead of a Lisp value
    (complete nr (start-write (nr-a nr) (nr-sa nr) (list (attribute-write 0 +cluster-basic-information+ 5 (tlv nil :string "Lamp 2")))))
    (is (string= "Lamp 2" (attribute-value (basic nr) 'node-label)))
    ;; a batch with every kind of miss
    (let* ((version (cluster-data-version (basic nr)))
           (statuses (complete nr (start-write (nr-a nr) (nr-sa nr)
                                               (list (attribute-write 0 +cluster-basic-information+ 6 (tlv nil :string "DEU"))
                                                     (attribute-write 0 +cluster-basic-information+ 1 "x")
                                                     (attribute-write 9 +cluster-basic-information+ 5 "x")
                                                     (attribute-write 0 #x9999 5 (tlv nil :string "x"))
                                                     (attribute-write 0 +cluster-basic-information+ 200 (tlv nil :string "x"))
                                                     (attribute-write 0 +cluster-basic-information+ 5 (tlv nil :unsigned 1))
                                                     (attribute-write 0 +cluster-basic-information+ 5 "stale" :data-version (1+ version))
                                                     (attribute-write 0 +cluster-basic-information+ 6 "DE" :data-version version))))))
      (is (equal '(:constraint-error :unsupported-write :unsupported-endpoint :unsupported-cluster
                   :unsupported-attribute :invalid-data-type :data-version-mismatch :success)
                 (mapcar (lambda (s) (im-status-name (im-status-status (attribute-status-status s)))) statuses)))
      (is (string= "DE" (attribute-value (basic nr) 'location)))
      (is (string= "Lamp 2" (attribute-value (basic nr) 'node-label))))
    ;; appending to a list
    (let ((statuses (complete nr (start-write (nr-a nr) (nr-sa nr)
                                              (list (make-attribute-data :path (attribute-path 1 +echo+ 1 :list-index :null)
                                                                         :data (tlv nil :string "c")))))))
      (is (im-status-success-p (attribute-status-status (first statuses))))
      (is (equal '("a" "b" "c") (attribute-value (echo nr) 'names))))
    ;; a wildcard write path fails the whole request
    (is (eq :invalid-action (status-of (lambda () (complete nr (start-write (nr-a nr) (nr-sa nr)
                                                                            (list (make-attribute-data :path (attribute-path nil #x28 5)
                                                                                                       :data (tlv nil :string "x")))))))))
    (signals error (attribute-write 0 #x9999 5 "needs a TLV element"))
    ;; the client checks a Lisp value against the definition before sending
    (is (eq :constraint-error (status-of (lambda () (attribute-write 0 +cluster-basic-information+ 6 "DEU")))))))

;;; ------------------------------------------------------------------
;;; Invoke

(test invoke-commands
  (let* ((changes '())
         (nr (make-node-rig)))
    (setf (command-handler (nr-light nr) 'toggle)
          (let ((old (command-handler (nr-light nr) 'toggle)))
            (lambda (cluster fields) (push *interaction-session* changes) (funcall old cluster fields))))
    (let ((responses (complete nr (start-invoke (nr-a nr) (nr-sa nr) (command-path 1 +cluster-on-off+ 2) nil))))
      (is (= 1 (length responses)))
      (multiple-value-bind (value kind) (invoke-response-value (first responses))
        (is (eq :status kind))
        (is (im-status-success-p value)))
      (is (equalp (command-path 1 6 2) (invoke-response-path (first responses))))
      (is (eq t (light-on nr)))
      ;; the handler saw the session the command came in on
      (is (equal (list (nr-sb nr)) changes)))
    ;; a command with a response
    (let ((responses (complete nr (start-invoke (nr-a nr) (nr-sa nr) (command-path 1 +echo+ 0)
                                                (command-fields +echo+ 'echo '(:text "ab" :times 2))))))
      (multiple-value-bind (value known) (invoke-response-value (first responses))
        (is (eq t known))
        (is (equal '(:text "abab" :length 4) value)))
      (is (= 1 (command-path-command (invoke-response-path (first responses))))))
    ;; statuses
    (flet ((status (path &optional fields)
             (multiple-value-bind (value kind)
                 (invoke-response-value (first (complete nr (start-invoke (nr-a nr) (nr-sa nr) path fields))))
               (is (eq :status kind))
               (values (im-status-name (im-status-status value)) (im-status-cluster-status value)))))
      (is (eq :unsupported-command (status (command-path 1 +cluster-on-off+ 9))))
      (is (eq :unsupported-endpoint (status (command-path 7 +cluster-on-off+ 2))))
      (is (eq :unsupported-cluster (status (command-path 1 #x9999 2))))
      (is (eq :invalid-command (status (command-path 1 +echo+ 0))))
      (is (eq :needs-timed-interaction (status (command-path 1 +echo+ 3))))
      (multiple-value-bind (name cluster-status) (status (command-path 1 +echo+ 2))
        (is (eq :failure name))
        (is (= 42 cluster-status))))
    ;; MaxPathsPerInvoke is one
    (let ((cell (raw-exchange nr +opcode-im-invoke-request+
                              (make-invoke-request :invoke-requests (list (make-command-data :path (command-path 1 6 1))
                                                                          (make-command-data :path (command-path 1 6 0)))))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :invalid-action (received-status cell))))
    ;; unknown opcode and garbage
    (let ((cell (raw-exchange nr #x0F (make-status-response))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :invalid-action (received-status cell))))
    (let ((cell (raw-exchange nr +opcode-im-read-request+ (ascii "not tlv at all"))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :invalid-action (received-status cell))))
    (settle nr)
    (is (null (exchange-manager-exchanges (rig-b (nr-rig nr)))))))

;;; ------------------------------------------------------------------
;;; Timed interactions

(test timed-interactions
  (let ((nr (make-node-rig)))
    (let* ((before (sent nr))
           (statuses (complete nr (start-write (nr-a nr) (nr-sa nr)
                                               (list (attribute-write 0 +cluster-basic-information+ 5 "timed"))
                                               :timed 5))))
      (is (im-status-success-p (attribute-status-status (first statuses))))
      (is (string= "timed" (attribute-value (basic nr) 'node-label)))
      ;; timed request, status, write, response, ack
      (is (= 5 (- (sent nr) before))))
    (multiple-value-bind (value kind)
        (invoke-response-value (first (complete nr (start-invoke (nr-a nr) (nr-sa nr) (command-path 1 +echo+ 3) nil :timed 2))))
      (is (eq :status kind))
      (is (im-status-success-p value)))
    ;; a timed request that expires before the action
    (multiple-value-bind (cell exchange) (raw-exchange nr +opcode-im-timed-request+ (make-timed-request :timeout 100))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :success (received-status cell)))
      (advance (rig-clock (nr-rig nr)) 1)
      (pump (nr-rig nr) :rounds 2)
      (setf (car cell) nil)
      (exchange-send exchange +opcode-im-write-request+
                     (nth-value 1 (encode-interaction-message
                                   (make-write-request :timed-request t
                                                       :write-requests (list (attribute-write 0 #x28 5 "late"))))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :timeout (received-status cell)))
      (is (string= "timed" (attribute-value (basic nr) 'node-label))))
    ;; an untimed action after a timed request, and a timed flag without one
    (multiple-value-bind (cell exchange) (raw-exchange nr +opcode-im-timed-request+ (make-timed-request :timeout 5000))
      (pump (nr-rig nr) :rounds 4)
      (setf (car cell) nil)
      (exchange-send exchange +opcode-im-invoke-request+
                     (nth-value 1 (encode-interaction-message
                                   (make-invoke-request :invoke-requests (list (make-command-data :path (command-path 1 6 1)))))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :timed-request-mismatch (received-status cell)))
      (is (eq nil (light-on nr))))
    (let ((cell (raw-exchange nr +opcode-im-write-request+
                              (make-write-request :timed-request t
                                                  :write-requests (list (attribute-write 0 #x28 5 "x"))))))
      (pump (nr-rig nr) :rounds 4)
      (is (eq :timed-request-mismatch (received-status cell))))
    ;; a timed request nobody follows up expires the exchange on the server
    (settle nr)
    (is (= 0 (count-if-not #'exchange-initiator-p (exchange-manager-exchanges (rig-b (nr-rig nr))))))
    (raw-exchange nr +opcode-im-timed-request+ (make-timed-request :timeout 1000))
    (pump (nr-rig nr) :rounds 4)
    (is (= 1 (count-if-not #'exchange-initiator-p (exchange-manager-exchanges (rig-b (nr-rig nr))))))
    (advance (rig-clock (nr-rig nr)) 3)
    (pump (nr-rig nr) :rounds 4)
    (is (= 1 (count-if-not #'exchange-initiator-p (exchange-manager-exchanges (rig-b (nr-rig nr))))))
    (advance (rig-clock (nr-rig nr)) 4)
    (pump (nr-rig nr) :rounds 4)
    (is (= 0 (count-if-not #'exchange-initiator-p (exchange-manager-exchanges (rig-b (nr-rig nr))))))))

;;; ------------------------------------------------------------------
;;; Subscribe

(defun subscribe (nr paths &rest args &key (min-interval 1) (max-interval 10) &allow-other-keys)
  (let ((reports (list nil)))
    (values (complete nr (apply #'start-subscribe (nr-a nr) (nr-sa nr) paths
                                :min-interval min-interval :max-interval max-interval
                                :on-report (lambda (subscription attributes)
                                             (push (list (now nr) subscription attributes) (car reports)))
                                args))
            reports)))

(defun wait-reports (nr cell count &key (max-rounds 1000))
  "Run until CELL holds COUNT reports; the reports, oldest first."
  (run-rig (nr-rig nr) (lambda () (>= (length (car cell)) count)) :max-rounds max-rounds)
  (reverse (car cell)))

(test subscribe-and-report
  (let ((nr (make-node-rig)))
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)))
      (is (subscription-active-p sub))
      (is (= 10 (subscription-max-interval sub)))
      (is (= 1 (length (subscription-primed-reports sub))))
      (is (eq nil (attribute-report-value (first (subscription-primed-reports sub)))))
      (is (= 1 (length (interaction-model-subscriptions (nr-b nr)))))
      (is (= (subscription-id sub) (server-subscription-id (first (interaction-model-subscriptions (nr-b nr))))))
      (is (equal (list sub) (interaction-model-client-subscriptions (nr-a nr))))
      ;; a change after a quiet minimum interval is reported at once
      (settle nr :seconds 2)
      (let ((t0 (now nr)))
        (setf (attribute-value (nr-light nr) 'on-off) t)
        (let ((reports (wait-reports nr cell 1)))
          (is (= 1 (length reports)))
          (destructuring-bind (at subscription attributes) (first reports)
            (is (eq sub subscription))
            (is (<= 0 (- at t0) 0.3) "reported ~,2f s after the change" (- at t0))
            (is (= 1 (length attributes)))
            (is (eq t (attribute-report-value (first attributes))))
            (is (equalp (attribute-path 1 6 0) (attribute-report-path (first attributes)))))))
      ;; a change right after a report waits for the minimum interval
      (let ((t1 (first (first (car cell)))))
        (setf (attribute-value (nr-light nr) 'on-off) nil)
        (let ((reports (wait-reports nr cell 2)))
          (destructuring-bind (at subscription attributes) (second reports)
            (declare (ignore subscription))
            (is (<= 1.0 (- at t1) 1.3) "reported ~,2f s after the previous report" (- at t1))
            (is (eq nil (attribute-report-value (first attributes)))))))
      ;; a change to something else is not reported
      (setf (attribute-value (basic nr) 'node-label) "x")
      (run-rig (nr-rig nr) (lambda () nil) :max-rounds 60)
      (is (= 2 (length (car cell))))
      ;; without changes an empty report keeps the subscription alive at the maximum interval
      (let ((reports (wait-reports nr cell 3)))
        (destructuring-bind (at subscription attributes) (third reports)
          (declare (ignore subscription))
          (is (null attributes))
          (is (<= 9.5 (- at (first (second reports))) 10.5))))
      (is (subscription-active-p sub))
      ;; the subscriber leaves: the next report is refused and the server forgets it
      (unsubscribe sub)
      (is (not (subscription-active-p sub)))
      (is (null (interaction-model-client-subscriptions (nr-a nr))))
      (run-rig (nr-rig nr) (lambda () (null (interaction-model-subscriptions (nr-b nr)))) :max-rounds 400)
      (is (null (interaction-model-subscriptions (nr-b nr))))
      (is (= 3 (length (car cell)))))))

(test subscribe-coalesces-changes
  (let ((nr (make-node-rig)))
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 nil nil)) :min-interval 2 :max-interval 30)
      (is (= (length (cluster-attribute-ids (nr-light nr)))
             (count +cluster-on-off+ (subscription-primed-reports sub)
                    :key (lambda (r) (attribute-path-cluster (attribute-report-path r))))))
      ;; several changes inside the minimum interval make one report
      (setf (attribute-value (nr-light nr) 'on-off) t)
      (run-rig (nr-rig nr) (lambda () nil) :max-rounds 10)
      (setf (attribute-value (nr-light nr) 'on-off) nil)
      (setf (attribute-value (node-cluster (nr-node nr) 1 +cluster-identify+) 'identify-time) 7)
      (let ((reports (wait-reports nr cell 1)))
        (is (= 1 (length reports)))
        (let ((attributes (third (first reports))))
          (is (= 2 (length attributes)))
          (is (eq nil (attribute-report-value (find 0 attributes :key (lambda (r) (attribute-path-attribute (attribute-report-path r)))))))
          (is (= 7 (attribute-report-value (find +cluster-identify+ attributes
                                                 :key (lambda (r) (attribute-path-cluster (attribute-report-path r)))))))))
      ;; a change on another endpoint is outside the subscription
      (setf (attribute-value (basic nr) 'node-label) "y")
      (run-rig (nr-rig nr) (lambda () nil) :max-rounds 100)
      (is (= 1 (length (car cell)))))))

(test subscribe-sees-endpoints-come-and-go
  "A bridge adds and removes endpoints: the root's PartsList is reported,
and the gone endpoint answers UNSUPPORTED_ENDPOINT."
  (let ((nr (make-node-rig)))
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path nil +cluster-descriptor+ 3)) :min-interval 0 :max-interval 30)
      (is (= 2 (length (subscription-primed-reports sub))))
      (let ((hall (make-bridged-endpoint 2 :node-label "Hall" :unique-id "h1"
                                           :device-types (list (cons +device-type-on-off-light+ 3))
                                           :clusters (list (make-on-off-cluster)))))
        (add-endpoint (nr-node nr) hall)
        (let ((attributes (third (first (wait-reports nr cell 1)))))
          (is (= 1 (length attributes)))
          (is (equalp (attribute-path 0 +cluster-descriptor+ 3) (attribute-report-path (first attributes))))
          (is (equal '(1 2) (attribute-report-value (first attributes)))))
        ;; the new endpoint is readable, bridged device basic information included
        (is (string= "Hall" (attribute-report-value (read-one nr (attribute-path 2 +cluster-bridged-device-basic-information+ 5)))))
        (is (eq t (attribute-report-value (read-one nr (attribute-path 2 +cluster-bridged-device-basic-information+ 17)))))
        (settle nr :seconds 1)
        (remove-endpoint (nr-node nr) hall)
        (let ((attributes (third (second (wait-reports nr cell 2)))))
          (is (= 1 (length attributes)))
          (is (equal '(1) (attribute-report-value (first attributes)))))
        (is (eq :unsupported-endpoint (report-status (read-one nr (attribute-path 2 +cluster-on-off+ 0)))))
        ;; a change on the gone endpoint reaches nobody
        (setf (attribute-value (find-cluster hall 'on-off) 'on-off) t)
        (run-rig (nr-rig nr) (lambda () nil) :max-rounds 60)
        (is (= 2 (length (car cell)))))
      (unsubscribe sub))))

(test subscribe-replaces-and-keeps
  (let ((nr (make-node-rig)))
    (let ((first (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)))))
      (is (= 1 (length (interaction-model-subscriptions (nr-b nr)))))
      (let ((second (subscribe nr (list (attribute-path 0 +cluster-basic-information+ 5)) :keep-subscriptions t)))
        (is (= 2 (length (interaction-model-subscriptions (nr-b nr)))))
        (is (/= (subscription-id first) (subscription-id second))))
      ;; without KeepSubscriptions the earlier ones go
      (let ((third (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)))))
        (is (= 1 (length (interaction-model-subscriptions (nr-b nr)))))
        (is (= (subscription-id third) (server-subscription-id (first (interaction-model-subscriptions (nr-b nr))))))))
    ;; bad requests
    (is (eq :invalid-action (status-of (lambda () (subscribe nr (list (attribute-path 1 6 0)) :min-interval 5 :max-interval 2)))))
    (is (eq :invalid-action (status-of (lambda () (subscribe nr '())))))
    ;; the server caps the maximum interval
    (let ((*max-subscription-interval* 20))
      (let ((sub (subscribe nr (list (attribute-path 1 6 0)) :min-interval 1 :max-interval 3600)))
        (is (= 20 (subscription-max-interval sub)))
        (is (= 20 (server-subscription-max-interval (first (interaction-model-subscriptions (nr-b nr))))))))))

(test subscribe-chunked-priming
  (let ((nr (make-node-rig)))
    (let ((*max-report-payload* 150))
      (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path nil nil nil)) :min-interval 0 :max-interval 5)
        (declare (ignore cell))
        (is (subscription-active-p sub))
        (is (= (loop :for endpoint :in (node-endpoints (nr-node nr))
                     :sum (loop :for cluster :in (endpoint-clusters endpoint) :sum (length (cluster-attribute-ids cluster))))
               (length (subscription-primed-reports sub))))
        (is (= 1 (length (interaction-model-subscriptions (nr-b nr)))))))))

(test subscription-dies-with-the-link
  (let ((nr (make-node-rig)))
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)) :min-interval 0 :max-interval 4)
      (let ((failures '()))
        (setf (subscription-on-failure sub) (lambda (s reason) (push (list s reason) failures)))
        ;; B can no longer reach A
        (setf (network-drop (rig-network (nr-rig nr)))
              (lambda (octets from to) (declare (ignore octets to)) (= from (rig-b-port (nr-rig nr)))))
        (setf (attribute-value (nr-light nr) 'on-off) t)
        (run-rig (nr-rig nr) (lambda () (and (null (interaction-model-subscriptions (nr-b nr)))
                                             (null (interaction-model-client-subscriptions (nr-a nr)))))
                 :max-rounds 1000)
        ;; the server gave up after the retransmissions, the client after MaxInterval plus grace
        (is (null (interaction-model-subscriptions (nr-b nr))))
        (is (null (interaction-model-client-subscriptions (nr-a nr))))
        (is (not (subscription-active-p sub)))
        (is (equal (list (list sub :timeout)) failures))
        (is (null (car cell)))))))

(test subscription-report-fails-on-the-server
  "The subscriber answers a report with an error: the server drops the subscription."
  (let ((nr (make-node-rig)))
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)) :min-interval 0 :max-interval 4)
      (declare (ignore cell))
      ;; forget it on the client without telling anyone
      (setf (interaction-model-client-subscriptions (nr-a nr)) '())
      (setf (attribute-value (nr-light nr) 'on-off) t)
      (run-rig (nr-rig nr) (lambda () (null (interaction-model-subscriptions (nr-b nr)))) :max-rounds 200)
      (is (null (interaction-model-subscriptions (nr-b nr))))
      (is (subscription-active-p sub)))))  ; the forgotten object is just stale

;;; ------------------------------------------------------------------
;;; Odds and ends

(test client-without-a-node
  (let ((nr (make-node-rig)))
    ;; B asks A, which serves nothing
    (let ((interaction (start-read (nr-b nr) (nr-sb nr) (list (attribute-path 0 #x28 1)))))
      (is (eq :unsupported-node (status-of (lambda () (complete nr interaction)))))))
  ;; both sides serve a node: both can read
  (let ((nr (make-node-rig :node-on-a t)))
    (is (string= "ACME" (attribute-report-value (first (complete nr (start-read (nr-b nr) (nr-sb nr) (list (attribute-path 0 #x28 1))))))))
    (is (string= "ACME" (attribute-report-value (read-one nr (attribute-path 0 #x28 1)))))))

(test interaction-callbacks-and-abort
  (let* ((nr (make-node-rig))
         (done '())
         (interaction (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 0 #x28 1))
                                  :on-complete (lambda (i) (push i done)))))
    (is (interaction-running-p interaction))
    (is (eq :read (interaction-kind interaction)))
    (complete nr interaction)
    (is (equal (list interaction) done))
    (is (interaction-complete-p interaction))
    ;; aborting leaves nothing behind
    (let ((aborted (start-read (nr-a nr) (nr-sa nr) (list (attribute-path 0 #x28 1)))))
      (interaction-abort aborted)
      (is (interaction-failed-p aborted))
      (pump (nr-rig nr) :rounds 8)
      (is (null (exchange-manager-exchanges (rig-a (nr-rig nr))))))
    ;; closing the model unregisters it
    (interaction-model-close (nr-b nr))
    (let ((cell (raw-exchange nr +opcode-im-read-request+ (make-read-request :attribute-requests (list (attribute-path 0 #x28 1))))))
      (pump (nr-rig nr) :rounds 4)
      (is (null (find :message (events cell) :key #'first))))))

;;; ------------------------------------------------------------------
;;; Over UDP, the server in its own thread, PASE first

(test interaction-over-udp
  (with-udp-rig (a b host port)
    (multiple-value-bind (node light) (light-node)
      (let* ((ma (make-interaction-model a))
             (mb (make-interaction-model b :node node))
             (ca (make-secure-channel a))
             (stop nil)
             (thread (progn
                       (make-secure-channel b :pase-passcode *passcode* :pase-salt *salt* :pase-iterations 1000)
                       (bt:make-thread (lambda () (exchange-manager-run b :until (lambda () stop) :timeout 120))
                                       :name "matter server"))))
        (declare (ignorable mb))
        (unwind-protect
             (let ((session (establish-pase-session ca host port :passcode *passcode*)))
               (is (session-secured-p session))
               ;; read
               (let ((reports (read-attributes ma session (list (attribute-path 0 +cluster-basic-information+ 3)
                                                                (attribute-path 1 +cluster-on-off+ 0)))))
                 (is (= 2 (length reports)))
                 (is (string= "Lamp" (attribute-report-value (first reports))))
                 (is (eq nil (attribute-report-value (second reports)))))
               ;; write
               (let ((statuses (write-attributes ma session (list (attribute-write 0 +cluster-basic-information+ 5 "udp")))))
                 (is (im-status-success-p (attribute-status-status (first statuses)))))
               (is (string= "udp" (attribute-report-value (first (read-attributes ma session (list (attribute-path 0 #x28 5)))))))
               ;; invoke
               (invoke-command ma session (command-path 1 +cluster-on-off+ 1) nil)
               (is (eq t (attribute-report-value (first (read-attributes ma session (list (attribute-path 1 6 0)))))))
               (let ((responses (invoke-command ma session (command-path 1 +echo+ 0) (command-fields +echo+ 'echo '(:text "udp")))))
                 (is (equal '(:text "udp" :length 3) (invoke-response-value (first responses)))))
               ;; subscribe: the toggle through the server's own thread is reported
               (let* ((reports '())
                      (sub (subscribe-attributes ma session (list (attribute-path 1 +cluster-on-off+ 0))
                                                 :min-interval 0 :max-interval 2
                                                 :on-report (lambda (s attributes) (declare (ignore s)) (push attributes reports)))))
                 (is (subscription-active-p sub))
                 (is (eq t (attribute-report-value (first (subscription-primed-reports sub)))))
                 (invoke-command ma session (command-path 1 +cluster-on-off+ 2) nil)
                 (exchange-manager-run a :until (lambda () reports) :timeout 5)
                 (is (= 1 (length reports)))
                 (is (eq nil (attribute-report-value (first (first reports)))))
                 ;; the empty keep-alive
                 (exchange-manager-run a :until (lambda () (= 2 (length reports))) :timeout 5)
                 (is (= 2 (length reports)))
                 (is (null (first reports)))
                 (unsubscribe sub))
               ;; a timed write
               (write-attributes ma session (list (attribute-write 0 +cluster-basic-information+ 5 "timed")) :timed 2)
               (is (string= "timed" (attribute-report-value (first (read-attributes ma session (list (attribute-path 0 #x28 5)))))))
               (is (eq nil (attribute-value light 'on-off))))
          (setf stop t)
          (bt:join-thread thread))))))

(test interaction-wait-times-out
  (with-udp-rig (a b host port)
    (declare (ignore b host))
    (let* ((ma (make-interaction-model a))
           (keys (derive-session-keys (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
           ;; a session to a port where nothing answers
           (session (make-secured-session :type :pase :role :initiator :local-session-id 5 :peer-session-id 6 :keys keys
                                          :peer-host "127.0.0.1" :peer-port (1+ port))))
      (add-session (exchange-manager-session-manager a) session)
      (let ((t0 (exchange-manager-now a)))
        (is (eq :timeout (status-of (lambda () (read-attributes ma session (list (attribute-path 0 #x28 1)) :timeout 0.5)))))
        (is (<= 0.5 (- (exchange-manager-now a) t0) 2.0)))
      (is (null (exchange-manager-exchanges a))))))
