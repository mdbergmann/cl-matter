;;;; interaction-codec.lisp -- the Interaction Model messages (Matter Core
;;;; Specification chapter 10, "Interaction Model Encoding"): paths,
;;;; information blocks and the ten messages of protocol 0x0001.
;;;;
;;;;   opcode  message                 direction
;;;;   0x01    StatusResponse          either, closes or continues an action
;;;;   0x02    ReadRequest             client -> server
;;;;   0x03    SubscribeRequest        client -> server
;;;;   0x04    SubscribeResponse       server -> client
;;;;   0x05    ReportData              server -> client
;;;;   0x06    WriteRequest            client -> server
;;;;   0x07    WriteResponse           server -> client
;;;;   0x08    InvokeRequest           client -> server
;;;;   0x09    InvokeResponse          server -> client
;;;;   0x0A    TimedRequest            client -> server
;;;;
;;;; Every message is an anonymous TLV structure with context tags; the
;;;; last field, tag 255, is the InteractionModelRevision.  Paths are TLV
;;;; lists, information blocks TLV structures.  Attribute and command data
;;;; travel as TLV-ELEMENTs here: the data model (data-model.lisp) turns
;;;; them into Lisp values and back, the engine (interaction.lisp) moves
;;;; them over exchanges.  Fields left NIL are not sent; integers are
;;;; checked against their wire widths.

(in-package :cl-matter)

(defparameter *interaction-model-revision* 11
  "The InteractionModelRevision we put in every message (Matter 1.2/1.3).")

;;; ------------------------------------------------------------------
;;; Status codes (section 8.10)

(defconstant +im-status-success+                  #x00)
(defconstant +im-status-failure+                  #x01)
(defconstant +im-status-invalid-subscription+     #x7D)
(defconstant +im-status-unsupported-access+       #x7E)
(defconstant +im-status-unsupported-endpoint+     #x7F)
(defconstant +im-status-invalid-action+           #x80)
(defconstant +im-status-unsupported-command+      #x81)
(defconstant +im-status-invalid-command+          #x85)
(defconstant +im-status-unsupported-attribute+    #x86)
(defconstant +im-status-constraint-error+         #x87)
(defconstant +im-status-unsupported-write+        #x88)
(defconstant +im-status-resource-exhausted+       #x89)
(defconstant +im-status-not-found+                #x8B)
(defconstant +im-status-unreportable-attribute+   #x8C)
(defconstant +im-status-invalid-data-type+        #x8D)
(defconstant +im-status-unsupported-read+         #x8F)
(defconstant +im-status-data-version-mismatch+    #x92)
(defconstant +im-status-timeout+                  #x94)
(defconstant +im-status-unsupported-node+         #x9B)
(defconstant +im-status-busy+                     #x9C)
(defconstant +im-status-access-restricted+        #x9D)
(defconstant +im-status-unsupported-cluster+      #xC3)
(defconstant +im-status-no-upstream-subscription+ #xC5)
(defconstant +im-status-needs-timed-interaction+  #xC6)
(defconstant +im-status-unsupported-event+        #xC7)
(defconstant +im-status-paths-exhausted+          #xC8)
(defconstant +im-status-timed-request-mismatch+   #xC9)
(defconstant +im-status-failsafe-required+        #xCA)
(defconstant +im-status-invalid-in-state+         #xCB)
(defconstant +im-status-no-command-response+      #xCC)

(defparameter *im-status-names*
  '((#x00 . :success) (#x01 . :failure) (#x7D . :invalid-subscription)
    (#x7E . :unsupported-access) (#x7F . :unsupported-endpoint) (#x80 . :invalid-action)
    (#x81 . :unsupported-command) (#x85 . :invalid-command) (#x86 . :unsupported-attribute)
    (#x87 . :constraint-error) (#x88 . :unsupported-write) (#x89 . :resource-exhausted)
    (#x8B . :not-found) (#x8C . :unreportable-attribute) (#x8D . :invalid-data-type)
    (#x8F . :unsupported-read) (#x92 . :data-version-mismatch) (#x94 . :timeout)
    (#x9B . :unsupported-node) (#x9C . :busy) (#x9D . :access-restricted)
    (#xC3 . :unsupported-cluster) (#xC5 . :no-upstream-subscription)
    (#xC6 . :needs-timed-interaction) (#xC7 . :unsupported-event) (#xC8 . :paths-exhausted)
    (#xC9 . :timed-request-mismatch) (#xCA . :failsafe-required) (#xCB . :invalid-in-state)
    (#xCC . :no-command-response)))

(defun im-status-name (code)
  "The keyword of an Interaction Model status CODE, or the code itself when unknown."
  (or (cdr (assoc code *im-status-names*)) code))

(defun im-status-code (status)
  "STATUS, a keyword like :UNSUPPORTED-ATTRIBUTE or a code, as a code."
  (cond ((integerp status) status)
        ((car (rassoc status *im-status-names*)))
        (t (error "~s is not an Interaction Model status" status))))

;;; ------------------------------------------------------------------
;;; Conditions

(define-condition interaction-error (error)
  ((message :initarg :message :reader interaction-error-message)
   (status :initarg :status :initform +im-status-invalid-action+ :reader interaction-error-status)
   (cluster-status :initarg :cluster-status :initform nil :reader interaction-error-cluster-status))
  (:report (lambda (c stream)
             (format stream "Interaction Model ~a: ~a"
                     (im-status-name (interaction-error-status c)) (interaction-error-message c))))
  (:documentation "An interaction failed.  STATUS is the Interaction Model
status code that describes it (and goes into a StatusResponse or status IB
when we are the server)."))

(defun %im-fail (status format &rest args)
  (error 'interaction-error :status (im-status-code status) :message (apply #'format nil format args)))

;;; ------------------------------------------------------------------
;;; Encoding helpers

(defconstant +im-tag-revision+ 255)

(defun %im-unsigned (tag value bits what)
  "A context-tagged unsigned element, or NIL for a NIL VALUE."
  (when value
    (unless (and (integerp value) (<= 0 value) (< value (ash 1 bits)))
      (%im-fail :invalid-action "~a must be an unsigned ~d-bit integer, got ~s" what bits value))
    (tlv tag :unsigned value)))

(defun %im-boolean (tag value)
  (tlv tag :boolean (and value t)))

(defun %im-message (&rest elements)
  "An anonymous structure of the non-NIL ELEMENTS plus the revision."
  (tlv nil :structure (append (remove nil elements)
                              (list (tlv +im-tag-revision+ :unsigned *interaction-model-revision*)))))

(defun %im-array (tag items encoder)
  "An array of ITEMS encoded anonymously by ENCODER, or NIL when there are none."
  (when items
    (tlv tag :array (mapcar (lambda (item) (funcall encoder nil item)) items))))

(defun %retag (element tag)
  "ELEMENT with TAG instead of its own."
  (make-tlv-element tag (tlv-element-type element) (tlv-element-value element)))

;;; ------------------------------------------------------------------
;;; Decoding helpers

(defun %ib (element type what)
  "ELEMENT must be a TLV container of TYPE; returns it."
  (unless (and (tlv-element-p element) (eq type (tlv-element-type element)))
    (%im-fail :invalid-action "~a must be a TLV ~a, got ~a" what type
              (if (tlv-element-p element) (tlv-element-type element) element)))
  element)

(defun %ib-field (container tag what &key optional)
  (let ((field (tlv-ref container tag)))
    (when (and (null field) (not optional))
      (%im-fail :invalid-action "~a is missing (tag ~d)" what tag))
    field))

(defun %ib-unsigned (container tag what &key optional (bits 64))
  (let ((field (%ib-field container tag what :optional optional)))
    (when field
      (unless (and (eq :unsigned (tlv-element-type field)) (< (tlv-element-value field) (ash 1 bits)))
        (%im-fail :invalid-action "~a must be an unsigned ~d-bit integer, got ~a" what bits field))
      (tlv-element-value field))))

(defun %ib-boolean (container tag what &key (optional t))
  (let ((field (%ib-field container tag what :optional optional)))
    (when field
      (unless (eq :boolean (tlv-element-type field))
        (%im-fail :invalid-action "~a must be a boolean, got ~a" what field))
      (tlv-element-value field))))

(defun %ib-array (container tag what decoder &key (optional t))
  (let ((field (%ib-field container tag what :optional optional)))
    (when field
      (%ib field :array what)
      (mapcar decoder (tlv-element-value field)))))

(defun %im-decode (octets what)
  "OCTETS -> the anonymous TLV structure of a message."
  (multiple-value-bind (element end)
      (handler-case (tlv-decode octets)
        (tlv-error (e) (%im-fail :invalid-action "malformed ~a: ~a" what e)))
    (unless (and (eq :structure (tlv-element-type element)) (null (tlv-element-tag element)))
      (%im-fail :invalid-action "~a must be an anonymous TLV structure, got ~a" what element))
    (unless (= end (length octets))
      (%im-fail :invalid-action "~a has ~d trailing octet~:p" what (- (length octets) end)))
    element))

;;; ------------------------------------------------------------------
;;; Paths (10.6.2, 10.6.8, 10.6.11)

(defstruct attribute-path
  "AttributePathIB.  A NIL field is a wildcard (or absent).  LIST-INDEX is
NIL, an index, or :NULL (append, in a write)."
  (node nil) (endpoint nil) (cluster nil) (attribute nil) (list-index nil)
  (tag-compression nil))

(defmethod print-object ((p attribute-path) stream)
  (print-unreadable-object (p stream :type t)
    (format stream "~@[~d/~]~a/~a/~a~@[[~a]~]"
            (attribute-path-node p)
            (or (attribute-path-endpoint p) "*")
            (if (attribute-path-cluster p) (format nil "#x~4,'0x" (attribute-path-cluster p)) "*")
            (if (attribute-path-attribute p) (format nil "#x~4,'0x" (attribute-path-attribute p)) "*")
            (attribute-path-list-index p))))

(defun attribute-path (endpoint cluster attribute &key node list-index)
  "A path; NIL fields are wildcards."
  (make-attribute-path :node node :endpoint endpoint :cluster cluster :attribute attribute :list-index list-index))

(defun attribute-path-concrete-p (path)
  (and (attribute-path-endpoint path) (attribute-path-cluster path) (attribute-path-attribute path) t))

(defun attribute-path-matches-p (pattern path)
  "Does the possibly wildcarded PATTERN cover the concrete PATH?"
  (flet ((ok (a b) (or (null a) (eql a b))))
    (and (ok (attribute-path-endpoint pattern) (attribute-path-endpoint path))
         (ok (attribute-path-cluster pattern) (attribute-path-cluster path))
         (ok (attribute-path-attribute pattern) (attribute-path-attribute path)))))

(defun attribute-path-tlv (tag path)
  (tlv tag :list
       (remove nil (list (and (attribute-path-tag-compression path) (tlv 0 :boolean t))
                         (%im-unsigned 1 (attribute-path-node path) 64 "path node id")
                         (%im-unsigned 2 (attribute-path-endpoint path) 16 "path endpoint")
                         (%im-unsigned 3 (attribute-path-cluster path) 32 "path cluster id")
                         (%im-unsigned 4 (attribute-path-attribute path) 32 "path attribute id")
                         (let ((index (attribute-path-list-index path)))
                           (cond ((null index) nil)
                                 ((eq index :null) (tlv 5 :null))
                                 (t (%im-unsigned 5 index 16 "path list index"))))))))

(defun tlv-attribute-path (element)
  (%ib element :list "AttributePathIB")
  (let ((index (%ib-field element 5 "list index" :optional t)))
    (make-attribute-path
     :tag-compression (%ib-boolean element 0 "EnableTagCompression")
     :node (%ib-unsigned element 1 "path node id" :optional t)
     :endpoint (%ib-unsigned element 2 "path endpoint" :optional t :bits 16)
     :cluster (%ib-unsigned element 3 "path cluster id" :optional t :bits 32)
     :attribute (%ib-unsigned element 4 "path attribute id" :optional t :bits 32)
     :list-index (cond ((null index) nil)
                       ((eq :null (tlv-element-type index)) :null)
                       (t (%ib-unsigned element 5 "path list index" :bits 16))))))

(defstruct cluster-path
  "ClusterPathIB."
  (node nil) (endpoint nil) (cluster nil))

(defun cluster-path-tlv (tag path)
  (tlv tag :list (remove nil (list (%im-unsigned 0 (cluster-path-node path) 64 "cluster path node id")
                                   (%im-unsigned 1 (cluster-path-endpoint path) 16 "cluster path endpoint")
                                   (%im-unsigned 2 (cluster-path-cluster path) 32 "cluster path cluster id")))))

(defun tlv-cluster-path (element)
  (%ib element :list "ClusterPathIB")
  (make-cluster-path :node (%ib-unsigned element 0 "cluster path node id" :optional t)
                     :endpoint (%ib-unsigned element 1 "cluster path endpoint" :optional t :bits 16)
                     :cluster (%ib-unsigned element 2 "cluster path cluster id" :optional t :bits 32)))

(defstruct command-path
  "CommandPathIB; the endpoint may be a wildcard (NIL) in group messages only."
  (endpoint nil) (cluster 0) (command 0))

(defmethod print-object ((p command-path) stream)
  (print-unreadable-object (p stream :type t)
    (format stream "~a/#x~4,'0x/#x~2,'0x" (or (command-path-endpoint p) "*")
            (command-path-cluster p) (command-path-command p))))

(defun command-path (endpoint cluster command)
  (make-command-path :endpoint endpoint :cluster cluster :command command))

(defun command-path-tlv (tag path)
  (tlv tag :list (remove nil (list (%im-unsigned 0 (command-path-endpoint path) 16 "command path endpoint")
                                   (%im-unsigned 1 (command-path-cluster path) 32 "command path cluster id")
                                   (%im-unsigned 2 (command-path-command path) 32 "command path command id")))))

(defun tlv-command-path (element)
  (%ib element :list "CommandPathIB")
  (make-command-path :endpoint (%ib-unsigned element 0 "command path endpoint" :optional t :bits 16)
                     :cluster (%ib-unsigned element 1 "command path cluster id" :bits 32)
                     :command (%ib-unsigned element 2 "command path command id" :bits 32)))

(defstruct event-path
  "EventPathIB."
  (node nil) (endpoint nil) (cluster nil) (event nil) (urgent nil))

(defun event-path-tlv (tag path)
  (tlv tag :list (remove nil (list (%im-unsigned 0 (event-path-node path) 64 "event path node id")
                                   (%im-unsigned 1 (event-path-endpoint path) 16 "event path endpoint")
                                   (%im-unsigned 2 (event-path-cluster path) 32 "event path cluster id")
                                   (%im-unsigned 3 (event-path-event path) 32 "event path event id")
                                   (and (event-path-urgent path) (tlv 4 :boolean t))))))

(defun tlv-event-path (element)
  (%ib element :list "EventPathIB")
  (make-event-path :node (%ib-unsigned element 0 "event path node id" :optional t)
                   :endpoint (%ib-unsigned element 1 "event path endpoint" :optional t :bits 16)
                   :cluster (%ib-unsigned element 2 "event path cluster id" :optional t :bits 32)
                   :event (%ib-unsigned element 3 "event path event id" :optional t :bits 32)
                   :urgent (%ib-boolean element 4 "IsUrgent")))

;;; ------------------------------------------------------------------
;;; Status and the information blocks (10.6)

(defstruct (im-status (:constructor make-im-status (&key (status 0) cluster-status)))
  "StatusIB: an Interaction Model STATUS code and an optional cluster-specific one."
  (status 0) (cluster-status nil))

(defmethod print-object ((s im-status) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "~a~@[ cluster ~d~]" (im-status-name (im-status-status s)) (im-status-cluster-status s))))

(defun im-status (status &optional cluster-status)
  (make-im-status :status (im-status-code status) :cluster-status cluster-status))

(defun im-status-success-p (status)
  (= +im-status-success+ (im-status-status status)))

(defun im-status-tlv (tag status)
  (tlv tag :structure (remove nil (list (%im-unsigned 0 (im-status-status status) 8 "status")
                                        (%im-unsigned 1 (im-status-cluster-status status) 8 "cluster status")))))

(defun tlv-im-status (element)
  (%ib element :structure "StatusIB")
  (make-im-status :status (%ib-unsigned element 0 "status" :bits 8)
                  :cluster-status (%ib-unsigned element 1 "cluster status" :optional t :bits 8)))

(defstruct attribute-data
  "AttributeDataIB: PATH's value DATA (a TLV-ELEMENT, its tag ignored) at DATA-VERSION."
  (data-version nil) (path nil) (data nil))

(defun attribute-data-tlv (tag data)
  (tlv tag :structure (remove nil (list (%im-unsigned 0 (attribute-data-data-version data) 32 "data version")
                                        (attribute-path-tlv 1 (attribute-data-path data))
                                        (%retag (attribute-data-data data) 2)))))

(defun tlv-attribute-data (element)
  (%ib element :structure "AttributeDataIB")
  (make-attribute-data :data-version (%ib-unsigned element 0 "data version" :optional t :bits 32)
                       :path (tlv-attribute-path (%ib-field element 1 "attribute data path"))
                       :data (%ib-field element 2 "attribute data")))

(defstruct attribute-status
  "AttributeStatusIB."
  (path nil) (status nil))

(defun attribute-status-tlv (tag status)
  (tlv tag :structure (list (attribute-path-tlv 0 (attribute-status-path status))
                            (im-status-tlv 1 (attribute-status-status status)))))

(defun tlv-attribute-status (element)
  (%ib element :structure "AttributeStatusIB")
  (make-attribute-status :path (tlv-attribute-path (%ib-field element 0 "attribute status path"))
                         :status (tlv-im-status (%ib-field element 1 "attribute status"))))

(defstruct attribute-report
  "AttributeReportIB: exactly one of STATUS (an ATTRIBUTE-STATUS) and DATA (an ATTRIBUTE-DATA)."
  (status nil) (data nil))

(defun attribute-report-path (report)
  (if (attribute-report-data report)
      (attribute-data-path (attribute-report-data report))
      (attribute-status-path (attribute-report-status report))))

(defmethod print-object ((r attribute-report) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~a ~a" (attribute-report-path r)
            (if (attribute-report-data r)
                (attribute-data-data (attribute-report-data r))
                (attribute-status-status (attribute-report-status r))))))

(defun attribute-report-tlv (tag report)
  (tlv tag :structure (remove nil (list (and (attribute-report-status report)
                                             (attribute-status-tlv 0 (attribute-report-status report)))
                                        (and (attribute-report-data report)
                                             (attribute-data-tlv 1 (attribute-report-data report)))))))

(defun tlv-attribute-report (element)
  (%ib element :structure "AttributeReportIB")
  (let ((status (%ib-field element 0 "attribute status" :optional t))
        (data (%ib-field element 1 "attribute data" :optional t)))
    (unless (and (or status data) (not (and status data)))
      (%im-fail :invalid-action "an AttributeReportIB has either a status or data"))
    (make-attribute-report :status (and status (tlv-attribute-status status))
                           :data (and data (tlv-attribute-data data)))))

(defstruct data-version-filter
  "DataVersionFilterIB."
  (path nil) (data-version 0))

(defun data-version-filter-tlv (tag filter)
  (tlv tag :structure (list (cluster-path-tlv 0 (data-version-filter-path filter))
                            (%im-unsigned 1 (data-version-filter-data-version filter) 32 "data version"))))

(defun tlv-data-version-filter (element)
  (%ib element :structure "DataVersionFilterIB")
  (make-data-version-filter :path (tlv-cluster-path (%ib-field element 0 "data version filter path"))
                            :data-version (%ib-unsigned element 1 "data version" :bits 32)))

(defstruct event-filter
  "EventFilterIB."
  (node nil) (event-min 0))

(defun event-filter-tlv (tag filter)
  (tlv tag :structure (remove nil (list (%im-unsigned 0 (event-filter-node filter) 64 "event filter node id")
                                        (%im-unsigned 1 (event-filter-event-min filter) 64 "EventMin")))))

(defun tlv-event-filter (element)
  (%ib element :structure "EventFilterIB")
  (make-event-filter :node (%ib-unsigned element 0 "event filter node id" :optional t)
                     :event-min (%ib-unsigned element 1 "EventMin")))

(defstruct event-data
  "EventDataIB.  Timestamps are NIL or integers; PRIORITY 0 debug, 1 info, 2 critical."
  (path nil) (event-number 0) (priority 0)
  (epoch-timestamp nil) (system-timestamp nil) (delta-epoch-timestamp nil) (delta-system-timestamp nil)
  (data nil))

(defun event-data-tlv (tag data)
  (tlv tag :structure
       (remove nil (list (event-path-tlv 0 (event-data-path data))
                         (%im-unsigned 1 (event-data-event-number data) 64 "event number")
                         (%im-unsigned 2 (event-data-priority data) 8 "event priority")
                         (%im-unsigned 3 (event-data-epoch-timestamp data) 64 "epoch timestamp")
                         (%im-unsigned 4 (event-data-system-timestamp data) 64 "system timestamp")
                         (%im-unsigned 5 (event-data-delta-epoch-timestamp data) 64 "delta epoch timestamp")
                         (%im-unsigned 6 (event-data-delta-system-timestamp data) 64 "delta system timestamp")
                         (and (event-data-data data) (%retag (event-data-data data) 7))))))

(defun tlv-event-data (element)
  (%ib element :structure "EventDataIB")
  (make-event-data :path (tlv-event-path (%ib-field element 0 "event path"))
                   :event-number (%ib-unsigned element 1 "event number")
                   :priority (%ib-unsigned element 2 "event priority" :bits 8)
                   :epoch-timestamp (%ib-unsigned element 3 "epoch timestamp" :optional t)
                   :system-timestamp (%ib-unsigned element 4 "system timestamp" :optional t)
                   :delta-epoch-timestamp (%ib-unsigned element 5 "delta epoch timestamp" :optional t)
                   :delta-system-timestamp (%ib-unsigned element 6 "delta system timestamp" :optional t)
                   :data (%ib-field element 7 "event data" :optional t)))

(defstruct event-status
  "EventStatusIB."
  (path nil) (status nil))

(defun event-status-tlv (tag status)
  (tlv tag :structure (list (event-path-tlv 0 (event-status-path status))
                            (im-status-tlv 1 (event-status-status status)))))

(defun tlv-event-status (element)
  (%ib element :structure "EventStatusIB")
  (make-event-status :path (tlv-event-path (%ib-field element 0 "event status path"))
                     :status (tlv-im-status (%ib-field element 1 "event status"))))

(defstruct event-report
  "EventReportIB: one of STATUS and DATA."
  (status nil) (data nil))

(defun event-report-tlv (tag report)
  (tlv tag :structure (remove nil (list (and (event-report-status report) (event-status-tlv 0 (event-report-status report)))
                                        (and (event-report-data report) (event-data-tlv 1 (event-report-data report)))))))

(defun tlv-event-report (element)
  (%ib element :structure "EventReportIB")
  (let ((status (%ib-field element 0 "event status" :optional t))
        (data (%ib-field element 1 "event data" :optional t)))
    (unless (and (or status data) (not (and status data)))
      (%im-fail :invalid-action "an EventReportIB has either a status or data"))
    (make-event-report :status (and status (tlv-event-status status))
                       :data (and data (tlv-event-data data)))))

(defstruct command-data
  "CommandDataIB: PATH with FIELDS (a TLV structure element or NIL) and an optional REF."
  (path nil) (fields nil) (ref nil))

(defun command-data-tlv (tag data)
  (tlv tag :structure (remove nil (list (command-path-tlv 0 (command-data-path data))
                                        (and (command-data-fields data) (%retag (command-data-fields data) 1))
                                        (%im-unsigned 2 (command-data-ref data) 16 "command ref")))))

(defun tlv-command-data (element)
  (%ib element :structure "CommandDataIB")
  (let ((fields (%ib-field element 1 "command fields" :optional t)))
    (when fields (%ib fields :structure "command fields"))
    (make-command-data :path (tlv-command-path (%ib-field element 0 "command path"))
                       :fields fields
                       :ref (%ib-unsigned element 2 "command ref" :optional t :bits 16))))

(defstruct command-status
  "CommandStatusIB."
  (path nil) (status nil) (ref nil))

(defun command-status-tlv (tag status)
  (tlv tag :structure (remove nil (list (command-path-tlv 0 (command-status-path status))
                                        (im-status-tlv 1 (command-status-status status))
                                        (%im-unsigned 2 (command-status-ref status) 16 "command ref")))))

(defun tlv-command-status (element)
  (%ib element :structure "CommandStatusIB")
  (make-command-status :path (tlv-command-path (%ib-field element 0 "command status path"))
                       :status (tlv-im-status (%ib-field element 1 "command status"))
                       :ref (%ib-unsigned element 2 "command ref" :optional t :bits 16)))

(defstruct invoke-response
  "InvokeResponseIB: one of COMMAND (a COMMAND-DATA, the response command) and STATUS (a COMMAND-STATUS)."
  (command nil) (status nil))

(defun invoke-response-path (response)
  (if (invoke-response-command response)
      (command-data-path (invoke-response-command response))
      (command-status-path (invoke-response-status response))))

(defun invoke-response-tlv (tag response)
  (tlv tag :structure (remove nil (list (and (invoke-response-command response)
                                             (command-data-tlv 0 (invoke-response-command response)))
                                        (and (invoke-response-status response)
                                             (command-status-tlv 1 (invoke-response-status response)))))))

(defun tlv-invoke-response (element)
  (%ib element :structure "InvokeResponseIB")
  (let ((command (%ib-field element 0 "response command" :optional t))
        (status (%ib-field element 1 "response status" :optional t)))
    (unless (and (or command status) (not (and command status)))
      (%im-fail :invalid-action "an InvokeResponseIB has either a command or a status"))
    (make-invoke-response :command (and command (tlv-command-data command))
                          :status (and status (tlv-command-status status)))))

;;; ------------------------------------------------------------------
;;; Messages (10.7)

(defstruct status-response
  "StatusResponseMessage."
  (status 0))

(defstruct read-request
  "ReadRequestMessage.  ATTRIBUTE-REQUESTS and EVENT-REQUESTS are lists of paths."
  (attribute-requests nil) (event-requests nil) (event-filters nil)
  (fabric-filtered nil) (data-version-filters nil))

(defstruct report-data
  "ReportDataMessage."
  (subscription-id nil) (attribute-reports nil) (event-reports nil)
  (more-chunked-messages nil) (suppress-response nil))

(defstruct subscribe-request
  "SubscribeRequestMessage; intervals in seconds."
  (keep-subscriptions nil) (min-interval-floor 0) (max-interval-ceiling 0)
  (attribute-requests nil) (event-requests nil) (event-filters nil)
  (fabric-filtered nil) (data-version-filters nil))

(defstruct subscribe-response
  "SubscribeResponseMessage; MAX-INTERVAL in seconds."
  (subscription-id 0) (max-interval 0))

(defstruct write-request
  "WriteRequestMessage.  WRITE-REQUESTS is a list of ATTRIBUTE-DATA."
  (suppress-response nil) (timed-request nil) (write-requests nil) (more-chunked-messages nil))

(defstruct write-response
  "WriteResponseMessage.  WRITE-RESPONSES is a list of ATTRIBUTE-STATUS."
  (write-responses nil))

(defstruct invoke-request
  "InvokeRequestMessage.  INVOKE-REQUESTS is a list of COMMAND-DATA."
  (suppress-response nil) (timed-request nil) (invoke-requests nil))

(defstruct invoke-response-message
  "InvokeResponseMessage.  INVOKE-RESPONSES is a list of INVOKE-RESPONSE."
  (suppress-response nil) (invoke-responses nil) (more-chunked-messages nil))

(defstruct timed-request
  "TimedRequestMessage; TIMEOUT in milliseconds."
  (timeout 0))

(defun encode-interaction-message (message)
  "MESSAGE, one of the message structs -> (values opcode octets)."
  (multiple-value-bind (opcode element)
      (etypecase message
        (status-response
         (values +opcode-im-status-response+
                 (%im-message (%im-unsigned 0 (im-status-code (status-response-status message)) 8 "status"))))
        (read-request
         (values +opcode-im-read-request+
                 (%im-message (%im-array 0 (read-request-attribute-requests message) #'attribute-path-tlv)
                              (%im-array 1 (read-request-event-requests message) #'event-path-tlv)
                              (%im-array 2 (read-request-event-filters message) #'event-filter-tlv)
                              (%im-boolean 3 (read-request-fabric-filtered message))
                              (%im-array 4 (read-request-data-version-filters message) #'data-version-filter-tlv))))
        (report-data
         (values +opcode-im-report-data+
                 (%im-message (%im-unsigned 0 (report-data-subscription-id message) 32 "subscription id")
                              (%im-array 1 (report-data-attribute-reports message) #'attribute-report-tlv)
                              (%im-array 2 (report-data-event-reports message) #'event-report-tlv)
                              (and (report-data-more-chunked-messages message) (tlv 3 :boolean t))
                              (and (report-data-suppress-response message) (tlv 4 :boolean t)))))
        (subscribe-request
         (values +opcode-im-subscribe-request+
                 (%im-message (%im-boolean 0 (subscribe-request-keep-subscriptions message))
                              (%im-unsigned 1 (round (subscribe-request-min-interval-floor message)) 16 "MinIntervalFloor")
                              (%im-unsigned 2 (round (subscribe-request-max-interval-ceiling message)) 16 "MaxIntervalCeiling")
                              (%im-array 3 (subscribe-request-attribute-requests message) #'attribute-path-tlv)
                              (%im-array 4 (subscribe-request-event-requests message) #'event-path-tlv)
                              (%im-array 5 (subscribe-request-event-filters message) #'event-filter-tlv)
                              (%im-boolean 7 (subscribe-request-fabric-filtered message))
                              (%im-array 8 (subscribe-request-data-version-filters message) #'data-version-filter-tlv))))
        (subscribe-response
         (values +opcode-im-subscribe-response+
                 (%im-message (%im-unsigned 0 (subscribe-response-subscription-id message) 32 "subscription id")
                              (%im-unsigned 2 (round (subscribe-response-max-interval message)) 16 "MaxInterval"))))
        (write-request
         (values +opcode-im-write-request+
                 (%im-message (and (write-request-suppress-response message) (tlv 0 :boolean t))
                              (%im-boolean 1 (write-request-timed-request message))
                              (tlv 2 :array (mapcar (lambda (d) (attribute-data-tlv nil d)) (write-request-write-requests message)))
                              (and (write-request-more-chunked-messages message) (tlv 3 :boolean t)))))
        (write-response
         (values +opcode-im-write-response+
                 (%im-message (tlv 0 :array (mapcar (lambda (s) (attribute-status-tlv nil s)) (write-response-write-responses message))))))
        (invoke-request
         (values +opcode-im-invoke-request+
                 (%im-message (%im-boolean 0 (invoke-request-suppress-response message))
                              (%im-boolean 1 (invoke-request-timed-request message))
                              (tlv 2 :array (mapcar (lambda (d) (command-data-tlv nil d)) (invoke-request-invoke-requests message))))))
        (invoke-response-message
         (values +opcode-im-invoke-response+
                 (%im-message (%im-boolean 0 (invoke-response-message-suppress-response message))
                              (tlv 1 :array (mapcar (lambda (r) (invoke-response-tlv nil r))
                                                    (invoke-response-message-invoke-responses message)))
                              (and (invoke-response-message-more-chunked-messages message) (tlv 2 :boolean t)))))
        (timed-request
         (values +opcode-im-timed-request+
                 (%im-message (%im-unsigned 0 (timed-request-timeout message) 16 "timeout")))))
    (values opcode (tlv-encode element))))

(defun decode-interaction-message (opcode octets)
  "The Interaction Model message of OPCODE in OCTETS as its struct; the
second value is the revision the peer sent (NIL when absent)."
  (let ((m (%im-decode octets (format nil "Interaction Model message #x~2,'0x" opcode))))
    (values
     (case opcode
       (#.+opcode-im-status-response+
        (make-status-response :status (%ib-unsigned m 0 "status" :bits 8)))
       (#.+opcode-im-read-request+
        (make-read-request :attribute-requests (%ib-array m 0 "AttributeRequests" #'tlv-attribute-path)
                           :event-requests (%ib-array m 1 "EventRequests" #'tlv-event-path)
                           :event-filters (%ib-array m 2 "EventFilters" #'tlv-event-filter)
                           :fabric-filtered (%ib-boolean m 3 "FabricFiltered")
                           :data-version-filters (%ib-array m 4 "DataVersionFilters" #'tlv-data-version-filter)))
       (#.+opcode-im-report-data+
        (make-report-data :subscription-id (%ib-unsigned m 0 "subscription id" :optional t :bits 32)
                          :attribute-reports (%ib-array m 1 "AttributeReports" #'tlv-attribute-report)
                          :event-reports (%ib-array m 2 "EventReports" #'tlv-event-report)
                          :more-chunked-messages (%ib-boolean m 3 "MoreChunkedMessages")
                          :suppress-response (%ib-boolean m 4 "SuppressResponse")))
       (#.+opcode-im-subscribe-request+
        (make-subscribe-request :keep-subscriptions (%ib-boolean m 0 "KeepSubscriptions")
                                :min-interval-floor (%ib-unsigned m 1 "MinIntervalFloor" :bits 16)
                                :max-interval-ceiling (%ib-unsigned m 2 "MaxIntervalCeiling" :bits 16)
                                :attribute-requests (%ib-array m 3 "AttributeRequests" #'tlv-attribute-path)
                                :event-requests (%ib-array m 4 "EventRequests" #'tlv-event-path)
                                :event-filters (%ib-array m 5 "EventFilters" #'tlv-event-filter)
                                :fabric-filtered (%ib-boolean m 7 "FabricFiltered")
                                :data-version-filters (%ib-array m 8 "DataVersionFilters" #'tlv-data-version-filter)))
       (#.+opcode-im-subscribe-response+
        (make-subscribe-response :subscription-id (%ib-unsigned m 0 "subscription id" :bits 32)
                                 :max-interval (%ib-unsigned m 2 "MaxInterval" :bits 16)))
       (#.+opcode-im-write-request+
        (make-write-request :suppress-response (%ib-boolean m 0 "SuppressResponse")
                            :timed-request (%ib-boolean m 1 "TimedRequest")
                            :write-requests (%ib-array m 2 "WriteRequests" #'tlv-attribute-data :optional nil)
                            :more-chunked-messages (%ib-boolean m 3 "MoreChunkedMessages")))
       (#.+opcode-im-write-response+
        (make-write-response :write-responses (%ib-array m 0 "WriteResponses" #'tlv-attribute-status :optional nil)))
       (#.+opcode-im-invoke-request+
        (make-invoke-request :suppress-response (%ib-boolean m 0 "SuppressResponse")
                             :timed-request (%ib-boolean m 1 "TimedRequest")
                             :invoke-requests (%ib-array m 2 "InvokeRequests" #'tlv-command-data :optional nil)))
       (#.+opcode-im-invoke-response+
        (make-invoke-response-message :suppress-response (%ib-boolean m 0 "SuppressResponse")
                                      :invoke-responses (%ib-array m 1 "InvokeResponses" #'tlv-invoke-response :optional nil)
                                      :more-chunked-messages (%ib-boolean m 2 "MoreChunkedMessages")))
       (#.+opcode-im-timed-request+
        (make-timed-request :timeout (%ib-unsigned m 0 "timeout" :bits 16)))
       (t (%im-fail :invalid-action "unknown Interaction Model opcode #x~2,'0x" opcode)))
     (%ib-unsigned m +im-tag-revision+ "InteractionModelRevision" :optional t :bits 8))))
