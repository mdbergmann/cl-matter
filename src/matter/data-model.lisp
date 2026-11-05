;;;; data-model.lisp -- the Matter data model (Matter Core Specification
;;;; chapter 7): a node of endpoints, each a set of cluster instances with
;;;; attributes and commands.
;;;;
;;;; A CLUSTER-DEFINITION, made with DEFINE-CLUSTER, says what a cluster
;;;; has: attributes (id, type, writable, default) and commands (id, field
;;;; types, response).  A CLUSTER is one instance of it on an endpoint:
;;;; its attribute values, its data version and its command handlers.
;;;; The five global attributes (ClusterRevision, FeatureMap, AttributeList,
;;;; AcceptedCommandList, GeneratedCommandList) are computed.
;;;;
;;;; Types are keywords or lists, mapped to TLV by VALUE-TLV / TLV-VALUE:
;;;;
;;;;   :bool                              T / NIL
;;;;   :uint8 .. :uint64, :int8 .. :int64  integers, also the aliases of
;;;;                                      *TYPE-ALIASES* (:vendor-id, :enum8 ...)
;;;;   :float :double                     reals
;;;;   :string / (:string MAX)            strings, MAX characters
;;;;   :octets / (:octets MAX)            octet vectors
;;;;   (:nullable TYPE)                   TYPE or :NULL
;;;;   (:list TYPE)                       a list
;;;;   (:struct (TAG :NAME TYPE [:optional]) ...)   a plist (:NAME value ...)
;;;;
;;;; Failures signal INTERACTION-ERROR with the Interaction Model status
;;;; the server answers with: CONSTRAINT_ERROR, INVALID_DATA_TYPE,
;;;; UNSUPPORTED_ATTRIBUTE, UNSUPPORTED_WRITE, UNSUPPORTED_COMMAND ...
;;;; Access control is not implemented: whoever has a session may do what
;;;; the definitions allow.

(in-package :cl-matter)

(defvar *interaction-session*
  nil
  "Bound to the SESSION an interaction arrived on while attribute writes
and command handlers run for it; NIL for local access.")

;;; ------------------------------------------------------------------
;;; Types

(defparameter *type-aliases*
  '((:enum8 . :uint8) (:enum16 . :uint16)
    (:bitmap8 . :uint8) (:bitmap16 . :uint16) (:bitmap32 . :uint32) (:bitmap64 . :uint64)
    (:percent . :uint8) (:percent100ths . :uint16)
    (:epoch-s . :uint32) (:epoch-us . :uint64) (:posix-ms . :uint64)
    (:systime-us . :uint64) (:systime-ms . :uint64) (:elapsed-s . :uint32)
    (:temperature . :int16) (:status . :uint8) (:priority . :uint8)
    (:node-id . :uint64) (:fabric-id . :uint64) (:fabric-idx . :uint8) (:vendor-id . :uint16)
    (:endpoint-no . :uint16) (:cluster-id . :uint32) (:attrib-id . :uint32) (:command-id . :uint32)
    (:event-id . :uint32) (:devtype-id . :uint32) (:group-id . :uint16) (:data-ver . :uint32)
    (:event-no . :uint64) (:single . :float))
  "Derived types and the base type each one is on the wire.")

(defparameter *integer-widths*
  '((:uint8 8 nil) (:uint16 16 nil) (:uint24 24 nil) (:uint32 32 nil)
    (:uint40 40 nil) (:uint48 48 nil) (:uint56 56 nil) (:uint64 64 nil)
    (:int8 8 t) (:int16 16 t) (:int24 24 t) (:int32 32 t)
    (:int40 40 t) (:int48 48 t) (:int56 56 t) (:int64 64 t)))

(defun resolve-type (type)
  "TYPE with aliases replaced by their base types."
  (loop :for alias := (and (keywordp type) (cdr (assoc type *type-aliases*)))
        :while alias :do (setf type alias))
  type)

(defun %type-kind (type)
  (if (consp type) (car type) type))

(defun %integer-range (kind)
  "(values min max) of an integer KIND, or NIL."
  (let ((spec (assoc kind *integer-widths*)))
    (when spec
      (destructuring-bind (bits signed) (cdr spec)
        (if signed
            (values (- (ash 1 (1- bits))) (1- (ash 1 (1- bits))))
            (values 0 (1- (ash 1 bits))))))))

(defun %constraint (format &rest args)
  (error 'interaction-error :status +im-status-constraint-error+ :message (apply #'format nil format args)))

(defun %bad-type (format &rest args)
  (error 'interaction-error :status +im-status-invalid-data-type+ :message (apply #'format nil format args)))

(defun %check-integer (kind value)
  (multiple-value-bind (min max) (%integer-range kind)
    (unless (integerp value) (%bad-type "~a must be an integer, got ~s" kind value))
    (unless (<= min value max) (%constraint "~a must be ~d..~d, got ~d" kind min max value))
    value))

(defun value-tlv (type tag value)
  "The Lisp VALUE of TYPE as a TLV-ELEMENT tagged TAG."
  (let* ((type (resolve-type type))
         (kind (%type-kind type))
         (args (and (consp type) (cdr type))))
    (case kind
      (:nullable (if (eq value :null) (tlv tag :null) (value-tlv (first args) tag value)))
      (:bool (unless (member value '(t nil)) (%bad-type "a boolean must be T or NIL, got ~s" value))
       (tlv tag :boolean value))
      ((:uint8 :uint16 :uint24 :uint32 :uint40 :uint48 :uint56 :uint64)
       (tlv tag :unsigned (%check-integer kind value)))
      ((:int8 :int16 :int24 :int32 :int40 :int48 :int56 :int64)
       (tlv tag :signed (%check-integer kind value)))
      ((:float :double)
       (unless (or (realp value) (member value '(:infinity :-infinity :nan)))
         (%bad-type "~a must be a real, got ~s" kind value))
       (tlv tag kind value))
      (:string
       (unless (stringp value) (%bad-type "a string must be a string, got ~s" value))
       (when (and (first args) (> (length value) (first args)))
         (%constraint "a string of at most ~d characters, got ~d" (first args) (length value)))
       (tlv tag :string value))
      (:octets
       (unless (%octets-p value) (%bad-type "an octet string must be an octet vector, got ~s" value))
       (when (and (first args) (> (length value) (first args)))
         (%constraint "an octet string of at most ~d octets, got ~d" (first args) (length value)))
       (tlv tag :octets (%octets value)))
      (:list
       (unless (listp value) (%bad-type "a list must be a list, got ~s" value))
       (tlv tag :array (mapcar (lambda (item) (value-tlv (first args) nil item)) value)))
      (:struct
       (unless (and (listp value) (evenp (length value))) (%bad-type "a structure must be a plist, got ~s" value))
       (tlv tag :structure
            (loop :for (field-tag name field-type . options) :in args
                  :for (field-value present) := (multiple-value-list (%plist-get value name))
                  :if present :collect (value-tlv field-type field-tag field-value)
                  :else :unless (member :optional options)
                          :do (%constraint "the structure field ~s is missing" name))))
      (t (error "unknown data model type ~s" type)))))

(defun %plist-get (plist key)
  "(values value present-p)."
  (loop :for (k v) :on plist :by #'cddr
        :when (eq k key) :do (return (values v t))
        :finally (return (values nil nil))))

(defun tlv-value (type element)
  "The Lisp value of TYPE in the TLV-ELEMENT ELEMENT."
  (let* ((type (resolve-type type))
         (kind (%type-kind type))
         (args (and (consp type) (cdr type)))
         (actual (tlv-element-type element))
         (value (tlv-element-value element)))
    (flet ((expect (&rest types)
             (unless (member actual types)
               (if (eq actual :null)
                   (%constraint "~a is not nullable" kind)
                   (%bad-type "~a expected, got TLV ~a" kind actual)))))
      (case kind
        (:nullable (if (eq actual :null) :null (tlv-value (first args) element)))
        (:bool (expect :boolean) value)
        ((:uint8 :uint16 :uint24 :uint32 :uint40 :uint48 :uint56 :uint64)
         (expect :unsigned) (%check-integer kind value))
        ((:int8 :int16 :int24 :int32 :int40 :int48 :int56 :int64)
         (expect :signed :unsigned) (%check-integer kind value))
        ((:float :double) (expect :float :double) value)
        (:string (expect :string)
         (when (and (first args) (> (length value) (first args)))
           (%constraint "a string of at most ~d characters, got ~d" (first args) (length value)))
         value)
        (:octets (expect :octets)
         (when (and (first args) (> (length value) (first args)))
           (%constraint "an octet string of at most ~d octets, got ~d" (first args) (length value)))
         value)
        (:list (expect :array)
         (mapcar (lambda (item) (tlv-value (first args) item)) value))
        (:struct (expect :structure)
         (loop :for (field-tag name field-type . options) :in args
               :for field := (tlv-ref element field-tag)
               :if field :append (list name (tlv-value field-type field))
               :else :unless (member :optional options)
                       :do (%constraint "the structure field ~s (tag ~d) is missing" name field-tag)))
        (t (error "unknown data model type ~s" type))))))

;;; ------------------------------------------------------------------
;;; Definitions

(defstruct attribute-definition
  "One attribute of a cluster.  COMPUTED, a function of the cluster
instance, replaces the stored value; OPTIONAL attributes exist on an
instance only when given a value.  A FABRIC-SCOPED attribute is a list of
plists each carrying :FABRIC-INDEX: a fabric reads and writes its own
entries, and the FABRIC-SENSITIVE fields of other fabrics' entries are
withheld.  CHECK, a function of (cluster new-value), validates a peer's
write and signals INTERACTION-ERROR to refuse it."
  name (id 0) (type :uint8) (writable nil) (default nil) (computed nil) (optional nil)
  (fabric-scoped nil) (fabric-sensitive nil) (check nil))

(defstruct command-definition
  "One command of a cluster.  FIELDS is a (:struct ...) field list;
RESPONSE names the generated command it is answered with; GENERATED
commands are responses, never accepted; TIMED ones need a timed interaction."
  name (id 0) (fields nil) (response nil) (generated nil) (timed nil))

(defstruct cluster-definition
  name (id 0) (revision 1) (attributes '()) (commands '()))

(defmethod print-object ((d cluster-definition) stream)
  (print-unreadable-object (d stream :type t)
    (format stream "~a #x~4,'0x" (cluster-definition-name d) (cluster-definition-id d))))

(defvar *cluster-definitions* (make-hash-table :test 'equal)
  "Cluster definitions by name (a symbol, as a string) and by id.")

(defun %definition-key (designator)
  (if (symbolp designator) (symbol-name designator) designator))

(defun register-cluster-definition (definition)
  (setf (gethash (%definition-key (cluster-definition-name definition)) *cluster-definitions*) definition
        (gethash (cluster-definition-id definition) *cluster-definitions*) definition)
  definition)

(defun find-cluster-definition (designator &optional (errorp t))
  "The definition named or numbered DESIGNATOR."
  (or (gethash (%definition-key designator) *cluster-definitions*)
      (and errorp (error "no cluster definition ~s" designator))))

(defun %find-by-name-or-id (list designator name-reader id-reader)
  (if (integerp designator)
      (find designator list :key id-reader)
      (find (%definition-key designator) list :key (lambda (x) (symbol-name (funcall name-reader x))) :test #'string=)))

(defun find-attribute-definition (definition designator)
  (%find-by-name-or-id (cluster-definition-attributes definition) designator
                       #'attribute-definition-name #'attribute-definition-id))

(defun find-command-definition (definition designator)
  (%find-by-name-or-id (cluster-definition-commands definition) designator
                       #'command-definition-name #'command-definition-id))

(defmacro define-cluster (name (id &key (revision 1)) &body sections)
  "Define cluster NAME with ID.  SECTIONS:
  (:attributes (name id type &key writable default computed optional
                              fabric-scoped fabric-sensitive check) ...)
  (:commands (name id &key fields response generated timed) ...)"
  (let ((attributes (cdr (assoc :attributes sections)))
        (commands (cdr (assoc :commands sections))))
    `(register-cluster-definition
      (make-cluster-definition
       :name ',name :id ,id :revision ,revision
       :attributes (list ,@(loop :for (aname aid atype . options) :in attributes
                                 :collect `(make-attribute-definition
                                            :name ',aname :id ,aid :type ',atype
                                            :writable ,(getf options :writable)
                                            :default ,(getf options :default)
                                            :computed ,(getf options :computed)
                                            :optional ,(getf options :optional)
                                            :fabric-scoped ,(getf options :fabric-scoped)
                                            :fabric-sensitive ',(getf options :fabric-sensitive)
                                            :check ,(getf options :check))))
       :commands (list ,@(loop :for (cname cid . options) :in commands
                               :collect `(make-command-definition
                                          :name ',cname :id ,cid
                                          :fields ',(getf options :fields)
                                          :response ',(getf options :response)
                                          :generated ,(getf options :generated)
                                          :timed ,(getf options :timed))))))))

;;; Global attributes (7.13)

(defconstant +attribute-cluster-revision+       #xFFFD)
(defconstant +attribute-feature-map+            #xFFFC)
(defconstant +attribute-attribute-list+         #xFFFB)
(defconstant +attribute-accepted-command-list+  #xFFF9)
(defconstant +attribute-generated-command-list+ #xFFF8)

(defun global-attribute-p (id)
  (<= #xF000 id #xFFFF))

(defparameter *global-attribute-definitions*
  (list (make-attribute-definition :name 'cluster-revision :id +attribute-cluster-revision+ :type :uint16
                                   :computed (lambda (c) (cluster-definition-revision (cluster-definition c))))
        (make-attribute-definition :name 'feature-map :id +attribute-feature-map+ :type :bitmap32
                                   :computed (lambda (c) (cluster-feature-map c)))
        (make-attribute-definition :name 'attribute-list :id +attribute-attribute-list+ :type '(:list :attrib-id)
                                   :computed (lambda (c) (cluster-attribute-ids c)))
        (make-attribute-definition :name 'accepted-command-list :id +attribute-accepted-command-list+
                                   :type '(:list :command-id)
                                   :computed (lambda (c) (cluster-accepted-command-ids c)))
        (make-attribute-definition :name 'generated-command-list :id +attribute-generated-command-list+
                                   :type '(:list :command-id)
                                   :computed (lambda (c) (cluster-generated-command-ids c)))))

;;; ------------------------------------------------------------------
;;; Instances

(defstruct (cluster (:constructor %make-cluster))
  "One cluster on an endpoint.  VALUES holds the stored attributes by id;
HANDLERS maps command ids to functions of (cluster fields-plist)."
  definition
  endpoint
  (values (make-hash-table))
  (data-version (random (ash 1 32)))
  (feature-map 0)
  (handlers '()))

(defmethod print-object ((c cluster) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a #x~4,'0x~@[ on endpoint ~d~]" (cluster-name c) (cluster-id c)
            (and (cluster-endpoint c) (endpoint-id (cluster-endpoint c))))))

(defun cluster-id (cluster) (cluster-definition-id (cluster-definition cluster)))
(defun cluster-name (cluster) (cluster-definition-name (cluster-definition cluster)))
(defun cluster-revision (cluster) (cluster-definition-revision (cluster-definition cluster)))

(defun make-cluster (definition &rest initargs &key (feature-map 0) handlers &allow-other-keys)
  "An instance of DEFINITION (a name, id or CLUSTER-DEFINITION).  The
other INITARGS name attributes and set their initial values; HANDLERS is
an alist of (command-name-or-id . function)."
  (let* ((definition (if (cluster-definition-p definition) definition (find-cluster-definition definition)))
         (cluster (%make-cluster :definition definition :feature-map feature-map)))
    (dolist (attribute (cluster-definition-attributes definition))
      (unless (or (attribute-definition-computed attribute) (attribute-definition-optional attribute))
        (setf (gethash (attribute-definition-id attribute) (cluster-values cluster))
              (attribute-definition-default attribute))))
    (loop :for (key value) :on initargs :by #'cddr
          :unless (member key '(:feature-map :handlers))
            :do (let ((attribute (find-attribute-definition definition key)))
                  (unless attribute (error "~a has no attribute ~s" definition key))
                  (%store-attribute cluster attribute value)))
    (loop :for (command . handler) :in handlers
          :do (setf (command-handler cluster command) handler))
    cluster))

(defun %attribute (cluster designator &optional (errorp t))
  (or (find-attribute-definition (cluster-definition cluster) designator)
      (%find-by-name-or-id *global-attribute-definitions* designator
                           #'attribute-definition-name #'attribute-definition-id)
      (and errorp (%im-fail :unsupported-attribute "~a has no attribute ~s" cluster designator))))

(defun attribute-present-p (cluster designator)
  "Does CLUSTER have a value (or a computation) for the attribute?"
  (let ((attribute (%attribute cluster designator nil)))
    (and attribute
         (or (attribute-definition-computed attribute)
             (nth-value 1 (gethash (attribute-definition-id attribute) (cluster-values cluster)))))))

(defun cluster-attribute-ids (cluster)
  "The ids of the attributes CLUSTER has, globals included, ascending."
  (sort (append (loop :for attribute :in (cluster-definition-attributes (cluster-definition cluster))
                      :when (attribute-present-p cluster (attribute-definition-id attribute))
                        :collect (attribute-definition-id attribute))
                (mapcar #'attribute-definition-id *global-attribute-definitions*))
        #'<))

(defun cluster-accepted-command-ids (cluster)
  "The commands CLUSTER has a handler for."
  (sort (mapcar #'car (cluster-handlers cluster)) #'<))

(defun cluster-generated-command-ids (cluster)
  "The responses of the accepted commands."
  (sort (remove-duplicates
         (loop :for entry :in (cluster-handlers cluster)
               :for command := (find-command-definition (cluster-definition cluster) (car entry))
               :for response := (and command (command-definition-response command)
                                     (find-command-definition (cluster-definition cluster)
                                                              (command-definition-response command)))
               :when response :collect (command-definition-id response)))
        #'<))

(defun attribute-value (cluster designator)
  "The Lisp value of CLUSTER's attribute (a name or id)."
  (let ((attribute (%attribute cluster designator)))
    (if (attribute-definition-computed attribute)
        (funcall (attribute-definition-computed attribute) cluster)
        (multiple-value-bind (value present) (gethash (attribute-definition-id attribute) (cluster-values cluster))
          (unless present (%im-fail :unsupported-attribute "~a does not have the optional attribute ~a"
                                    cluster (attribute-definition-name attribute)))
          value))))

(defun %store-attribute (cluster attribute value)
  (when (attribute-definition-computed attribute)
    (%im-fail :unsupported-write "~a of ~a is computed" (attribute-definition-name attribute) cluster))
  (value-tlv (attribute-definition-type attribute) nil value) ; validates
  (setf (gethash (attribute-definition-id attribute) (cluster-values cluster)) value))

(defun %attribute-changed (cluster attribute-id)
  (setf (cluster-data-version cluster) (logand #xFFFFFFFF (1+ (cluster-data-version cluster))))
  (let ((endpoint (cluster-endpoint cluster)))
    (when (and endpoint (endpoint-node endpoint))
      (dolist (listener (node-listeners (endpoint-node endpoint)))
        (funcall listener (endpoint-id endpoint) (cluster-id cluster) attribute-id)))))

(defun (setf attribute-value) (value cluster designator)
  "Set the attribute, type-checked; bumps the data version and tells the
node's listeners.  Works on read-only attributes too: this is the
application's side, not the peer's."
  (let ((attribute (%attribute cluster designator)))
    (%store-attribute cluster attribute value)
    (%attribute-changed cluster (attribute-definition-id attribute))
    value))

(defun %fabric-scoped-view (items fabric-index filtered sensitive)
  "The entries of a fabric-scoped list as the fabric FABRIC-INDEX (0: none)
reads them: only its own when FILTERED, else every entry with the SENSITIVE
fields of the other fabrics' entries withheld."
  (if filtered
      (remove-if-not (lambda (item) (eql fabric-index (getf item :fabric-index))) items)
      (mapcar (lambda (item)
                (if (eql fabric-index (getf item :fabric-index))
                    item
                    (loop :for (key value) :on item :by #'cddr
                          :unless (member key sensitive) :append (list key value))))
              items)))

(defun read-attribute (cluster attribute-id &key (fabric-index 0) fabric-filtered)
  "The attribute's value as an anonymous TLV-ELEMENT, for a report to the
fabric FABRIC-INDEX (0: a PASE session or local access); FABRIC-FILTERED
is the read request's flag."
  (let* ((attribute (%attribute cluster attribute-id))
         (value (attribute-value cluster attribute-id)))
    (when (attribute-definition-fabric-scoped attribute)
      (setf value (%fabric-scoped-view value fabric-index fabric-filtered (attribute-definition-fabric-sensitive attribute))))
    (value-tlv (attribute-definition-type attribute) nil value)))

(defun %stamp-fabric (item fabric-index)
  (let ((copy (copy-list item)))
    (setf (getf copy :fabric-index) fabric-index)
    copy))

(defun %merge-fabric-items (old fabric-index new-own)
  "OLD with the entries of FABRIC-INDEX replaced in place by NEW-OWN:
surplus new ones go at the end, surplus old ones disappear."
  (let ((remaining new-own) (out '()))
    (dolist (item old)
      (if (eql fabric-index (getf item :fabric-index))
          (when remaining (push (pop remaining) out))
          (push item out)))
    (append (nreverse out) remaining)))

(defun write-attribute (cluster attribute-id element &key list-index (fabric-index 0))
  "A peer on the fabric FABRIC-INDEX (0: none) writes the TLV ELEMENT to the
attribute.  LIST-INDEX :NULL appends to a list attribute, an index
replaces one item.  A fabric-scoped list needs a fabric: the write
replaces that fabric's entries only, each stamped with its index, and an
index counts within them.  Signals INTERACTION-ERROR with
UNSUPPORTED_ATTRIBUTE, UNSUPPORTED_WRITE, UNSUPPORTED_ACCESS,
INVALID_DATA_TYPE or CONSTRAINT_ERROR, or what the attribute's CHECK
signals."
  (let* ((attribute (%attribute cluster attribute-id))
         (type (resolve-type (attribute-definition-type attribute)))
         (scoped (attribute-definition-fabric-scoped attribute)))
    (unless (and (attribute-definition-writable attribute) (not (attribute-definition-computed attribute)))
      (%im-fail :unsupported-write "~a of ~a is not writable" (attribute-definition-name attribute) cluster))
    (unless (attribute-present-p cluster attribute-id)
      (%im-fail :unsupported-attribute "~a does not have the optional attribute ~a"
                cluster (attribute-definition-name attribute)))
    (when (and scoped (not (plusp fabric-index)))
      (%im-fail :unsupported-access "~a of ~a is fabric-scoped: no fabric on this session"
                (attribute-definition-name attribute) cluster))
    (let* ((old (attribute-value cluster attribute-id))
           (own (if scoped (remove-if-not (lambda (item) (eql fabric-index (getf item :fabric-index))) old) old))
           (new-own
             (cond ((null list-index)
                    (let ((value (tlv-value type element)))
                      (if scoped (mapcar (lambda (item) (%stamp-fabric item fabric-index)) value) value)))
                   ((not (eq :list (%type-kind type)))
                    (%im-fail :unsupported-write "~a of ~a is not a list" (attribute-definition-name attribute) cluster))
                   (t (let ((item (tlv-value (second type) element)))
                        (when scoped (setf item (%stamp-fabric item fabric-index)))
                        (cond ((eq list-index :null) (append own (list item)))
                              ((< -1 list-index (length own))
                               (let ((new (copy-list own))) (setf (nth list-index new) item) new))
                              (t (%constraint "list index ~d is out of range (~d items)" list-index (length own))))))))
           (value (if scoped (%merge-fabric-items old fabric-index new-own) new-own)))
      (when (attribute-definition-check attribute)
        (funcall (attribute-definition-check attribute) cluster value))
      (%store-attribute cluster attribute value)
      (%attribute-changed cluster (attribute-definition-id attribute))
      value)))

(defun command-handler (cluster designator)
  (let ((command (find-command-definition (cluster-definition cluster) designator)))
    (and command (cdr (assoc (command-definition-id command) (cluster-handlers cluster))))))

(defun (setf command-handler) (handler cluster designator)
  "Install HANDLER, a function of (cluster fields-plist), for the command;
NIL removes it.  A handler of a command with a response returns the
response's field plist; any other returns a status (NIL = success)."
  (let ((command (find-command-definition (cluster-definition cluster) designator)))
    (unless command (error "~a has no command ~s" cluster designator))
    (when (command-definition-generated command)
      (error "~a is a response, it cannot be handled" (command-definition-name command)))
    (setf (cluster-handlers cluster) (remove (command-definition-id command) (cluster-handlers cluster) :key #'car))
    (when handler (push (cons (command-definition-id command) handler) (cluster-handlers cluster)))
    handler))

(defun invoke-cluster-command (cluster command-id fields)
  "A peer invokes command COMMAND-ID with FIELDS (a TLV structure element
or NIL).  Returns (values response-command-id response-element) when the
command has a response, (values nil status) otherwise, STATUS an IM-STATUS.
Signals INTERACTION-ERROR for UNSUPPORTED_COMMAND and INVALID_COMMAND."
  (let* ((definition (cluster-definition cluster))
         (command (find-command-definition definition command-id))
         (handler (and command (cdr (assoc (command-definition-id command) (cluster-handlers cluster))))))
    (unless (and command handler (not (command-definition-generated command)))
      (%im-fail :unsupported-command "~a does not accept command #x~2,'0x" cluster command-id))
    (let* ((field-types (command-definition-fields command))
           (plist (cond ((null field-types)
                         (when (and fields (tlv-element-value fields))
                           (%im-fail :invalid-command "~a takes no fields" (command-definition-name command)))
                         nil)
                        (t (handler-case (tlv-value (cons :struct field-types)
                                                    (or fields (tlv nil :structure nil)))
                             (interaction-error (e)
                               (%im-fail :invalid-command "bad fields for ~a: ~a"
                                         (command-definition-name command) (interaction-error-message e)))))))
           (result (funcall handler cluster plist))
           (response (and (command-definition-response command)
                          (find-command-definition definition (command-definition-response command)))))
      (if response
          (values (command-definition-id response)
                  (value-tlv (cons :struct (command-definition-fields response)) nil result))
          (values nil (cond ((null result) (make-im-status))
                            ((im-status-p result) result)
                            ((eq result t) (make-im-status))
                            (t (im-status result))))))))

;;; ------------------------------------------------------------------
;;; Endpoints and the node

(defstruct (endpoint (:constructor %make-endpoint))
  "An endpoint: DEVICE-TYPES is a list of (device-type-id . revision)."
  (id 0)
  (device-types '())
  (clusters '())
  node)

(defmethod print-object ((e endpoint) stream)
  (print-unreadable-object (e stream :type t)
    (format stream "~d (~d cluster~:p)" (endpoint-id e) (length (endpoint-clusters e)))))

(defun make-endpoint (id &key device-types clusters (descriptor t))
  "Endpoint ID with CLUSTERS; a Descriptor cluster is added unless DESCRIPTOR is NIL."
  (let ((endpoint (%make-endpoint :id id :device-types device-types)))
    (when descriptor (add-cluster endpoint (make-cluster 'descriptor)))
    (dolist (cluster clusters) (add-cluster endpoint cluster))
    endpoint))

(defun add-cluster (endpoint cluster)
  (when (find-cluster endpoint (cluster-id cluster))
    (error "~a already has cluster #x~4,'0x" endpoint (cluster-id cluster)))
  (setf (cluster-endpoint cluster) endpoint
        (endpoint-clusters endpoint) (append (endpoint-clusters endpoint) (list cluster)))
  cluster)

(defun find-cluster (endpoint designator)
  "The cluster named or numbered DESIGNATOR on ENDPOINT, or NIL."
  (if (integerp designator)
      (find designator (endpoint-clusters endpoint) :key #'cluster-id)
      (find (%definition-key designator) (endpoint-clusters endpoint)
            :key (lambda (c) (symbol-name (cluster-name c))) :test #'string=)))

(defstruct (node (:constructor %make-node))
  "The data model of one node: its ENDPOINTS, and LISTENERS called with
(endpoint-id cluster-id attribute-id) when an attribute changes."
  (endpoints '())
  (listeners '()))

(defun make-node (&key endpoints)
  (let ((node (%make-node)))
    (dolist (endpoint endpoints) (add-endpoint node endpoint))
    node))

(defun add-endpoint (node endpoint)
  (when (find-endpoint node (endpoint-id endpoint))
    (error "~a already has endpoint ~d" node (endpoint-id endpoint)))
  (setf (endpoint-node endpoint) node
        (node-endpoints node) (sort (cons endpoint (node-endpoints node)) #'< :key #'endpoint-id))
  endpoint)

(defun find-endpoint (node id)
  (find id (node-endpoints node) :key #'endpoint-id))

(defun node-cluster (node endpoint-id cluster)
  "The cluster CLUSTER (name or id) on endpoint ENDPOINT-ID, or NIL."
  (let ((endpoint (find-endpoint node endpoint-id)))
    (and endpoint (find-cluster endpoint cluster))))

(defun add-node-listener (node function)
  (push function (node-listeners node))
  function)

(defun remove-node-listener (node function)
  (setf (node-listeners node) (remove function (node-listeners node)))
  nil)
