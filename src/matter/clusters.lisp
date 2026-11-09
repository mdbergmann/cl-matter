;;;; clusters.lisp -- the first clusters: Descriptor, Basic Information and
;;;; Bridged Device Basic Information (Matter Core Specification chapter 9
;;;; and 11), Identify and On/Off (Matter Application Cluster Specification
;;;; chapters 1.2 and 1.5); and the endpoints of a bridge (Matter Device
;;;; Library Specification chapter 9: Aggregator and Bridged Node).  Each
;;;; is a DEFINE-CLUSTER plus, where the behaviour is generic, a
;;;; constructor that installs the command handlers.

(in-package :cl-matter)

;;; ------------------------------------------------------------------
;;; Descriptor (0x001D): what an endpoint is and holds, computed from it

(defconstant +cluster-basic-information+ #x0028)
(defconstant +cluster-bridged-device-basic-information+ #x0039)
(defconstant +cluster-identify+ #x0003)
(defconstant +cluster-on-off+ #x0006)

(defconstant +device-type-root-node+ #x0016)
(defconstant +device-type-aggregator+ #x000E)
(defconstant +device-type-bridged-node+ #x0013)
(defconstant +device-type-on-off-light+ #x0100)
(defconstant +device-type-on-off-plug-in-unit+ #x010A)
(defconstant +device-type-on-off-light-switch+ #x0103)

(defun %descriptor-device-types (cluster)
  (loop :for (id . revision) :in (endpoint-device-types (cluster-endpoint cluster))
        :collect (list :device-type id :revision revision)))

(defun %descriptor-server-list (cluster)
  (mapcar #'cluster-id (endpoint-clusters (cluster-endpoint cluster))))

(defun %descriptor-parts-list (cluster)
  "The root endpoint lists every other endpoint (the full-family pattern
of 9.5.5.3); any other lists the endpoints that have it as their parent."
  (let* ((endpoint (cluster-endpoint cluster))
         (node (endpoint-node endpoint)))
    (cond ((null node) '())
          ((= +endpoint-root+ (endpoint-id endpoint))
           (loop :for e :in (node-endpoints node)
                 :unless (= +endpoint-root+ (endpoint-id e)) :collect (endpoint-id e)))
          (t (mapcar #'endpoint-id (endpoint-parts node endpoint))))))

(define-cluster descriptor (+cluster-descriptor+ :revision 2)
  (:attributes
   (device-type-list 0 (:list (:struct (0 :device-type :devtype-id) (1 :revision :uint16)))
                     :computed #'%descriptor-device-types)
   (server-list 1 (:list :cluster-id) :computed #'%descriptor-server-list)
   (client-list 2 (:list :cluster-id) :computed (lambda (cluster) (declare (ignore cluster)) '()))
   (parts-list 3 (:list :endpoint-no) :computed #'%descriptor-parts-list)))

;;; ------------------------------------------------------------------
;;; Basic Information (0x0028), on the root endpoint

(defconstant +data-model-revision+ 17 "Matter 1.3's DataModelRevision.")
(defconstant +specification-version+ #x01030000 "Matter 1.3.0.")

(define-cluster basic-information (+cluster-basic-information+ :revision 3)
  (:attributes
   (data-model-revision 0 :uint16 :default +data-model-revision+)
   (vendor-name 1 (:string 32) :default "")
   (vendor-id 2 :vendor-id :default 0)
   (product-name 3 (:string 32) :default "")
   (product-id 4 :uint16 :default 0)
   (node-label 5 (:string 32) :default "" :writable t :write :manage)
   (location 6 (:string 2) :default "XX" :writable t :write :administer)
   (hardware-version 7 :uint16 :default 0)
   (hardware-version-string 8 (:string 64) :default "")
   (software-version 9 :uint32 :default 0)
   (software-version-string 10 (:string 64) :default "")
   (manufacturing-date 11 (:string 16) :optional t)
   (part-number 12 (:string 32) :optional t)
   (product-url 13 (:string 256) :optional t)
   (product-label 14 (:string 64) :optional t)
   (serial-number 15 (:string 32) :optional t)
   (local-config-disabled 16 :bool :default nil :writable t :optional t :write :manage)
   (reachable 17 :bool :default t :optional t)
   (unique-id 18 (:string 32) :optional t)
   (capability-minima 19 (:struct (0 :case-sessions-per-fabric :uint16) (1 :subscriptions-per-fabric :uint16))
                      :default '(:case-sessions-per-fabric 3 :subscriptions-per-fabric 3))
   (specification-version 21 :uint32 :default +specification-version+)
   (max-paths-per-invoke 22 :uint16 :default 1)))

;;; ------------------------------------------------------------------
;;; Bridged Device Basic Information (0x0039), on every bridged endpoint:
;;; Basic Information about the device behind the bridge, everything
;;; optional but Reachable.  UniqueID is what a controller keeps the
;;; device's identity by across bridge restarts and endpoint renumbering;
;;; Apple Home in particular wants one.

(define-cluster bridged-device-basic-information (+cluster-bridged-device-basic-information+ :revision 3)
  (:attributes
   (vendor-name 1 (:string 32) :optional t)
   (vendor-id 2 :vendor-id :optional t)
   (product-name 3 (:string 32) :optional t)
   (product-id 4 :uint16 :optional t)
   (node-label 5 (:string 32) :optional t :writable t :write :manage)
   (hardware-version 7 :uint16 :optional t)
   (hardware-version-string 8 (:string 64) :optional t)
   (software-version 9 :uint32 :optional t)
   (software-version-string 10 (:string 64) :optional t)
   (manufacturing-date 11 (:string 16) :optional t)
   (part-number 12 (:string 32) :optional t)
   (product-url 13 (:string 256) :optional t)
   (product-label 14 (:string 64) :optional t)
   (serial-number 15 (:string 32) :optional t)
   (reachable 17 :bool :default t)
   (unique-id 18 (:string 32) :optional t)
   (product-appearance 20 (:struct (0 :finish :enum8) (1 :primary-color (:nullable :enum8))) :optional t)))

;;; ------------------------------------------------------------------
;;; A bridge: an Aggregator endpoint whose parts are Bridged Node
;;; endpoints, one per device behind the bridge (Device Library 9.12 and
;;; 9.13; the device type revisions are Matter 1.3's).

(defun make-aggregator-endpoint (id &key clusters)
  "The endpoint a bridge gathers its bridged endpoints under: device type
Aggregator, a Descriptor whose PartsList is the endpoints with ID as
their parent, and CLUSTERS (none needed)."
  (make-endpoint id :device-types (list (cons +device-type-aggregator+ 1)) :clusters clusters))

(defun make-bridged-endpoint (id &key parent device-types clusters
                                   node-label unique-id (reachable t)
                                   vendor-name vendor-id product-name product-id
                                   hardware-version-string software-version-string serial-number)
  "One device behind a bridge: endpoint ID, a part of PARENT (the
aggregator's id), with DEVICE-TYPES (e.g. an On/Off Light) and the Bridged
Node device type, CLUSTERS and a Bridged Device Basic Information cluster
holding the given attributes -- NODE-LABEL is the name the controller shows,
UNIQUE-ID the identity it keeps the device by, REACHABLE whether the device
answers right now (see `bridged-device-basic-information' to change them)."
  (let ((initargs (list :reachable reachable)))
    (loop :for (key value) :on (list :node-label node-label :unique-id unique-id
                                     :vendor-name vendor-name :vendor-id vendor-id
                                     :product-name product-name :product-id product-id
                                     :hardware-version-string hardware-version-string
                                     :software-version-string software-version-string
                                     :serial-number serial-number)
            :by #'cddr
          :when value :do (setf initargs (list* key value initargs)))
    (make-endpoint id :parent parent
                      :device-types (append device-types (list (cons +device-type-bridged-node+ 2)))
                      :clusters (cons (apply #'make-cluster 'bridged-device-basic-information initargs)
                                      clusters))))

(defun bridged-device-basic-information (endpoint)
  "The Bridged Device Basic Information cluster of a bridged ENDPOINT, to
set its `reachable' or `node-label' with (setf attribute-value)."
  (find-cluster endpoint +cluster-bridged-device-basic-information+))

;;; ------------------------------------------------------------------
;;; Identify (0x0003)

(define-cluster identify (+cluster-identify+ :revision 4)
  (:attributes
   (identify-time 0 :uint16 :default 0 :writable t)
   (identify-type 1 :enum8 :default 0))
  (:commands
   (identify 0 :fields ((0 :identify-time :uint16)) :access :manage)
   (trigger-effect #x40 :fields ((0 :effect-identifier :enum8) (1 :effect-variant :enum8)) :access :manage)))

(defun make-identify-cluster (&key (identify-type 0) on-identify)
  "An Identify cluster whose Identify command sets IdentifyTime and calls
ON-IDENTIFY with the cluster and the seconds asked for."
  (let ((cluster (make-cluster 'identify :identify-type identify-type)))
    (setf (command-handler cluster 'identify)
          (lambda (cluster fields)
            (let ((seconds (getf fields :identify-time)))
              (setf (attribute-value cluster 'identify-time) seconds)
              (when on-identify (funcall on-identify cluster seconds))
              nil)))
    cluster))

;;; ------------------------------------------------------------------
;;; On/Off (0x0006)

(define-cluster on-off (+cluster-on-off+ :revision 6)
  (:attributes
   (on-off 0 :bool :default nil)
   (global-scene-control #x4000 :bool :default t :optional t)
   (on-time #x4001 :uint16 :default 0 :writable t :optional t)
   (off-wait-time #x4002 :uint16 :default 0 :writable t :optional t)
   (start-up-on-off #x4003 (:nullable :enum8) :default :null :writable t :optional t :write :manage))
  (:commands
   (off 0)
   (on 1)
   (toggle 2)
   (off-with-effect #x40 :fields ((0 :effect-identifier :enum8) (1 :effect-variant :enum8)))
   (on-with-recall-global-scene #x41)
   (on-with-timed-off #x42 :fields ((0 :on-off-control :bitmap8) (1 :on-time :uint16) (2 :off-wait-time :uint16)))))

(defun make-on-off-cluster (&key (on-off nil) on-change)
  "An On/Off cluster with Off, On and Toggle.  ON-CHANGE, when given, is
called with the cluster and the new state after each change."
  (let ((cluster (make-cluster 'on-off :on-off on-off)))
    (flet ((set-state (cluster state)
             (unless (eq state (attribute-value cluster 'on-off))
               (setf (attribute-value cluster 'on-off) state)
               (when on-change (funcall on-change cluster state)))
             nil))
      (setf (command-handler cluster 'off) (lambda (cluster fields) (declare (ignore fields)) (set-state cluster nil))
            (command-handler cluster 'on) (lambda (cluster fields) (declare (ignore fields)) (set-state cluster t))
            (command-handler cluster 'toggle) (lambda (cluster fields)
                                                (declare (ignore fields))
                                                (set-state cluster (not (attribute-value cluster 'on-off))))))
    cluster))

;;; ------------------------------------------------------------------
;;; A whole node

(defun make-basic-node (&rest basic-information &key (endpoints '()) &allow-other-keys)
  "A node with a root endpoint holding Basic Information (initialised from
the other keyword arguments, e.g. :VENDOR-NAME) and the given ENDPOINTS."
  (let ((initargs (loop :for (key value) :on basic-information :by #'cddr
                        :unless (eq key :endpoints) :append (list key value))))
    (make-node :endpoints
               (cons (make-endpoint +endpoint-root+
                                    :device-types (list (cons +device-type-root-node+ 3))
                                    :clusters (list (apply #'make-cluster 'basic-information initargs)))
                     endpoints))))
