;;;; clusters.lisp -- the first clusters: Descriptor and Basic Information
;;;; (Matter Core Specification chapter 9 and 11), Identify and On/Off
;;;; (Matter Application Cluster Specification chapters 1.2 and 1.5).
;;;; Each is a DEFINE-CLUSTER plus, where the behaviour is generic, a
;;;; constructor that installs the command handlers.

(in-package :cl-matter)

;;; ------------------------------------------------------------------
;;; Descriptor (0x001D): what an endpoint is and holds, computed from it

(defconstant +cluster-descriptor+ #x001D)
(defconstant +cluster-basic-information+ #x0028)
(defconstant +cluster-identify+ #x0003)
(defconstant +cluster-on-off+ #x0006)

(defconstant +endpoint-root+ 0)
(defconstant +device-type-root-node+ #x0016)
(defconstant +device-type-on-off-light+ #x0100)
(defconstant +device-type-on-off-plug-in-unit+ #x010A)
(defconstant +device-type-on-off-light-switch+ #x0103)

(defun %descriptor-device-types (cluster)
  (loop :for (id . revision) :in (endpoint-device-types (cluster-endpoint cluster))
        :collect (list :device-type id :revision revision)))

(defun %descriptor-server-list (cluster)
  (mapcar #'cluster-id (endpoint-clusters (cluster-endpoint cluster))))

(defun %descriptor-parts-list (cluster)
  "The root endpoint lists every other endpoint; others list none (no
composed devices yet)."
  (let* ((endpoint (cluster-endpoint cluster))
         (node (endpoint-node endpoint)))
    (if (and node (= +endpoint-root+ (endpoint-id endpoint)))
        (loop :for e :in (node-endpoints node)
              :unless (= +endpoint-root+ (endpoint-id e)) :collect (endpoint-id e))
        '())))

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
   (node-label 5 (:string 32) :default "" :writable t)
   (location 6 (:string 2) :default "XX" :writable t)
   (hardware-version 7 :uint16 :default 0)
   (hardware-version-string 8 (:string 64) :default "")
   (software-version 9 :uint32 :default 0)
   (software-version-string 10 (:string 64) :default "")
   (manufacturing-date 11 (:string 16) :optional t)
   (part-number 12 (:string 32) :optional t)
   (product-url 13 (:string 256) :optional t)
   (product-label 14 (:string 64) :optional t)
   (serial-number 15 (:string 32) :optional t)
   (local-config-disabled 16 :bool :default nil :writable t :optional t)
   (reachable 17 :bool :default t :optional t)
   (unique-id 18 (:string 32) :optional t)
   (capability-minima 19 (:struct (0 :case-sessions-per-fabric :uint16) (1 :subscriptions-per-fabric :uint16))
                      :default '(:case-sessions-per-fabric 3 :subscriptions-per-fabric 3))
   (specification-version 21 :uint32 :default +specification-version+)
   (max-paths-per-invoke 22 :uint16 :default 1)))

;;; ------------------------------------------------------------------
;;; Identify (0x0003)

(define-cluster identify (+cluster-identify+ :revision 4)
  (:attributes
   (identify-time 0 :uint16 :default 0 :writable t)
   (identify-type 1 :enum8 :default 0))
  (:commands
   (identify 0 :fields ((0 :identify-time :uint16)))
   (trigger-effect #x40 :fields ((0 :effect-identifier :enum8) (1 :effect-variant :enum8)))))

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
   (start-up-on-off #x4003 (:nullable :enum8) :default :null :writable t :optional t))
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
