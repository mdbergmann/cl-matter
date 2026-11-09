;;;; clusters.lisp -- the first clusters: Descriptor, Basic Information and
;;;; Bridged Device Basic Information (Matter Core Specification chapter 9
;;;; and 11), Identify and On/Off (Matter Application Cluster Specification
;;;; chapters 1.2 and 1.5), Boolean State and Temperature Measurement
;;;; (chapters 1.7 and 2.3), Window Covering and Thermostat (chapters 5.3
;;;; and 4.3); and the endpoints of a bridge (Matter Device
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
(defconstant +cluster-boolean-state+ #x0045)
(defconstant +cluster-temperature-measurement+ #x0402)
(defconstant +cluster-window-covering+ #x0102)
(defconstant +cluster-thermostat+ #x0201)

(defconstant +device-type-root-node+ #x0016)
(defconstant +device-type-aggregator+ #x000E)
(defconstant +device-type-bridged-node+ #x0013)
(defconstant +device-type-on-off-light+ #x0100)
(defconstant +device-type-on-off-plug-in-unit+ #x010A)
(defconstant +device-type-on-off-light-switch+ #x0103)
(defconstant +device-type-contact-sensor+ #x0015)
(defconstant +device-type-temperature-sensor+ #x0302)
(defconstant +device-type-window-covering+ #x0202)
(defconstant +device-type-thermostat+ #x0301)

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
;;; Boolean State (0x0045): one boolean, for a Contact Sensor (Device
;;; Library 7.1), whose StateValue is TRUE while the contact is closed.
;;; The StateChange event is not reported (events are not, yet).

(define-cluster boolean-state (+cluster-boolean-state+ :revision 1)
  (:attributes
   (state-value 0 :bool :default nil)))

(defun make-boolean-state-cluster (&key (state-value nil))
  "A Boolean State cluster holding STATE-VALUE; change it with
(setf attribute-value), subscribers hear of it."
  (make-cluster 'boolean-state :state-value state-value))

;;; ------------------------------------------------------------------
;;; Temperature Measurement (0x0402): MeasuredValue in hundredths of a
;;; degree Celsius, null while unknown; the bounds likewise.

(define-cluster temperature-measurement (+cluster-temperature-measurement+ :revision 4)
  (:attributes
   (measured-value 0 (:nullable :temperature) :default :null)
   (min-measured-value 1 (:nullable :temperature) :default :null)
   (max-measured-value 2 (:nullable :temperature) :default :null)
   (tolerance 3 :uint16 :optional t)))

(defun make-temperature-measurement-cluster (&key (measured-value :null) (min-measured-value :null)
                                               (max-measured-value :null))
  "A Temperature Measurement cluster: MEASURED-VALUE and the bounds in
hundredths of a degree Celsius, or :NULL.  `temperature-hundredths'
turns degrees into that."
  (make-cluster 'temperature-measurement :measured-value measured-value
                                         :min-measured-value min-measured-value
                                         :max-measured-value max-measured-value))

(defun temperature-hundredths (celsius)
  "CELSIUS, a real, as the int16 hundredths Temperature Measurement
carries, clamped to the type's range; anything else is :NULL."
  (if (realp celsius)
      (max -32768 (min 32767 (round (* 100 celsius))))
      :null))

;;; ------------------------------------------------------------------
;;; Window Covering (0x0102): a shutter, blind or awning.  Positions are
;;; in hundredths of a percent, 0 fully open and 10000 fully closed; the
;;; cluster keeps current and target, the application moves the covering
;;; and reports where it is with (setf attribute-value).

(define-cluster window-covering (+cluster-window-covering+ :revision 5)
  (:attributes
   (type 0 :enum8 :default 0)
   (physical-closed-limit-lift 1 :uint16 :optional t)
   (physical-closed-limit-tilt 2 :uint16 :optional t)
   (current-position-lift 3 (:nullable :uint16) :optional t)
   (current-position-tilt 4 (:nullable :uint16) :optional t)
   (number-of-actuations-lift 5 :uint16 :optional t)
   (number-of-actuations-tilt 6 :uint16 :optional t)
   (config-status 7 :bitmap8 :default 0)
   (current-position-lift-percentage 8 (:nullable :percent) :optional t)
   (current-position-tilt-percentage 9 (:nullable :percent) :optional t)
   (operational-status 10 :bitmap8 :default 0)
   (target-position-lift-percent100ths 11 (:nullable :percent100ths) :optional t)
   (target-position-tilt-percent100ths 12 (:nullable :percent100ths) :optional t)
   (end-product-type 13 :enum8 :default 0)
   (current-position-lift-percent100ths 14 (:nullable :percent100ths) :optional t)
   (current-position-tilt-percent100ths 15 (:nullable :percent100ths) :optional t)
   (installed-open-limit-lift 16 :uint16 :optional t)
   (installed-closed-limit-lift 17 :uint16 :optional t)
   (installed-open-limit-tilt 18 :uint16 :optional t)
   (installed-closed-limit-tilt 19 :uint16 :optional t)
   (mode 23 :bitmap8 :default 0 :writable t :write :manage)
   (safety-status 26 :bitmap16 :optional t))
  (:commands
   (up-or-open 0)
   (down-or-close 1)
   (stop-motion 2)
   (go-to-lift-value 4 :fields ((0 :lift-value :uint16)))
   (go-to-lift-percentage 5 :fields ((0 :lift-percent100ths-value :percent100ths)))
   (go-to-tilt-value 7 :fields ((0 :tilt-value :uint16)))
   (go-to-tilt-percentage 8 :fields ((0 :tilt-percent100ths-value :percent100ths)))))

(defparameter *window-covering-features*
  '((:lift . 1) (:tilt . 2) (:position-aware-lift . 4) (:absolute-position . 8) (:position-aware-tilt . 16))
  "The FeatureMap bits of Window Covering by name.")

(defun window-covering-features (names)
  "The FeatureMap of a Window Covering with the features NAMES (keywords of
`*window-covering-features*')."
  (reduce #'logior (mapcar (lambda (name)
                             (or (cdr (assoc name *window-covering-features*))
                                 (error "~s is not a Window Covering feature, one of ~{~s~^, ~} is"
                                        name (mapcar #'car *window-covering-features*))))
                           names)
          :initial-value 0))

(defun percent-hundredths (percent)
  "PERCENT, a real 0..100, as the percent100ths Window Covering carries
(0..10000, clamped); anything else is :NULL."
  (if (realp percent)
      (max 0 (min 10000 (round (* 100 percent))))
      :null))

(defun make-window-covering-cluster (&key (features '(:lift :position-aware-lift)) type
                                       (current-lift :null) (current-tilt :null)
                                       on-move on-lift on-tilt)
  "A Window Covering cluster with the FEATURES named (see
`*window-covering-features*'): with :LIFT it accepts UpOrOpen, DownOrClose
and StopMotion; with :POSITION-AWARE-LIFT it carries the lift position
(CURRENT-LIFT, in hundredths of a percent, 10000 closed) and its target
and accepts GoToLiftPercentage; :TILT and :POSITION-AWARE-TILT likewise
for the tilt (CURRENT-TILT, GoToTiltPercentage).  TYPE is the Type
attribute, default a roller shade, or a blind with lift and tilt when
there is tilt.

The application does the moving: ON-MOVE is called with the cluster and
:OPEN, :CLOSE or :STOP, ON-LIFT and ON-TILT with the cluster and the
target in hundredths of a percent, after the target attribute has been
set (open 0, close 10000, stop the current position).  Where it is now the
application reports with (setf attribute-value) on
CurrentPositionLiftPercent100ths and CurrentPositionTiltPercent100ths."
  (let* ((feature-map (window-covering-features features))
         (lift (member :lift features))
         (tilt (member :tilt features))
         (lift-aware (and lift (member :position-aware-lift features)))
         (tilt-aware (and tilt (member :position-aware-tilt features)))
         (cluster (apply #'make-cluster 'window-covering
                         :feature-map feature-map
                         :type (or type (if tilt 8 0))
                         :config-status (logior 1 (if lift-aware 8 0) (if tilt-aware 16 0))
                         (append (when lift-aware
                                   (list :current-position-lift-percent100ths current-lift
                                         :target-position-lift-percent100ths current-lift))
                                 (when tilt-aware
                                   (list :current-position-tilt-percent100ths current-tilt
                                         :target-position-tilt-percent100ths current-tilt))))))
    (labels ((target (attribute value)
               (when (attribute-present-p cluster attribute)
                 (setf (attribute-value cluster attribute) value)))
             (percent-field (fields key)
               (let ((value (getf fields key)))
                 (if (<= 0 value 10000) value :constraint-error)))
             (move (direction lift-target)
               (lambda (cluster fields)
                 (declare (ignore fields))
                 (when (attribute-present-p cluster 'target-position-lift-percent100ths)
                   (setf (attribute-value cluster 'target-position-lift-percent100ths)
                         (or lift-target (attribute-value cluster 'current-position-lift-percent100ths))))
                 (when on-move (funcall on-move cluster direction))
                 nil)))
      (when lift
        (setf (command-handler cluster 'up-or-open) (move :open 0)
              (command-handler cluster 'down-or-close) (move :close 10000)
              (command-handler cluster 'stop-motion) (move :stop nil)))
      (when lift-aware
        (setf (command-handler cluster 'go-to-lift-percentage)
              (lambda (cluster fields)
                (let ((value (percent-field fields :lift-percent100ths-value)))
                  (if (integerp value)
                      (progn
                        (target 'target-position-lift-percent100ths value)
                        (when on-lift (funcall on-lift cluster value))
                        nil)
                      value)))))
      (when tilt-aware
        (setf (command-handler cluster 'go-to-tilt-percentage)
              (lambda (cluster fields)
                (let ((value (percent-field fields :tilt-percent100ths-value)))
                  (if (integerp value)
                      (progn
                        (target 'target-position-tilt-percent100ths value)
                        (when on-tilt (funcall on-tilt cluster value))
                        nil)
                      value))))))
    cluster))

;;; ------------------------------------------------------------------
;;; Thermostat (0x0201), heating only: LocalTemperature and the
;;; OccupiedHeatingSetpoint an administrator writes or raises and lowers,
;;; both in hundredths of a degree; SystemMode Off or Heat.

(defun %check-heating-setpoint (cluster value)
  (unless (<= (attribute-value cluster 'min-heat-setpoint-limit)
              value
              (attribute-value cluster 'max-heat-setpoint-limit))
    (%constraint "the heating setpoint must be ~d..~d, got ~d"
                 (attribute-value cluster 'min-heat-setpoint-limit)
                 (attribute-value cluster 'max-heat-setpoint-limit)
                 value)))

(define-cluster thermostat (+cluster-thermostat+ :revision 6)
  (:attributes
   (local-temperature 0 (:nullable :temperature) :default :null)
   (outdoor-temperature 1 (:nullable :temperature) :optional t)
   (occupancy 2 :bitmap8 :optional t)
   (abs-min-heat-setpoint-limit 3 :temperature :default 700)
   (abs-max-heat-setpoint-limit 4 :temperature :default 3000)
   (pi-heating-demand 8 :uint8 :optional t)
   (occupied-heating-setpoint #x12 :temperature :default 2000 :writable t :check #'%check-heating-setpoint)
   (min-heat-setpoint-limit #x15 :temperature :default 700 :writable t :write :manage)
   (max-heat-setpoint-limit #x16 :temperature :default 3000 :writable t :write :manage)
   (control-sequence-of-operation #x1B :enum8 :default 2 :writable t :write :manage)
   (system-mode #x1C :enum8 :default 4 :writable t :write :manage)
   (thermostat-running-state #x29 :bitmap16 :optional t))
  (:commands
   (setpoint-raise-lower 0 :fields ((0 :mode :enum8) (1 :amount :int8)))))

(defconstant +thermostat-feature-heating+ 1)

(defun make-thermostat-cluster (&key (local-temperature :null) (occupied-heating-setpoint 2000)
                                  (min-heat-setpoint-limit 700) (max-heat-setpoint-limit 3000)
                                  (system-mode 4)
                                  on-setpoint-change on-system-mode-change)
  "A heating-only Thermostat cluster: LOCAL-TEMPERATURE and
OCCUPIED-HEATING-SETPOINT in hundredths of a degree (`temperature-hundredths'),
the setpoint kept within the limits, SYSTEM-MODE 0 (Off) or 4 (Heat).
ON-SETPOINT-CHANGE is called with the cluster and the new setpoint when a
peer writes it or sends SetpointRaiseLower, ON-SYSTEM-MODE-CHANGE with
the cluster and the new mode when a peer writes it.  The application
reports the temperature it measures and the setpoint set elsewhere with
(setf attribute-value), which runs neither."
  (let ((cluster (make-cluster 'thermostat
                               :feature-map +thermostat-feature-heating+
                               :local-temperature local-temperature
                               :occupied-heating-setpoint occupied-heating-setpoint
                               :min-heat-setpoint-limit min-heat-setpoint-limit
                               :max-heat-setpoint-limit max-heat-setpoint-limit
                               :abs-min-heat-setpoint-limit min-heat-setpoint-limit
                               :abs-max-heat-setpoint-limit max-heat-setpoint-limit
                               :system-mode system-mode)))
    (when on-setpoint-change
      (setf (attribute-write-handler cluster 'occupied-heating-setpoint) on-setpoint-change))
    (when on-system-mode-change
      (setf (attribute-write-handler cluster 'system-mode) on-system-mode-change))
    (setf (command-handler cluster 'setpoint-raise-lower)
          (lambda (cluster fields)
            ;; mode 0 heat, 1 cool, 2 both; the amount in tenths of a degree
            (when (member (getf fields :mode) '(0 2))
              (let ((setpoint (max (attribute-value cluster 'min-heat-setpoint-limit)
                                   (min (attribute-value cluster 'max-heat-setpoint-limit)
                                        (+ (attribute-value cluster 'occupied-heating-setpoint)
                                           (* 10 (getf fields :amount)))))))
                (unless (= setpoint (attribute-value cluster 'occupied-heating-setpoint))
                  (setf (attribute-value cluster 'occupied-heating-setpoint) setpoint)
                  (when on-setpoint-change (funcall on-setpoint-change cluster setpoint)))))
            nil))
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
