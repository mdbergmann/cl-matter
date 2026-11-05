;;;; commissioning.lisp -- commissioning (Matter Core Specification chapter
;;;; 5 and sections 11.10, 11.17, 11.9, 9.10): the clusters a commissionee
;;;; serves on its root endpoint and the flow a commissioner drives
;;;; against them.
;;;;
;;;; A DEVICE wraps a node, its Secure Channel and its Interaction Model
;;;; with five clusters -- General Commissioning (the fail-safe and
;;;; CommissioningComplete), Operational Credentials (attestation, the CSR,
;;;; AddTrustedRootCertificate / AddNOC / UpdateNOC / RemoveFabric and the
;;;; fabric table), Network Commissioning (an Ethernet interface, nothing
;;;; to configure), Access Control (the ACL, written by admins and applied
;;;; by access.lisp to every request) and Administrator Commissioning (an
;;;; administrator opens the commissioning window for the next one, 11.19)
;;;; -- and the fabric table behind them.  A fabric a commissioner adds
;;;; becomes a FABRIC in the table and in the Secure Channel, so CASE works
;;;; at once.
;;;;
;;;; The commissioning window (5.4.2.3) is the device's: open, it holds a
;;;; PASE verifier in the Secure Channel and a mode -- :BASIC with the
;;;; device's own passcode, under its own discriminator, or :ENHANCED with
;;;; the verifier and discriminator an administrator chose -- and it closes
;;;; by itself after its timeout, with CommissioningComplete, or when an
;;;; administrator revokes it.
;;;;
;;;; A COMMISSIONER owns a fabric and the key pair that roots it, and
;;;; COMMISSION runs the flow of section 5.5 over a PASE session: arm the
;;;; fail-safe, (set the regulatory configuration,) verify the device's
;;;; attestation, get a CSR, issue a NOC, install root and NOC, open a
;;;; CASE session as the new administrator, and complete.  The flow is a
;;;; chain of completions, so it runs under a polled manager as well as a
;;;; blocking one.
;;;;
;;;; The mDNS advertisements that go with the window and the fabric table
;;;; are discovery.lisp's; the device tells it through ON-ADVERTISING-CHANGE.
;;;;
;;;; Not done: UpdateNOC and RemoveFabric beyond the basics, persistence of
;;;; the fabric table.

(in-package :cl-matter)

(defconstant +cluster-general-commissioning+ #x0030)
(defconstant +cluster-network-commissioning+ #x0031)
(defconstant +cluster-operational-credentials+ #x003E)
(defconstant +cluster-administrator-commissioning+ #x003C)

;; CommissioningErrorEnum
(defconstant +commissioning-ok+ 0)
(defconstant +commissioning-value-outside-range+ 1)
(defconstant +commissioning-invalid-authentication+ 2)
(defconstant +commissioning-no-fail-safe+ 3)
(defconstant +commissioning-busy-with-other-admin+ 4)
;; RegulatoryLocationTypeEnum
(defconstant +regulatory-indoor+ 0)
(defconstant +regulatory-outdoor+ 1)
(defconstant +regulatory-indoor-outdoor+ 2)
;; NodeOperationalCertStatusEnum
(defconstant +noc-status-ok+ 0)
(defconstant +noc-status-invalid-public-key+ 1)
(defconstant +noc-status-invalid-node-op-id+ 2)
(defconstant +noc-status-invalid-noc+ 3)
(defconstant +noc-status-missing-csr+ 4)
(defconstant +noc-status-table-full+ 5)
(defconstant +noc-status-invalid-admin-subject+ 6)
(defconstant +noc-status-fabric-conflict+ 9)
(defconstant +noc-status-label-conflict+ 10)
(defconstant +noc-status-invalid-fabric-index+ 11)
(defconstant +network-commissioning-feature-ethernet+ #x04)
(defconstant +max-fabric-index+ 254)
(defconstant +max-cumulative-fail-safe-seconds+ 900)
;; Administrator Commissioning (11.19)
(defconstant +administrator-commissioning-feature-basic+ #x01 "The Basic feature: OpenBasicCommissioningWindow.")
;; CommissioningWindowStatusEnum
(defconstant +window-not-open+ 0)
(defconstant +enhanced-window-open+ 1)
(defconstant +basic-window-open+ 2)
;; the cluster's status codes
(defconstant +administrator-commissioning-busy+ 2)
(defconstant +administrator-commissioning-pake-parameter-error+ 3)
(defconstant +administrator-commissioning-window-not-open+ 4)
(defconstant +min-commissioning-timeout+ 180 "A window an administrator opens stays open at least 3 minutes (5.4.2.3) ...")
(defconstant +max-commissioning-timeout+ 900 "... and at most 15.")

(defparameter *fabric-removal-delay* 1.0d0
  "Seconds RemoveFabric waits before closing the fabric's sessions, so the
response reaches the peer first.")

;;; ------------------------------------------------------------------
;;; General Commissioning (11.10)

(define-cluster general-commissioning (+cluster-general-commissioning+ :revision 1)
  (:attributes
   (breadcrumb 0 :uint64 :default 0 :writable t :write :administer)
   (basic-commissioning-info 1 (:struct (0 :fail-safe-expiry-length-seconds :uint16)
                                        (1 :max-cumulative-failsafe-seconds :uint16))
                             :default '(:fail-safe-expiry-length-seconds 60 :max-cumulative-failsafe-seconds 900))
   (regulatory-config 2 :enum8 :default 2)
   (location-capability 3 :enum8 :default 2)
   (supports-concurrent-connection 4 :bool :default t))
  (:commands
   (arm-fail-safe 0 :fields ((0 :expiry-length-seconds :uint16) (1 :breadcrumb :uint64))
                  :response arm-fail-safe-response :access :administer)
   (arm-fail-safe-response 1 :fields ((0 :error-code :enum8) (1 :debug-text (:string 128))) :generated t)
   (set-regulatory-config 2 :fields ((0 :new-regulatory-config :enum8) (1 :country-code (:string 2)) (2 :breadcrumb :uint64))
                          :response set-regulatory-config-response :access :administer)
   (set-regulatory-config-response 3 :fields ((0 :error-code :enum8) (1 :debug-text (:string 128))) :generated t)
   (commissioning-complete 4 :response commissioning-complete-response :access :administer)
   (commissioning-complete-response 5 :fields ((0 :error-code :enum8) (1 :debug-text (:string 128))) :generated t)))

;;; ------------------------------------------------------------------
;;; Operational Credentials (11.17)

(defun %current-fabric-index (cluster)
  (declare (ignore cluster))
  (session-fabric-index *interaction-session*))

(define-cluster operational-credentials (+cluster-operational-credentials+ :revision 1)
  (:attributes
   (nocs 0 (:list (:struct (1 :noc (:octets 400) :optional) (2 :icac (:nullable (:octets 400)) :optional)
                           (254 :fabric-index :fabric-idx)))
         :default '() :fabric-scoped t :fabric-sensitive (:noc :icac) :read :administer)
   (fabrics 1 (:list (:struct (1 :root-public-key (:octets 65)) (2 :vendor-id :vendor-id) (3 :fabric-id :fabric-id)
                              (4 :node-id :node-id) (5 :label (:string 32)) (254 :fabric-index :fabric-idx)))
            :default '() :fabric-scoped t)
   (supported-fabrics 2 :uint8 :default 5)
   (commissioned-fabrics 3 :uint8 :default 0)
   (trusted-root-certificates 4 (:list (:octets 400)) :default '())
   (current-fabric-index 5 :fabric-idx :computed #'%current-fabric-index))
  (:commands
   (attestation-request 0 :fields ((0 :attestation-nonce (:octets 32))) :response attestation-response :access :administer)
   (attestation-response 1 :fields ((0 :attestation-elements (:octets 900)) (1 :attestation-signature (:octets 64))) :generated t)
   (certificate-chain-request 2 :fields ((0 :certificate-type :enum8)) :response certificate-chain-response :access :administer)
   (certificate-chain-response 3 :fields ((0 :certificate (:octets 600))) :generated t)
   (csr-request 4 :fields ((0 :csr-nonce (:octets 32)) (1 :is-for-update-noc :bool :optional)) :response csr-response
                :access :administer)
   (csr-response 5 :fields ((0 :nocsr-elements (:octets 900)) (1 :attestation-signature (:octets 64))) :generated t)
   (add-noc 6 :fields ((0 :noc-value (:octets 400)) (1 :icac-value (:octets 400) :optional) (2 :ipk-value (:octets 16))
                       (3 :case-admin-subject :uint64) (4 :admin-vendor-id :vendor-id))
            :response noc-response :access :administer)
   (update-noc 7 :fields ((0 :noc-value (:octets 400)) (1 :icac-value (:octets 400) :optional)) :response noc-response
               :access :administer)
   (noc-response 8 :fields ((0 :status-code :enum8) (1 :fabric-index :fabric-idx :optional) (2 :debug-text (:string 128) :optional))
                 :generated t)
   (update-fabric-label 9 :fields ((0 :label (:string 32))) :response noc-response :access :administer)
   (remove-fabric 10 :fields ((0 :fabric-index :fabric-idx)) :response noc-response :access :administer)
   (add-trusted-root-certificate 11 :fields ((0 :root-ca-certificate (:octets 400))) :access :administer)))

;;; ------------------------------------------------------------------
;;; Network Commissioning (11.9), an Ethernet interface: attributes only

(define-cluster network-commissioning (+cluster-network-commissioning+ :revision 1)
  (:attributes
   (max-networks 0 :uint8 :default 1 :read :administer)
   (networks 1 (:list (:struct (0 :network-id (:octets 32)) (1 :connected :bool))) :default '() :read :administer)
   (scan-max-time-seconds 2 :uint8 :optional t)
   (connect-max-time-seconds 3 :uint8 :optional t)
   (interface-enabled 4 :bool :default t :writable t :write :administer)
   (last-networking-status 5 (:nullable :enum8) :default :null :read :administer)
   (last-network-id 6 (:nullable (:octets 32)) :default :null :read :administer)
   (last-connect-error-value 7 (:nullable :int32) :default :null :read :administer)))

(defun make-ethernet-network-commissioning-cluster (&key (interface "eth0"))
  "A Network Commissioning cluster with the Ethernet feature: one connected
network named INTERFACE, nothing to scan or join."
  (make-cluster 'network-commissioning :feature-map +network-commissioning-feature-ethernet+
                                       :networks (list (list :network-id (%ascii-octets interface) :connected t))))

;;; ------------------------------------------------------------------
;;; Access Control (9.10): the ACL that access.lisp applies

(defparameter *subjects-per-acl-entry* 4)
(defparameter *targets-per-acl-entry* 3)
(defparameter *acl-entries-per-fabric* 4)

(defun %check-acl (cluster entries)
  "A peer's ACL write (9.10.5.3): every entry well formed, no more than
the cluster allows per fabric."
  (declare (ignore cluster))
  (let ((per-fabric (make-hash-table)))
    (dolist (entry entries)
      (let ((privilege (getf entry :privilege)) (auth-mode (getf entry :auth-mode))
            (subjects (getf entry :subjects)) (targets (getf entry :targets)))
        (unless (and privilege (<= +privilege-view+ privilege +privilege-administer+))
          (%constraint "an ACL entry needs a privilege 1..5, got ~s" privilege))
        (unless (and auth-mode (<= +auth-mode-pase+ auth-mode +auth-mode-group+))
          (%constraint "an ACL entry needs an auth mode 1..3, got ~s" auth-mode))
        (when (= auth-mode +auth-mode-pase+)
          (%constraint "ACL entries with the PASE auth mode cannot be written"))
        (when (and (= privilege +privilege-administer+) (/= auth-mode +auth-mode-case+))
          (%constraint "the Administer privilege needs the CASE auth mode"))
        (unless (eq subjects :null)
          (when (> (length subjects) *subjects-per-acl-entry*)
            (%constraint "at most ~d subjects per ACL entry, got ~d" *subjects-per-acl-entry* (length subjects)))
          (dolist (subject subjects)
            (unless (and (integerp subject) (plusp subject)) (%constraint "~s is not a subject" subject))))
        (unless (eq targets :null)
          (when (> (length targets) *targets-per-acl-entry*)
            (%constraint "at most ~d targets per ACL entry, got ~d" *targets-per-acl-entry* (length targets)))
          (dolist (target targets)
            (let ((cluster (getf target :cluster)) (endpoint (getf target :endpoint)) (device-type (getf target :device-type)))
              (when (and (eq cluster :null) (eq endpoint :null) (eq device-type :null))
                (%constraint "an ACL target needs a cluster, an endpoint or a device type"))
              (when (and (not (eq endpoint :null)) (not (eq device-type :null)))
                (%constraint "an ACL target names an endpoint or a device type, not both")))))
        (incf (gethash (getf entry :fabric-index) per-fabric 0))))
    (loop :for count :being :the :hash-values :of per-fabric
          :when (> count *acl-entries-per-fabric*)
            :do (error 'interaction-error :status +im-status-resource-exhausted+
                                          :message (format nil "at most ~d ACL entries per fabric" *acl-entries-per-fabric*)))))

(define-cluster access-control (+cluster-access-control+ :revision 1)
  (:attributes
   (acl 0 (:list (:struct (1 :privilege :enum8 :optional) (2 :auth-mode :enum8 :optional)
                          (3 :subjects (:nullable (:list :uint64)) :optional)
                          (4 :targets (:nullable (:list (:struct (0 :cluster (:nullable :cluster-id))
                                                                 (1 :endpoint (:nullable :endpoint-no))
                                                                 (2 :device-type (:nullable :devtype-id)))))
                              :optional)
                          (254 :fabric-index :fabric-idx :optional)))   ; a writer may leave it out: the session's is stamped
        :default '() :writable t :fabric-scoped t :fabric-sensitive (:privilege :auth-mode :subjects :targets)
        :check #'%check-acl :read :administer :write :administer)
   (subjects-per-access-control-entry 2 :uint16 :default 4)
   (targets-per-access-control-entry 3 :uint16 :default 3)
   (access-control-entries-per-fabric 4 :uint16 :default 4)))

(defun acl-entry (privilege auth-mode subjects &key (targets :null) (fabric-index 0))
  "An AccessControlEntryStruct plist: PRIVILEGE and AUTH-MODE (the
+PRIVILEGE-...+ / +AUTH-MODE-...+ values), SUBJECTS a list of node ids or
CAT subjects (or :NULL), TARGETS a list of (:cluster :endpoint
:device-type) plists or :NULL."
  (list :privilege privilege :auth-mode auth-mode :subjects subjects :targets targets :fabric-index fabric-index))

;;; ------------------------------------------------------------------
;;; Administrator Commissioning (11.19): the window for the next administrator

(define-cluster administrator-commissioning (+cluster-administrator-commissioning+ :revision 1)
  (:attributes
   (window-status 0 :enum8 :default 0)
   (admin-fabric-index 1 (:nullable :fabric-idx) :default :null)
   (admin-vendor-id 2 (:nullable :vendor-id) :default :null))
  (:commands
   ;; the verifier and salt are unbounded here: a wrong length is the cluster's PAKEParameterError, not CONSTRAINT_ERROR
   (open-commissioning-window 0 :fields ((0 :commissioning-timeout :uint16) (1 :pake-passcode-verifier :octets)
                                         (2 :discriminator :uint16) (3 :iterations :uint32) (4 :salt :octets))
                              :timed t :access :administer)
   (open-basic-commissioning-window 1 :fields ((0 :commissioning-timeout :uint16)) :timed t :access :administer)
   (revoke-commissioning 2 :timed t :access :administer)))

;;; ------------------------------------------------------------------
;;; The device: fabric table, fail-safe, the window and the cluster handlers

(define-condition commissioning-error (error)
  ((step :initarg :step :initform nil :reader commissioning-error-step)
   (message :initarg :message :reader commissioning-error-message))
  (:report (lambda (c stream)
             (format stream "commissioning~@[ (~a)~]: ~a" (commissioning-error-step c) (commissioning-error-message c))))
  (:documentation "A commissioning flow that could not go on; STEP names where."))

(defstruct (fail-safe (:constructor %make-fail-safe))
  "An armed fail-safe (11.10.6.2): who armed it, when it expires, and
what has been done under it that expiry would undo."
  session                               ; the session that armed it
  fabric                                ; that session's fabric (CASE), or NIL
  (expiry 0)                            ; manager time
  (armed-at 0)
  root                                  ; the RCAC AddTrustedRootCertificate brought
  keypair                               ; the key pair CSRRequest made
  (update-noc-p nil)                    ; ... for UpdateNOC
  added-fabric                          ; what AddNOC installed
  replaced-fabric                       ; (old . new) of UpdateNOC
  (noc-invoked nil))

(defstruct (device (:constructor %make-device))
  "A commissionable node: NODE's data model with the commissioning clusters
on its root endpoint, the Secure CHANNEL and Interaction MODEL that serve
it, the attestation CREDENTIALS, and the FABRICS it has been commissioned
into (FABRICs with their indices)."
  node channel model manager credentials
  (vendor-id 0) (product-id 0)
  (discriminator 0)                     ; the 12-bit discriminator of the onboarding payload (5.1.1.5)
  (fabrics '())
  (max-fabrics 5)
  (next-fabric-index 1)
  fail-safe
  general-commissioning operational-credentials network-commissioning access-control administrator-commissioning
  ;; the commissioning window
  (window-mode nil)                     ; NIL (closed), :basic or :enhanced
  window-expiry                         ; manager time it closes by itself, or NIL
  window-discriminator                  ; the one the commissionable advertisement carries
  window-fabric                         ; the fabric of the administrator who opened it, or NIL
  basic-verifier basic-salt basic-iterations ; the device's own PASE parameters: what the basic window accepts
  on-commissioned
  on-fabric-removed
  on-advertising-change                 ; called with the device when what it should advertise changed
  advertiser                            ; what START-DEVICE-ADVERTISING keeps (discovery.lisp)
  timer
  (scheduled '()))                      ; (time . function): work done once a response is out

(defmethod print-object ((d device) stream)
  (print-unreadable-object (d stream :type t)
    (format stream "vendor ~4,'0x product ~4,'0x, ~d fabric~:p~@[, ~(~a~) window open~]~@[, fail-safe armed~]"
            (device-vendor-id d) (device-product-id d) (length (device-fabrics d))
            (device-window-mode d) (device-fail-safe d))))

(defun device-now (device) (exchange-manager-now (device-manager device)))

(defun %schedule (device delay function)
  "Run FUNCTION DELAY seconds from now, from the poll loop: for what a
command handler must not do before its response has left."
  (push (cons (+ (device-now device) delay) function) (device-scheduled device))
  (wake-timer (device-manager device) (device-timer device)))

(defun %close-session-later (device session)
  (%schedule device *fabric-removal-delay*
             (lambda () (when (session-active-p session) (close-session (device-channel device) session)))))
(defun %trace-device (device format &rest args) (apply #'%trace (device-manager device) format args))

(defun device-acl (device)
  "The ACL entries, plists as ACL-ENTRY makes them."
  (attribute-value (device-access-control device) 'acl))

(defun (setf device-acl) (entries device)
  (setf (attribute-value (device-access-control device) 'acl) entries))

(defun find-device-fabric (device index)
  "The fabric with INDEX in DEVICE's table, or NIL."
  (find index (device-fabrics device) :key #'fabric-index))

(defun %advertising-changed (device)
  "The commissioning window or the fabric table changed: whoever
advertises the device (START-DEVICE-ADVERTISING) is told."
  (when (device-on-advertising-change device)
    (funcall (device-on-advertising-change device) device)))

(defun random-discriminator ()
  "A 12-bit discriminator (5.1.1.5)."
  (let ((octets (random-octets 2)))
    (logand (logior (ash (aref octets 0) 8) (aref octets 1)) #xFFF)))

(defun make-device (&key node channel model credentials vendor-id product-id (max-fabrics 5) fabrics
                      passcode salt iterations verifier window-timeout (discriminator (random-discriminator))
                      (location-capability +regulatory-indoor-outdoor+) (regulatory-config location-capability)
                      (fail-safe-expiry 60) (ethernet-interface "eth0")
                      on-commissioned on-fabric-removed)
  "A device from NODE (a data model with a root endpoint holding Basic
Information; MAKE-BASIC-NODE makes one), CHANNEL (its Secure Channel) and
MODEL (its Interaction Model serving NODE, made here when NIL), with the
attestation CREDENTIALS (TEST-ATTESTATION-CREDENTIALS for development).
VENDOR-ID and PRODUCT-ID default to Basic Information's.  FABRICS are
fabrics it already belongs to (restored by the application).  PASSCODE
(or VERIFIER) with SALT and ITERATIONS are the device's own PASE
parameters: they open the basic commissioning window at once, for
WINDOW-TIMEOUT seconds (default: until it is closed), and an administrator
can open it again with OpenBasicCommissioningWindow; DISCRIMINATOR
(default: random) is the 12-bit one of the onboarding payload that the
commissionable advertisement carries.  ON-COMMISSIONED is called with the
device and the new fabric after CommissioningComplete, ON-FABRIC-REMOVED
with the device and a fabric that was removed."
  (unless (node-p node) (error "MAKE-DEVICE needs a NODE"))
  (unless (secure-channel-p channel) (error "MAKE-DEVICE needs the node's SECURE-CHANNEL"))
  (let* ((manager (secure-channel-manager channel))
         (model (or model (make-interaction-model manager :node node)))
         (root (or (find-endpoint node +endpoint-root+) (error "the node has no root endpoint")))
         (basic (or (find-cluster root 'basic-information) (error "the root endpoint has no Basic Information cluster")))
         (device (%make-device :node node :channel channel :model model :manager manager :credentials credentials
                               :vendor-id (or vendor-id (attribute-value basic 'vendor-id))
                               :product-id (or product-id (attribute-value basic 'product-id))
                               :discriminator (%check-id discriminator 12 "the discriminator")
                               :max-fabrics max-fabrics
                               :on-commissioned on-commissioned :on-fabric-removed on-fabric-removed)))
    (unless (eq (interaction-model-node model) node) (error "the Interaction Model does not serve this node"))
    (when (and vendor-id (/= vendor-id (attribute-value basic 'vendor-id)))
      (setf (attribute-value basic 'vendor-id) vendor-id))
    (when (and product-id (/= product-id (attribute-value basic 'product-id)))
      (setf (attribute-value basic 'product-id) product-id))
    (setf (device-general-commissioning device)
          (add-cluster root (make-cluster 'general-commissioning
                                          :basic-commissioning-info (list :fail-safe-expiry-length-seconds fail-safe-expiry
                                                                          :max-cumulative-failsafe-seconds +max-cumulative-fail-safe-seconds+)
                                          :location-capability location-capability
                                          :regulatory-config regulatory-config))
          (device-operational-credentials device)
          (add-cluster root (make-cluster 'operational-credentials :supported-fabrics max-fabrics))
          (device-network-commissioning device)
          (add-cluster root (make-ethernet-network-commissioning-cluster :interface ethernet-interface))
          (device-access-control device)
          (add-cluster root (make-cluster 'access-control))
          (device-administrator-commissioning device)
          (add-cluster root (make-cluster 'administrator-commissioning
                                          :feature-map (if (or passcode verifier) +administrator-commissioning-feature-basic+ 0))))
    (when (or passcode verifier)
      (setf (device-basic-verifier device) (%check-window-verifier (or verifier (spake2p-verifier passcode salt iterations)))
            (device-basic-salt device) (%check-pbkdf-parameters salt iterations)
            (device-basic-iterations device) iterations))
    (%install-handlers device)
    (dolist (fabric fabrics) (%install-fabric device fabric))
    (setf (device-timer device) (add-timer manager (lambda (now) (%device-timer device now))))
    (let ((previous (secure-channel-on-session-closed channel)))
      (setf (secure-channel-on-session-closed channel)
            (lambda (channel session)
              (when previous (funcall previous channel session))
              (%device-session-closed device session))))
    (when (device-basic-verifier device)
      (open-commissioning-window device :timeout window-timeout))
    device))

;;; The commissioning window

(defun %check-window-verifier (verifier)
  "VERIFIER is the 97 octets w0 || L with L a point on the curve, or a PASE-ERROR."
  (unless (and (%octets-p verifier) (= (length verifier) +spake2p-verifier-length+))
    (%pase-fail "a PASE verifier is ~d octets (w0 || L), got ~a" +spake2p-verifier-length+
                (if (%octets-p verifier) (format nil "~d octets" (length verifier)) verifier)))
  (handler-case (p256-decode-point (subseq verifier +p256-scalar-length+) "the verifier's L")
    (error (e) (%pase-fail "the verifier's L: ~a" e)))
  verifier)

(defun %window-attributes (device)
  "The Administrator Commissioning attributes follow the window."
  (let ((cluster (device-administrator-commissioning device))
        (fabric (device-window-fabric device)))
    (setf (attribute-value cluster 'window-status) (ecase (device-window-mode device)
                                                     ((nil) +window-not-open+)
                                                     (:basic +basic-window-open+)
                                                     (:enhanced +enhanced-window-open+))
          (attribute-value cluster 'admin-fabric-index) (if fabric (fabric-index fabric) :null)
          (attribute-value cluster 'admin-vendor-id) (if fabric (fabric-vendor-id fabric) :null))))

(defun open-commissioning-window (device &key passcode verifier salt iterations timeout (mode :basic) discriminator fabric)
  "Open the commissioning window: accept PASE from a commissioner holding
PASSCODE (or its VERIFIER) with SALT and ITERATIONS -- without them, the
device's own, the ones MAKE-DEVICE was given -- for TIMEOUT seconds (NIL:
until it is closed).  MODE :ENHANCED is the window an administrator opens
for the next one (11.19): the advertisement carries DISCRIMINATOR
(default: the device's) and the enhanced commissioning mode, and FABRIC,
the administrator's, shows in AdminFabricIndex and AdminVendorId.  A
window already open is replaced."
  ;; everything is checked before anything changes: a refused call leaves the window as it was
  (unless (member mode '(:basic :enhanced)) (error "the window mode is :BASIC or :ENHANCED, not ~s" mode))
  (when (and timeout (not (and (realp timeout) (plusp timeout))))
    (error "the window timeout is a number of seconds or NIL, not ~s" timeout))
  (setf discriminator (if discriminator (%check-id discriminator 12 "the discriminator") (device-discriminator device)))
  (cond ((or passcode verifier)
         (setf salt (%check-pbkdf-parameters salt iterations)
               verifier (%check-window-verifier (or verifier (spake2p-verifier passcode salt iterations)))))
        ((device-basic-verifier device)
         (setf verifier (device-basic-verifier device)
               salt (device-basic-salt device)
               iterations (device-basic-iterations device)))
        (t (error "~a has no passcode of its own: the window needs one" device)))
  (set-pase-verifier (device-channel device) verifier salt iterations)
  (setf (device-window-mode device) mode
        (device-window-expiry device) (and timeout (+ (device-now device) timeout))
        (device-window-discriminator device) discriminator
        (device-window-fabric device) fabric)
  (%window-attributes device)
  (when timeout (%wake device))
  (%trace-device device "commissioning window open: ~(~a~), discriminator ~d~@[, ~a s~]~@[, opened by ~a~]"
                 mode (device-window-discriminator device) timeout fabric)
  (%advertising-changed device)
  device)

(defun close-commissioning-window (device)
  "Close the commissioning window: no more PASE.  The Administrator
Commissioning attributes and the advertisement follow."
  (let ((was-open (device-window-mode device)))
    (set-pase-verifier (device-channel device) nil nil nil)
    (setf (device-window-mode device) nil
          (device-window-expiry device) nil
          (device-window-discriminator device) nil
          (device-window-fabric device) nil)
    (%window-attributes device)
    (when was-open (%trace-device device "commissioning window closed"))
    (%advertising-changed device)
    device))

(defun commissioning-window-open-p (device)
  (and (device-window-mode device) t))

;;; The fabric table

(defun %allocate-fabric-index (device)
  (loop :repeat +max-fabric-index+
        :for index := (device-next-fabric-index device)
        :do (setf (device-next-fabric-index device) (if (>= index +max-fabric-index+) 1 (1+ index)))
        :unless (find-device-fabric device index) :return index
        :finally (error "no free fabric index")))

(defun %refresh-credentials (device)
  "The Operational Credentials attributes follow the fabric table."
  (let ((cluster (device-operational-credentials device))
        (fabrics (device-fabrics device)))
    (setf (attribute-value cluster 'nocs)
          (mapcar (lambda (f) (list :noc (certificate-octets* (fabric-noc f))
                                    :icac (if (fabric-icac f) (certificate-octets* (fabric-icac f)) :null)
                                    :fabric-index (fabric-index f)))
                  fabrics)
          (attribute-value cluster 'fabrics)
          (mapcar (lambda (f) (list :root-public-key (fabric-root-public-key f) :vendor-id (fabric-vendor-id f)
                                    :fabric-id (fabric-fabric-id f) :node-id (fabric-node-id f)
                                    :label (fabric-label f) :fabric-index (fabric-index f)))
                  fabrics)
          (attribute-value cluster 'commissioned-fabrics) (length fabrics)
          (attribute-value cluster 'trusted-root-certificates)
          (remove-duplicates (mapcar (lambda (f) (certificate-octets* (fabric-rcac f))) fabrics) :test #'equalp))))

(defun %install-fabric (device fabric)
  "FABRIC joins the table (with its index, or a fresh one) and the Secure Channel."
  (when (zerop (fabric-index fabric)) (setf (fabric-index fabric) (%allocate-fabric-index device)))
  (when (find-device-fabric device (fabric-index fabric))
    (error "fabric index ~d is in use" (fabric-index fabric)))
  (setf (device-fabrics device) (append (device-fabrics device) (list fabric)))
  (pushnew fabric (secure-channel-fabrics (device-channel device)))
  (%refresh-credentials device)
  (%advertising-changed device)
  fabric)

(defun %fabric-sessions (device fabric)
  (remove-if-not (lambda (s) (eq fabric (session-fabric s))) (secure-channel-sessions (device-channel device))))

(defun %uninstall-fabric (device fabric &key (notify t))
  "FABRIC leaves the table, the channel, the ACL, and its sessions are closed."
  (setf (device-fabrics device) (remove fabric (device-fabrics device))
        (secure-channel-fabrics (device-channel device)) (remove fabric (secure-channel-fabrics (device-channel device))))
  (setf (secure-channel-resumptions (device-channel device))
        (remove fabric (secure-channel-resumptions (device-channel device)) :key #'case-resumption-fabric))
  (setf (device-acl device) (remove (fabric-index fabric) (device-acl device) :key (lambda (e) (getf e :fabric-index))))
  ;; 11.19.7.2: the window it opened stays, AdminFabricIndex and AdminVendorId go null
  (when (eq fabric (device-window-fabric device))
    (setf (device-window-fabric device) nil)
    (%window-attributes device))
  (dolist (session (%fabric-sessions device fabric))
    (close-session (device-channel device) session))
  ;; a PASE session that AddNOC put on this fabric loses it
  (dolist (session (secure-channel-sessions (device-channel device)))
    (when (and (eq :pase (session-type session)) (eq fabric (session-fabric session)))
      (setf (session-fabric session) nil)))
  (setf (fabric-index fabric) 0)
  (%refresh-credentials device)
  (%advertising-changed device)
  (%trace-device device "fabric ~a removed" fabric)
  (when (and notify (device-on-fabric-removed device))
    (funcall (device-on-fabric-removed device) device fabric))
  fabric)

(defun remove-device-fabric (device fabric)
  "The application removes FABRIC (a FABRIC or its index) from DEVICE."
  (let ((fabric (if (integerp fabric) (find-device-fabric device fabric) fabric)))
    (when (and fabric (member fabric (device-fabrics device)))
      (%uninstall-fabric device fabric))))

;;; The fail-safe

(defun %session-owner (session)
  "What identifies the owner of a fail-safe: a CASE session's fabric, else the session."
  (or (and (eq :case (session-type session)) (session-fabric session)) session))

(defun %fail-safe-owned-by-p (fail-safe session)
  (eq (%session-owner (fail-safe-session fail-safe)) (%session-owner session)))

(defun %require-fail-safe (device session)
  "The armed fail-safe SESSION may act under, or FAILSAFE_REQUIRED /
UNSUPPORTED_ACCESS."
  (let ((fail-safe (device-fail-safe device)))
    (unless fail-safe (%im-fail :failsafe-required "the fail-safe is not armed"))
    (unless (%fail-safe-owned-by-p fail-safe session)
      (%im-fail :unsupported-access "the fail-safe was armed by another administrator"))
    fail-safe))

(defun %disarm-fail-safe (device &key revert)
  "Disarm; with REVERT undo what was done under it (expiry, ArmFailSafe 0).
The Breadcrumb goes back to 0 either way (11.10.6.1): a commissioner that
finds it set takes the node for one whose last commissioning broke off
after AddNOC and skips straight to CASE."
  (let ((fail-safe (device-fail-safe device)))
    (when fail-safe
      (setf (device-fail-safe device) nil
            (attribute-value (device-general-commissioning device) 'breadcrumb) 0)
      (when revert
        (%trace-device device "fail-safe expired: reverting")
        (let ((added (fail-safe-added-fabric fail-safe))
              (replaced (fail-safe-replaced-fabric fail-safe)))
          (when (and added (member added (device-fabrics device)))
            (%uninstall-fabric device added :notify nil))
          (when replaced
            (%restore-fabric device (cdr replaced) (car replaced))))
        ;; section 11.10.6.2.2: the PASE session the commissioning ran on ends
        (let ((session (fail-safe-session fail-safe)))
          (when (and (eq :pase (session-type session)) (session-active-p session))
            (%close-session-later device session))))
      fail-safe)))

(defun %device-session-closed (device session)
  "A session went away: a fail-safe it armed expires with it."
  (let ((fail-safe (device-fail-safe device)))
    (when (and fail-safe (eq session (fail-safe-session fail-safe)))
      (%trace-device device "the session that armed the fail-safe closed")
      (%disarm-fail-safe device :revert t))))

(defun %device-timer (device now)
  "Fail-safe expiry, the window's timeout and scheduled fabric removals;
the next time to look."
  (let ((fail-safe (device-fail-safe device)) (next nil))
    (flet ((consider (time) (when (or (null next) (< time next)) (setf next time))))
      (when fail-safe
        (if (>= now (fail-safe-expiry fail-safe))
            (%disarm-fail-safe device :revert t)
            (consider (fail-safe-expiry fail-safe))))
      (let ((expiry (device-window-expiry device)))
        (when expiry
          (if (>= now expiry)
              (progn (%trace-device device "the commissioning window timed out")
                     (close-commissioning-window device))
              (consider expiry))))
      (dolist (entry (copy-list (device-scheduled device)))
        (if (>= now (car entry))
            (progn (setf (device-scheduled device) (remove entry (device-scheduled device)))
                   (funcall (cdr entry)))
            (consider (car entry)))))
    (or next (+ now 60d0))))

(defun %wake (device) (wake-timer (device-manager device) (device-timer device)))

;;; The handlers

(defun %install-handlers (device)
  (let ((gc (device-general-commissioning device))
        (oc (device-operational-credentials device))
        (ac (device-administrator-commissioning device)))
    (flet ((handler (cluster name function)
             (setf (command-handler cluster name)
                   (lambda (cluster fields) (funcall function device cluster fields)))))
      (handler gc 'arm-fail-safe #'%arm-fail-safe)
      (handler gc 'set-regulatory-config #'%set-regulatory-config)
      (handler gc 'commissioning-complete #'%commissioning-complete)
      (handler oc 'attestation-request #'%attestation-request)
      (handler oc 'certificate-chain-request #'%certificate-chain-request)
      (handler oc 'csr-request #'%csr-request)
      (handler oc 'add-trusted-root-certificate #'%add-trusted-root-certificate)
      (handler oc 'add-noc #'%add-noc)
      (handler oc 'update-noc #'%update-noc)
      (handler oc 'update-fabric-label #'%update-fabric-label)
      (handler oc 'remove-fabric #'%remove-fabric)
      (handler ac 'open-commissioning-window #'%open-commissioning-window)
      (when (device-basic-verifier device)   ; the Basic feature: without a passcode of its own, UNSUPPORTED_COMMAND
        (handler ac 'open-basic-commissioning-window #'%open-basic-commissioning-window))
      (handler ac 'revoke-commissioning #'%revoke-commissioning))))

(defun %session ()
  (or *interaction-session* (%im-fail :unsupported-access "no session")))

(defun %commissioning-response (code &optional (text ""))
  (list :error-code code :debug-text text))

(defun %arm-fail-safe (device cluster fields)
  (let* ((session (%session))
         (seconds (getf fields :expiry-length-seconds))
         (fail-safe (device-fail-safe device))
         (now (device-now device)))
    (cond ((and fail-safe (not (%fail-safe-owned-by-p fail-safe session)))
           (%commissioning-response +commissioning-busy-with-other-admin+ "armed by another administrator"))
          ((zerop seconds)
           (%disarm-fail-safe device :revert t)
           (%commissioning-response +commissioning-ok+))
          (t
           (let ((seconds (min seconds +max-cumulative-fail-safe-seconds+)))
             (if fail-safe
                 (setf (fail-safe-expiry fail-safe) (+ now seconds))
                 (setf (device-fail-safe device)
                       (%make-fail-safe :session session :fabric (session-fabric session)
                                        :expiry (+ now seconds) :armed-at now)))
             (setf (attribute-value cluster 'breadcrumb) (getf fields :breadcrumb))
             (%wake device)
             (%trace-device device "fail-safe armed for ~d s" seconds)
             (%commissioning-response +commissioning-ok+))))))

(defun %set-regulatory-config (device cluster fields)
  (let ((config (getf fields :new-regulatory-config))
        (country (getf fields :country-code))
        (capability (attribute-value cluster 'location-capability)))
    (unless (<= +regulatory-indoor+ config +regulatory-indoor-outdoor+)
      (%constraint "regulatory configuration ~d is out of range" config))
    (unless (= 2 (length country)) (%constraint "a country code is two characters, got ~s" country))
    (cond ((and (/= capability +regulatory-indoor-outdoor+) (/= config capability))
           (%commissioning-response +commissioning-value-outside-range+ "the location capability does not allow it"))
          (t
           (setf (attribute-value cluster 'regulatory-config) config
                 (attribute-value cluster 'breadcrumb) (getf fields :breadcrumb))
           (let ((basic (node-cluster (device-node device) +endpoint-root+ 'basic-information)))
             (when basic (setf (attribute-value basic 'location) country)))
           (%commissioning-response +commissioning-ok+)))))

(defun %commissioning-complete (device cluster fields)
  (declare (ignore cluster fields))
  (let ((session (%session))
        (fail-safe (device-fail-safe device)))
    (cond ((not (eq :case (session-type session)))
           (%commissioning-response +commissioning-invalid-authentication+ "CommissioningComplete needs a CASE session"))
          ((null fail-safe)
           (%commissioning-response +commissioning-no-fail-safe+ "the fail-safe is not armed"))
          ((not (eq (session-fabric session) (or (fail-safe-added-fabric fail-safe)
                                                 (cdr (fail-safe-replaced-fabric fail-safe))
                                                 (fail-safe-fabric fail-safe))))
           (%commissioning-response +commissioning-invalid-authentication+ "not the fabric the fail-safe was armed for"))
          (t
           (let ((fabric (fail-safe-added-fabric fail-safe)))
             (%disarm-fail-safe device)
             (when fabric
               (close-commissioning-window device)
               (%trace-device device "commissioned into ~a" fabric)
               (when (device-on-commissioned device)
                 (funcall (device-on-commissioned device) device fabric))))
           (%commissioning-response +commissioning-ok+)))))

(defun %require-credentials (device)
  (or (device-credentials device)
      (error 'interaction-error :status +im-status-failure+ :message "the device has no attestation credentials")))

(defun %attestation-challenge (session)
  (or (session-attestation-challenge session)
      (%im-fail :unsupported-access "attestation needs a secured session")))

(defun %check-request-nonce (nonce what)
  (unless (= (length nonce) +attestation-nonce-length+)
    (%constraint "~a is ~d octets, got ~d" what +attestation-nonce-length+ (length nonce)))
  nonce)

(defun %attestation-request (device cluster fields)
  (declare (ignore cluster))
  (let* ((credentials (%require-credentials device))
         (nonce (%check-request-nonce (getf fields :attestation-nonce) "the attestation nonce"))
         (challenge (%attestation-challenge (%session)))
         (elements (encode-attestation-elements
                    :certification-declaration (attestation-credentials-certification-declaration credentials)
                    :nonce nonce :timestamp 0
                    :firmware-info (attestation-credentials-firmware-info credentials))))
    (list :attestation-elements elements
          :attestation-signature (sign-attestation (attestation-credentials-keypair credentials) elements challenge))))

(defun %certificate-chain-request (device cluster fields)
  (declare (ignore cluster))
  (let ((credentials (%require-credentials device))
        (type (getf fields :certificate-type)))
    (list :certificate (cond ((= type +certificate-chain-dac+) (attestation-credentials-dac credentials))
                             ((= type +certificate-chain-pai+) (attestation-credentials-pai credentials))
                             (t (%im-fail :invalid-command "certificate type ~d is neither DAC nor PAI" type))))))

(defun %csr-request (device cluster fields)
  (declare (ignore cluster))
  (let* ((session (%session))
         (credentials (%require-credentials device))
         (fail-safe (%require-fail-safe device session))
         (nonce (%check-request-nonce (getf fields :csr-nonce) "the CSR nonce"))
         (for-update (getf fields :is-for-update-noc))
         (challenge (%attestation-challenge session)))
    (when (and for-update (not (eq :case (session-type session))))
      (%im-fail :invalid-command "a CSR for UpdateNOC needs a CASE session"))
    (when (fail-safe-noc-invoked fail-safe)
      (%constraint "AddNOC or UpdateNOC was already invoked under this fail-safe"))
    (let* ((keypair (generate-p256-keypair))
           (elements (encode-nocsr-elements :csr (make-certificate-signing-request keypair) :nonce nonce)))
      (setf (fail-safe-keypair fail-safe) keypair
            (fail-safe-update-noc-p fail-safe) (and for-update t))
      (list :nocsr-elements elements
            :attestation-signature (sign-attestation (attestation-credentials-keypair credentials) elements challenge)))))

(defun %add-trusted-root-certificate (device cluster fields)
  (declare (ignore cluster))
  (let ((fail-safe (%require-fail-safe device (%session))))
    (when (fail-safe-noc-invoked fail-safe)
      (%constraint "AddNOC or UpdateNOC was already invoked under this fail-safe"))
    (when (fail-safe-root fail-safe)
      (%constraint "a root certificate was already added under this fail-safe"))
    (setf (fail-safe-root fail-safe)
          (handler-case (validate-rcac (getf fields :root-ca-certificate))
            (certificate-error (e) (%im-fail :invalid-command "the root certificate: ~a" (certificate-error-message e)))))
    nil))

(defun %noc-response (status &key fabric-index text)
  (append (list :status-code status)
          (when fabric-index (list :fabric-index fabric-index))
          (when text (list :debug-text text))))

(defun %add-noc (device cluster fields)
  (declare (ignore cluster))
  (let* ((session (%session))
         (fail-safe (%require-fail-safe device session))
         (ipk (getf fields :ipk-value))
         (admin-subject (getf fields :case-admin-subject)))
    (when (fail-safe-noc-invoked fail-safe)
      (%constraint "AddNOC or UpdateNOC was already invoked under this fail-safe"))
    (unless (= (length ipk) +epoch-key-length+)
      (%constraint "the IPK is ~d octets, got ~d" +epoch-key-length+ (length ipk)))
    (let ((keypair (fail-safe-keypair fail-safe))
          (root (fail-safe-root fail-safe)))
      (cond ((or (null keypair) (fail-safe-update-noc-p fail-safe))
             (%noc-response +noc-status-missing-csr+ :text "no CSRRequest preceded AddNOC"))
            ((null root)
             (%noc-response +noc-status-invalid-noc+ :text "no AddTrustedRootCertificate preceded AddNOC"))
            ((>= (length (device-fabrics device)) (device-max-fabrics device))
             (%noc-response +noc-status-table-full+))
            ((not (or (operational-node-id-p admin-subject) (cat-subject-p admin-subject)))
             (%noc-response +noc-status-invalid-admin-subject+))
            (t
             (let ((noc (handler-case (decode-certificate (getf fields :noc-value))
                          (certificate-error (e)
                            (return-from %add-noc (%noc-response +noc-status-invalid-noc+ :text (certificate-error-message e)))))))
               (unless (equalp (certificate-public-key noc) (p256-keypair-public keypair))
                 (return-from %add-noc (%noc-response +noc-status-invalid-public-key+)))
               (unless (operational-node-id-p (certificate-node-id noc))
                 (return-from %add-noc (%noc-response +noc-status-invalid-node-op-id+)))
               (let ((fabric (handler-case
                                 (make-fabric :rcac root :icac (getf fields :icac-value) :noc noc
                                              :operational-keypair keypair :epoch-key ipk
                                              :vendor-id (getf fields :admin-vendor-id))
                               (certificate-error (e)
                                 (return-from %add-noc (%noc-response +noc-status-invalid-noc+ :text (certificate-error-message e)))))))
                 (when (find-if (lambda (f) (and (= (fabric-fabric-id f) (fabric-fabric-id fabric))
                                                 (equalp (fabric-root-public-key f) (fabric-root-public-key fabric))))
                                (device-fabrics device))
                   (return-from %add-noc (%noc-response +noc-status-fabric-conflict+)))
                 (%install-fabric device fabric)
                 (setf (fail-safe-added-fabric fail-safe) fabric
                       (fail-safe-noc-invoked fail-safe) t)
                 ;; the administrator's ACL entry (5.5: the commissioner's CaseAdminSubject)
                 (setf (device-acl device)
                       (append (device-acl device)
                               (list (acl-entry +privilege-administer+ +auth-mode-case+ (list admin-subject)
                                                :fabric-index (fabric-index fabric)))))
                 ;; the PASE session now acts for this fabric (11.17.7.8)
                 (when (eq :pase (session-type session))
                   (setf (session-fabric session) fabric))
                 (%trace-device device "AddNOC: ~a as fabric index ~d" fabric (fabric-index fabric))
                 (%noc-response +noc-status-ok+ :fabric-index (fabric-index fabric)))))))))

(defun %restore-fabric (device current previous)
  "PREVIOUS takes CURRENT's place in the table, the channel and the sessions (UpdateNOC and its undo)."
  (setf (device-fabrics device) (substitute previous current (device-fabrics device))
        (secure-channel-fabrics (device-channel device)) (substitute previous current (secure-channel-fabrics (device-channel device))))
  (dolist (session (secure-channel-sessions (device-channel device)))
    (when (eq current (session-fabric session)) (setf (session-fabric session) previous)))
  (setf (fabric-index current) 0)
  (%refresh-credentials device))

(defun %update-noc (device cluster fields)
  (declare (ignore cluster))
  (let* ((session (%session))
         (fail-safe (%require-fail-safe device session))
         (fabric (session-fabric session)))
    (unless (and (eq :case (session-type session)) fabric)
      (%im-fail :unsupported-access "UpdateNOC needs a CASE session"))
    (when (fail-safe-noc-invoked fail-safe)
      (%constraint "AddNOC or UpdateNOC was already invoked under this fail-safe"))
    (let ((keypair (fail-safe-keypair fail-safe)))
      (unless (and keypair (fail-safe-update-noc-p fail-safe))
        (return-from %update-noc (%noc-response +noc-status-missing-csr+ :text "no CSRRequest for UpdateNOC preceded it")))
      (let ((noc (handler-case (decode-certificate (getf fields :noc-value))
                   (certificate-error (e)
                     (return-from %update-noc (%noc-response +noc-status-invalid-noc+ :text (certificate-error-message e)))))))
        (unless (equalp (certificate-public-key noc) (p256-keypair-public keypair))
          (return-from %update-noc (%noc-response +noc-status-invalid-public-key+)))
        (let ((new (handler-case
                       (make-fabric :rcac (fabric-rcac fabric) :icac (getf fields :icac-value) :noc noc
                                    :operational-keypair keypair :epoch-key (fabric-epoch-key fabric)
                                    :vendor-id (fabric-vendor-id fabric) :label (fabric-label fabric)
                                    :index (fabric-index fabric))
                     (certificate-error (e)
                       (return-from %update-noc (%noc-response +noc-status-invalid-noc+ :text (certificate-error-message e)))))))
          (unless (= (fabric-fabric-id new) (fabric-fabric-id fabric))
            (return-from %update-noc (%noc-response +noc-status-invalid-noc+ :text "the NOC is for another fabric")))
          (%restore-fabric device fabric new)
          (setf (fail-safe-replaced-fabric fail-safe) (cons fabric new)
                (fail-safe-noc-invoked fail-safe) t)
          (%noc-response +noc-status-ok+ :fabric-index (fabric-index new)))))))

(defun %update-fabric-label (device cluster fields)
  (declare (ignore cluster))
  (let* ((session (%session))
         (fabric (and (eq :case (session-type session)) (session-fabric session)))
         (label (getf fields :label)))
    (unless fabric (%im-fail :unsupported-access "UpdateFabricLabel needs a CASE session"))
    (cond ((find-if (lambda (f) (and (not (eq f fabric)) (string= label (fabric-label f)) (plusp (length label))))
                    (device-fabrics device))
           (%noc-response +noc-status-label-conflict+ :fabric-index (fabric-index fabric)))
          (t (setf (fabric-label fabric) label)
             (%refresh-credentials device)
             (%noc-response +noc-status-ok+ :fabric-index (fabric-index fabric))))))

(defun %remove-fabric (device cluster fields)
  (declare (ignore cluster))
  (let* ((index (getf fields :fabric-index))
         (fabric (find-device-fabric device index)))
    (cond ((null fabric) (%noc-response +noc-status-invalid-fabric-index+ :fabric-index index))
          (t
           (%schedule device *fabric-removal-delay*
                      (lambda () (when (member fabric (device-fabrics device)) (%uninstall-fabric device fabric))))
           (%noc-response +noc-status-ok+ :fabric-index index)))))

;;; Administrator Commissioning

(defun %administrator-commissioning-fail (code format &rest args)
  "FAILURE with one of the cluster's status codes."
  (error 'interaction-error :status +im-status-failure+ :cluster-status code :message (apply #'format nil format args)))

(defun %check-commissioning-timeout (seconds)
  (unless (<= +min-commissioning-timeout+ seconds +max-commissioning-timeout+)
    (%im-fail :invalid-command "a commissioning window stays open ~d..~d seconds, not ~d"
              +min-commissioning-timeout+ +max-commissioning-timeout+ seconds))
  seconds)

(defun %require-closed-window (device)
  "Busy while a window is open or a fail-safe is armed: commissioning is going on."
  (when (device-window-mode device)
    (%administrator-commissioning-fail +administrator-commissioning-busy+ "a commissioning window is already open"))
  (when (device-fail-safe device)
    (%administrator-commissioning-fail +administrator-commissioning-busy+ "the fail-safe is armed: commissioning is going on")))

(defun %open-commissioning-window (device cluster fields)
  (declare (ignore cluster))
  (let* ((session (%session))
         (seconds (%check-commissioning-timeout (getf fields :commissioning-timeout)))
         (verifier (getf fields :pake-passcode-verifier))
         (discriminator (getf fields :discriminator))
         (iterations (getf fields :iterations))
         (salt (getf fields :salt)))
    (unless (<= discriminator #xFFF)
      (%im-fail :invalid-command "the discriminator is 12 bits, got ~d" discriminator))
    ;; 11.19.8.1: anything wrong with the PAKE parameters is PAKEParameterError
    (handler-case (progn (%check-pbkdf-parameters salt iterations)
                         (%check-window-verifier verifier))
      (pase-error (e)
        (%administrator-commissioning-fail +administrator-commissioning-pake-parameter-error+ "~a" (pase-error-message e))))
    (%require-closed-window device)
    (open-commissioning-window device :verifier verifier :salt salt :iterations iterations :timeout seconds
                                      :mode :enhanced :discriminator discriminator :fabric (session-fabric session))
    nil))

(defun %open-basic-commissioning-window (device cluster fields)
  (declare (ignore cluster))
  (let ((session (%session))
        (seconds (%check-commissioning-timeout (getf fields :commissioning-timeout))))
    (%require-closed-window device)
    (open-commissioning-window device :timeout seconds :mode :basic :fabric (session-fabric session))
    nil))

(defun %revoke-commissioning (device cluster fields)
  (declare (ignore cluster fields))
  (let ((session (%session)))
    (unless (device-window-mode device)
      (%administrator-commissioning-fail +administrator-commissioning-window-not-open+ "no commissioning window is open"))
    (close-commissioning-window device)
    ;; 11.19.8.3: a PASE session in progress ends with the window (not the revoker's own)
    (dolist (other (secure-channel-sessions (device-channel device)))
      (when (and (eq :pase (session-type other)) (not (eq other session)) (session-active-p other))
        (%trace-device device "revoked: closing ~a" other)
        (%close-session-later device other)))
    nil))

;;; ------------------------------------------------------------------
;;; The commissioner

(defstruct (commissioner (:constructor %make-commissioner))
  "An administrator of FABRIC: its Secure CHANNEL and Interaction MODEL,
and the ROOT-KEYPAIR (and ICA-KEYPAIR under an ICAC) that issue NOCs."
  channel model fabric root-keypair ica-keypair
  (vendor-id #xFFF1)
  (next-node-id 2)
  trust-store
  cd-signing-keys)

(defmethod print-object ((c commissioner) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a" (commissioner-fabric c))))

(defun make-commissioner (channel model &key fabric root-keypair ica-keypair (vendor-id #xFFF1)
                                            (fabric-id 1) (node-id 1) (first-node-id 2)
                                            (trust-store *paa-trust-store*) (cd-signing-keys *cd-signing-keys*))
  "A commissioner on CHANNEL (its Secure Channel) and MODEL (its
Interaction Model).  FABRIC with ROOT-KEYPAIR (and ICA-KEYPAIR when the
NOCs come from an ICAC) are the fabric it administers; without them a
fabric FABRIC-ID is created with this node as NODE-ID.  Devices get node
ids from FIRST-NODE-ID up.  TRUST-STORE and CD-SIGNING-KEYS are what
attestation is checked against."
  (unless (eq (secure-channel-manager channel) (interaction-model-manager model))
    (error "the channel and the model must share one exchange manager"))
  (if fabric
      (unless root-keypair (error "a commissioner's fabric needs its root key pair to issue NOCs"))
      (multiple-value-setq (fabric root-keypair ica-keypair)
        (make-test-fabric :fabric-id fabric-id :node-id node-id :vendor-id vendor-id)))
  (pushnew fabric (secure-channel-fabrics channel))
  (%make-commissioner :channel channel :model model :fabric fabric
                      :root-keypair root-keypair :ica-keypair ica-keypair :vendor-id vendor-id
                      :next-node-id first-node-id :trust-store trust-store :cd-signing-keys cd-signing-keys))

(defun commissioner-issue-noc (commissioner public-key node-id &key case-auth-tags)
  "A NOC on the commissioner's fabric for PUBLIC-KEY and NODE-ID."
  (let ((fabric (commissioner-fabric commissioner)))
    (make-node-certificate :public-key public-key :node-id node-id :fabric-id (fabric-fabric-id fabric)
                           :case-auth-tags case-auth-tags
                           :issuer (or (fabric-icac fabric) (fabric-rcac fabric))
                           :issuer-keypair (or (commissioner-ica-keypair commissioner) (commissioner-root-keypair commissioner)))))

(defstruct (commissioning (:constructor %make-commissioning))
  "One commissioning flow.  STATE is :RUNNING, :COMPLETE (RESULT is a
plist: :node-id :fabric :session (the CASE session) :pase-session :dac
:pai :attestation :fabric-index) or :FAILED (CONDITION says why)."
  commissioner host port passcode salt iterations node-id country-code regulatory-location
  (fail-safe-seconds 60) (attestation :verify) case-auth-tags
  (state :running) (step :pase) result condition on-complete
  pase-session case-session attestation-nonce csr-nonce dac pai attestation-result
  csr-public-key noc fabric-index vendor-id product-id)

(defmethod print-object ((c commissioning) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a:~d ~a ~a" (commissioning-host c) (commissioning-port c) (commissioning-step c) (commissioning-state c))))

(defun commissioning-running-p (c) (eq :running (commissioning-state c)))
(defun commissioning-complete-p (c) (eq :complete (commissioning-state c)))
(defun commissioning-failed-p (c) (eq :failed (commissioning-state c)))

(defun %commissioning-manager (c)
  (secure-channel-manager (commissioner-channel (commissioning-commissioner c))))

(defun %commissioning-done (c state)
  (setf (commissioning-state c) state)
  (when (commissioning-on-complete c) (funcall (commissioning-on-complete c) c)))

(defun %commissioning-fail (c condition)
  (when (commissioning-running-p c)
    (%trace (%commissioning-manager c) "commissioning failed at ~a: ~a" (commissioning-step c) condition)
    (setf (commissioning-condition c) condition)
    ;; closing the PASE session lets the device expire its fail-safe at once
    (let ((pase (commissioning-pase-session c)))
      (when (and pase (session-active-p pase))
        (close-session (commissioner-channel (commissioning-commissioner c)) pase)))
    (%commissioning-done c :failed)))

(defun %commissioning-error (c format &rest args)
  (error 'commissioning-error :step (commissioning-step c) :message (apply #'format nil format args)))

(defmacro %commissioning-guard ((c) &body body)
  "Run BODY for commissioning C; any error fails it."
  `(handler-case (progn ,@body)
     (error (e) (%commissioning-fail ,c e))))

(defun %commissioning-invoke (c session cluster command fields next)
  "Invoke COMMAND of CLUSTER on the root endpoint over SESSION; NEXT gets
the response plist (or the flow fails on a status)."
  (let* ((model (commissioner-model (commissioning-commissioner c)))
         (definition (find-cluster-definition cluster)))
    (start-invoke model session
                  (command-path +endpoint-root+ (cluster-definition-id definition)
                                (command-definition-id (find-command-definition definition command)))
                  (command-fields cluster command fields)
                  :on-complete
                  (lambda (interaction)
                    (%commissioning-guard (c)
                      (when (interaction-failed-p interaction) (error (interaction-condition interaction)))
                      (let ((response (first (interaction-result interaction))))
                        (unless response (%commissioning-error c "~a got no response" command))
                        (multiple-value-bind (value kind) (invoke-response-value response)
                          (cond ((not (eq kind :status)) (funcall next value))
                                ((im-status-success-p value) (funcall next nil)) ; a command without a response
                                (t (%commissioning-error c "~a was answered ~a" command
                                                         (im-status-name (im-status-status value))))))))))))

(defun %commissioning-read (c session paths next)
  (let ((model (commissioner-model (commissioning-commissioner c))))
    (start-read model session paths
                :on-complete (lambda (interaction)
                               (%commissioning-guard (c)
                                 (when (interaction-failed-p interaction) (error (interaction-condition interaction)))
                                 (funcall next (interaction-result interaction)))))))

(defun %expect-commissioning-ok (c response what)
  (let ((code (getf response :error-code)))
    (unless (eql code +commissioning-ok+)
      (%commissioning-error c "~a failed with CommissioningError ~d~@[: ~a~]" what code
                            (let ((text (getf response :debug-text))) (and (plusp (length text)) text))))))

(defun %commissioning-step (c step)
  "Run STEP of the flow; each step ends by asking for the next one."
  (setf (commissioning-step c) step)
  (%trace (%commissioning-manager c) "commissioning ~a:~d: ~a" (commissioning-host c) (commissioning-port c) step)
  (let* ((commissioner (commissioning-commissioner c))
         (channel (commissioner-channel commissioner))
         (fabric (commissioner-fabric commissioner))
         (pase (commissioning-pase-session c)))
    (%commissioning-guard (c)
      (ecase step
        (:pase
         (start-pase channel (commissioning-host c) (commissioning-port c)
                     :passcode (commissioning-passcode c) :salt (commissioning-salt c)
                     :iterations (commissioning-iterations c)
                     :on-complete (lambda (handshake)
                                    (%commissioning-guard (c)
                                      (unless (handshake-complete-p handshake) (error (handshake-error handshake)))
                                      (setf (commissioning-pase-session c) (handshake-session handshake))
                                      (%commissioning-step c :arm-fail-safe)))))
        (:arm-fail-safe
         (%commissioning-invoke c pase 'general-commissioning 'arm-fail-safe
                                (list :expiry-length-seconds (commissioning-fail-safe-seconds c) :breadcrumb 1)
                                (lambda (response)
                                  (%expect-commissioning-ok c response "ArmFailSafe")
                                  (%commissioning-step c :read-basic-information))))
        (:read-basic-information
         (%commissioning-read c pase (list (attribute-path +endpoint-root+ +cluster-basic-information+ 2)
                                           (attribute-path +endpoint-root+ +cluster-basic-information+ 4))
                              (lambda (reports)
                                (setf (commissioning-vendor-id c) (attribute-report-value (first reports))
                                      (commissioning-product-id c) (attribute-report-value (second reports)))
                                (unless (and (integerp (commissioning-vendor-id c)) (integerp (commissioning-product-id c)))
                                  (%commissioning-error c "Basic Information has no vendor and product id"))
                                (%commissioning-step c :regulatory-config))))
        (:regulatory-config
         (if (commissioning-country-code c)
             (%commissioning-invoke c pase 'general-commissioning 'set-regulatory-config
                                    (list :new-regulatory-config (or (commissioning-regulatory-location c) +regulatory-indoor-outdoor+)
                                          :country-code (commissioning-country-code c) :breadcrumb 2)
                                    (lambda (response)
                                      (%expect-commissioning-ok c response "SetRegulatoryConfig")
                                      (%commissioning-step c :dac)))
             (%commissioning-step c :dac)))
        (:dac
         (%commissioning-invoke c pase 'operational-credentials 'certificate-chain-request
                                (list :certificate-type +certificate-chain-dac+)
                                (lambda (response)
                                  (setf (commissioning-dac c) (getf response :certificate))
                                  (%commissioning-step c :pai))))
        (:pai
         (%commissioning-invoke c pase 'operational-credentials 'certificate-chain-request
                                (list :certificate-type +certificate-chain-pai+)
                                (lambda (response)
                                  (setf (commissioning-pai c) (getf response :certificate))
                                  (%commissioning-step c :attestation))))
        (:attestation
         (setf (commissioning-attestation-nonce c) (random-octets +attestation-nonce-length+))
         (%commissioning-invoke c pase 'operational-credentials 'attestation-request
                                (list :attestation-nonce (commissioning-attestation-nonce c))
                                (lambda (response)
                                  (%verify-commissioning-attestation c response)
                                  (%commissioning-step c :csr))))
        (:csr
         (setf (commissioning-csr-nonce c) (random-octets +attestation-nonce-length+))
         (%commissioning-invoke c pase 'operational-credentials 'csr-request
                                (list :csr-nonce (commissioning-csr-nonce c))
                                (lambda (response)
                                  (setf (commissioning-csr-public-key c)
                                        (verify-nocsr :elements (getf response :nocsr-elements)
                                                      :signature (getf response :attestation-signature)
                                                      :challenge (session-attestation-challenge pase)
                                                      :nonce (commissioning-csr-nonce c)
                                                      :dac-public-key (certificate-public-key (decode-certificate-der (commissioning-dac c)))))
                                  (%commissioning-step c :add-root))))
        (:add-root
         (%commissioning-invoke c pase 'operational-credentials 'add-trusted-root-certificate
                                (list :root-ca-certificate (certificate-octets* (fabric-rcac fabric)))
                                (lambda (response) (declare (ignore response)) (%commissioning-step c :add-noc))))
        (:add-noc
         (unless (commissioning-node-id c)
           (setf (commissioning-node-id c) (commissioner-next-node-id commissioner))
           (incf (commissioner-next-node-id commissioner)))
         (setf (commissioning-noc c)
               (commissioner-issue-noc commissioner (commissioning-csr-public-key c) (commissioning-node-id c)
                                       :case-auth-tags (commissioning-case-auth-tags c)))
         (%commissioning-invoke c pase 'operational-credentials 'add-noc
                                (append (list :noc-value (certificate-octets* (commissioning-noc c)))
                                        (when (fabric-icac fabric) (list :icac-value (certificate-octets* (fabric-icac fabric))))
                                        (list :ipk-value (fabric-epoch-key fabric)
                                              :case-admin-subject (fabric-node-id fabric)
                                              :admin-vendor-id (commissioner-vendor-id commissioner)))
                                (lambda (response)
                                  (unless (eql +noc-status-ok+ (getf response :status-code))
                                    (%commissioning-error c "AddNOC failed with NodeOperationalCertStatus ~d~@[: ~a~]"
                                                          (getf response :status-code) (getf response :debug-text)))
                                  (setf (commissioning-fabric-index c) (getf response :fabric-index))
                                  (%commissioning-step c :case))))
        (:case
         (start-case channel (commissioning-host c) (commissioning-port c)
                     :fabric fabric :peer-node-id (commissioning-node-id c) :resume nil
                     :on-complete (lambda (handshake)
                                    (%commissioning-guard (c)
                                      (unless (handshake-complete-p handshake) (error (handshake-error handshake)))
                                      (setf (commissioning-case-session c) (handshake-session handshake))
                                      (%commissioning-step c :complete)))))
        (:complete
         (%commissioning-invoke c (commissioning-case-session c) 'general-commissioning 'commissioning-complete nil
                                (lambda (response)
                                  (%expect-commissioning-ok c response "CommissioningComplete")
                                  (%commissioning-step c :done))))
        (:done
         (close-session channel pase)
         (setf (commissioning-result c)
               (list :node-id (commissioning-node-id c) :fabric fabric :fabric-index (commissioning-fabric-index c)
                     :session (commissioning-case-session c) :pase-session pase
                     :dac (commissioning-dac c) :pai (commissioning-pai c)
                     :attestation (commissioning-attestation-result c)
                     :vendor-id (commissioning-vendor-id c) :product-id (commissioning-product-id c)))
         (%trace (%commissioning-manager c) "commissioned ~a:~d as node ~16,'0x"
                 (commissioning-host c) (commissioning-port c) (commissioning-node-id c))
         (%commissioning-done c :complete))))))

(defun %verify-commissioning-attestation (c response)
  (let ((commissioner (commissioning-commissioner c))
        (pase (commissioning-pase-session c)))
    (ecase (commissioning-attestation c)
      (:verify
       (setf (commissioning-attestation-result c)
             (verify-device-attestation :dac (commissioning-dac c) :pai (commissioning-pai c)
                                        :elements (getf response :attestation-elements)
                                        :signature (getf response :attestation-signature)
                                        :challenge (session-attestation-challenge pase)
                                        :nonce (commissioning-attestation-nonce c)
                                        :vendor-id (commissioning-vendor-id c) :product-id (commissioning-product-id c)
                                        :trust-store (commissioner-trust-store commissioner)
                                        :cd-signing-keys (commissioner-cd-signing-keys commissioner))))
      (:ignore
       ;; still the signature: the device must hold the DAC's key
       (unless (verify-attestation-signature (certificate-public-key (decode-certificate-der (commissioning-dac c)))
                                             (getf response :attestation-elements)
                                             (session-attestation-challenge pase)
                                             (getf response :attestation-signature))
         (%commissioning-error c "the attestation signature is not the DAC's"))
       (setf (commissioning-attestation-result c) (list :dac (decode-certificate-der (commissioning-dac c))))))))

(defun start-commissioning (commissioner host port &key passcode salt iterations node-id country-code
                                                       regulatory-location (fail-safe-seconds 60)
                                                       (attestation :verify) case-auth-tags on-complete)
  "Commission the device at HOST:PORT with PASSCODE (SALT and ITERATIONS
when known) into the commissioner's fabric as NODE-ID (default: the next
free one), the flow of section 5.5.  COUNTRY-CODE sets the regulatory
configuration (REGULATORY-LOCATION, default indoor/outdoor).  ATTESTATION
:VERIFY checks the device's DAC chain and certification declaration
against the trust store; :IGNORE accepts any device whose signature is
its DAC's (development devices).  Returns the COMMISSIONING; ON-COMPLETE
is called with it when it is done."
  (let ((c (%make-commissioning :commissioner commissioner :host host :port port
                                :passcode passcode :salt salt :iterations iterations
                                :node-id node-id :country-code country-code :regulatory-location regulatory-location
                                :fail-safe-seconds fail-safe-seconds :attestation attestation
                                :case-auth-tags case-auth-tags :on-complete on-complete)))
    (unless (member attestation '(:verify :ignore)) (error "ATTESTATION is :VERIFY or :IGNORE, not ~s" attestation))
    (%commissioning-step c :pase)
    c))

(defun commissioning-wait (c &key (timeout 120))
  "Run the manager until commissioning C is done: its result plist, or
the error it failed with is signalled."
  (exchange-manager-run (%commissioning-manager c) :until (lambda () (not (commissioning-running-p c))) :timeout timeout)
  (when (commissioning-running-p c)
    (%commissioning-fail c (make-condition 'commissioning-error :step (commissioning-step c)
                                                                :message (format nil "no progress in ~a seconds" timeout))))
  (if (commissioning-complete-p c)
      (commissioning-result c)
      (error (commissioning-condition c))))

(defun commission (commissioner host port &rest args &key (timeout 120) &allow-other-keys)
  "START-COMMISSIONING and wait: the result plist, or an error."
  (commissioning-wait (apply #'start-commissioning commissioner host port :allow-other-keys t args) :timeout timeout))
