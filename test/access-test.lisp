(defpackage :cl-matter.access.tests
  (:use :cl :fiveam :cl-matter)
  (:import-from :cl-matter.exchange.tests
                #:make-rig #:rig-a #:rig-b #:rig-clock #:rig-b-port #:rig-a-port
                #:pump #:run-rig #:secured-pair)
  (:import-from :cl-matter.interaction.tests
                #:+echo+ #:nr #:%make-nr #:nr-rig #:nr-a #:nr-b #:nr-node #:nr-light #:nr-sa #:nr-sb
                #:complete #:read-one #:report-status #:light-on #:settle #:subscribe #:wait-reports #:now)
  (:import-from :cl-matter.data-model.tests #:make-echo-cluster))
(in-package :cl-matter.access.tests)

(def-suite access-tests :description "Access control: privileges, the ACL, and its enforcement"
  :in cl-matter.tests:test-suite)
(in-suite access-tests)

;;; ------------------------------------------------------------------
;;; Privileges and the definitions

(test privilege-hierarchy
  (is (= 1 (privilege-value :view)))
  (is (= 5 (privilege-value +privilege-administer+)))
  (is (eq :manage (privilege-name 4)))
  (signals error (privilege-value :root))
  (signals error (privilege-value 6))
  (signals error (privilege-name 0))
  ;; 6.6.2.2: what each privilege includes
  (flet ((grants (held) (remove-if-not (lambda (p) (privilege-grants-p held p)) '(:view :proxy-view :operate :manage :administer))))
    (is (equal '(:view) (grants :view)))
    (is (equal '(:view :proxy-view) (grants :proxy-view)))
    (is (equal '(:view :operate) (grants :operate)))
    (is (equal '(:view :operate :manage) (grants :manage)))
    (is (equal '(:view :proxy-view :operate :manage :administer) (grants :administer)))))

(defun attribute-privileges (cluster attribute)
  (let ((a (find-attribute-definition (find-cluster-definition cluster) attribute)))
    (list (privilege-name (attribute-definition-read-privilege a)) (privilege-name (attribute-definition-write-privilege a)))))

(defun command-privilege (cluster command)
  (privilege-name (command-definition-privilege (find-command-definition (find-cluster-definition cluster) command))))

(test definitions-carry-privileges
  ;; the defaults: View to read, Operate to write and invoke
  (is (equal '(:view :operate) (attribute-privileges 'on-off 'on-off)))
  (is (equal '(:view :operate) (attribute-privileges 'test-echo 'names)))
  (is (eq :operate (command-privilege 'on-off 'toggle)))
  (is (eq :operate (command-privilege 'test-echo 'echo)))
  ;; the specification's overrides
  (is (equal '(:view :manage) (attribute-privileges 'on-off 'start-up-on-off)))
  (is (equal '(:view :manage) (attribute-privileges 'basic-information 'node-label)))
  (is (equal '(:view :administer) (attribute-privileges 'basic-information 'location)))
  (is (eq :manage (command-privilege 'identify 'identify)))
  (is (eq :manage (command-privilege 'identify 'trigger-effect)))
  (is (equal '(:administer :administer) (attribute-privileges 'access-control 'acl)))
  (is (equal '(:view :operate) (attribute-privileges 'access-control 'subjects-per-access-control-entry)))
  (is (equal '(:administer :operate) (attribute-privileges 'operational-credentials 'nocs)))
  (is (equal '(:view :operate) (attribute-privileges 'operational-credentials 'fabrics)))
  (dolist (command '(attestation-request certificate-chain-request csr-request add-noc update-noc
                     update-fabric-label remove-fabric add-trusted-root-certificate))
    (is (eq :administer (command-privilege 'operational-credentials command)) "~a" command))
  (dolist (command '(arm-fail-safe set-regulatory-config commissioning-complete))
    (is (eq :administer (command-privilege 'general-commissioning command)) "~a" command))
  (is (equal '(:view :administer) (attribute-privileges 'general-commissioning 'breadcrumb)))
  (is (equal '(:administer :operate) (attribute-privileges 'network-commissioning 'networks)))
  (is (equal '(:view :administer) (attribute-privileges 'network-commissioning 'interface-enabled)))
  (is (equal '(:view :operate) (attribute-privileges 'network-commissioning 'scan-max-time-seconds)))
  ;; the global attributes are readable with View
  (is (= +privilege-view+ (attribute-definition-read-privilege (find +attribute-cluster-revision+ *global-attribute-definitions*
                                                                     :key #'attribute-definition-id)))))

;;; ------------------------------------------------------------------
;;; Subjects and entries, without a network

(defun case-session (&key (node-id #x1111) cats (fabric-index 1))
  "A CASE session as the server sees it, with a fabric at FABRIC-INDEX (0: none)."
  (let ((session (make-secured-session :type :case :role :responder :local-session-id 1 :peer-session-id 2
                                       :keys (derive-session-keys (make-array 32 :element-type '(unsigned-byte 8)))
                                       :local-node-id #x2222 :peer-node-id node-id :peer-case-auth-tags cats)))
    (when (plusp fabric-index)
      (let ((fabric (make-test-fabric :node-id #x2222)))
        (setf (fabric-index fabric) fabric-index
              (session-fabric session) fabric)))
    session))

(defun pase-session ()
  (make-secured-session :type :pase :role :responder :local-session-id 1 :peer-session-id 2
                        :keys (derive-session-keys (make-array 32 :element-type '(unsigned-byte 8)))))

(defun acl-node (&rest entries)
  "(values node light-endpoint acl-cluster): a root with Access Control holding ENTRIES, a light on endpoint 1."
  (let* ((node (make-basic-node :vendor-id 1 :product-id 2
                                :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                                  :clusters (list (make-identify-cluster) (make-on-off-cluster))))))
         (acl (add-cluster (find-endpoint node 0) (make-cluster 'access-control))))
    (setf (attribute-value acl 'acl) entries)
    (values node (find-endpoint node 1) acl)))

(test subjects-of-a-session
  (is (null (session-subjects (pase-session))))
  (is (equal '(#x1111) (session-subjects (case-session))))
  (is (equal (list #x1111 #xFFFFFFFDABCD0002 #xFFFFFFFD00010001)
             (session-subjects (case-session :cats '(#xABCD0002 #x00010001)))))
  (is (= #xFFFFFFFDABCD0002 (cat-subject #xABCD0002)))
  (signals error (cat-subject #xABCD0000))
  (is (cat-subject-p #xFFFFFFFDABCD0002))
  (is (not (cat-subject-p #xFFFFFFFDABCD0000)))
  (is (not (cat-subject-p #xFFFFFFFCABCD0002)))
  (is (not (cat-subject-p #x1111))))

(test entries-and-subjects
  (multiple-value-bind (node light) (acl-node)
    (let ((admin (acl-entry +privilege-administer+ +auth-mode-case+ '(#x1111) :fabric-index 1)))
      (flet ((granted (privilege &key (session (case-session)) (entries (list admin)))
               (setf (attribute-value (node-cluster node 0 +cluster-access-control+) 'acl) entries)
               (access-granted-p node session light +cluster-on-off+ privilege)))
        ;; nobody, the commissioner, a stranger
        (is (eq t (granted :administer :session nil :entries '())))
        (is (eq t (granted :administer :session (pase-session) :entries '())))
        (is (eq nil (granted :view :entries '())))
        ;; an unsecured session holds nothing, a CASE session without a fabric neither
        (is (eq nil (granted :view :session (make-unsecured-session :role :responder :ephemeral-node-id 7))))
        (is (eq nil (granted :view :session (case-session :fabric-index 0))))
        ;; the privilege held includes the lower ones
        (dolist (p '(:view :proxy-view :operate :manage :administer)) (is (eq t (granted p)) "admin holds ~a" p))
        (let ((operate (list (acl-entry +privilege-operate+ +auth-mode-case+ '(#x1111) :fabric-index 1))))
          (is (eq t (granted :view :entries operate)))
          (is (eq t (granted :operate :entries operate)))
          (is (eq nil (granted :manage :entries operate)))
          (is (eq nil (granted :proxy-view :entries operate))))
        (let ((proxy (list (acl-entry +privilege-proxy-view+ +auth-mode-case+ '(#x1111) :fabric-index 1))))
          (is (eq t (granted :view :entries proxy)))
          (is (eq nil (granted :operate :entries proxy))))
        ;; another fabric's entry, another node's entry, an entry for everybody on the fabric
        (is (eq nil (granted :view :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ '(#x1111) :fabric-index 2)))))
        (is (eq nil (granted :view :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ '(#x1112) :fabric-index 1)))))
        (is (eq t (granted :view :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ '(7 #x1111) :fabric-index 1)))))
        (is (eq t (granted :administer :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ :null :fabric-index 1)))))
        (is (eq t (granted :administer :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ '() :fabric-index 1)))))
        ;; the Group and PASE auth modes never match a CASE session
        (is (eq nil (granted :view :entries (list (acl-entry +privilege-administer+ +auth-mode-group+ '(#x1111) :fabric-index 1)))))
        (is (eq nil (granted :view :entries (list (acl-entry +privilege-administer+ +auth-mode-pase+ :null :fabric-index 1)))))
        (is (eq t (granted :administer :entries (list (acl-entry +privilege-administer+ +auth-mode-case+ '(#x1111) :fabric-index 1 :targets '())))))
        ;; one entry granting among several
        (is (eq t (granted :operate :entries (list (acl-entry +privilege-view+ +auth-mode-case+ '(#x1111) :fabric-index 1)
                                                   (acl-entry +privilege-operate+ +auth-mode-case+ :null :fabric-index 1)))))
        ;; a node without an Access Control cluster is not controlled at all
        (let ((bare (make-basic-node :vendor-id 1 :product-id 2 :endpoints (list (make-endpoint 1 :clusters (list (make-on-off-cluster)))))))
          (is (eq t (access-granted-p bare (case-session :fabric-index 0) (find-endpoint bare 1) +cluster-on-off+ :administer))))))))

(test entries-and-case-authenticated-tags
  (multiple-value-bind (node light) (acl-node)
    (flet ((granted (entry-subject &rest cats)
             (setf (attribute-value (node-cluster node 0 +cluster-access-control+) 'acl)
                   (list (acl-entry +privilege-operate+ +auth-mode-case+ (list entry-subject) :fabric-index 1)))
             (access-granted-p node (case-session :node-id #x3333 :cats cats) light +cluster-on-off+ :operate)))
      ;; 6.6.2.1.2: the identifier must be the same, the session's version at least the entry's
      (is (eq t (granted #xFFFFFFFDABCD0002 #xABCD0002)))
      (is (eq t (granted #xFFFFFFFDABCD0001 #xABCD0002)))
      (is (eq nil (granted #xFFFFFFFDABCD0003 #xABCD0002)))
      (is (eq nil (granted #xFFFFFFFDABCE0002 #xABCD0002)))
      (is (eq nil (granted #xFFFFFFFDABCD0002)))
      (is (eq t (granted #xFFFFFFFDABCD0002 #x00010001 #xABCD0005)))
      ;; a node id entry does not match a CAT, nor a CAT entry a node id
      (is (eq nil (granted #xABCD0002 #xABCD0002)))
      (is (eq nil (granted #xFFFFFFFD00003333 #xABCD0002)))
      (is (eq t (granted #x3333 #xABCD0002))))))

(test entries-and-targets
  (multiple-value-bind (node light) (acl-node)
    (let ((root (find-endpoint node 0)))
      (flet ((granted (endpoint cluster &rest targets)
               (setf (attribute-value (node-cluster node 0 +cluster-access-control+) 'acl)
                     (list (acl-entry +privilege-operate+ +auth-mode-case+ '(#x1111) :fabric-index 1
                                      :targets (if targets targets :null))))
               (access-granted-p node (case-session) endpoint cluster :operate))
             (target (&key (cluster :null) (endpoint :null) (device-type :null))
               (list :cluster cluster :endpoint endpoint :device-type device-type)))
        (is (eq t (granted light +cluster-on-off+)))
        (is (eq t (granted root +cluster-basic-information+)))
        ;; by cluster
        (is (eq t (granted light +cluster-on-off+ (target :cluster +cluster-on-off+))))
        (is (eq nil (granted light +cluster-identify+ (target :cluster +cluster-on-off+))))
        (is (eq t (granted root +cluster-on-off+ (target :cluster +cluster-on-off+))))
        ;; by endpoint
        (is (eq t (granted light +cluster-identify+ (target :endpoint 1))))
        (is (eq nil (granted root +cluster-basic-information+ (target :endpoint 1))))
        ;; by device type
        (is (eq t (granted light +cluster-on-off+ (target :device-type +device-type-on-off-light+))))
        (is (eq nil (granted root +cluster-basic-information+ (target :device-type +device-type-on-off-light+))))
        (is (eq t (granted root +cluster-basic-information+ (target :device-type +device-type-root-node+))))
        ;; cluster and endpoint, cluster and device type
        (is (eq t (granted light +cluster-on-off+ (target :cluster +cluster-on-off+ :endpoint 1))))
        (is (eq nil (granted light +cluster-identify+ (target :cluster +cluster-on-off+ :endpoint 1))))
        (is (eq nil (granted root +cluster-on-off+ (target :cluster +cluster-on-off+ :endpoint 1))))
        (is (eq nil (granted light +cluster-on-off+ (target :cluster +cluster-on-off+ :device-type +device-type-root-node+))))
        ;; any one of several targets
        (is (eq t (granted light +cluster-identify+ (target :cluster +cluster-on-off+) (target :endpoint 1))))
        (is (eq nil (granted root +cluster-identify+ (target :cluster +cluster-on-off+) (target :endpoint 1))))))))

;;; ------------------------------------------------------------------
;;; Enforcement over the rig: a CASE session on fabric 1 from node #x1111

(defun make-acl-rig (&rest entries)
  "A node rig whose node serves an Access Control cluster with ENTRIES and
whose sessions are CASE on fabric 1 (A is node #x1111)."
  (let ((rig (make-rig)))
    (multiple-value-bind (sa sb) (secured-pair rig :type :case)
      (let* ((light (make-on-off-cluster))
             (node (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id 1
                                    :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                                      :clusters (list (make-identify-cluster) light (make-echo-cluster))))))
             (fabric (make-test-fabric :node-id #x2222)))
        (setf (fabric-index fabric) 1
              (session-fabric sb) fabric)
        (let ((acl (add-cluster (find-endpoint node 0) (make-cluster 'access-control))))
          (setf (attribute-value acl 'acl) entries))
        (%make-nr :rig rig :node node :light light :sa sa :sb sb
                  :a (make-interaction-model (rig-a rig))
                  :b (make-interaction-model (rig-b rig) :node node))))))

(defun entry (privilege &key (subjects '(#x1111)) (targets :null))
  (acl-entry (privilege-value privilege) +auth-mode-case+ subjects :targets targets :fabric-index 1))

(defun set-acl (nr &rest entries)
  (setf (attribute-value (node-cluster (nr-node nr) 0 +cluster-access-control+) 'acl) entries))

(defun read-status (nr path)
  "The status name of a concrete read, or :DATA when it reported data."
  (let ((report (read-one nr path)))
    (if (attribute-report-data report) :data (report-status report))))

(defun read-all (nr path)
  "The attribute paths a (wildcard) read reported, data or status."
  (mapcar #'attribute-report-path (complete nr (start-read (nr-a nr) (nr-sa nr) (list path)))))

(defun write-status (nr endpoint cluster attribute value)
  (im-status-name (im-status-status (attribute-status-status
                                     (first (complete nr (start-write (nr-a nr) (nr-sa nr)
                                                                      (list (attribute-write endpoint cluster attribute value)))))))))

(defun invoke-status (nr endpoint cluster command &optional fields)
  "The status name of an invoke, or :RESPONSE when a command response came back."
  (let* ((definition (find-cluster-definition cluster))
         (responses (complete nr (start-invoke (nr-a nr) (nr-sa nr)
                                               (command-path endpoint (cluster-definition-id definition)
                                                             (command-definition-id (find-command-definition definition command)))
                                               (command-fields cluster command fields)))))
    (multiple-value-bind (value kind) (invoke-response-value (first responses))
      (if (eq kind :status) (im-status-name (im-status-status value)) :response))))

(test reads-are-checked
  (let ((nr (make-acl-rig)))
    ;; nothing granted: a concrete path is refused, a wildcard finds nothing
    (is (eq :unsupported-access (read-status nr (attribute-path 1 +cluster-on-off+ 0))))
    (is (eq :unsupported-access (read-status nr (attribute-path 1 +cluster-on-off+ +attribute-cluster-revision+))))
    (is (eq :unsupported-access (read-status nr (attribute-path 0 +cluster-basic-information+ 1))))
    (is (null (read-all nr (attribute-path 1 nil nil))))
    (is (null (read-all nr (attribute-path nil nil nil))))
    ;; what does not exist is reported as such, before access is considered
    (is (eq :unsupported-endpoint (read-status nr (attribute-path 9 +cluster-on-off+ 0))))
    (is (eq :unsupported-cluster (read-status nr (attribute-path 1 #x9999 0))))
    (is (eq :unsupported-attribute (read-status nr (attribute-path 1 +cluster-on-off+ 99))))
    ;; View on the light only
    (set-acl nr (entry :view :targets (list (list :cluster +cluster-on-off+ :endpoint :null :device-type :null))))
    (is (eq :data (read-status nr (attribute-path 1 +cluster-on-off+ 0))))
    (is (eq :data (read-status nr (attribute-path 1 +cluster-on-off+ +attribute-attribute-list+))))
    (is (eq :unsupported-access (read-status nr (attribute-path 1 +cluster-identify+ 0))))
    (let ((paths (read-all nr (attribute-path nil nil nil))))
      (is (plusp (length paths)))
      (is (every (lambda (p) (and (= 1 (attribute-path-endpoint p)) (= +cluster-on-off+ (attribute-path-cluster p)))) paths)))
    ;; the ACL itself takes Administer
    (set-acl nr (entry :manage))
    (is (eq :unsupported-access (read-status nr (attribute-path 0 +cluster-access-control+ 0))))
    (is (eq :data (read-status nr (attribute-path 0 +cluster-access-control+ 2))))
    (is (eq :data (read-status nr (attribute-path 1 +cluster-identify+ 0))))
    (set-acl nr (entry :administer))
    (is (eq :data (read-status nr (attribute-path 0 +cluster-access-control+ 0))))))

(test writes-are-checked
  (let ((nr (make-acl-rig (entry :view))))
    (is (eq :unsupported-access (write-status nr 1 +cluster-identify+ 0 5)))
    (is (= 0 (attribute-value (node-cluster (nr-node nr) 1 +cluster-identify+) 'identify-time)))
    ;; what cannot be written at all is refused as such before access is considered
    (is (eq :unsupported-write (write-status nr 1 +cluster-on-off+ 0 t)))
    (is (eq :unsupported-attribute (write-status nr 1 +cluster-identify+ 99 (tlv nil :unsigned 5))))
    (is (eq :unsupported-cluster (write-status nr 1 #x9999 0 (tlv nil :unsigned 5))))
    ;; Operate writes IdentifyTime, not NodeLabel (Manage) nor Location (Administer)
    (set-acl nr (entry :operate))
    (is (eq :success (write-status nr 1 +cluster-identify+ 0 5)))
    (is (= 5 (attribute-value (node-cluster (nr-node nr) 1 +cluster-identify+) 'identify-time)))
    (is (eq :unsupported-access (write-status nr 0 +cluster-basic-information+ 5 "Hall")))
    (set-acl nr (entry :manage))
    (is (eq :success (write-status nr 0 +cluster-basic-information+ 5 "Hall")))
    (is (eq :unsupported-access (write-status nr 0 +cluster-basic-information+ 6 "DE")))
    (set-acl nr (entry :administer))
    (is (eq :success (write-status nr 0 +cluster-basic-information+ 6 "DE")))
    ;; a write of several attributes answers each on its own
    (set-acl nr (entry :operate :targets (list (list :cluster +cluster-identify+ :endpoint :null :device-type :null))))
    (let ((statuses (complete nr (start-write (nr-a nr) (nr-sa nr)
                                              (list (attribute-write 1 +cluster-identify+ 0 7)
                                                    (attribute-write 1 +echo+ 1 '("a")))))))
      (is (equal '(:success :unsupported-access)
                 (mapcar (lambda (s) (im-status-name (im-status-status (attribute-status-status s)))) statuses))))))

(test invokes-are-checked
  (let ((nr (make-acl-rig (entry :view))))
    (is (eq :unsupported-access (invoke-status nr 1 'on-off 'toggle)))
    (is (eq nil (light-on nr)))
    ;; what does not exist is reported as such before access is considered
    (is (eq :unsupported-command (invoke-status nr 1 'on-off 'off-with-effect '(:effect-identifier 0 :effect-variant 0))))
    (is (eq :unsupported-endpoint (invoke-status nr 9 'on-off 'toggle)))
    ;; a timed command is refused for access before it is refused for not being timed
    (is (eq :unsupported-access (invoke-status nr 1 'test-echo 'timed-only)))
    (set-acl nr (entry :operate))
    (is (eq :needs-timed-interaction (invoke-status nr 1 'test-echo 'timed-only)))
    (is (eq :success (invoke-status nr 1 'on-off 'toggle)))
    (is (eq t (light-on nr)))
    (is (eq :response (invoke-status nr 1 'test-echo 'echo '(:text "hi"))))
    ;; Identify takes Manage
    (is (eq :unsupported-access (invoke-status nr 1 'identify 'identify '(:identify-time 3))))
    (set-acl nr (entry :manage))
    (is (eq :success (invoke-status nr 1 'identify 'identify '(:identify-time 3))))
    ;; by target: the light's endpoint only
    (set-acl nr (entry :operate :targets (list (list :cluster :null :endpoint 1 :device-type :null))))
    (is (eq :success (invoke-status nr 1 'on-off 'toggle)))
    (is (eq nil (light-on nr)))
    (is (eq :data (read-status nr (attribute-path 1 +cluster-identify+ 0))))
    (is (eq :unsupported-access (read-status nr (attribute-path 0 +cluster-basic-information+ 1))))))

(test subscriptions-are-checked
  (let ((nr (make-acl-rig (entry :view :targets (list (list :cluster +cluster-on-off+ :endpoint :null :device-type :null))))))
    ;; a wildcard subscription primes with what may be read and reports only that
    (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 nil nil)))
      (is (subscription-active-p sub))
      (is (plusp (length (subscription-primed-reports sub))))
      (is (every (lambda (r) (= +cluster-on-off+ (attribute-path-cluster (attribute-report-path r))))
                 (subscription-primed-reports sub)))
      (settle nr :seconds 2)
      (setf (attribute-value (node-cluster (nr-node nr) 1 +cluster-identify+) 'identify-time) 9)
      (setf (attribute-value (nr-light nr) 'on-off) t)
      (let ((reports (wait-reports nr cell 1)))
        (destructuring-bind (at subscription attributes) (first reports)
          (declare (ignore at subscription))
          (is (= 1 (length attributes)))
          (is (equalp (attribute-path 1 +cluster-on-off+ 0) (attribute-report-path (first attributes))))))
      ;; the privilege goes away: the next change is left out of the report
      (set-acl nr)
      (settle nr :seconds 2)
      (setf (attribute-value (nr-light nr) 'on-off) nil)
      (let ((reports (wait-reports nr cell 2)))
        (is (null (third (second reports)))))
      (is (subscription-active-p sub)))
    ;; a concrete subscription is primed with the refusal and reports it
    (let ((nr (make-acl-rig)))
      (multiple-value-bind (sub cell) (subscribe nr (list (attribute-path 1 +cluster-on-off+ 0)))
        (is (subscription-active-p sub))
        (is (= 1 (length (subscription-primed-reports sub))))
        (is (eq :unsupported-access (report-status (first (subscription-primed-reports sub)))))
        (settle nr :seconds 2)
        (setf (attribute-value (nr-light nr) 'on-off) t)
        (let ((reports (wait-reports nr cell 1)))
          (is (eq :unsupported-access (report-status (first (third (first reports)))))))
        ;; granted now: the next change is reported with its data
        (set-acl nr (entry :view))
        (settle nr :seconds 2)
        (setf (attribute-value (nr-light nr) 'on-off) nil)
        (let ((reports (wait-reports nr cell 2)))
          (is (eq nil (attribute-report-value (first (third (second reports)))))))))))

(test pase-and-local-access-are-free
  ;; the same node over a PASE pair: the commissioner's implicit Administer
  (let ((nr (make-acl-rig)))
    (multiple-value-bind (sa sb) (secured-pair (nr-rig nr) :type :pase :local-a 31 :local-b 32)
      (declare (ignore sb))
      (setf (nr-sa nr) sa)
      (is (eq :data (read-status nr (attribute-path 0 +cluster-access-control+ 0))))
      (is (eq :success (write-status nr 0 +cluster-basic-information+ 6 "DE")))
      (is (eq :success (invoke-status nr 1 'on-off 'toggle)))
      (is (eq t (light-on nr))))
    ;; and the application itself asks nobody
    (let ((*interaction-session* nil))
      (write-attribute (node-cluster (nr-node nr) 0 +cluster-basic-information+) 6 (tlv nil :string "FR"))
      (is (string= "FR" (attribute-value (node-cluster (nr-node nr) 0 +cluster-basic-information+) 'location))))))
