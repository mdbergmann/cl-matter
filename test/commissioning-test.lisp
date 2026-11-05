;;;; commissioning-test.lisp -- the commissioning clusters, the device's
;;;; fail-safe, fabric table and commissioning window, fabric-scoped
;;;; attributes, and the commissioner's flow, on the in-memory rig and over
;;;; UDP.

(defpackage :cl-matter.commissioning.tests
  (:use :cl :fiveam :cl-matter)
  (:import-from :cl-matter.exchange.tests
                #:make-rig #:rig-a #:rig-b #:rig-clock #:rig-network #:rig-a-port #:rig-b-port
                #:pump #:run-rig #:advance #:clock-now #:secured-pair #:ascii #:octets-from #:with-udp-rig
                #:*salt* #:*passcode*)
  (:import-from :cl-matter.data-model.tests #:status-of)
  (:import-from :cl-matter.attestation.tests #:reason-of #:hex))
(in-package :cl-matter.commissioning.tests)

(def-suite commissioning-tests :description "Commissioning: the clusters, the device, the commissioner"
  :in cl-matter.tests:test-suite)
(in-suite commissioning-tests)

;;; ------------------------------------------------------------------
;;; A device on B, a commissioner on A

(defstruct (cr (:constructor %make-cr))
  "A commissioning rig: the RIG, the DEVICE on B, the COMMISSIONER on A, and the events seen."
  rig device commissioner ma mb (commissioned '()) (removed '()))

(defun light-node ()
  (make-basic-node :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id #x8000
                   :endpoints (list (make-endpoint 1 :device-types (list (cons +device-type-on-off-light+ 3))
                                                     :clusters (list (make-on-off-cluster))))))

(defun make-commissioning-rig (&key trace (passcode *passcode*) (credentials (test-attestation-credentials))
                                 icac (max-fabrics 5) commissioner-args device-args)
  (let* ((rig (make-rig :trace trace))
         (cr (%make-cr :rig rig))
         (cb (make-secure-channel (rig-b rig)))
         (mb (make-interaction-model (rig-b rig) :node (light-node)))
         (ca (make-secure-channel (rig-a rig)))
         (ma (make-interaction-model (rig-a rig))))
    (setf (cr-mb cr) mb (cr-ma cr) ma
          (cr-device cr) (apply #'make-device :node (interaction-model-node mb) :channel cb :model mb
                                              :credentials credentials :max-fabrics max-fabrics
                                              :passcode passcode :salt *salt* :iterations 1000
                                              :on-commissioned (lambda (device fabric) (declare (ignore device)) (push fabric (cr-commissioned cr)))
                                              :on-fabric-removed (lambda (device fabric) (declare (ignore device)) (push fabric (cr-removed cr)))
                                              device-args)
          (cr-commissioner cr) (if icac
                                   (multiple-value-bind (fabric root ica) (make-test-fabric :fabric-id #x77 :node-id 1 :icac t)
                                     (apply #'make-commissioner ca ma :fabric fabric :root-keypair root :ica-keypair ica commissioner-args))
                                   (apply #'make-commissioner ca ma :fabric-id #x1D commissioner-args)))
    cr))

(defun rig-run (cr until &key (max-rounds 3000))
  (run-rig (cr-rig cr) until :max-rounds max-rounds)
  (pump (cr-rig cr) :rounds 6))

(defun commission-on-rig (cr &rest args)
  "Run the flow on the rig: the result plist, or the error signalled."
  (let ((c (apply #'start-commissioning (cr-commissioner cr) "mem" (rig-b-port (cr-rig cr)) :passcode *passcode* args)))
    (rig-run cr (lambda () (not (commissioning-running-p c))))
    (cond ((commissioning-running-p c) (error "commissioning stuck at ~a" (commissioning-step c)))
          ((commissioning-failed-p c) (error (commissioning-condition c)))
          (t (values (commissioning-result c) c)))))

(defun finish (cr interaction)
  "Run the rig until INTERACTION is done; its result, or its error signalled."
  (rig-run cr (lambda () (not (interaction-running-p interaction))))
  (cond ((interaction-running-p interaction) (error "~a did not finish" interaction))
        ((interaction-failed-p interaction) (error (interaction-condition interaction)))
        (t (interaction-result interaction))))

(defun invoke-on (cr session cluster command &optional fields &key (endpoint 0) timed)
  "Invoke COMMAND of CLUSTER on the device's ENDPOINT from A (as a timed
interaction of TIMED seconds when given); the response plist, or the
status keyword when it was refused, with the cluster status as the
second value."
  (let* ((definition (find-cluster-definition cluster))
         (responses (finish cr (start-invoke (cr-ma cr) session
                                             (command-path endpoint (cluster-definition-id definition)
                                                           (command-definition-id (find-command-definition definition command)))
                                             (command-fields cluster command fields)
                                             :timed timed))))
    (multiple-value-bind (value kind) (invoke-response-value (first responses))
      (if (eq kind :status)
          (values (im-status-name (im-status-status value)) (im-status-cluster-status value))
          value))))

(defun read-on (cr session endpoint cluster attribute &key fabric-filtered)
  (attribute-report-value (first (finish cr (start-read (cr-ma cr) session (list (attribute-path endpoint cluster attribute))
                                                         :fabric-filtered fabric-filtered)))))

(defun write-on (cr session endpoint cluster attribute value)
  "The status keyword of a write."
  (im-status-name (im-status-status (attribute-status-status
                                     (first (finish cr (start-write (cr-ma cr) session
                                                                    (list (attribute-write endpoint cluster attribute value)))))))))

(defun pase-pair (cr &key (local-a 11) (local-b 22))
  "A PASE session pair with real keys and an attestation challenge."
  (secured-pair (cr-rig cr) :type :pase :local-a local-a :local-b local-b))

(defun commission-and-open (cr &rest args)
  "Commission, then open a CASE session from A as the admin: (values result case-session)."
  (let ((result (apply #'commission-on-rig cr args)))
    (values result (getf result :session))))

(defun device-fabric (cr) (first (device-fabrics (cr-device cr))))
(defun device-case-session (cr)
  "The device's side of the CASE session the commissioner holds."
  (find :case (secure-channel-sessions (device-channel (cr-device cr))) :key #'session-type))
(defun gc-cluster (cr) (device-general-commissioning (cr-device cr)))
(defun oc-cluster (cr) (device-operational-credentials (cr-device cr)))
(defun now (cr) (clock-now (rig-clock (cr-rig cr))))
(defun pass-time (cr seconds) (rig-run cr (lambda () nil) :max-rounds (round seconds 0.05d0)))

;;; ------------------------------------------------------------------
;;; The whole flow

(test commission-on-the-rig
  (let ((cr (make-commissioning-rig)))
    (multiple-value-bind (result c) (commission-on-rig cr)
      (is (commissioning-complete-p c))
      (is (= 2 (getf result :node-id)))
      (is (= 1 (getf result :fabric-index)))
      (is (eq (commissioner-fabric (cr-commissioner cr)) (getf result :fabric)))
      (is (= #xFFF1 (getf result :vendor-id)))
      (is (= #x8000 (getf result :product-id)))
      (is (certificate-p (getf (getf result :attestation) :dac)))
      (is (string= "CSA00000SWC00000-00" (getf (getf (getf result :attestation) :certification-declaration) :certificate-id)))
      (let ((session (getf result :session)) (device (cr-device cr)))
        ;; the CASE session is live, the PASE one closed
        (is (eq :case (session-type session)))
        (is (session-active-p session))
        (is (not (session-active-p (getf result :pase-session))))
        ;; CommissioningComplete disarmed the fail-safe: the breadcrumb the flow wrote is gone
        (is (= 0 (attribute-value (gc-cluster cr) 'breadcrumb)))
        ;; the device's fabric table
        (is (= 1 (length (device-fabrics device))))
        (let ((fabric (device-fabric cr)))
          (is (= 2 (fabric-node-id fabric)))
          (is (= #x1D (fabric-fabric-id fabric)))
          (is (= 1 (fabric-index fabric)))
          (is (= #xFFF1 (fabric-vendor-id fabric)))
          (is (equalp (fabric-root-public-key (commissioner-fabric (cr-commissioner cr))) (fabric-root-public-key fabric)))
          (is (equalp (fabric-ipk (commissioner-fabric (cr-commissioner cr))) (fabric-ipk fabric)))
          (is (member fabric (secure-channel-fabrics (device-channel device))))
          (is (equal (list fabric) (cr-commissioned cr))))
        ;; the admin's ACL entry
        (is (equal (list (acl-entry +privilege-administer+ +auth-mode-case+ '(1) :fabric-index 1)) (device-acl device)))
        ;; the fail-safe is gone, the window closed
        (is (null (device-fail-safe device)))
        (is (not (commissioning-window-open-p device)))
        ;; over the CASE session: the attributes the commissioner sees
        (is (= 1 (read-on cr session 0 +cluster-operational-credentials+ 5)))
        (is (= 1 (read-on cr session 0 +cluster-operational-credentials+ 3)))
        (let ((nocs (read-on cr session 0 +cluster-operational-credentials+ 0 :fabric-filtered t)))
          (is (= 1 (length nocs)))
          (is (= 2 (certificate-node-id (decode-certificate (getf (first nocs) :noc)))))
          (is (eq :null (getf (first nocs) :icac)))
          (is (= 1 (getf (first nocs) :fabric-index))))
        (let ((fabrics (read-on cr session 0 +cluster-operational-credentials+ 1)))
          (is (= 1 (length fabrics)))
          (is (= #x1D (getf (first fabrics) :fabric-id)))
          (is (= 2 (getf (first fabrics) :node-id)))
          (is (string= "" (getf (first fabrics) :label))))
        (let ((roots (read-on cr session 0 +cluster-operational-credentials+ 4)))
          (is (= 1 (length roots)))
          (is (equalp (certificate-octets* (fabric-rcac (commissioner-fabric (cr-commissioner cr)))) (first roots))))
        (let ((acl (read-on cr session 0 +cluster-access-control+ 0)))
          (is (= 1 (length acl)))
          (is (= 5 (getf (first acl) :privilege)))
          (is (equal '(1) (getf (first acl) :subjects))))
        ;; the descriptor lists the four clusters
        (let ((servers (read-on cr session 0 +cluster-descriptor+ 1)))
          (is (subsetp (list +cluster-general-commissioning+ +cluster-operational-credentials+
                             +cluster-network-commissioning+ +cluster-access-control+)
                       servers)))
        (is (= +network-commissioning-feature-ethernet+ (read-on cr session 0 +cluster-network-commissioning+ +attribute-feature-map+)))
        (is (equalp (list (list :network-id (ascii "eth0") :connected t)) (read-on cr session 0 +cluster-network-commissioning+ 1)))
        ;; the light works over the new session
        (is (eq :success (invoke-on cr session 'on-off 'on nil :endpoint 1)))
        (is (eq t (read-on cr session 1 +cluster-on-off+ 0)))
        ;; nothing left open
        (is (null (exchange-manager-exchanges (rig-a (cr-rig cr)))))
        (is (null (exchange-manager-exchanges (rig-b (cr-rig cr)))))
        (is (null (secure-channel-handshakes (device-channel device))))))))

(test commission-with-icac-country-and-node-id
  (let ((cr (make-commissioning-rig :icac t)))
    (let ((result (commission-on-rig cr :node-id #xABCD :country-code "DE" :regulatory-location +regulatory-indoor+
                                        :case-auth-tags '(#xABCD0001))))
      (is (= #xABCD (getf result :node-id)))
      (let ((fabric (device-fabric cr)))
        (is (= #xABCD (fabric-node-id fabric)))
        (is (= #x77 (fabric-fabric-id fabric)))
        (is (fabric-icac fabric))
        (is (equal '(#xABCD0001) (fabric-case-auth-tags fabric))))
      (is (string= "DE" (attribute-value (node-cluster (device-node (cr-device cr)) 0 'basic-information) 'location)))
      (is (= +regulatory-indoor+ (attribute-value (gc-cluster cr) 'regulatory-config)))
      (is (= 0 (attribute-value (gc-cluster cr) 'breadcrumb)))   ; SetRegulatoryConfig wrote 2; CommissioningComplete reset it
      (let ((nocs (read-on cr (getf result :session) 0 +cluster-operational-credentials+ 0 :fabric-filtered t)))
        (is (not (eq :null (getf (first nocs) :icac)))))
      (is (= 2 (commissioner-next-node-id (cr-commissioner cr))))))) ; an explicit node id does not consume one

(test second-fabric-and-conflicts
  (let* ((cr (make-commissioning-rig))
         (first-result (commission-on-rig cr))
         (ma (cr-ma cr))
         (second (make-commissioner (commissioner-channel (cr-commissioner cr)) ma :fabric-id #x2E :vendor-id #xFFF2)))
    ;; the window closed after the first commissioning: a second commissioner needs it open
    (signals error (let ((*handshake-timeout* 2)) (commission-on-rig (let ((copy (copy-cr cr))) (setf (cr-commissioner copy) second) copy))))
    (open-commissioning-window (cr-device cr) :passcode *passcode* :salt *salt* :iterations 1000)
    (let* ((cr2 (let ((copy (copy-cr cr))) (setf (cr-commissioner copy) second) copy))
           (result (commission-on-rig cr2)))
      (is (= 2 (getf result :fabric-index)))
      (is (= 2 (length (device-fabrics (cr-device cr)))))
      (is (= 2 (read-on cr (getf result :session) 0 +cluster-operational-credentials+ 5)))
      (is (= 1 (read-on cr (getf first-result :session) 0 +cluster-operational-credentials+ 5)))
      ;; each admin sees its own NOC only when filtering, the others' entries bare otherwise
      (let ((nocs (read-on cr (getf result :session) 0 +cluster-operational-credentials+ 0)))
        (is (= 2 (length nocs)))
        (is (null (getf (first nocs) :noc)))
        (is (= 1 (getf (first nocs) :fabric-index)))
        (is (getf (second nocs) :noc)))
      (is (= 1 (length (read-on cr (getf result :session) 0 +cluster-operational-credentials+ 0 :fabric-filtered t))))
      (is (= 2 (length (read-on cr (getf result :session) 0 +cluster-access-control+ 0))))
      (is (= 1 (length (read-on cr (getf result :session) 0 +cluster-access-control+ 0 :fabric-filtered t))))
      (is (= 2 (length (read-on cr (getf result :session) 0 +cluster-operational-credentials+ 4))))
      ;; the first fabric again: FabricConflict, and the fail-safe's expiry cleans up
      (open-commissioning-window (cr-device cr) :passcode *passcode* :salt *salt* :iterations 1000)
      (let ((c (start-commissioning (cr-commissioner cr) "mem" (rig-b-port (cr-rig cr)) :passcode *passcode*
                                                                                     :fail-safe-seconds 10)))
        (rig-run cr (lambda () (not (commissioning-running-p c))))
        (is (commissioning-failed-p c))
        (is (eq :add-noc (commissioning-step c)))
        (is (typep (commissioning-condition c) 'commissioning-error))
        (is (search "NodeOperationalCertStatus 9" (princ-to-string (commissioning-condition c))))
        (is (= 2 (length (device-fabrics (cr-device cr)))))
        ;; the commissioner closed its PASE session; the device's fail-safe expired with it
        (is (not (session-active-p (commissioning-pase-session c))))
        (is (null (device-fail-safe (cr-device cr))))
        (is (= 2 (length (device-fabrics (cr-device cr)))))))))

(test attestation-decides
  (let ((cr (make-commissioning-rig :commissioner-args (list :trust-store '()))))
    (let ((c (start-commissioning (cr-commissioner cr) "mem" (rig-b-port (cr-rig cr)) :passcode *passcode*)))
      (rig-run cr (lambda () (not (commissioning-running-p c))))
      (is (commissioning-failed-p c))
      (is (eq :attestation (commissioning-step c)))
      (is (typep (commissioning-condition c) 'attestation-error))
      (is (eq :paa-not-found (attestation-error-reason (commissioning-condition c))))
      (is (null (device-fabrics (cr-device cr)))))
    ;; the failed try closed its PASE session, the fail-safe expired with it: a new flow starts clean
    (is (null (device-fail-safe (cr-device cr))))
    (let ((result (commission-on-rig cr :attestation :ignore)))
      (is (= 1 (getf result :fabric-index)))
      (is (= 1 (length (device-fabrics (cr-device cr)))))
      (is (equal '(:dac) (loop :for (k) :on (getf result :attestation) :by #'cddr :collect k)))))
  ;; a device whose Basic Information disagrees with its DAC
  (let ((cr (make-commissioning-rig :device-args (list :product-id #x9000))))
    (let ((c (start-commissioning (cr-commissioner cr) "mem" (rig-b-port (cr-rig cr)) :passcode *passcode*)))
      (rig-run cr (lambda () (not (commissioning-running-p c))))
      (is (commissioning-failed-p c))
      (is (eq :cd-product-id-mismatch (attestation-error-reason (commissioning-condition c)))))))

;;; ------------------------------------------------------------------
;;; The clusters by hand, over a PASE session

(test fail-safe-and-credentials-commands
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr))
         (commissioner (cr-commissioner cr))
         (fabric (commissioner-fabric commissioner)))
    (multiple-value-bind (sa sb) (pase-pair cr)
      (declare (ignore sb))
      ;; before the fail-safe
      (is (eq :failsafe-required (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce (octets-from 0 32)))))
      (is (eq :failsafe-required (invoke-on cr sa 'operational-credentials 'add-trusted-root-certificate
                                            (list :root-ca-certificate (certificate-octets* (fabric-rcac fabric))))))
      (is (eq :failsafe-required (invoke-on cr sa 'operational-credentials 'add-noc
                                            (list :noc-value (certificate-octets* (fabric-noc fabric)) :ipk-value (octets-from 0 16)
                                                  :case-admin-subject 1 :admin-vendor-id 1))))
      (is (equal (list :error-code +commissioning-invalid-authentication+ :debug-text "CommissioningComplete needs a CASE session")
                 (invoke-on cr sa 'general-commissioning 'commissioning-complete)))
      ;; attestation needs no fail-safe
      (let* ((nonce (octets-from 0 32))
             (response (invoke-on cr sa 'operational-credentials 'attestation-request (list :attestation-nonce nonce)))
             (dac (decode-certificate-der (getf (invoke-on cr sa 'operational-credentials 'certificate-chain-request
                                                          (list :certificate-type 1))
                                                :certificate))))
        (is (verify-attestation-signature (certificate-public-key dac) (getf response :attestation-elements)
                                          (session-attestation-challenge sa) (getf response :attestation-signature)))
        (is (equalp nonce (getf (decode-attestation-elements (getf response :attestation-elements)) :nonce)))
        (is (equalp (attestation-credentials-pai (device-credentials device))
                    (getf (invoke-on cr sa 'operational-credentials 'certificate-chain-request (list :certificate-type 2)) :certificate))))
      (is (eq :invalid-command (invoke-on cr sa 'operational-credentials 'certificate-chain-request (list :certificate-type 3))))
      (is (eq :constraint-error (invoke-on cr sa 'operational-credentials 'attestation-request (list :attestation-nonce (octets-from 0 31)))))
      ;; arm
      (is (= 0 (getf (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 30 :breadcrumb 7)) :error-code)))
      (is (device-fail-safe device))
      (is (= 7 (attribute-value (gc-cluster cr) 'breadcrumb)))
      (is (< 29 (- (fail-safe-expiry (device-fail-safe device)) (now cr)) 30.1))
      ;; re-arm extends; the cap applies
      (pass-time cr 1)
      (is (= 0 (getf (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 5000 :breadcrumb 8)) :error-code)))
      (is (< 899 (- (fail-safe-expiry (device-fail-safe device)) (now cr)) 900.1))
      ;; another session cannot take it
      (multiple-value-bind (sa2 sb2) (pase-pair cr :local-a 33 :local-b 44)
        (declare (ignore sb2))
        (is (= +commissioning-busy-with-other-admin+
               (getf (invoke-on cr sa2 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 30 :breadcrumb 0)) :error-code)))
        (is (eq :unsupported-access (invoke-on cr sa2 'operational-credentials 'csr-request (list :csr-nonce (octets-from 0 32))))))
      ;; AddNOC before any CSR: MissingCsr
      (is (= +noc-status-missing-csr+
             (getf (invoke-on cr sa 'operational-credentials 'add-noc
                              (list :noc-value (certificate-octets* (fabric-noc fabric)) :ipk-value (octets-from 0 16)
                                    :case-admin-subject 1 :admin-vendor-id 1))
                   :status-code)))
      ;; a refused AddNOC does not use up the fail-safe: the CSR can still be asked for
      (is (getf (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce (octets-from 0 32))) :nocsr-elements))
      (is (= 8 (attribute-value (gc-cluster cr) 'breadcrumb)))
      (is (= 0 (getf (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 0 :breadcrumb 0)) :error-code)))
      (is (null (device-fail-safe device)))
      (is (= 0 (attribute-value (gc-cluster cr) 'breadcrumb)))   ; 11.10.6.1: reset with the fail-safe
      (pass-time cr (+ *fabric-removal-delay* 0.5))
      (is (not (session-active-p sa)))   ; ArmFailSafe 0 expires the fail-safe: the PASE session with it
      )
    ;; a fresh PASE session: the CSR, root and NOC path with every refusal on the way
    (multiple-value-bind (sa sb) (pase-pair cr :local-a 55 :local-b 66)
      (declare (ignore sb))
      (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 1))
      (let* ((nonce (octets-from 32 64))
             (response (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce nonce)))
             (dac (decode-certificate-der (attestation-credentials-dac (device-credentials device))))
             (public-key (verify-nocsr :elements (getf response :nocsr-elements) :signature (getf response :attestation-signature)
                                       :challenge (session-attestation-challenge sa) :nonce nonce
                                       :dac-public-key (certificate-public-key dac))))
        (is (= 65 (length public-key)))
        (is (eq :invalid-command (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce nonce :is-for-update-noc t))))
        (is (eq :constraint-error (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce (octets-from 0 8)))))
        ;; AddNOC before the root: InvalidNOC
        (let ((noc (commissioner-issue-noc commissioner public-key 5)))
          (is (= +noc-status-invalid-noc+
                 (getf (invoke-on cr sa 'operational-credentials 'add-noc
                                  (list :noc-value (certificate-octets* noc) :ipk-value (fabric-epoch-key fabric)
                                        :case-admin-subject 1 :admin-vendor-id #xFFF1))
                       :status-code))))
        ;; disarming expires the fail-safe and, with it, this PASE session
        (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 0 :breadcrumb 0))))
    (multiple-value-bind (sa sb) (pase-pair cr :local-a 77 :local-b 88)
      (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 1))
      ;; a bad root, then the root, then a second root
      (is (eq :invalid-command (invoke-on cr sa 'operational-credentials 'add-trusted-root-certificate
                                          (list :root-ca-certificate (certificate-octets* (fabric-noc fabric))))))
      (is (eq :success (invoke-on cr sa 'operational-credentials 'add-trusted-root-certificate
                                  (list :root-ca-certificate (certificate-octets* (fabric-rcac fabric))))))
      (is (eq :constraint-error (invoke-on cr sa 'operational-credentials 'add-trusted-root-certificate
                                           (list :root-ca-certificate (certificate-octets* (fabric-rcac fabric))))))
      (let* ((nonce (octets-from 0 32))
             (response (invoke-on cr sa 'operational-credentials 'csr-request (list :csr-nonce nonce)))
             (public-key (getf (decode-nocsr-elements (getf response :nocsr-elements)) :csr))
             (public-key (decode-certificate-signing-request public-key))
             (wrong-key (generate-p256-keypair))
             (noc (commissioner-issue-noc commissioner public-key 5)))
        (flet ((add-noc (&rest overrides)
                 (let ((fields (list :noc-value (certificate-octets* noc) :ipk-value (fabric-epoch-key fabric)
                                     :case-admin-subject 1 :admin-vendor-id #xFFF1)))
                   (loop :for (k v) :on overrides :by #'cddr :do (setf (getf fields k) v))
                   (invoke-on cr sa 'operational-credentials 'add-noc fields))))
          (is (eq :constraint-error (add-noc :ipk-value (octets-from 0 15))))
          (is (= +noc-status-invalid-admin-subject+ (getf (add-noc :case-admin-subject 0) :status-code)))
          (is (= +noc-status-invalid-admin-subject+ (getf (add-noc :case-admin-subject #xFFFFFFFD00000000) :status-code)))
          ;; the fail-safe keeps the root and the key pair across refused attempts and a re-arm
          (invoke-on cr sa 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 1))
          (is (= +noc-status-invalid-public-key+
                 (getf (add-noc :noc-value (certificate-octets* (commissioner-issue-noc commissioner (p256-keypair-public wrong-key) 5)))
                       :status-code)))
          (is (= +noc-status-invalid-noc+ (getf (add-noc :noc-value (octets-from 0 10)) :status-code)))
          ;; a NOC signed by another root than the one added
          (let ((other (make-test-fabric :fabric-id #x1D :node-id 1)))
            (multiple-value-bind (f root) (make-test-fabric :fabric-id #x1D :node-id 1)
              (declare (ignore f))
              (is (= +noc-status-invalid-noc+
                     (getf (add-noc :noc-value (certificate-octets* (make-node-certificate :public-key public-key :node-id 5 :fabric-id #x1D
                                                                                          :issuer (fabric-rcac other) :issuer-keypair root)))
                           :status-code)))))
          ;; at last
          (let ((response (add-noc :case-admin-subject #xFFFFFFFD0001ABCD)))
            (is (= +noc-status-ok+ (getf response :status-code)))
            (is (= 1 (getf response :fabric-index))))
          (is (= 1 (length (device-fabrics device))))
          (is (= 5 (fabric-node-id (device-fabric cr))))
          (is (equal '(#xFFFFFFFD0001ABCD) (getf (first (device-acl device)) :subjects)))
          ;; the PASE session (the device's side of it) now acts for the fabric
          (is (= 1 (session-fabric-index sb)))
          (is (= 0 (session-fabric-index sa)))
          (is (= 1 (read-on cr sa 0 +cluster-operational-credentials+ 5)))
          (is (= 1 (length (read-on cr sa 0 +cluster-operational-credentials+ 0 :fabric-filtered t))))
          ;; a second AddNOC under the same fail-safe
          (is (eq :constraint-error (add-noc)))
          ;; CommissioningComplete needs CASE; the fail-safe expiry undoes it all
          (is (= +commissioning-invalid-authentication+
                 (getf (invoke-on cr sa 'general-commissioning 'commissioning-complete) :error-code)))
          (pass-time cr 62)
          (is (null (device-fail-safe device)))
          (is (null (device-fabrics device)))
          (is (null (device-acl device)))
          (is (null (secure-channel-fabrics (device-channel device))))
          (is (not (session-active-p sa)))
          (is (null (cr-removed cr)))   ; a revert is not a removal the application hears of
          (is (= 0 (attribute-value (oc-cluster cr) 'commissioned-fabrics))))))))

(test regulatory-config
  (let ((cr (make-commissioning-rig :device-args (list :location-capability +regulatory-indoor+))))
    (multiple-value-bind (sa sb) (pase-pair cr)
      (declare (ignore sb))
      (is (= +regulatory-indoor+ (read-on cr sa 0 +cluster-general-commissioning+ 3)))
      (is (= +commissioning-value-outside-range+
             (getf (invoke-on cr sa 'general-commissioning 'set-regulatory-config
                              (list :new-regulatory-config +regulatory-outdoor+ :country-code "US" :breadcrumb 3))
                   :error-code)))
      (is (= +commissioning-ok+
             (getf (invoke-on cr sa 'general-commissioning 'set-regulatory-config
                              (list :new-regulatory-config +regulatory-indoor+ :country-code "US" :breadcrumb 3))
                   :error-code)))
      (is (string= "US" (read-on cr sa 0 +cluster-basic-information+ 6)))
      (is (= 3 (read-on cr sa 0 +cluster-general-commissioning+ 0)))
      (is (eq :constraint-error (invoke-on cr sa 'general-commissioning 'set-regulatory-config
                                           (list :new-regulatory-config 5 :country-code "US" :breadcrumb 3))))
      (is (eq :constraint-error (invoke-on cr sa 'general-commissioning 'set-regulatory-config
                                           (list :new-regulatory-config 0 :country-code "U" :breadcrumb 3))))
      ;; the breadcrumb is writable
      (is (eq :success (write-on cr sa 0 +cluster-general-commissioning+ 0 99)))
      (is (= 99 (attribute-value (gc-cluster cr) 'breadcrumb)))
      (is (equal '(:fail-safe-expiry-length-seconds 60 :max-cumulative-failsafe-seconds 900)
                 (read-on cr sa 0 +cluster-general-commissioning+ 1)))
      (is (eq t (read-on cr sa 0 +cluster-general-commissioning+ 4))))))

;;; ------------------------------------------------------------------
;;; After commissioning: fabric management and the ACL over CASE

(test fabric-labels-and-removal
  (let ((cr (make-commissioning-rig)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      (is (= +noc-status-ok+ (getf (invoke-on cr session 'operational-credentials 'update-fabric-label (list :label "Home")) :status-code)))
      (is (string= "Home" (fabric-label (device-fabric cr))))
      (is (string= "Home" (getf (first (read-on cr session 0 +cluster-operational-credentials+ 1)) :label)))
      ;; a second fabric cannot take the label
      (open-commissioning-window (cr-device cr) :passcode *passcode* :salt *salt* :iterations 1000)
      (let* ((second (make-commissioner (commissioner-channel (cr-commissioner cr)) (cr-ma cr) :fabric-id #x2E))
             (cr2 (let ((copy (copy-cr cr))) (setf (cr-commissioner copy) second) copy))
             (session2 (getf (commission-on-rig cr2) :session)))
        (is (= +noc-status-label-conflict+
               (getf (invoke-on cr session2 'operational-credentials 'update-fabric-label (list :label "Home")) :status-code)))
        (is (= +noc-status-ok+ (getf (invoke-on cr session2 'operational-credentials 'update-fabric-label (list :label "Away")) :status-code)))
        ;; fabric-scoped commands over PASE are refused
        (multiple-value-bind (sa sb) (pase-pair cr :local-a 91 :local-b 92)
          (declare (ignore sb))
          (is (eq :unsupported-access (invoke-on cr sa 'operational-credentials 'update-fabric-label (list :label "x")))))
        ;; removal
        (is (= +noc-status-invalid-fabric-index+
               (getf (invoke-on cr session 'operational-credentials 'remove-fabric (list :fabric-index 9)) :status-code)))
        (is (= +noc-status-ok+ (getf (invoke-on cr session2 'operational-credentials 'remove-fabric (list :fabric-index 2)) :status-code)))
        ;; the response went out before the session died
        (is (session-active-p session2))
        (pass-time cr (+ *fabric-removal-delay* 0.5))
        (is (not (session-active-p session2)))
        (is (= 1 (length (device-fabrics (cr-device cr)))))
        (is (= 1 (length (cr-removed cr))))
        (is (= #x2E (fabric-fabric-id (first (cr-removed cr)))))
        (is (= 1 (length (device-acl (cr-device cr)))))
        (is (= 1 (length (read-on cr session 0 +cluster-operational-credentials+ 4))))
        ;; the application can remove a fabric too
        (remove-device-fabric (cr-device cr) 1)
        (is (null (device-fabrics (cr-device cr))))
        (pass-time cr 0.3)
        (is (not (session-active-p session)))
        (is (= 2 (length (cr-removed cr))))))))

(test acl-writes
  (let ((cr (make-commissioning-rig)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      (flet ((write-acl (entries) (write-on cr session 0 +cluster-access-control+ 0 entries))
             (entry (privilege auth-mode subjects &rest more) (apply #'acl-entry privilege auth-mode subjects more)))
        ;; a whole-list write replaces our fabric's entries, stamped with its index whatever the peer sent
        (is (eq :success (write-acl (list (entry 5 2 '(1)) (entry 3 2 '(100 101) :fabric-index 7)))))
        (let ((acl (device-acl (cr-device cr))))
          (is (= 2 (length acl)))
          (is (every (lambda (e) (= 1 (getf e :fabric-index))) acl))
          (is (equal '(100 101) (getf (second acl) :subjects))))
        (is (= 2 (length (read-on cr session 0 +cluster-access-control+ 0 :fabric-filtered t))))
        ;; refusals
        (is (eq :constraint-error (write-acl (list (entry 5 1 '(1))))))            ; PASE auth mode
        (is (eq :constraint-error (write-acl (list (entry 5 3 '(1))))))            ; Administer needs CASE
        (is (eq :constraint-error (write-acl (list (entry 6 2 '(1))))))            ; privilege out of range
        (is (eq :constraint-error (write-acl (list (entry 3 2 '(1 2 3 4 5))))))    ; too many subjects
        (is (eq :constraint-error (write-acl (list (entry 3 2 :null :targets (list '(:cluster :null :endpoint :null :device-type :null)))))))
        (is (eq :constraint-error (write-acl (list (entry 3 2 :null :targets (list '(:cluster 6 :endpoint 1 :device-type 256)))))))
        (is (eq :constraint-error (write-acl (list (list :subjects '(1) :fabric-index 1)))))
        (is (eq :resource-exhausted (write-acl (loop :repeat 5 :collect (entry 3 2 '(1))))))
        ;; the refused writes changed nothing
        (is (= 2 (length (device-acl (cr-device cr)))))
        ;; targets that are fine
        (is (eq :success (write-acl (list (entry 5 2 '(1))
                                          (entry 3 2 :null :targets (list '(:cluster 6 :endpoint 1 :device-type :null)
                                                                          '(:cluster :null :endpoint :null :device-type 256)))))))
        (is (equal '(:cluster 6 :endpoint 1 :device-type :null) (first (getf (second (device-acl (cr-device cr))) :targets))))
        ;; over PASE: no fabric, no write
        (multiple-value-bind (sa sb) (pase-pair cr :local-a 91 :local-b 92)
          (declare (ignore sb))
          (is (eq :unsupported-access (write-on cr sa 0 +cluster-access-control+ 0 (list (entry 5 2 '(1))))))
          ;; and a read over PASE sees the entries bare
          (let ((acl (read-on cr sa 0 +cluster-access-control+ 0)))
            (is (= 2 (length acl)))
            (is (equal '(:fabric-index 1) (first acl))))
          (is (null (read-on cr sa 0 +cluster-access-control+ 0 :fabric-filtered t))))
        ;; another fabric's admin sees only its own entries in full
        (open-commissioning-window (cr-device cr) :passcode *passcode* :salt *salt* :iterations 1000)
        (let* ((second (make-commissioner (commissioner-channel (cr-commissioner cr)) (cr-ma cr) :fabric-id #x2E))
               (cr2 (let ((copy (copy-cr cr))) (setf (cr-commissioner copy) second) copy))
               (session2 (getf (commission-on-rig cr2) :session)))
          (let ((acl (read-on cr session2 0 +cluster-access-control+ 0)))
            (is (= 3 (length acl)))
            (is (= 2 (count '(:fabric-index 1) acl :test #'equal)))
            (is (= 5 (getf (third acl) :privilege))))
          (is (eq :success (write-on cr session2 0 +cluster-access-control+ 0 (list (entry 5 2 '(1)) (entry 4 2 '(9))))))
          (is (= 4 (length (device-acl (cr-device cr)))))
          (is (= 2 (length (read-on cr session 0 +cluster-access-control+ 0 :fabric-filtered t))))
          ;; appending through a list index
          (let ((statuses (finish cr (start-write (cr-ma cr) session2
                                                  (list (make-attribute-data
                                                         :path (attribute-path 0 +cluster-access-control+ 0 :list-index :null)
                                                         :data (value-tlv (attribute-definition-type
                                                                           (find-attribute-definition (find-cluster-definition 'access-control) 'acl))
                                                                          nil (list (entry 1 2 '(77))))))))))
            ;; the item type is the struct, but the write sent a list: INVALID_DATA_TYPE
            (is (eq :invalid-data-type (im-status-name (im-status-status (attribute-status-status (first statuses)))))))
          (let ((statuses (finish cr (start-write (cr-ma cr) session2
                                                  (list (make-attribute-data
                                                         :path (attribute-path 0 +cluster-access-control+ 0 :list-index :null)
                                                         :data (value-tlv '(:struct (1 :privilege :enum8) (2 :auth-mode :enum8)
                                                                            (3 :subjects (:nullable (:list :uint64)))
                                                                            (4 :targets (:nullable (:list :uint64)))
                                                                            (254 :fabric-index :fabric-idx))
                                                                          nil (entry 1 2 '(77)))))))))
            (is (eq :success (im-status-name (im-status-status (attribute-status-status (first statuses)))))))
          (is (= 3 (length (read-on cr session2 0 +cluster-access-control+ 0 :fabric-filtered t))))
          (is (= 5 (length (device-acl (cr-device cr))))))))))

(test acl-enforced-after-commissioning
  (let ((cr (make-commissioning-rig)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      (flet ((read-status (session endpoint cluster attribute)
               (multiple-value-bind (value kind) (read-on cr session endpoint cluster attribute)
                 (if (eq kind :status) (im-status-name (im-status-status value)) :data))))
        ;; the administrator's entry from AddNOC lets the commissioner do everything
        (is (eq :data (read-status session 0 +cluster-access-control+ 0)))
        (is (eq :data (read-status session 0 +cluster-operational-credentials+ 0)))
        (is (eq :success (invoke-on cr session 'on-off 'toggle nil :endpoint 1)))
        (is (eq t (attribute-value (node-cluster (device-node (cr-device cr)) 1 +cluster-on-off+) 'on-off)))
        ;; it demotes itself to Operate, with the entry as chip-tool writes it (no FabricIndex
        ;; field: the server stamps the session's): the lamp still answers, the administration does not
        (let ((statuses (finish cr (start-write (cr-ma cr) session
                                                (list (make-attribute-data
                                                       :path (attribute-path 0 +cluster-access-control+ 0)
                                                       :data (tlv nil :array
                                                                  (list (tlv nil :structure
                                                                             (list (tlv 1 :unsigned +privilege-operate+)
                                                                                   (tlv 2 :unsigned +auth-mode-case+)
                                                                                   (tlv 3 :array (list (tlv nil :unsigned 1)))
                                                                                   (tlv 4 :null)))))))))))
          (is (eq :success (im-status-name (im-status-status (attribute-status-status (first statuses)))))))
        (let ((acl (device-acl (cr-device cr))))
          (is (= 1 (length acl)))
          (is (= +privilege-operate+ (getf (first acl) :privilege)))
          (is (equal '(1) (getf (first acl) :subjects)))
          (is (= 1 (getf (first acl) :fabric-index))))
        (is (eq :success (invoke-on cr session 'on-off 'toggle nil :endpoint 1)))
        (is (eq :data (read-status session 0 +cluster-operational-credentials+ 1)))
        (is (eq :unsupported-access (read-status session 0 +cluster-access-control+ 0)))
        (is (eq :unsupported-access (read-status session 0 +cluster-operational-credentials+ 0)))
        (is (eq :unsupported-access (invoke-on cr session 'general-commissioning 'arm-fail-safe
                                               (list :expiry-length-seconds 60 :breadcrumb 0))))
        (is (eq :unsupported-access (invoke-on cr session 'operational-credentials 'remove-fabric (list :fabric-index 1))))
        (is (eq :unsupported-access (write-on cr session 0 +cluster-basic-information+ 5 "Hall")))
        ;; and cannot get the privilege back
        (is (eq :unsupported-access (write-on cr session 0 +cluster-access-control+ 0
                                              (list (acl-entry +privilege-administer+ +auth-mode-case+ '(1))))))
        (is (= 1 (length (device-fabrics (cr-device cr)))))
        ;; a commissioner over PASE administers without an entry
        (multiple-value-bind (sa sb) (pase-pair cr :local-a 91 :local-b 92)
          (declare (ignore sb))
          (is (eq :data (read-status sa 0 +cluster-access-control+ 0)))
          (is (= 1 (length (read-on cr sa 0 +cluster-access-control+ 0))))
          (is (= +privilege-operate+ (getf (first (device-acl (cr-device cr))) :privilege))))))))

(test update-noc
  (let ((cr (make-commissioning-rig)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      (let ((device (cr-device cr)) (commissioner (cr-commissioner cr)) (old (device-fabric cr)))
        (is (eq :failsafe-required
                (invoke-on cr session 'operational-credentials 'update-noc (list :noc-value (certificate-octets* (fabric-noc old))))))
        ;; needs the fail-safe, armed over CASE by this fabric
        (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 0))
        (is (eq (fail-safe-fabric (device-fail-safe device)) old))
        (is (= +noc-status-missing-csr+
               (getf (invoke-on cr session 'operational-credentials 'update-noc (list :noc-value (certificate-octets* (fabric-noc old))))
                     :status-code)))
        (let* ((nonce (octets-from 0 32))
               (response (invoke-on cr session 'operational-credentials 'csr-request (list :csr-nonce nonce :is-for-update-noc t)))
               (public-key (decode-certificate-signing-request (getf (decode-nocsr-elements (getf response :nocsr-elements)) :csr)))
               (noc (commissioner-issue-noc commissioner public-key 2)))
          ;; AddNOC is not what this CSR was for
          (is (= +noc-status-missing-csr+
                 (getf (invoke-on cr session 'operational-credentials 'add-noc
                                  (list :noc-value (certificate-octets* noc) :ipk-value (octets-from 0 16) :case-admin-subject 1 :admin-vendor-id 1))
                       :status-code)))
          (let ((response (invoke-on cr session 'operational-credentials 'update-noc (list :noc-value (certificate-octets* noc)))))
            (is (= +noc-status-ok+ (getf response :status-code)))
            (is (= 1 (getf response :fabric-index))))
          (let ((new (device-fabric cr)))
            (is (not (eq old new)))
            (is (= 1 (fabric-index new)))
            (is (equalp (p256-keypair-public (fabric-operational-keypair new)) public-key))
            (is (eq new (session-fabric (device-case-session cr))))
            (is (= 0 (fabric-index old)))
            ;; CommissioningComplete over the session commits it
            (is (= +commissioning-ok+ (getf (invoke-on cr session 'general-commissioning 'commissioning-complete) :error-code)))
            (is (null (device-fail-safe device)))
            (is (eq new (device-fabric cr)))
            (is (= 1 (length (cr-commissioned cr))))  ; not a new fabric: no second call
            ;; a CASE session with the new NOC
            (let ((case2 (start-case (commissioner-channel commissioner) "mem" (rig-b-port (cr-rig cr))
                                     :fabric (commissioner-fabric commissioner) :peer-node-id 2 :resume nil)))
              (rig-run cr (lambda () (not (handshake-running-p case2))))
              (is (handshake-complete-p case2)))))
        ;; an UpdateNOC whose fail-safe expires is undone
        (let ((before (device-fabric cr)))
          (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 5 :breadcrumb 0))
          (let* ((response (invoke-on cr session 'operational-credentials 'csr-request (list :csr-nonce (octets-from 0 32) :is-for-update-noc t)))
                 (public-key (decode-certificate-signing-request (getf (decode-nocsr-elements (getf response :nocsr-elements)) :csr))))
            (is (= +noc-status-ok+ (getf (invoke-on cr session 'operational-credentials 'update-noc
                                                    (list :noc-value (certificate-octets* (commissioner-issue-noc commissioner public-key 2))))
                                         :status-code)))
            (is (not (eq before (device-fabric cr))))
            (pass-time cr 6)
            (is (eq before (device-fabric cr)))
            (is (eq before (session-fabric (device-case-session cr))))
            (is (session-active-p session))))))))

;;; ------------------------------------------------------------------
;;; Fabric-scoped attributes in the data model, without a network

(test fabric-scoped-attribute-semantics
  (let* ((cluster (make-cluster 'access-control))
         (type (attribute-definition-type (find-attribute-definition (find-cluster-definition 'access-control) 'acl))))
    (setf (attribute-value cluster 'acl) (list (acl-entry 5 2 '(1) :fabric-index 1) (acl-entry 3 2 '(2) :fabric-index 2)))
    ;; reads
    (flet ((read-as (index &optional filtered) (tlv-value type (read-attribute cluster 0 :fabric-index index :fabric-filtered filtered))))
      (is (= 2 (length (read-as 1))))
      (is (equal '(5) (mapcar (lambda (e) (getf e :privilege)) (remove-if-not (lambda (e) (getf e :privilege)) (read-as 1)))))
      (is (equal '(:fabric-index 2) (second (read-as 1))))
      (is (equal (list (acl-entry 3 2 '(2) :fabric-index 2)) (read-as 2 t)))
      (is (null (read-as 0 t)))
      (is (equal '((:fabric-index 1) (:fabric-index 2)) (read-as 0))))
    ;; writes
    (flet ((write-as (index value &key list-index)
             (write-attribute cluster 0 (value-tlv (if list-index (second type) type) nil value)
                              :list-index list-index :fabric-index index)))
      (is (eq :unsupported-access (status-of (lambda () (write-as 0 (list (acl-entry 5 2 '(1))))))))
      (write-as 2 (list (acl-entry 4 2 '(9)) (acl-entry 1 2 '(8))))
      (is (equal (list (acl-entry 5 2 '(1) :fabric-index 1) (acl-entry 4 2 '(9) :fabric-index 2) (acl-entry 1 2 '(8) :fabric-index 2))
                 (attribute-value cluster 'acl)))
      (write-as 1 '())
      (is (= 2 (length (attribute-value cluster 'acl))))
      (is (every (lambda (e) (= 2 (getf e :fabric-index))) (attribute-value cluster 'acl)))
      (write-as 1 (acl-entry 5 2 '(1)) :list-index :null)
      (is (= 3 (length (attribute-value cluster 'acl))))
      (write-as 2 (acl-entry 3 2 '(7)) :list-index 1)
      (is (equal '(7) (getf (second (attribute-value cluster 'acl)) :subjects)))
      (is (eq :constraint-error (status-of (lambda () (write-as 2 (acl-entry 3 2 '(7)) :list-index 2)))))
      (is (eq :resource-exhausted (status-of (lambda () (write-as 2 (loop :repeat 5 :collect (acl-entry 3 2 '(7))))))))
      ;; the check runs on the whole new value: a bad entry in a list write
      (is (eq :constraint-error (status-of (lambda () (write-as 2 (list (acl-entry 3 2 '(7)) (acl-entry 5 1 '(7)))))))))
    ;; an ordinary list is untouched by fabric indices
    (let ((basic (make-cluster 'basic-information)))
      (is (equalp (read-attribute basic 1) (read-attribute basic 1 :fabric-index 3 :fabric-filtered t))))))

(test cat-subjects
  (is (cat-subject-p #xFFFFFFFD0001ABCD))
  (is (cat-subject-p #xFFFFFFFDFFFF0001))
  (is (not (cat-subject-p #xFFFFFFFD00010000)))  ; version 0
  (is (not (cat-subject-p #xFFFFFFFC0001ABCD)))
  (is (not (cat-subject-p 1)))
  (is (not (cat-subject-p nil))))

(test make-device-checks
  (let* ((rig (make-rig))
         (channel (make-secure-channel (rig-b rig)))
         (node (light-node)))
    (signals error (make-device :node nil :channel channel))
    (signals error (make-device :node node :channel nil))
    (signals error (make-device :node (make-node) :channel channel))
    (signals error (make-device :node node :channel channel :model (make-interaction-model (rig-b rig) :node (light-node))))
    (let ((device (make-device :node node :channel channel :credentials (test-attestation-credentials) :vendor-id #xFFF2 :product-id 7)))
      (is (= #xFFF2 (device-vendor-id device)))
      (is (= #xFFF2 (attribute-value (node-cluster node 0 'basic-information) 'vendor-id)))
      (is (= 7 (attribute-value (node-cluster node 0 'basic-information) 'product-id)))
      (is (not (commissioning-window-open-p device)))
      (is (interaction-model-p (device-model device)))
      (open-commissioning-window device :passcode 1234 :salt *salt* :iterations 1000)
      (is (commissioning-window-open-p device))
      (close-commissioning-window device)
      (is (not (commissioning-window-open-p device)))
      ;; a restored fabric keeps its index
      (let ((fabric (make-test-fabric :fabric-id 9 :node-id 3)))
        (setf (fabric-index fabric) 4)
        (let ((device2 (make-device :node (light-node) :channel (make-secure-channel (rig-a rig)) :fabrics (list fabric))))
          (is (eq fabric (find-device-fabric device2 4)))
          (is (= 1 (attribute-value (device-operational-credentials device2) 'commissioned-fabrics)))
          (is (member fabric (secure-channel-fabrics (device-channel device2))))
          (signals error (make-device :node (light-node) :channel (make-secure-channel (rig-a rig)) :fabrics (list fabric fabric))))))
    (signals error (start-commissioning (make-commissioner (make-secure-channel (rig-a rig)) (make-interaction-model (rig-a rig)))
                                        "mem" 1 :passcode 1 :attestation :maybe))
    (signals error (make-commissioner (make-secure-channel (rig-a rig)) (make-interaction-model (rig-b rig))))
    (signals error (make-commissioner (make-secure-channel (rig-a rig)) (make-interaction-model (rig-a rig))
                                      :fabric (make-test-fabric)))))

;;; ------------------------------------------------------------------
;;; Administrator Commissioning: the window for the next administrator

(defun window-attributes (cr session)
  "(window-status admin-fabric-index admin-vendor-id) as the peer of SESSION reads them."
  (loop :for id :from 0 :to 2
        :collect (read-on cr session 0 +cluster-administrator-commissioning+ id)))

(defun ac-invoke (cr session command &optional fields)
  "A timed invoke of the Administrator Commissioning COMMAND: (values status cluster-status)."
  (invoke-on cr session 'administrator-commissioning command fields :timed 10))

(defun second-commissioner (cr &key (fabric-id #x2E))
  "Another administrator on A's channel and model, with a fabric of its own."
  (make-commissioner (commissioner-channel (cr-commissioner cr)) (cr-ma cr) :fabric-id fabric-id :node-id 1 :vendor-id #xFFF2))

(defun commission-as (cr commissioner passcode)
  "Run COMMISSIONER's flow against the device with PASSCODE (salt and iterations from the device)."
  (let ((c (start-commissioning commissioner "mem" (rig-b-port (cr-rig cr)) :passcode passcode)))
    (rig-run cr (lambda () (not (commissioning-running-p c))))
    (cond ((commissioning-running-p c) (error "commissioning stuck at ~a" (commissioning-step c)))
          ((commissioning-failed-p c) (error (commissioning-condition c)))
          (t (commissioning-result c)))))

(test administrator-commissioning-definition
  (let ((definition (find-cluster-definition 'administrator-commissioning)))
    (is (= #x003C (cluster-definition-id definition)))
    (dolist (command '(open-commissioning-window open-basic-commissioning-window revoke-commissioning))
      (let ((c (find-command-definition definition command)))
        (is (command-definition-timed c) "~a is timed" command)
        (is (= +privilege-administer+ (command-definition-privilege c)) "~a takes Administer" command)))
    (is (= 0 (command-definition-id (find-command-definition definition 'open-commissioning-window))))
    (is (= 1 (command-definition-id (find-command-definition definition 'open-basic-commissioning-window))))
    (is (= 2 (command-definition-id (find-command-definition definition 'revoke-commissioning))))))

(test the-device-window
  "The window from the device's side: the basic one MAKE-DEVICE opens, its
timeout, an enhanced one, the attributes and the advertisement inputs."
  (let* ((cr (make-commissioning-rig :device-args (list :window-timeout 300)))
         (device (cr-device cr))
         (ac (device-administrator-commissioning device)))
    (is (eq :basic (device-window-mode device)))
    (is (commissioning-window-open-p device))
    (is (= (device-discriminator device) (device-window-discriminator device)))
    (is (null (device-window-fabric device)))
    (is (< 299 (- (device-window-expiry device) (now cr)) 300.1))
    (is (= +administrator-commissioning-feature-basic+ (cluster-feature-map ac)))
    (is (= +basic-window-open+ (attribute-value ac 'window-status)))
    (is (eq :null (attribute-value ac 'admin-fabric-index)))
    (is (eq :null (attribute-value ac 'admin-vendor-id)))
    (is (search "basic window open" (princ-to-string device)))
    ;; it times out by itself
    (advance (rig-clock (cr-rig cr)) 301)
    (pump (cr-rig cr))
    (is (not (commissioning-window-open-p device)))
    (is (null (device-window-expiry device)))
    (is (= +window-not-open+ (attribute-value ac 'window-status)))
    (is (null (secure-channel-pase-verifier (device-channel device))))
    ;; opened again without parameters: the device's own
    (open-commissioning-window device)
    (is (eq :basic (device-window-mode device)))
    (is (null (device-window-expiry device)))
    (is (equalp (spake2p-verifier *passcode* *salt* 1000) (secure-channel-pase-verifier (device-channel device))))
    ;; an enhanced one replaces it, under its own discriminator, for a fabric
    (let ((fabric (make-test-fabric :fabric-id 5)))
      (setf (fabric-index fabric) 3)
      (open-commissioning-window device :passcode 55555555 :salt *salt* :iterations 2000 :mode :enhanced
                                        :discriminator #xABC :fabric fabric :timeout 180)
      (is (eq :enhanced (device-window-mode device)))
      (is (= #xABC (device-window-discriminator device)))
      (is (eq fabric (device-window-fabric device)))
      (is (= 2000 (secure-channel-pase-iterations (device-channel device))))
      (is (= +enhanced-window-open+ (attribute-value ac 'window-status)))
      (is (= 3 (attribute-value ac 'admin-fabric-index)))
      (is (= #xFFF1 (attribute-value ac 'admin-vendor-id)))
      (is (search "enhanced window open" (princ-to-string device))))
    (close-commissioning-window device)
    (is (= +window-not-open+ (attribute-value ac 'window-status)))
    (is (eq :null (attribute-value ac 'admin-fabric-index)))
    ;; bad arguments
    (signals error (open-commissioning-window device :mode :fancy))
    (signals error (open-commissioning-window device :timeout -1))
    (signals error (open-commissioning-window device :discriminator 4096))
    (signals pase-error (open-commissioning-window device :verifier (octets-from 0 10) :salt *salt* :iterations 1000))
    (signals pase-error (open-commissioning-window device :verifier (octets-from 0 97) :salt *salt* :iterations 1000)) ; L is not a point
    (signals pase-error (open-commissioning-window device :passcode 20202021 :salt *salt* :iterations 10))
    (is (not (commissioning-window-open-p device)))
    ;; a device without a passcode of its own has no basic window
    (let ((bare (make-device :node (light-node) :channel (make-secure-channel (rig-a (cr-rig cr))))))
      (is (not (commissioning-window-open-p bare)))
      (is (= 0 (cluster-feature-map (device-administrator-commissioning bare))))
      (signals error (open-commissioning-window bare))
      (open-commissioning-window bare :passcode 1234 :salt *salt* :iterations 1000)
      (is (eq :basic (device-window-mode bare))))))

(test administrator-commissioning-commands
  "OpenCommissioningWindow, OpenBasicCommissioningWindow and RevokeCommissioning
over the first administrator's CASE session, with every refusal."
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr))
         (salt (octets-from 1 33))
         (good (list :commissioning-timeout 180 :pake-passcode-verifier (spake2p-verifier 87654321 salt 1000)
                     :discriminator #x123 :iterations 1000 :salt salt)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      ;; after commissioning: closed, nobody's
      (is (equal (list +window-not-open+ :null :null) (window-attributes cr session)))
      (is (not (commissioning-window-open-p device)))
      ;; the commands are timed
      (is (eq :needs-timed-interaction (invoke-on cr session 'administrator-commissioning 'revoke-commissioning)))
      (is (eq :needs-timed-interaction (invoke-on cr session 'administrator-commissioning 'open-commissioning-window good)))
      ;; nothing to revoke
      (is (equal (list :failure +administrator-commissioning-window-not-open+)
                 (multiple-value-list (ac-invoke cr session 'revoke-commissioning))))
      ;; the timeout and the discriminator: INVALID_COMMAND
      (flet ((with (&rest changes)
               (let ((fields (copy-list good)))
                 (loop :for (key value) :on changes :by #'cddr :do (setf (getf fields key) value))
                 fields)))
        (is (eq :invalid-command (ac-invoke cr session 'open-commissioning-window (with :commissioning-timeout 179))))
        (is (eq :invalid-command (ac-invoke cr session 'open-commissioning-window (with :commissioning-timeout 901))))
        (is (eq :invalid-command (ac-invoke cr session 'open-commissioning-window (with :discriminator 4096))))
        (is (eq :invalid-command (ac-invoke cr session 'open-basic-commissioning-window (list :commissioning-timeout 0))))
        ;; the PAKE parameters: the cluster's PAKEParameterError
        (dolist (bad (list (with :iterations 999) (with :iterations 100001)
                           (with :salt (octets-from 0 15)) (with :salt (octets-from 0 33))
                           (with :pake-passcode-verifier (octets-from 0 96))
                           (with :pake-passcode-verifier (octets-from 0 97))))   ; L off the curve
          (is (equal (list :failure +administrator-commissioning-pake-parameter-error+)
                     (multiple-value-list (ac-invoke cr session 'open-commissioning-window bad)))
              "~s" bad))
        (is (not (commissioning-window-open-p device)))
        ;; an armed fail-safe: Busy
        (is (= 0 (getf (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 0))
                       :error-code)))
        (is (equal (list :failure +administrator-commissioning-busy+)
                   (multiple-value-list (ac-invoke cr session 'open-commissioning-window good))))
        (is (equal (list :failure +administrator-commissioning-busy+)
                   (multiple-value-list (ac-invoke cr session 'open-basic-commissioning-window (list :commissioning-timeout 180)))))
        (is (= 0 (getf (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 0 :breadcrumb 0))
                       :error-code)))
        ;; open: the window is enhanced, the administrator's, under the given discriminator
        (is (eq :success (ac-invoke cr session 'open-commissioning-window good)))
        (is (eq :enhanced (device-window-mode device)))
        (is (= #x123 (device-window-discriminator device)))
        (is (eq (device-fabric cr) (device-window-fabric device)))
        (is (< 179 (- (device-window-expiry device) (now cr)) 180.1))
        (is (equal (list +enhanced-window-open+ 1 #xFFF1) (window-attributes cr session)))
        (is (equalp (getf good :pake-passcode-verifier) (secure-channel-pase-verifier (device-channel device))))
        (is (equalp salt (secure-channel-pase-salt (device-channel device))))
        ;; a second window: Busy, either kind
        (is (equal (list :failure +administrator-commissioning-busy+)
                   (multiple-value-list (ac-invoke cr session 'open-commissioning-window good))))
        (is (equal (list :failure +administrator-commissioning-busy+)
                   (multiple-value-list (ac-invoke cr session 'open-basic-commissioning-window (list :commissioning-timeout 180)))))
        ;; a PASE session that is up when the window is revoked goes with it; the revoker's CASE session stays
        (multiple-value-bind (sa sb) (pase-pair cr :local-a 71 :local-b 72)
          (is (eq :success (ac-invoke cr session 'revoke-commissioning)))
          (is (not (commissioning-window-open-p device)))
          (is (equal (list +window-not-open+ :null :null) (window-attributes cr session)))
          (is (session-active-p sb))
          (pass-time cr (+ *fabric-removal-delay* 0.5))
          (is (not (session-active-p sb)))
          (is (not (session-active-p sa)))
          (is (session-active-p session)))
        ;; the basic window again, for 180 s, then it times out
        (is (eq :success (ac-invoke cr session 'open-basic-commissioning-window (list :commissioning-timeout 180))))
        (is (eq :basic (device-window-mode device)))
        (is (= (device-discriminator device) (device-window-discriminator device)))
        (is (equal (list +basic-window-open+ 1 #xFFF1) (window-attributes cr session)))
        (is (equalp (spake2p-verifier *passcode* *salt* 1000) (secure-channel-pase-verifier (device-channel device))))
        (advance (rig-clock (cr-rig cr)) 181)
        (pump (cr-rig cr))
        (is (not (commissioning-window-open-p device)))
        (is (equal (list +window-not-open+ :null :null) (window-attributes cr session)))
        ;; an Operate peer may read the attributes and not open a window
        (write-on cr session 0 +cluster-access-control+ 0 (list (acl-entry +privilege-operate+ +auth-mode-case+ '(1))))
        (is (equal (list +window-not-open+ :null :null) (window-attributes cr session)))
        (is (eq :unsupported-access (ac-invoke cr session 'open-commissioning-window good)))
        (is (eq :unsupported-access (ac-invoke cr session 'revoke-commissioning)))))))

(test a-second-administrator-through-the-window
  "The first administrator asks for a window; a second commissioner comes in
through it with the passcode of the onboarding payload; the window closes
with CommissioningComplete; the second administrator's fabric leaving the
node nulls the window attributes of a window it opened."
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr))
         (admin2 (second-commissioner cr)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      ;; the request from the commissioner's side
      (signals error (start-commissioning-window-request (cr-commissioner cr) session :timeout 10))
      (signals pase-error (start-commissioning-window-request (cr-commissioner cr) session :iterations 10))
      (let ((seen '()))
        (multiple-value-bind (interaction payload)
            (start-commissioning-window-request (cr-commissioner cr) session :discriminator #x555 :timeout 240
                                                                             :vendor-id #xFFF1 :product-id #x8000
                                                                             :on-complete (lambda (i p) (push (list i p) seen)))
          (finish cr interaction)
          (is (= 1 (length seen)))
          (is (eq interaction (first (first seen))))
          (is (eq payload (second (first seen))))
          (is (onboarding-payload-p payload))
          (is (= #x555 (onboarding-payload-discriminator payload)))
          (is (passcode-valid-p (onboarding-payload-passcode payload)))
          (is (/= *passcode* (onboarding-payload-passcode payload)))
          (is (= #xFFF1 (onboarding-payload-vendor-id payload)))
          (is (= 11 (length (encode-manual-pairing-code payload))))   ; what the user types into the second commissioner
          ;; the device: enhanced, 240 s, for fabric 1
          (is (eq :enhanced (device-window-mode device)))
          (is (= #x555 (device-window-discriminator device)))
          (is (equal (list +enhanced-window-open+ 1 #xFFF1) (window-attributes cr session)))
          (is (< 239 (- (device-window-expiry device) (now cr)) 240.1))
          ;; the old passcode is no good now, the new one is
          (signals error (commission-as cr admin2 *passcode*))
          (is (eq :enhanced (device-window-mode device)))    ; a failed attempt leaves the window open
          (let ((result2 (commission-as cr admin2 (onboarding-payload-passcode payload))))
            (is (= 2 (getf result2 :fabric-index)))
            (is (= 2 (length (device-fabrics device))))
            (is (= 2 (length (cr-commissioned cr))))
            ;; CommissioningComplete closed the window
            (is (not (commissioning-window-open-p device)))
            (is (equal (list +window-not-open+ :null :null) (window-attributes cr session)))
            ;; both administrators work
            (let ((session2 (getf result2 :session)))
              (is (eq :success (invoke-on cr session2 'on-off 'toggle nil :endpoint 1)))
              (is (eq :success (invoke-on cr session 'on-off 'toggle nil :endpoint 1)))
              (is (= 2 (length (read-on cr session2 0 +cluster-operational-credentials+ 1))))
              ;; the second opens a basic window; its fabric is removed: the window stays, the attributes go null
              (is (eq :success (ac-invoke cr session2 'open-basic-commissioning-window (list :commissioning-timeout 180))))
              (is (equal (list +basic-window-open+ 2 #xFFF2) (window-attributes cr session)))
              (is (eq :success (ac-invoke cr session2 'revoke-commissioning)))
              (is (eq :success (ac-invoke cr session2 'open-basic-commissioning-window (list :commissioning-timeout 180))))
              (remove-device-fabric device 2)
              (is (= 1 (length (device-fabrics device))))
              (is (commissioning-window-open-p device))
              (is (null (device-window-fabric device)))
              (is (equal (list +basic-window-open+ :null :null) (window-attributes cr session)))
              ;; the first administrator closes it
              (is (eq :success (ac-invoke cr session 'revoke-commissioning)))
              (is (not (commissioning-window-open-p device))))))))))

;;; ------------------------------------------------------------------
;;; Over UDP, the device polling in its own thread

(test commission-over-udp
  (with-udp-rig (a b host port)
    (let* ((cb (make-secure-channel b))
           (mb (make-interaction-model b :node (light-node)))
           (device (make-device :node (interaction-model-node mb) :channel cb :model mb
                                :credentials (test-attestation-credentials)
                                :passcode *passcode* :salt *salt* :iterations 1000))
           (ca (make-secure-channel a))
           (ma (make-interaction-model a))
           (commissioner (make-commissioner ca ma :fabric-id #x5A))
           (stop nil)
           (thread (bt:make-thread (lambda () (exchange-manager-run b :until (lambda () stop) :timeout 120))
                                   :name "matter device")))
      (unwind-protect
           (let ((result (commission commissioner host port :passcode *passcode* :country-code "AT" :timeout 60)))
             (is (= 2 (getf result :node-id)))
             (is (= 1 (length (device-fabrics device))))
             (is (string= "AT" (attribute-value (node-cluster (device-node device) 0 'basic-information) 'location)))
             (let ((session (getf result :session)))
               (is (eq :case (session-type session)))
               (is (= 1 (attribute-report-value (first (read-attributes ma session (list (attribute-path 0 +cluster-operational-credentials+ 5)))))))
               (invoke-command ma session (command-path 1 +cluster-on-off+ 1) nil)
               (is (eq t (attribute-value (node-cluster (device-node device) 1 'on-off) 'on-off)))
               ;; a second CASE session resumes
               (let ((again (establish-case-session ca host port :fabric (commissioner-fabric commissioner) :peer-node-id 2)))
                 (is (session-active-p again))
                 (close-session ca again))
               (close-session ca session)))
        (setf stop t)
        (bt:join-thread thread)))))
