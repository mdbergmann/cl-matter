;;;; persistence-test.lisp -- what survives a restart: the state file, a
;;;; fabric's round trip, the device committing at CommissioningComplete
;;;; and not before, a restarted device and commissioner resuming where
;;;; they were, and MAKE-DEVICE :STORAGE keeping the file by itself.

(defpackage :cl-matter.persistence.tests
  (:use :cl :fiveam :cl-matter)
  (:import-from :cl-matter.exchange.tests #:rig-a #:rig-b #:rig-b-port #:pump #:run-rig #:*salt* #:*passcode*)
  (:import-from :cl-matter.commissioning.tests
                #:make-commissioning-rig #:cr-rig #:cr-device #:cr-commissioner #:cr-ma #:cr-commissioned #:cr-removed
                #:commission-on-rig #:commission-and-open #:rig-run #:invoke-on #:read-on #:write-on
                #:device-fabric #:pass-time #:light-node))
(in-package :cl-matter.persistence.tests)

(def-suite persistence-tests :description "Persistence: the state file, fabrics and devices across a restart"
  :in cl-matter.tests:test-suite)
(in-suite persistence-tests)

(defun octets (&rest bytes) (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun temp-path (name)
  (format nil "~a/cl-matter-~a-~d.state" (or (uiop:getenv "TMPDIR") "/tmp") name (random 1000000)))

(defmacro with-temp-file ((var name) &body body)
  `(let ((,var (temp-path ,name)))
     (unwind-protect (progn ,@body)
       (when (probe-file ,var) (delete-file ,var)))))

(defun finish-handshake (cr handshake)
  (rig-run cr (lambda () (not (handshake-running-p handshake))))
  (when (handshake-failed-p handshake) (error (handshake-condition handshake)))
  handshake)

;;; ------------------------------------------------------------------
;;; The state file

(test state-file-round-trip
  "Every kind of datum a state holds comes back the same; what is not data is refused."
  (with-temp-file (path "round-trip")
    (let ((state (list :format +state-format+ :n 0 :big (expt 2 64) :neg -7 :nothing nil :yes t
                       :text (format nil "quote \" backslash \\ newline~%end") :empty ""
                       :octets (octets 0 1 127 128 255) :no-octets (octets)
                       :nested (list (list :a 1) (list :b (octets 9)) nil t) :dotted (cons 1 2)
                       :null :null)))
      (is (equal path (write-state-file state path)))
      (let ((back (read-state-file path)))
        (is (equalp state back))
        (is (typep (getf back :octets) '(vector (unsigned-byte 8))))
        (is (typep (getf back :no-octets) '(vector (unsigned-byte 8))))
        (is (stringp (getf back :text)))
        (is (eq :null (getf back :null)))))
    ;; the file is plain text the standard reader reads, without #.
    (with-open-file (out path :direction :output :if-exists :supersede)
      (format out "(:format ~d :x #.(list 1))" +state-format+))
    (signals state-error (read-state-file path))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (format out "(:format ~d :x some-symbol)" +state-format+))
    (signals state-error (read-state-file path))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (format out "(:format 999)"))
    (signals state-error (read-state-file path))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (format out "not a state at all"))
    (signals state-error (read-state-file path)))
  ;; no file: NIL, not an error
  (is (null (read-state-file (temp-path "missing"))))
  ;; what cannot be written is refused before the file is touched
  (signals state-error (with-temp-file (path "bad") (write-state-file (list :format 1 :f 1.5) path)))
  (signals state-error (with-temp-file (path "bad") (write-state-file (list :format 1 :s 'symbol) path)))
  (signals state-error (with-temp-file (path "bad") (write-state-file (list :format 1 :v (vector 300)) path))))

;;; ------------------------------------------------------------------
;;; A fabric

(test fabric-round-trip
  (multiple-value-bind (fabric root ica) (make-test-fabric :fabric-id #x77 :node-id #x1234 :icac t :case-auth-tags '(#x00010001)
                                                           :vendor-id #xFFF2)
    (declare (ignore root ica))
    (setf (fabric-label fabric) "Home" (fabric-index fabric) 3)
    (let* ((state (fabric-state fabric))
           (back (fabric-from-state state)))
      (is (= 3 (getf state :index)))
      (is (= 32 (length (getf state :private-key))))
      (is (= #x77 (fabric-fabric-id back)))
      (is (= #x1234 (fabric-node-id back)))
      (is (equal '(#x00010001) (fabric-case-auth-tags back)))
      (is (= 3 (fabric-index back)))
      (is (string= "Home" (fabric-label back)))
      (is (= #xFFF2 (fabric-vendor-id back)))
      (is (certificate-p (fabric-icac back)))
      (is (equalp (fabric-root-public-key fabric) (fabric-root-public-key back)))
      (is (equalp (fabric-compressed-fabric-id fabric) (fabric-compressed-fabric-id back)))
      (is (equalp (fabric-ipk fabric) (fabric-ipk back)))
      (is (equalp (p256-keypair-public (fabric-operational-keypair fabric))
                  (p256-keypair-public (fabric-operational-keypair back))))
      ;; through a file, with an ICAC-less fabric too
      (with-temp-file (path "fabric")
        (write-state-file (list :format +state-format+ :fabric state) path)
        (is (= #x77 (fabric-fabric-id (fabric-from-state (getf (read-state-file path) :fabric))))))
      (let ((plain (fabric-state (make-test-fabric :fabric-id 5 :node-id 6))))
        (is (null (getf plain :icac)))
        (is (null (fabric-icac (fabric-from-state plain)))))
      ;; a private key that is not the NOC's, a chain that is broken
      (let ((wrong (copy-list state)))
        (setf (getf wrong :private-key) (p256-keypair-private (generate-p256-keypair)))
        (signals state-error (fabric-from-state wrong)))
      (let ((wrong (copy-list state)))
        (setf (getf wrong :rcac) (certificate-octets* (fabric-rcac (make-test-fabric))))
        (signals state-error (fabric-from-state wrong)))
      (signals state-error (fabric-from-state (list :index 1))))))

;;; ------------------------------------------------------------------
;;; The device commits at CommissioningComplete

(test the-device-commits-at-commissioning-complete
  "DEVICE-STATE shows nothing of a fabric the fail-safe still holds; the
hook fires on every change and the state it sees is the committed one."
  (let* ((changes '())
         (cr (make-commissioning-rig :device-args (list :on-state-change
                                                        (lambda (device) (push (cons (and (device-fail-safe device) t)
                                                                                     (device-state device))
                                                                               changes)))))
         (device (cr-device cr)))
    (let ((empty (device-state device)))
      (is (= +state-format+ (getf empty :format)))
      (is (null (getf empty :fabrics)))
      (is (null (getf empty :acl)))
      (is (= 1 (getf empty :next-fabric-index)))
      (is (string= "" (getf empty :node-label)))
      (is (string= "XX" (getf empty :location)))
      (is (= 2 (getf empty :regulatory-config))))
    (multiple-value-bind (result session) (commission-and-open cr :country-code "DE")
      (declare (ignore result))
      ;; the hook fired while the fail-safe was armed (the regulatory config, the admin's ACL entry):
      ;; those states carry no fabric and no ACL
      (let ((armed (remove-if-not #'car changes)))
        (is (plusp (length armed)))
        (dolist (change armed)
          (is (null (getf (cdr change) :fabrics)))
          (is (null (getf (cdr change) :acl)))))
      ;; CommissioningComplete committed: the last state has it all
      (let ((state (cdr (first changes))))
        (is (null (car (first changes))))
        (is (= 1 (length (getf state :fabrics))))
        (is (= 1 (getf (first (getf state :fabrics)) :index)))
        (is (= 2 (getf state :next-fabric-index)))
        (is (equal (list (acl-entry +privilege-administer+ +auth-mode-case+ '(1) :fabric-index 1)) (getf state :acl)))
        (is (= 1 (length (getf state :resumptions))))
        (is (= 1 (getf (first (getf state :resumptions)) :peer-node-id)))
        (is (string= "DE" (getf state :location)))
        (is (equalp state (device-state device))))
      ;; a label, the node label: changes the hook sees
      (let ((count (length changes)))
        (invoke-on cr session 'operational-credentials 'update-fabric-label (list :label "Home"))
        (is (= (1+ count) (length changes)))
        (is (string= "Home" (getf (first (getf (cdr (first changes)) :fabrics)) :label)))
        (is (eq :success (write-on cr session 0 +cluster-basic-information+ 5 "Kitchen")))
        (is (= (+ 2 count) (length changes)))
        (is (string= "Kitchen" (getf (cdr (first changes)) :node-label)))
        ;; an attribute that is not kept changes nothing
        (is (eq :success (invoke-on cr session 'on-off 'on nil :endpoint 1)))
        (is (= (+ 2 count) (length changes))))
      ;; the fail-safe armed again and left to expire: nothing of it is kept, nothing is saved
      (let ((count (length changes)))
        (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 60 :breadcrumb 7))
        (is (= 7 (attribute-value (device-general-commissioning device) 'breadcrumb)))
        (invoke-on cr session 'general-commissioning 'arm-fail-safe (list :expiry-length-seconds 0 :breadcrumb 0))
        (is (= count (length changes))))
      ;; removal is committed at once
      (remove-device-fabric device 1)
      (is (null (getf (cdr (first changes)) :fabrics)))
      (is (null (getf (cdr (first changes)) :acl)))
      (is (null (getf (cdr (first changes)) :resumptions)))
      (is (= 2 (getf (cdr (first changes)) :next-fabric-index))))))

;;; ------------------------------------------------------------------
;;; A restart: a new device and a new commissioner from the states

(test a-restarted-device-and-commissioner
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr))
         (commissioner (cr-commissioner cr)))
    (multiple-value-bind (result session) (commission-and-open cr)
      (declare (ignore result))
      (invoke-on cr session 'operational-credentials 'update-fabric-label (list :label "Home"))
      (write-on cr session 0 +cluster-basic-information+ 5 "Kitchen")
      (is (eq :success (write-on cr session 0 +cluster-access-control+ 0
                                 (list (acl-entry +privilege-administer+ +auth-mode-case+ '(1) :fabric-index 1)
                                       (acl-entry +privilege-operate+ +auth-mode-case+ '(99) :fabric-index 1))))))
    (let ((device-state (device-state device))
          (commissioner-state (commissioner-state commissioner)))
      ;; the states go through a file
      (with-temp-file (path "restart")
        (write-state-file device-state path)
        (setf device-state (read-state-file path))
        (write-state-file commissioner-state path)
        (setf commissioner-state (read-state-file path)))
      (is (= 1 (length (getf commissioner-state :resumptions))))
      (is (= 3 (getf commissioner-state :next-node-id)))
      ;; both come up on a new rig
      (let* ((cr2 (make-commissioning-rig :device-args (list :state device-state)
                                          :commissioner-args (list :state commissioner-state)))
             (device2 (cr-device cr2))
             (commissioner2 (cr-commissioner cr2)))
        ;; the device: its fabric under its index, the ACL, the attributes; no window
        (is (= 1 (length (device-fabrics device2))))
        (let ((fabric (device-fabric cr2)))
          (is (= 1 (fabric-index fabric)))
          (is (= #x1D (fabric-fabric-id fabric)))
          (is (= 2 (fabric-node-id fabric)))
          (is (string= "Home" (fabric-label fabric)))
          (is (member fabric (secure-channel-fabrics (device-channel device2))))
          (is (= 1 (length (secure-channel-resumptions (device-channel device2)))))
          (is (eq fabric (case-resumption-fabric (first (secure-channel-resumptions (device-channel device2)))))))
        (is (= 2 (length (device-acl device2))))
        (is (= 2 (cl-matter::device-next-fabric-index device2)))
        (is (string= "Kitchen" (attribute-value (node-cluster (device-node device2) 0 'basic-information) 'node-label)))
        (is (= 1 (attribute-value (device-operational-credentials device2) 'commissioned-fabrics)))
        (is (not (commissioning-window-open-p device2)))
        (is (= 0 (attribute-value (device-general-commissioning device2) 'breadcrumb)))
        ;; the commissioner: the same fabric, the same root, the next node id
        (is (= #x1D (fabric-fabric-id (commissioner-fabric commissioner2))))
        (is (equalp (fabric-root-public-key (commissioner-fabric commissioner)) (fabric-root-public-key (commissioner-fabric commissioner2))))
        (is (equalp (p256-keypair-private (commissioner-root-keypair commissioner)) (p256-keypair-private (commissioner-root-keypair commissioner2))))
        (is (= 3 (commissioner-next-node-id commissioner2)))
        ;; CASE resumes across the restart, and the administrator is still one
        (let* ((hs (finish-handshake cr2 (start-case (commissioner-channel commissioner2) "mem" (rig-b-port (cr-rig cr2))
                                                     :fabric (commissioner-fabric commissioner2) :peer-node-id 2)))
               (session2 (handshake-session hs)))
          (is (handshake-complete-p hs))
          (is (case-resumed-p (handshake-machine hs)))
          (is (eq (commissioner-fabric commissioner2) (session-fabric session2)))
          (is (= 1 (fabric-index (session-fabric (find :case (secure-channel-sessions (device-channel device2)) :key #'session-type)))))
          (is (equal '(:privilege 5 :auth-mode 2 :subjects (1) :targets :null :fabric-index 1)
                     (first (read-on cr2 session2 0 +cluster-access-control+ 0))))
          (is (string= "Home" (getf (first (read-on cr2 session2 0 +cluster-operational-credentials+ 1)) :label)))
          (is (eq :success (invoke-on cr2 session2 'on-off 'on nil :endpoint 1)))
          ;; the restored commissioner commissions the next device with the next node id
          (open-commissioning-window device2 :timeout 300)
          (let* ((cr3 (make-commissioning-rig :commissioner-args (list :state (commissioner-state commissioner2))))
                 (result3 (commission-on-rig cr3)))
            (is (= 3 (getf result3 :node-id)))
            (is (= #x1D (fabric-fabric-id (device-fabric cr3))))
            (is (= 4 (commissioner-next-node-id (cr-commissioner cr3))))))))))

(test restore-refuses-what-does-not-fit
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr)))
    (commission-and-open cr)
    (let ((state (device-state device)))
      ;; into a device with fabrics
      (signals state-error (restore-device-state device state))
      (is (= 1 (length (device-fabrics device))))
      ;; a wrong format, a duplicated index, an index out of range, too many fabrics, a bad next index
      (flet ((fresh (&rest args) (cr-device (apply #'make-commissioning-rig args)))
             (with (state &rest changes)
               (let ((copy (copy-list state)))
                 (loop :for (key value) :on changes :by #'cddr :do (setf (getf copy key) value))
                 copy)))
        (signals state-error (restore-device-state (fresh) (with state :format 2)))
        (signals state-error (restore-device-state (fresh) (with state :fabrics (list (first (getf state :fabrics))
                                                                                        (first (getf state :fabrics))))))
        (signals state-error (restore-device-state (fresh) (with state :fabrics (list (with (first (getf state :fabrics)) :index 0)))))
        (signals state-error (restore-device-state (fresh) (with state :fabrics (list (with (first (getf state :fabrics)) :index 255)))))
        (signals state-error (restore-device-state (fresh :max-fabrics 1)
                                                   (with state :fabrics (list (first (getf state :fabrics))
                                                                              (with (fabric-state (make-test-fabric)) :index 2)))))
        (signals state-error (restore-device-state (fresh) (with state :next-fabric-index 0)))
        (signals state-error (restore-device-state (fresh) (with state :fabrics (list (with (first (getf state :fabrics)) :private-key (octets 1 2 3))))))
        ;; a refused state leaves the device as it was: the window opens as for a fresh one
        (let ((device (fresh)))
          (signals state-error (restore-device-state device (with state :next-fabric-index 0)))
          (is (null (device-fabrics device)))
          (is (commissioning-window-open-p device)))
        ;; a resumption record for a fabric not in the state is dropped, not an error
        (let ((device (fresh)))
          (restore-device-state device (with state :resumptions (list (with (first (getf state :resumptions)) :fabric-index 7))))
          (is (= 1 (length (device-fabrics device))))
          (is (null (secure-channel-resumptions (device-channel device)))))
        ;; MAKE-DEVICE :STATE and :FABRICS together: the state's fabric joins the other
        (let ((device (fresh :device-args (list :state state :fabrics (list (make-test-fabric :fabric-id #x99))))))
          (is (= 2 (length (device-fabrics device))))
          (is (equal '(1 2) (sort (mapcar #'fabric-index (device-fabrics device)) #'<))))))
    ;; the commissioner's state checks
    (let ((state (commissioner-state (cr-commissioner cr))))
      (flet ((fresh (state) (make-commissioning-rig :commissioner-args (list :state state))))
        (signals state-error (fresh (list :format 2)))
        (let ((wrong (copy-list state)))
          (setf (getf wrong :root-private-key) (p256-keypair-private (generate-p256-keypair)))
          (signals state-error (fresh wrong)))))))

;;; ------------------------------------------------------------------
;;; MAKE-DEVICE :STORAGE keeps the file by itself

(test storage-file-follows-the-device
  (with-temp-file (path "storage")
    (let* ((cr (make-commissioning-rig :device-args (list :storage path)))
           (device (cr-device cr)))
      (is (equal path (device-storage device)))
      (is (null (probe-file path)))               ; nothing to keep yet
      (is (commissioning-window-open-p device))
      (multiple-value-bind (result session) (commission-and-open cr)
        (declare (ignore result))
        (is (probe-file path))
        (let ((state (read-state-file path)))
          (is (= 1 (length (getf state :fabrics))))
          (is (equalp state (device-state device))))
        (invoke-on cr session 'operational-credentials 'update-fabric-label (list :label "Lab"))
        (is (string= "Lab" (getf (first (getf (read-state-file path) :fabrics)) :label)))
        ;; a new device from the file: commissioned, window closed, the same administrator gets in
        (let* ((cr2 (make-commissioning-rig :device-args (list :storage path)
                                            :commissioner-args (list :state (commissioner-state (cr-commissioner cr)))))
               (device2 (cr-device cr2)))
          (is (= 1 (length (device-fabrics device2))))
          (is (string= "Lab" (fabric-label (device-fabric cr2))))
          (is (not (commissioning-window-open-p device2)))
          (let* ((hs (finish-handshake cr2 (start-case (commissioner-channel (cr-commissioner cr2)) "mem" (rig-b-port (cr-rig cr2))
                                                       :fabric (commissioner-fabric (cr-commissioner cr2)) :peer-node-id 2)))
                 (session2 (handshake-session hs)))
            (is (case-resumed-p (handshake-machine hs)))
            ;; the new resumption record went to the file
            (is (equalp (case-resumption-resumption-id (session-resumption session2))
                        (getf (first (getf (read-state-file path) :resumptions)) :resumption-id)))
            ;; RemoveFabric: the file follows, and a device from it is fresh again
            (is (= +noc-status-ok+ (getf (invoke-on cr2 session2 'operational-credentials 'remove-fabric (list :fabric-index 1)) :status-code)))
            (pass-time cr2 (+ *fabric-removal-delay* 0.5))
            (is (null (device-fabrics device2)))
            (is (null (getf (read-state-file path) :fabrics)))
            (is (= 2 (getf (read-state-file path) :next-fabric-index)))
            (let ((device3 (cr-device (make-commissioning-rig :device-args (list :storage path)))))
              (is (null (device-fabrics device3)))
              (is (= 2 (cl-matter::device-next-fabric-index device3)))
              (is (commissioning-window-open-p device3)))))))))
