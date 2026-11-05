;;;; persistence.lisp -- what a node keeps across restarts (Matter Core
;;;; Specification sections 11.17.5, 9.10.5 and 11.1.5): the fabric table
;;;; with its operational key pairs and IPKs, the ACL, the CASE resumption
;;;; records, and the attributes an administrator wrote -- NodeLabel,
;;;; Location, the regulatory configuration.
;;;;
;;;; A state is a plist of plain data: integers, strings, keywords, NIL/T,
;;;; octet vectors and lists of those.  DEVICE-STATE takes the snapshot --
;;;; of what is *committed*: a fabric AddNOC installed under an armed
;;;; fail-safe is not in it until CommissioningComplete, exactly as the
;;;; fail-safe's expiry would leave the node -- and RESTORE-DEVICE-STATE
;;;; puts it back into a fresh device.  WRITE-STATE-FILE / READ-STATE-FILE
;;;; keep a state in a file the standard reader reads back (no #. and no
;;;; symbols but keywords, NIL and T), and MAKE-DEVICE :STORAGE does both
;;;; by itself: it restores the file at start and rewrites it after every
;;;; change that matters.
;;;;
;;;; A commissioner has the same: COMMISSIONER-STATE keeps the fabric it
;;;; administers with the key pairs that root it, the next node id to hand
;;;; out and its resumption records, so a controller resumes its sessions
;;;; after a restart instead of starting new fabrics.

(in-package :cl-matter)

(defconstant +state-format+ 1 "The :FORMAT a state carries; a reader refuses what it does not know.")

(define-condition state-error (error)
  ((message :initarg :message :reader state-error-message))
  (:report (lambda (c stream) (format stream "~a" (state-error-message c))))
  (:documentation "A state that cannot be read, written or restored."))

(defun %state-fail (format &rest args)
  (error 'state-error :message (apply #'format nil format args)))

;;; ------------------------------------------------------------------
;;; The file format

(defun %write-state-datum (x stream)
  "X in a form the standard reader gives back: NIL/T spelled out, keywords
with their colon, strings escaped, octet vectors as #(...)."
  (cond ((null x) (write-string "NIL" stream))
        ((eq x t) (write-string "T" stream))
        ((keywordp x) (write-char #\: stream) (write-string (symbol-name x) stream))
        ((integerp x) (format stream "~d" x))
        ((stringp x) (prin1 x stream))
        ((consp x)
         (write-char #\( stream)
         (loop :for (datum . rest) :on x
               :do (%write-state-datum datum stream)
                   (cond ((null rest))
                         ((consp rest) (write-char #\Space stream))
                         (t (write-string " . " stream) (%write-state-datum rest stream))))
         (write-char #\) stream))
        ((and (vectorp x) (not (stringp x)) (every (lambda (o) (and (integerp o) (<= 0 o 255))) x))
         (write-char #\# stream) (write-char #\( stream)
         (loop :for o :across x :for first := t :then nil
               :do (unless first (write-char #\Space stream))
                   (format stream "~d" o))
         (write-char #\) stream))
        (t (%state-fail "~s cannot be kept in a state file" x))))

(defun %read-state-datum (x)
  "The reader's vectors are simple vectors of integers: octets again.  Only
what %WRITE-STATE-DATUM writes is accepted."
  (cond ((or (null x) (eq x t) (keywordp x) (integerp x) (stringp x)) x)
        ((consp x) (cons (%read-state-datum (car x)) (%read-state-datum (cdr x))))
        ((and (vectorp x) (every (lambda (o) (and (integerp o) (<= 0 o 255))) x))
         (coerce x 'octets))
        (t (%state-fail "~s is not state file data" x))))

(defun write-state-file (state pathname)
  "Write STATE (a plist as DEVICE-STATE or COMMISSIONER-STATE make it) to
PATHNAME, replacing what is there."
  (ensure-directories-exist pathname)
  (with-open-file (out pathname :direction :output :if-exists :supersede :if-does-not-exist :create)
    (write-string ";; cl-matter state -- do not edit while the node runs" out)
    (terpri out)
    (%write-state-datum state out)
    (terpri out))
  pathname)

(defun read-state-file (pathname)
  "The state in PATHNAME, or NIL when there is no such file.  A file that
is not a state file is STATE-ERROR."
  (with-open-file (in pathname :direction :input :if-does-not-exist nil)
    (when in
      (let ((state (let ((*read-eval* nil) (*package* (find-package :cl-matter)) (*read-default-float-format* 'double-float))
                     (handler-case (%read-state-datum (read in nil :eof))
                       (error (e) (%state-fail "~a is not a state file: ~a" pathname e))))))
        (unless (and (listp state) (eql (getf state :format) +state-format+))
          (%state-fail "~a is not a state file of format ~d" pathname +state-format+))
        state))))

;;; ------------------------------------------------------------------
;;; A fabric

(defun fabric-state (fabric)
  "FABRIC as plain data: its credentials as TLV, the operational private
key, the IPK epoch key, vendor id, label and index."
  (list :index (fabric-index fabric)
        :rcac (certificate-octets* (fabric-rcac fabric))
        :icac (and (fabric-icac fabric) (certificate-octets* (fabric-icac fabric)))
        :noc (certificate-octets* (fabric-noc fabric))
        :private-key (p256-keypair-private (fabric-operational-keypair fabric))
        :epoch-key (fabric-epoch-key fabric)
        :vendor-id (fabric-vendor-id fabric)
        :label (fabric-label fabric)))

(defun fabric-from-state (state)
  "The FABRIC of a FABRIC-STATE plist, its chain validated again."
  (handler-case
      (make-fabric :rcac (getf state :rcac) :icac (getf state :icac) :noc (getf state :noc)
                   :operational-keypair (make-p256-keypair (getf state :private-key))
                   :epoch-key (getf state :epoch-key)
                   :vendor-id (getf state :vendor-id 0) :label (getf state :label "")
                   :index (getf state :index 0))
    (error (e) (%state-fail "fabric ~@[~d ~]cannot be restored: ~a" (getf state :index) e))))

(defun %resumption-state (resumption)
  (list :fabric-index (fabric-index (case-resumption-fabric resumption))
        :peer-node-id (case-resumption-peer-node-id resumption)
        :resumption-id (case-resumption-resumption-id resumption)
        :shared-secret (case-resumption-shared-secret resumption)
        :peer-case-auth-tags (case-resumption-peer-case-auth-tags resumption)))

(defun %resumption-from-state (state fabric)
  (make-case-resumption :fabric fabric
                        :peer-node-id (getf state :peer-node-id)
                        :resumption-id (getf state :resumption-id)
                        :shared-secret (getf state :shared-secret)
                        :peer-case-auth-tags (getf state :peer-case-auth-tags)))

(defun %resumptions-state (channel fabrics)
  "The channel's resumption records on FABRICS, as plain data."
  (loop :for r :in (secure-channel-resumptions channel)
        :when (member (case-resumption-fabric r) fabrics)
          :collect (%resumption-state r)))

(defun %restore-resumptions (channel states fabrics)
  "Resumption records back into CHANNEL; one for a fabric not in FABRICS is dropped."
  (dolist (state states)
    (let ((fabric (find (getf state :fabric-index) fabrics :key #'fabric-index)))
      (when fabric (%remember-resumption channel (%resumption-from-state state fabric))))))

;;; ------------------------------------------------------------------
;;; The device

(defvar *device-restoring* nil "True while RESTORE-DEVICE-STATE writes into a device: nothing is saved back.")

(defun %committed-fabrics (device)
  "The fabric table as a restart would find it: without the fabric a
fail-safe still holds, with the one UpdateNOC replaced in place of its
replacement."
  (let ((fabrics (device-fabrics device))
        (fail-safe (device-fail-safe device)))
    (when fail-safe
      (let ((added (fail-safe-added-fabric fail-safe))
            (replaced (fail-safe-replaced-fabric fail-safe)))
        (when added (setf fabrics (remove added fabrics)))
        (when replaced (setf fabrics (substitute (car replaced) (cdr replaced) fabrics)))))
    fabrics))

(defun device-state (device)
  "DEVICE's persistent state, a plist of plain data: the committed fabric
table (FABRIC-STATEs), the next fabric index, the ACL entries of those
fabrics, the CASE resumption records, and NodeLabel, Location and the
regulatory configuration."
  (let* ((fabrics (%committed-fabrics device))
         (indices (mapcar #'fabric-index fabrics))
         (basic (node-cluster (device-node device) +endpoint-root+ 'basic-information)))
    (list :format +state-format+
          :next-fabric-index (device-next-fabric-index device)
          :fabrics (mapcar #'fabric-state fabrics)
          :acl (remove-if-not (lambda (entry) (member (getf entry :fabric-index) indices)) (device-acl device))
          :resumptions (%resumptions-state (device-channel device) fabrics)
          :node-label (attribute-value basic 'node-label)
          :location (attribute-value basic 'location)
          :regulatory-config (attribute-value (device-general-commissioning device) 'regulatory-config))))

(defun restore-device-state (device state)
  "Put STATE (as DEVICE-STATE made it) into DEVICE: the fabrics join the
table under their old indices, the ACL, the resumption records and the
attributes come back.  The device must hold no fabric yet; a state that
does not fit is STATE-ERROR and leaves the device as it was."
  (unless (and (listp state) (eql (getf state :format) +state-format+))
    (%state-fail "not a device state of format ~d: ~s" +state-format+ state))
  (when (device-fabrics device)
    (%state-fail "~a already has fabrics: a state is restored into a fresh device" device))
  (let ((fabrics (mapcar #'fabric-from-state (getf state :fabrics)))
        (next (getf state :next-fabric-index 1))
        (basic (node-cluster (device-node device) +endpoint-root+ 'basic-information)))
    (dolist (fabric fabrics)
      (when (or (zerop (fabric-index fabric)) (> (fabric-index fabric) +max-fabric-index+))
        (%state-fail "fabric ~a has no valid index" fabric))
      (when (> (count (fabric-index fabric) fabrics :key #'fabric-index) 1)
        (%state-fail "fabric index ~d is in the state twice" (fabric-index fabric))))
    (unless (and (integerp next) (<= 1 next +max-fabric-index+))
      (%state-fail "the next fabric index ~s is out of range" next))
    (when (> (length fabrics) (device-max-fabrics device))
      (%state-fail "~d fabrics in the state, the device holds ~d" (length fabrics) (device-max-fabrics device)))
    (let ((*device-restoring* t))
      (setf (device-next-fabric-index device) next)
      (dolist (fabric fabrics) (%install-fabric device fabric))
      (setf (device-acl device) (getf state :acl))
      (%restore-resumptions (device-channel device) (getf state :resumptions) fabrics)
      (let ((label (getf state :node-label)) (location (getf state :location))
            (regulatory (getf state :regulatory-config)))
        (when label (setf (attribute-value basic 'node-label) label))
        (when location (setf (attribute-value basic 'location) location))
        (when regulatory (setf (attribute-value (device-general-commissioning device) 'regulatory-config) regulatory)))))
  device)

(defun %state-changed (device)
  "Something persistent changed: the application's ON-STATE-CHANGE hears
of it, and the storage file is rewritten."
  (unless *device-restoring*
    (when (device-on-state-change device)
      (funcall (device-on-state-change device) device))
    (when (device-storage device)
      (write-state-file (device-state device) (device-storage device)))))

(defun %persistent-attribute-p (endpoint-id cluster-id attribute-id)
  "The attributes whose writes are kept."
  (and (= endpoint-id +endpoint-root+)
       (or (and (= cluster-id +cluster-access-control+) (= attribute-id 0))
           (and (= cluster-id +cluster-basic-information+) (member attribute-id '(5 6)))
           (and (= cluster-id +cluster-general-commissioning+) (= attribute-id 2)))))

(defun %watch-device-state (device)
  "After every persistent change -- an attribute above, a CASE session
with a new resumption record -- the state is saved."
  (add-node-listener (device-node device)
                     (lambda (endpoint-id cluster-id attribute-id)
                       (when (%persistent-attribute-p endpoint-id cluster-id attribute-id)
                         (%state-changed device))))
  (let* ((channel (device-channel device))
         (previous (secure-channel-on-session channel)))
    (setf (secure-channel-on-session channel)
          (lambda (channel session)
            (when previous (funcall previous channel session))
            (when (eq :case (session-type session))
              (%state-changed device))))))

;;; ------------------------------------------------------------------
;;; The commissioner

(defun commissioner-state (commissioner)
  "The commissioner's persistent state: its fabric with the root (and ICA)
key pair, the vendor id, the next node id, and its resumption records."
  (let ((fabric (commissioner-fabric commissioner)))
    (list :format +state-format+
          :fabric (fabric-state fabric)
          :root-private-key (p256-keypair-private (commissioner-root-keypair commissioner))
          :ica-private-key (and (commissioner-ica-keypair commissioner)
                                (p256-keypair-private (commissioner-ica-keypair commissioner)))
          :vendor-id (commissioner-vendor-id commissioner)
          :next-node-id (commissioner-next-node-id commissioner)
          :resumptions (%resumptions-state (commissioner-channel commissioner) (list fabric)))))

(defun %commissioner-from-state (state channel model &rest args &key &allow-other-keys)
  "MAKE-COMMISSIONER from a COMMISSIONER-STATE; ARGS are its other keywords."
  (unless (and (listp state) (eql (getf state :format) +state-format+))
    (%state-fail "not a commissioner state of format ~d: ~s" +state-format+ state))
  (let* ((fabric (fabric-from-state (getf state :fabric)))
         (root (make-p256-keypair (getf state :root-private-key)))
         (ica (and (getf state :ica-private-key) (make-p256-keypair (getf state :ica-private-key)))))
    (unless (equalp (p256-keypair-public root) (fabric-root-public-key fabric))
      (%state-fail "the root key pair in the state does not root its fabric"))
    (when (and (fabric-icac fabric) (not ica))
      (%state-fail "the fabric has an ICAC but the state no ICA key pair"))
    (let ((commissioner (apply #'make-commissioner channel model
                               :fabric fabric :root-keypair root :ica-keypair ica
                               :vendor-id (getf state :vendor-id (fabric-vendor-id fabric))
                               :first-node-id (getf state :next-node-id 2)
                               args)))
      (%restore-resumptions channel (getf state :resumptions) (list fabric))
      commissioner)))
