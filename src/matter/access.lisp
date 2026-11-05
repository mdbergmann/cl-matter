;;;; access.lisp -- access control (Matter Core Specification section
;;;; 6.6): whether the peer of a session may read, write or invoke what it
;;;; asks for, decided from the Access Control List the node keeps in its
;;;; Access Control cluster (defined in commissioning.lisp; the entries are
;;;; plists as ACL-ENTRY makes them).
;;;;
;;;; A request's subject descriptor is the session's auth mode, its fabric
;;;; index and its subjects: the peer's operational node id and one subject
;;;; per CASE Authenticated Tag of its NOC.  An ACL entry grants its
;;;; privilege, and the ones that privilege includes (6.6.2.2), when it is
;;;; on the subject's fabric, has its auth mode, names one of its subjects
;;;; (or none at all), and targets the cluster, endpoint or device type
;;;; asked for (or everything).  A PASE session holds Administer on every
;;;; endpoint without an entry (6.6.2.1.1: the commissioner), which is why
;;;; the cluster refuses entries with the PASE auth mode.  Local access
;;;; (no session) is not controlled, and neither is a node that serves no
;;;; Access Control cluster: it has nothing to be configured with.
;;;;
;;;; Not done: the Group auth mode (there are no group sessions), the
;;;; Extension attribute, the Access Restriction List of Matter 1.4.

(in-package :cl-matter)

(defconstant +cluster-access-control+ #x001F)

;; AuthModeEnum
(defconstant +auth-mode-pase+ 1)
(defconstant +auth-mode-case+ 2)
(defconstant +auth-mode-group+ 3)

(defconstant +cat-subject-prefix+ #xFFFFFFFD "The high 32 bits of a CASE Authenticated Tag subject (6.6.2.1.2).")

(defun cat-subject (cat)
  "The 64-bit subject that names the CASE Authenticated Tag CAT (32 bits)."
  (unless (case-auth-tag-p cat) (error "~s is not a CASE Authenticated Tag" cat))
  (logior (ash +cat-subject-prefix+ 32) cat))

(defun cat-subject-p (subject)
  "True when SUBJECT (64 bits) names a CASE Authenticated Tag: #xFFFFFFFD in
the high half, a tag with a non-zero version in the low."
  (and (integerp subject)
       (= +cat-subject-prefix+ (ash subject -32))
       (case-auth-tag-p (logand subject #xFFFFFFFF))))

(defun session-subjects (session)
  "The subjects the peer of a CASE SESSION acts as: its node id, then the
CAT subjects of its NOC.  NIL for any other session."
  (when (eq :case (session-type session))
    (cons (session-peer-node-id session)
          (mapcar #'cat-subject (session-peer-case-auth-tags session)))))

(defun %subject-matches-p (entry-subject subject)
  "Does ENTRY-SUBJECT, from an ACL entry, cover SUBJECT, one of a session's?
A CAT subject covers a CAT with the same identifier and a version that is
not older (6.6.2.1.2); a node id covers itself."
  (if (cat-subject-p entry-subject)
      (and (cat-subject-p subject)
           (= (ldb (byte 16 16) entry-subject) (ldb (byte 16 16) subject))
           (>= (ldb (byte 16 0) subject) (ldb (byte 16 0) entry-subject)))
      (eql entry-subject subject)))

(defun %target-matches-p (target endpoint cluster-id)
  "Does the AccessControlTargetStruct TARGET cover CLUSTER-ID on ENDPOINT?"
  (let ((cluster (getf target :cluster :null))
        (endpoint-id (getf target :endpoint :null))
        (device-type (getf target :device-type :null)))
    (and (or (eq cluster :null) (eql cluster cluster-id))
         (or (eq endpoint-id :null) (eql endpoint-id (endpoint-id endpoint)))
         (or (eq device-type :null) (and (assoc device-type (endpoint-device-types endpoint)) t)))))

(defun acl-entry-grants-p (entry privilege fabric-index auth-mode subjects endpoint cluster-id)
  "Does the ACL ENTRY grant PRIVILEGE on CLUSTER-ID of ENDPOINT to a peer of
AUTH-MODE on the fabric FABRIC-INDEX acting as SUBJECTS (6.6.5.2)?  Null
(or empty) subjects stand for every subject, null targets for everything."
  (let ((entry-subjects (getf entry :subjects :null))
        (targets (getf entry :targets :null)))
    (flet ((any-p (list) (or (eq list :null) (null list))))
      (and (eql fabric-index (getf entry :fabric-index))
           (eql auth-mode (getf entry :auth-mode))
           (privilege-grants-p (getf entry :privilege) privilege)
           (or (any-p entry-subjects)
               (some (lambda (entry-subject)
                       (some (lambda (subject) (%subject-matches-p entry-subject subject)) subjects))
                     entry-subjects))
           (or (any-p targets)
               (some (lambda (target) (%target-matches-p target endpoint cluster-id)) targets))))))

(defun node-access-control-entries (node)
  "The ACL of NODE: the entries of the Access Control cluster on its root
endpoint, or :NONE when it serves no such cluster."
  (let ((cluster (node-cluster node +endpoint-root+ +cluster-access-control+)))
    (if cluster (attribute-value cluster 'acl) :none)))

(defun access-granted-p (node session endpoint cluster-id privilege)
  "May the peer of SESSION exercise PRIVILEGE (a value or name) on cluster
CLUSTER-ID of ENDPOINT, an ENDPOINT of NODE?  Local access (SESSION NIL)
and a node without an Access Control cluster are unrestricted; a PASE
session holds Administer everywhere; a CASE session holds what its
fabric's ACL entries grant it; any other session holds nothing."
  (let ((privilege (privilege-value privilege)))
    (cond ((null session) t)
          ((eq :none (node-access-control-entries node)) t)
          ((eq :pase (session-type session)) t)
          ((not (eq :case (session-type session))) nil)
          (t (let ((fabric-index (session-fabric-index session))
                   (subjects (session-subjects session)))
               (and (plusp fabric-index)
                    (some (lambda (entry)
                            (acl-entry-grants-p entry privilege fabric-index +auth-mode-case+ subjects endpoint cluster-id))
                          (node-access-control-entries node))
                    t))))))
