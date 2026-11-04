;;;; fabric.lisp -- a node's membership in a fabric (Matter Core
;;;; Specification sections 4.14.2, 4.15.2, 6.4 and 11.17): the operational
;;;; credentials, the key pair the NOC certifies, the identity protection
;;;; key, and the identifiers derived from them.
;;;;
;;;;   CompressedFabricIdentifier = HKDF(root public key x||y, fabric id BE, "CompressedFabric", 8)
;;;;   OperationalGroupKey (IPK)  = HKDF(epoch key, compressed fabric id, "GroupKey v1.0", 16)
;;;;   GroupSessionId             = HKDF(operational group key, nil, "GroupKeyHash", 2) as BE 16 bits
;;;;   CASE destination id        = HMAC(IPK, initiatorRandom || root public key || fabric id LE || node id LE)
;;;;
;;;; A FABRIC is what both CASE roles are given: it validates its chain on
;;;; construction and knows everything a Sigma exchange needs.

(in-package :cl-matter)

(defconstant +compressed-fabric-id-length+ 8)
(defconstant +epoch-key-length+ 16)
(defconstant +ipk-length+ 16)

(defun %check-id (value bits what)
  (unless (and (integerp value) (<= 0 value (1- (ash 1 bits))))
    (%cert-fail "~a must be a ~d-bit unsigned integer, got ~s" what bits value))
  value)

(defun compressed-fabric-id (root-public-key fabric-id)
  "The 8-octet compressed fabric identifier of the fabric FABRIC-ID under
ROOT-PUBLIC-KEY (65 octets); the second value is it as an integer."
  (let ((root (%check-octet-vector "the root public key" root-public-key)))
    (unless (p256-point-p root) (%cert-fail "the root public key is not a point on P-256"))
    (%check-id fabric-id 64 "the fabric id")
    (let ((octets (hkdf-sha256 (subseq root 1) (%integer-octets fabric-id 8)
                               (%ascii-octets "CompressedFabric") +compressed-fabric-id-length+)))
      (values octets (%octets-integer octets)))))

(defun operational-group-key (epoch-key compressed-fabric-id)
  "The operational group key of EPOCH-KEY (16 octets) on the fabric with
COMPRESSED-FABRIC-ID (8 octets): for epoch key 0 of the IPK key set, the
IPK itself."
  (let ((epoch-key (%check-octet-vector "the epoch key" epoch-key))
        (fabric (%check-octet-vector "the compressed fabric id" compressed-fabric-id)))
    (unless (= (length epoch-key) +epoch-key-length+)
      (%cert-fail "an epoch key is ~d octets, got ~d" +epoch-key-length+ (length epoch-key)))
    (unless (= (length fabric) +compressed-fabric-id-length+)
      (%cert-fail "a compressed fabric id is ~d octets, got ~d" +compressed-fabric-id-length+ (length fabric)))
    (hkdf-sha256 epoch-key fabric (%ascii-octets "GroupKey v1.0") +ipk-length+)))

(defun group-session-id (operational-group-key)
  "The 16-bit group session id of an operational group key."
  (%octets-integer (hkdf-sha256 operational-group-key nil (%ascii-octets "GroupKeyHash") 2)))

(defun case-destination-id (ipk initiator-random root-public-key fabric-id node-id)
  "The 32-octet destination identifier of Sigma1 (section 4.14.2.3)."
  (%check-id fabric-id 64 "the fabric id")
  (%check-id node-id 64 "the node id")
  (let ((random (%check-octet-vector "the initiator random" initiator-random))
        (root (%check-octet-vector "the root public key" root-public-key)))
    (unless (= (length random) 32) (%cert-fail "the initiator random is 32 octets, got ~d" (length random)))
    (unless (= (length root) +p256-point-length+)
      (%cert-fail "the root public key is ~d octets, got ~d" +p256-point-length+ (length root)))
    (let ((message (make-array (+ 32 +p256-point-length+ 16) :element-type '(unsigned-byte 8))))
      (replace message random)
      (replace message root :start1 32)
      (dotimes (i 8) (setf (aref message (+ 32 +p256-point-length+ i)) (ldb (byte 8 (* 8 i)) fabric-id)))
      (dotimes (i 8) (setf (aref message (+ 32 +p256-point-length+ 8 i)) (ldb (byte 8 (* 8 i)) node-id)))
      (hmac-sha256 ipk message))))

;;; ------------------------------------------------------------------
;;; The fabric

(defstruct (fabric (:constructor %make-fabric))
  "This node's place in one fabric: the validated credentials and what is
derived from them.  OPERATIONAL-KEYPAIR is the key pair the NOC certifies."
  (rcac nil :read-only t)               ; CERTIFICATE
  (icac nil :read-only t)               ; CERTIFICATE or NIL
  (noc nil :read-only t)                ; CERTIFICATE
  (operational-keypair nil :read-only t)
  (node-id 0 :read-only t)
  (fabric-id 0 :read-only t)
  (case-auth-tags nil :read-only t)
  (root-public-key nil :read-only t)    ; 65 octets
  (compressed-fabric-id nil :read-only t) ; 8 octets
  (epoch-key nil :read-only t)          ; the IPK epoch key, 16 octets
  (ipk nil :read-only t)                ; the operational IPK, 16 octets
  (vendor-id 0)
  (label ""))

(defmethod print-object ((f fabric) stream)
  (print-unreadable-object (f stream :type t)
    (format stream "~16,'0x node ~16,'0x" (fabric-fabric-id f) (fabric-node-id f))))

(defun make-fabric (&key rcac icac noc operational-keypair epoch-key (vendor-id 0) (label "") time)
  "A fabric from the credentials NOC, ICAC (optional) and RCAC (certificates
or TLV octets), the OPERATIONAL-KEYPAIR the NOC certifies, and the IPK
EPOCH-KEY (16 octets) the fabric's key set holds at epoch 0.  The chain is
validated (at Matter epoch TIME when given); a NOC for another key pair is
CERTIFICATE-ERROR."
  (unless (p256-keypair-p operational-keypair)
    (%cert-fail "the operational key pair must be a P256-KEYPAIR"))
  (let ((rcac (certificate rcac)) (icac (and icac (certificate icac))) (noc (certificate noc)))
    (multiple-value-bind (node-id fabric-id cats noc-public-key root-public-key)
        (validate-certificate-chain noc icac rcac :time time)
      (unless (equalp noc-public-key (p256-keypair-public operational-keypair))
        (%cert-fail "the NOC certifies a different public key than the operational key pair's"))
      (let* ((compressed (compressed-fabric-id root-public-key fabric-id))
             (epoch-key (%check-octet-vector "the epoch key" epoch-key)))
        (%make-fabric :rcac rcac :icac icac :noc noc
                      :operational-keypair operational-keypair
                      :node-id node-id :fabric-id fabric-id :case-auth-tags cats
                      :root-public-key root-public-key
                      :compressed-fabric-id compressed
                      :epoch-key epoch-key
                      :ipk (operational-group-key epoch-key compressed)
                      :vendor-id vendor-id :label label)))))

(defun fabric-operational-instance-name (fabric &optional (node-id (fabric-node-id fabric)))
  "The DNS-SD instance name of NODE-ID on FABRIC: <compressed fabric id>-<node id>,
16 uppercase hex digits each (section 4.3.2.1)."
  (format nil "~16,'0x-~16,'0x" (nth-value 1 (compressed-fabric-id (fabric-root-public-key fabric)
                                                                   (fabric-fabric-id fabric)))
          node-id))

(defun fabric-destination-id (fabric initiator-random &optional (node-id (fabric-node-id fabric)))
  "The Sigma1 destination id that addresses NODE-ID (default: this node) on FABRIC."
  (case-destination-id (fabric-ipk fabric) initiator-random (fabric-root-public-key fabric)
                       (fabric-fabric-id fabric) node-id))

(defun make-test-fabric (&key (fabric-id #x1D) (node-id 1) (rcac-id 1) icac case-auth-tags epoch-key
                           (vendor-id #xFFF1))
  "A fabric with freshly generated credentials: an RCAC, an ICAC when ICAC
is true, and a NOC for NODE-ID -- for tests and for a commissioner that
roots its own fabric.  Returns (values fabric root-keypair ica-keypair)."
  (let* ((root-keypair (generate-p256-keypair))
         (ica-keypair (and icac (generate-p256-keypair)))
         (node-keypair (generate-p256-keypair))
         (rcac (make-root-certificate :keypair root-keypair :rcac-id rcac-id))
         (icac (and icac (make-ica-certificate :keypair ica-keypair :icac-id 1 :fabric-id fabric-id
                                               :issuer rcac :issuer-keypair root-keypair)))
         (noc (make-node-certificate :public-key node-keypair :node-id node-id :fabric-id fabric-id
                                     :case-auth-tags case-auth-tags
                                     :issuer (or icac rcac) :issuer-keypair (or ica-keypair root-keypair))))
    (values (make-fabric :rcac rcac :icac icac :noc noc :operational-keypair node-keypair
                         :epoch-key (or epoch-key (random-octets +epoch-key-length+))
                         :vendor-id vendor-id)
            root-keypair ica-keypair)))

(defun fabric-add-node (fabric node-id &key root-keypair ica-keypair case-auth-tags)
  "Another node's credentials on FABRIC, signed by ROOT-KEYPAIR (or by the
ICAC with ICA-KEYPAIR): a fabric for NODE-ID sharing the root and IPK."
  (let* ((node-keypair (generate-p256-keypair))
         (issuer (if ica-keypair (fabric-icac fabric) (fabric-rcac fabric)))
         (noc (make-node-certificate :public-key node-keypair :node-id node-id
                                     :fabric-id (fabric-fabric-id fabric)
                                     :case-auth-tags case-auth-tags
                                     :issuer issuer :issuer-keypair (or ica-keypair root-keypair))))
    (make-fabric :rcac (fabric-rcac fabric) :icac (and ica-keypair (fabric-icac fabric)) :noc noc
                 :operational-keypair node-keypair :epoch-key (fabric-epoch-key fabric)
                 :vendor-id (fabric-vendor-id fabric) :label (fabric-label fabric))))
