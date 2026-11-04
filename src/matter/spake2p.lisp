;;;; spake2p.lisp -- SPAKE2+ on P-256 with SHA-256, HKDF-SHA256 and
;;;; HMAC-SHA256 (RFC 9383; Matter Core Specification section 3.10).
;;;;
;;;; The two parties are the prover (Matter's commissioner, who knows the
;;;; passcode) and the verifier (the commissionee, who stores w0 and L
;;;; and never learns the passcode).  The shares, Z, V and the transcript
;;;; follow RFC 9383 exactly, so its appendix vectors check them.  The key
;;;; schedule is the one Matter froze from the draft the RFC grew out of:
;;;;
;;;;   Ka || Ke   = SHA-256(TT)                     16 octets each
;;;;   KcA || KcB = HKDF(Ka, salt nil, "ConfirmationKeys", 32)
;;;;   cA = HMAC(KcA, pB)   cB = HMAC(KcB, pA)
;;;;
;;;; Ke is what the PASE session keys are derived from.  Curve arithmetic
;;;; is Ironclad's (Jacobian coordinates, Montgomery ladder); the cofactor
;;;; of P-256 is 1, so the cofactor multiplications of the RFC are the
;;;; identity and only the point-at-infinity checks remain.

(in-package :cl-matter)

(define-condition spake2p-error (crypto-error) ()
  (:documentation "A malformed SPAKE2+ input: a share off the curve, a scalar out of range."))

(define-condition spake2p-confirmation-error (spake2p-error) ()
  (:default-initargs :message "SPAKE2+ key confirmation failed: the peer does not hold the same passcode")
  (:documentation "The peer's confirmation MAC did not verify: wrong passcode, or a tampered exchange."))

(defun %spake2p-fail (format &rest args)
  (error 'spake2p-error :message (apply #'format nil format args)))

;;; ------------------------------------------------------------------
;;; P-256 points as SPAKE2+ sees them (the arithmetic is in p256.lisp)

(defun %p256-decode-point (octets what)
  "OCTETS (65, uncompressed) -> an Ironclad point on the curve, or SPAKE2P-ERROR."
  (let ((octets (%check-octet-vector what octets)))
    (unless (= (length octets) +p256-point-length+)
      (%spake2p-fail "~a must be an uncompressed P-256 point of ~d octets, got ~d"
                     what +p256-point-length+ (length octets)))
    (handler-case (ironclad:ec-decode-point :secp256r1 octets)
      (error () (%spake2p-fail "~a is not a point on P-256" what)))))

(defun %p256-encode-point (point what)
  "POINT -> 65 octets; the point at infinity is SPAKE2P-ERROR (it is never a
valid share, Z or V)."
  (handler-case (ironclad:ec-encode-point point)
    (error () (%spake2p-fail "~a is the point at infinity" what))))

(defun %scalar (value what)
  "VALUE, an integer or a 32-octet big-endian vector -> an integer in [1, n-1]."
  (let ((n (cond ((integerp value) value)
                 ((and (vectorp value) (not (stringp value)))
                  (unless (= (length value) +p256-scalar-length+)
                    (%spake2p-fail "~a must be ~d octets, got ~d" what +p256-scalar-length+ (length value)))
                  (%octets-integer value))
                 (t (%spake2p-fail "~a must be an integer or a ~d-octet vector, got ~s"
                                   what +p256-scalar-length+ value)))))
    (unless (< 0 n *p256-order*)
      (%spake2p-fail "~a must be in [1, n-1] of P-256, got ~d" what n))
    n))

;;; The fixed points M and N of RFC 9383 section 4 for P-256 (uncompressed;
;;; the RFC lists them compressed and the transcript carries them uncompressed).

(defparameter *spake2p-m*
  (%hex-octets "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"))
(defparameter *spake2p-n*
  (%hex-octets "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"))

;;; ------------------------------------------------------------------
;;; The password-derived values (section 3.10 / RFC 9383 section 3.2)

(defconstant +spake2p-ws-length+ 40
  "CRYPTO_W_SIZE_BYTES: each of w0s and w1s is the group size plus 8 octets,
reduced mod n so the bias of the reduction is negligible.")

(defun passcode-octets (passcode)
  "The PBKDF2 password of a Matter passcode: its 32-bit value, little endian."
  (unless (and (integerp passcode) (<= 0 passcode #xFFFFFFFF))
    (%spake2p-fail "a passcode is a 32-bit integer, got ~s" passcode))
  (let ((out (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) passcode)))))

(defun spake2p-w0w1 (passcode salt iterations)
  "w0 and w1 (integers mod n) of PASSCODE under SALT and ITERATIONS:
w0s || w1s = PBKDF2-SHA256(passcode LE32, salt, iterations, 80 octets)."
  (let* ((ws (pbkdf2-sha256 (passcode-octets passcode) salt iterations (* 2 +spake2p-ws-length+)))
         (w0 (mod (%octets-integer (subseq ws 0 +spake2p-ws-length+)) *p256-order*))
         (w1 (mod (%octets-integer (subseq ws +spake2p-ws-length+)) *p256-order*)))
    (values w0 w1)))

(defun spake2p-l (w1)
  "L = w1 * G, the verifier's registration record: 65 octets."
  (%p256-encode-point (%p256-mul (%p256-generator) (%scalar w1 "w1")) "L"))

(defconstant +spake2p-verifier-length+ (+ +p256-scalar-length+ +p256-point-length+)
  "A serialized PAKE verifier: w0 (32 octets, big endian) || L (65 octets).")

(defun spake2p-verifier (passcode salt iterations)
  "The 97-octet verifier w0 || L a commissionee stores for PASSCODE."
  (multiple-value-bind (w0 w1) (spake2p-w0w1 passcode salt iterations)
    (let ((out (make-array +spake2p-verifier-length+ :element-type '(unsigned-byte 8))))
      (replace out (%integer-octets w0 +p256-scalar-length+))
      (replace out (spake2p-l w1) :start1 +p256-scalar-length+)
      out)))

(defun spake2p-verifier-parts (verifier)
  "A 97-octet verifier -> (values w0-octets L-octets)."
  (let ((verifier (%check-octet-vector "SPAKE2+ verifier" verifier)))
    (unless (= (length verifier) +spake2p-verifier-length+)
      (%spake2p-fail "a SPAKE2+ verifier has ~d octets (w0 || L), got ~d"
                     +spake2p-verifier-length+ (length verifier)))
    (values (subseq verifier 0 +p256-scalar-length+)
            (subseq verifier +p256-scalar-length+))))

;;; ------------------------------------------------------------------
;;; The protocol

(defstruct (spake2p (:constructor %make-spake2p))
  "One party's state.  ROLE is :PROVER or :VERIFIER; STATE goes :STARTED
(own share computed) -> :DERIVED (peer share taken, keys and confirmations
computed) -> :CONFIRMED (peer confirmation verified; KE may be used)."
  (role :prover :type (member :prover :verifier))
  (state :started :type (member :started :derived :confirmed))
  (context nil)
  (id-prover nil)
  (id-verifier nil)
  (w0 0 :type integer)
  (w1 nil)                               ; prover only
  (l-point nil)                          ; verifier only, L as a point
  (scalar 0 :type integer)               ; x or y
  (share nil)                            ; pA or pB, 65 octets
  (peer-share nil)
  (z nil)
  (v nil)
  (transcript nil)
  (ka nil)
  (ke nil)
  (kca nil)
  (kcb nil)
  (confirmation nil)                     ; the MAC we send
  (expected-confirmation nil))           ; the MAC the peer must send

(defmethod print-object ((s spake2p) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "~a ~a" (spake2p-role s) (spake2p-state s))))

(defun spake2p-start (role &key context w0 w1 l id-prover id-verifier scalar)
  "Begin SPAKE2+ as ROLE (:PROVER with W0 and W1, :VERIFIER with W0 and L)
under CONTEXT and the identities (octet vectors; NIL = empty, as in
Matter).  W0 and W1 are integers or 32-octet vectors; L is a 65-octet
point.  SCALAR fixes the ephemeral x or y for test vectors; the default is
a fresh random one.  The share to send is SPAKE2P-SHARE."
  (unless (member role '(:prover :verifier))
    (%spake2p-fail "the SPAKE2+ role is :PROVER or :VERIFIER, got ~s" role))
  (let* ((w0 (%scalar w0 "w0"))
         (w1 (and (eq role :prover) (%scalar (or w1 (%spake2p-fail "a prover needs w1")) "w1")))
         (l (and (eq role :verifier) (%p256-decode-point (or l (%spake2p-fail "a verifier needs L")) "L")))
         (scalar (if scalar (%scalar scalar "the ephemeral scalar") (random-p256-scalar)))
         (blind (ironclad:ec-decode-point :secp256r1 (if (eq role :prover) *spake2p-m* *spake2p-n*)))
         ;; pA = x*G + w0*M   pB = y*G + w0*N
         (share (%p256-encode-point (%p256-add (%p256-mul (%p256-generator) scalar)
                                               (%p256-mul blind w0))
                                    "the own share")))
    (%make-spake2p :role role
                   :context (if context (%check-octet-vector "SPAKE2+ context" context) (%octets #()))
                   :id-prover (if id-prover (%check-octet-vector "idProver" id-prover) (%octets #()))
                   :id-verifier (if id-verifier (%check-octet-vector "idVerifier" id-verifier) (%octets #()))
                   :w0 w0 :w1 w1 :l-point l :scalar scalar :share share)))

(defun %transcript (s)
  "TT: every item prefixed with its 64-bit little-endian length."
  (let ((out (%new-buffer 512)))
    (dolist (item (list (spake2p-context s) (spake2p-id-prover s) (spake2p-id-verifier s)
                        *spake2p-m* *spake2p-n*
                        (if (eq (spake2p-role s) :prover) (spake2p-share s) (spake2p-peer-share s))
                        (if (eq (spake2p-role s) :prover) (spake2p-peer-share s) (spake2p-share s))
                        (spake2p-z s) (spake2p-v s)
                        (%integer-octets (spake2p-w0 s) +p256-scalar-length+)))
      (%put-le out (length item) 8)
      (%put-octets out item))
    (%finish-buffer out)))

(defun spake2p-derive (s peer-share)
  "Take the peer's share (65 octets): computes Z, V, the transcript, Ka,
Ke, the confirmation keys and both confirmation MACs.  Returns the
confirmation to send to the peer; the peer's is checked by
SPAKE2P-CONFIRM.  SPAKE2P-ERROR when PEER-SHARE is not on the curve or
makes Z or V the point at infinity."
  (unless (eq (spake2p-state s) :started)
    (%spake2p-fail "SPAKE2+ ~a has already taken the peer share" (spake2p-role s)))
  (let* ((what (if (eq (spake2p-role s) :prover) "pB" "pA"))
         (peer (%p256-decode-point peer-share what))
         (w0 (spake2p-w0 s))
         (n *p256-order*)
         ;; the peer's share with the other party's blinding removed:
         ;; prover: pB - w0*N   verifier: pA - w0*M
         (neg-blind (%p256-neg (ironclad:ec-decode-point
                                :secp256r1 (if (eq (spake2p-role s) :prover) *spake2p-n* *spake2p-m*))))
         (k (spake2p-scalar s))
         ;; Z = k*(peer - w0*blind) = k*peer + (k*w0)*(-blind)
         (z (%p256-add (%p256-mul peer k) (%p256-mul neg-blind (mod (* k w0) n))))
         (v (if (eq (spake2p-role s) :prover)
                ;; V = w1*(pB - w0*N)
                (let ((w1 (spake2p-w1 s)))
                  (%p256-add (%p256-mul peer w1) (%p256-mul neg-blind (mod (* w1 w0) n))))
                ;; V = y*L
                (%p256-mul (spake2p-l-point s) k))))
    (setf (spake2p-peer-share s) (%check-octet-vector what peer-share)
          (spake2p-z s) (%p256-encode-point z "Z")
          (spake2p-v s) (%p256-encode-point v "V")
          (spake2p-transcript s) (%transcript s))
    (let* ((kae (sha256 (spake2p-transcript s)))
           (ka (subseq kae 0 16))
           (ke (subseq kae 16 32))
           (kcab (hkdf-sha256 ka nil (%ascii-octets "ConfirmationKeys") 32))
           (kca (subseq kcab 0 16))
           (kcb (subseq kcab 16 32))
           (ca (hmac-sha256 kca (if (eq (spake2p-role s) :prover) (spake2p-peer-share s) (spake2p-share s))))
           (cb (hmac-sha256 kcb (if (eq (spake2p-role s) :prover) (spake2p-share s) (spake2p-peer-share s)))))
      (setf (spake2p-ka s) ka (spake2p-ke s) ke (spake2p-kca s) kca (spake2p-kcb s) kcb)
      (if (eq (spake2p-role s) :prover)
          (setf (spake2p-confirmation s) ca (spake2p-expected-confirmation s) cb)
          (setf (spake2p-confirmation s) cb (spake2p-expected-confirmation s) ca))
      (setf (spake2p-state s) :derived)
      (spake2p-confirmation s))))

(defun %octets-equal-constant-time (a b)
  (and (= (length a) (length b))
       (let ((diff 0))
         (dotimes (i (length a) (zerop diff))
           (setf diff (logior diff (logxor (aref a i) (aref b i))))))))

(defun spake2p-confirm (s peer-confirmation)
  "Verify the peer's confirmation MAC (32 octets).  T, or
SPAKE2P-CONFIRMATION-ERROR; afterwards SPAKE2P-KE is the shared key."
  (unless (eq (spake2p-state s) :derived)
    (%spake2p-fail "SPAKE2+ ~a cannot confirm in state ~a" (spake2p-role s) (spake2p-state s)))
  (let ((mac (%check-octet-vector "the peer confirmation" peer-confirmation)))
    (unless (%octets-equal-constant-time mac (spake2p-expected-confirmation s))
      (error 'spake2p-confirmation-error))
    (setf (spake2p-state s) :confirmed)
    t))

(defun spake2p-shared-key (s)
  "Ke, 16 octets, once the peer is confirmed."
  (unless (eq (spake2p-state s) :confirmed)
    (%spake2p-fail "SPAKE2+ ~a: the shared key is available only after the peer is confirmed"
                   (spake2p-role s)))
  (spake2p-ke s))
