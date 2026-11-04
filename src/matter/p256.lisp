;;;; p256.lisp -- the NIST P-256 curve (secp256r1) as Matter uses it:
;;;; key pairs, ECDH for CASE, ECDSA with SHA-256 for certificates and the
;;;; Sigma signatures, and the point arithmetic SPAKE2+ builds on.
;;;;
;;;; The arithmetic is Ironclad's (Jacobian coordinates, Montgomery
;;;; ladder).  Points travel as 65 octets, uncompressed SEC 1 (04 || x || y);
;;;; scalars and private keys as 32 big-endian octets; signatures as the
;;;; 64 octets r || s of Matter's CRYPTO_SIGNATURE_LENGTH_BYTES, never DER.
;;;; ECDSA signs a digest the caller computed, as the SDK's
;;;; ECDSA_sign_hash does.

(in-package :cl-matter)

(define-condition p256-error (crypto-error) ()
  (:documentation "A malformed P-256 input: a point off the curve, a scalar or key out of range."))

(defun %p256-fail (format &rest args)
  (error 'p256-error :message (apply #'format nil format args)))

(defconstant +p256-scalar-length+ 32)
(defconstant +p256-point-length+ 65 "An uncompressed SEC 1 point: 04 || x || y.")
(defconstant +p256-signature-length+ 64 "r || s, 32 octets each.")
(defconstant +p256-shared-secret-length+ 32 "The x coordinate of the ECDH point.")

(defparameter *p256-order*
  115792089210356248762697446949407573529996955224135760342422259061068512044369
  "The order n of the P-256 base point.")

(defun %p256-generator ()
  (ironclad:ec-decode-point
   :secp256r1
   (%hex-octets "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))

(defun %p256-mul (point k) (ironclad:ec-scalar-mult point k))
(defun %p256-add (p q) (ironclad:ec-add p q))

(defun %p256-neg (point)
  "-POINT, as (n - 1) * POINT."
  (ironclad:ec-scalar-mult point (1- *p256-order*)))

(defun %mod-inverse (a m)
  "a^-1 mod m by the extended Euclidean algorithm; A must be invertible."
  (let ((r0 m) (r1 (mod a m)) (t0 0) (t1 1))
    (loop :until (zerop r1)
          :do (let ((q (floor r0 r1)))
                (psetf r0 r1 r1 (- r0 (* q r1)))
                (psetf t0 t1 t1 (- t0 (* q t1)))))
    (unless (= r0 1)
      (%p256-fail "~d has no inverse modulo ~d" a m))
    (mod t0 m)))

(defun random-p256-scalar ()
  "A uniform scalar in [1, n-1] from the cryptographic random source."
  (loop :for k := (%octets-integer (random-octets +p256-scalar-length+))
        :when (< 0 k *p256-order*) :return k))

;;; ------------------------------------------------------------------
;;; Points and scalars at the API

(defun p256-decode-point (octets &optional (what "the point"))
  "OCTETS (65, uncompressed) -> an Ironclad point on the curve, or P256-ERROR."
  (let ((octets (%check-octet-vector what octets)))
    (unless (= (length octets) +p256-point-length+)
      (%p256-fail "~a must be an uncompressed P-256 point of ~d octets, got ~d"
                  what +p256-point-length+ (length octets)))
    (handler-case (ironclad:ec-decode-point :secp256r1 octets)
      (error () (%p256-fail "~a is not a point on P-256" what)))))

(defun p256-encode-point (point &optional (what "the point"))
  "POINT -> 65 octets; the point at infinity is P256-ERROR."
  (handler-case (ironclad:ec-encode-point point)
    (error () (%p256-fail "~a is the point at infinity" what))))

(defun p256-point-p (octets)
  "True when OCTETS is a valid uncompressed point on the curve."
  (handler-case (progn (p256-decode-point octets) t)
    (crypto-error () nil)))

(defun %p256-private-scalar (private what)
  "PRIVATE, an integer or 32 octets -> an integer in [1, n-1]."
  (let ((d (cond ((integerp private) private)
                 ((and (vectorp private) (not (stringp private)))
                  (unless (= (length private) +p256-scalar-length+)
                    (%p256-fail "~a must be ~d octets, got ~d" what +p256-scalar-length+ (length private)))
                  (%octets-integer private))
                 (t (%p256-fail "~a must be an integer or a ~d-octet vector, got ~s"
                                what +p256-scalar-length+ private)))))
    (unless (< 0 d *p256-order*)
      (%p256-fail "~a must be in [1, n-1] of P-256" what))
    d))

(defun %p256-x (point)
  "The x coordinate of POINT as an integer."
  (%octets-integer (subseq (p256-encode-point point) 1 (1+ +p256-scalar-length+))))

;;; ------------------------------------------------------------------
;;; Key pairs

(defstruct (p256-keypair (:constructor %make-p256-keypair (private public)))
  "An operational or ephemeral key pair: PRIVATE is 32 octets, PUBLIC 65."
  (private nil :read-only t)
  (public nil :read-only t))

(defmethod print-object ((k p256-keypair) stream)
  (print-unreadable-object (k stream :type t)
    (format stream "~{~2,'0x~}..." (coerce (subseq (p256-keypair-public k) 1 5) 'list))))

(defun p256-public-key (private)
  "The public key of PRIVATE (an integer or 32 octets): d * G, 65 octets."
  (p256-encode-point (%p256-mul (%p256-generator) (%p256-private-scalar private "the private key"))))

(defun make-p256-keypair (private)
  "A key pair from PRIVATE, an integer or 32 octets."
  (let ((d (%p256-private-scalar private "the private key")))
    (%make-p256-keypair (%integer-octets d +p256-scalar-length+) (p256-public-key d))))

(defun generate-p256-keypair ()
  "A fresh key pair from the cryptographic random source."
  (make-p256-keypair (random-p256-scalar)))

(defun p256-keypair-octets (keypair)
  "The SDK's serialized form: public key (65) || private key (32), 97 octets."
  (%concat-octets (p256-keypair-public keypair) (p256-keypair-private keypair)))

(defun p256-keypair-from-octets (octets)
  "The inverse of P256-KEYPAIR-OCTETS; checks that the two halves match."
  (let ((octets (%check-octet-vector "the serialized key pair" octets)))
    (unless (= (length octets) (+ +p256-point-length+ +p256-scalar-length+))
      (%p256-fail "a serialized P-256 key pair is ~d octets, got ~d"
                  (+ +p256-point-length+ +p256-scalar-length+) (length octets)))
    (let ((keypair (make-p256-keypair (subseq octets +p256-point-length+))))
      (unless (equalp (p256-keypair-public keypair) (subseq octets 0 +p256-point-length+))
        (%p256-fail "the public key of the serialized key pair does not match its private key"))
      keypair)))

;;; ------------------------------------------------------------------
;;; ECDH (CRYPTO_ECDH)

(defun p256-ecdh (private peer-public)
  "The shared secret of our PRIVATE key (integer, 32 octets or a P256-KEYPAIR)
and the peer's public key (65 octets): the x coordinate of d * Q, 32 octets."
  (let* ((d (%p256-private-scalar (if (p256-keypair-p private) (p256-keypair-private private) private)
                                  "the private key"))
         (q (p256-decode-point peer-public "the peer's public key"))
         (shared (%p256-mul q d)))
    (handler-case (subseq (ironclad:ec-encode-point shared) 1 (1+ +p256-scalar-length+))
      (error () (%p256-fail "the ECDH shared point is the point at infinity")))))

;;; ------------------------------------------------------------------
;;; ECDSA (CRYPTO_SIGN / CRYPTO_VERIFY), SHA-256 digests

(defun %p256-digest-integer (digest what)
  (let ((digest (%check-octet-vector what digest)))
    (unless (= (length digest) 32)
      (%p256-fail "~a must be a 32-octet SHA-256 digest, got ~d octets" what (length digest)))
    (%octets-integer digest)))

(defun p256-sign-digest (private digest)
  "ECDSA over the 32-octet DIGEST with PRIVATE (integer, 32 octets or a
P256-KEYPAIR): r || s, 64 octets."
  (let* ((d (%p256-private-scalar (if (p256-keypair-p private) (p256-keypair-private private) private)
                                  "the private key"))
         (e (%p256-digest-integer digest "the digest"))
         (n *p256-order*)
         (g (%p256-generator)))
    (loop
      (let* ((k (random-p256-scalar))
             (r (mod (%p256-x (%p256-mul g k)) n))
             (s (if (zerop r) 0 (mod (* (%mod-inverse k n) (+ e (* d r))) n))))
        (unless (or (zerop r) (zerop s))
          (return (%concat-octets (%integer-octets r +p256-scalar-length+)
                                  (%integer-octets s +p256-scalar-length+))))))))

(defun p256-sign (private message)
  "P256-SIGN-DIGEST over SHA-256 of MESSAGE."
  (p256-sign-digest private (sha256 (%check-octet-vector "the message" message))))

(defun p256-verify-digest (public digest signature)
  "True when SIGNATURE (64 octets, r || s) is PUBLIC's ECDSA signature over
the 32-octet DIGEST.  A malformed public key is P256-ERROR; a malformed
signature is simply invalid."
  (let ((q (p256-decode-point public "the public key"))
        (e (%p256-digest-integer digest "the digest"))
        (signature (%check-octet-vector "the signature" signature))
        (n *p256-order*))
    (and (= (length signature) +p256-signature-length+)
         (let ((r (%octets-integer (subseq signature 0 +p256-scalar-length+)))
               (s (%octets-integer (subseq signature +p256-scalar-length+))))
           (and (< 0 r n) (< 0 s n)
                (let* ((w (%mod-inverse s n))
                       (point (%p256-add (%p256-mul (%p256-generator) (mod (* e w) n))
                                         (%p256-mul q (mod (* r w) n)))))
                  (handler-case (= r (mod (%p256-x point) n))
                    (crypto-error () nil))))))))

(defun p256-verify (public message signature)
  "P256-VERIFY-DIGEST over SHA-256 of MESSAGE."
  (p256-verify-digest public (sha256 (%check-octet-vector "the message" message)) signature))
