(in-package :cl-matter.net)

;;; The contract.  Each backend file defines these functions for one Lisp
;;; implementation; this file holds what is shared: the conditions, the
;;; documentation of every operation, and WITH-UDP-SOCKET.

(define-condition net-error (error)
  ((message :initarg :message :reader net-error-message))
  (:report (lambda (c stream)
             (format stream "~a" (net-error-message c))))
  (:documentation "A socket operation failed; MESSAGE says what and why."))

(define-condition not-supported (net-error)
  ((operation :initarg :operation :reader not-supported-operation))
  (:report (lambda (c stream)
             (format stream "~a is not supported by the ~a backend of cl-matter/net"
                     (not-supported-operation c) (lisp-implementation-type))))
  (:documentation "The operation exists in the protocol but this backend
cannot do it (yet): multicast on a backend without setsockopt, IPv6 on an
IPv4-only TCP/IP stack."))

(defclass socket ()
  ()
  (:documentation "An unconnected datagram socket.  Backends subclass it
and keep their handle in a slot of their own."))

(defgeneric open-udp-socket (&key port address family reuse-address)
  (:documentation "Bind an unconnected datagram socket and return a SOCKET.
PORT 0 picks a free port.  ADDRESS is a literal address of this machine to
bind, NIL binds every address of FAMILY (:ipv4, the default, or :ipv6).
REUSE-ADDRESS lets several sockets share a port, which a multicast listener
on mDNS port 5353 needs."))

(defgeneric close-socket (socket)
  (:documentation "Close SOCKET.  Closing twice is harmless."))

(defgeneric socket-local-endpoint (socket)
  (:documentation "The address and port SOCKET is bound to, as two values."))

(defgeneric (setf socket-timeout) (seconds socket)
  (:documentation "Make RECEIVE-FROM give up after SECONDS (NIL: wait forever)."))

(defgeneric send-to (socket buffer host port &key start end)
  (:documentation "Send BUFFER[START,END) as one datagram to HOST:PORT.  HOST
is a literal address or a host name.  Returns the number of bytes sent."))

(defgeneric receive-from (socket buffer &key start end)
  (:documentation "Receive one datagram into BUFFER[START,END) and return
three values: the datagram length, the sender's address and the sender's
port.  Returns NIL when the socket's timeout elapsed first."))

(defgeneric multicast-join (socket group &optional interface)
  (:documentation "Join multicast GROUP on INTERFACE (a name, an index or an
IPv4 address of the interface; NIL for the OS default)."))

(defgeneric multicast-leave (socket group &optional interface)
  (:documentation "Leave multicast GROUP joined on INTERFACE."))

(defgeneric multicast-configure (socket &key hops loopback interface)
  (:documentation "Outgoing multicast settings of SOCKET: HOPS (TTL),
LOOPBACK (whether this host hears its own transmissions), INTERFACE to
send on.  A keyword left out keeps the current setting."))

(defgeneric network-interfaces ()
  (:documentation "The network interfaces of this host, a list of plists
with :NAME, :INDEX, :FLAGS (a subset of :UP :LOOPBACK :MULTICAST) and
:ADDRESSES (a list of address strings)."))

(defgeneric ipv6-supported-p ()
  (:documentation "True when this host can bind IPv6 sockets."))

(defmacro with-udp-socket ((var &rest open-args) &body body)
  "Bind VAR to a socket opened with OPEN-UDP-SOCKET and OPEN-ARGS for the
extent of BODY, closing it on every exit."
  `(let ((,var (open-udp-socket ,@open-args)))
     (unwind-protect (progn ,@body)
       (close-socket ,var))))
