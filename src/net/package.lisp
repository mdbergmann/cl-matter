(defpackage :cl-matter.net
  (:use :cl)
  (:nicknames :matter-net)
  (:documentation "The datagram socket layer discovery protocols need: an
unconnected UDP socket bound to a local port, send-to / receive-from with the
peer's address, multicast group membership, the list of network interfaces.
Addresses are strings everywhere (\"192.168.1.5\", \"ff02::fb\", \"fe80::1%en0\").
Every function here is implemented once per Lisp implementation in a
backend-<impl>.lisp file; PROTOCOL.LISP is the contract they fulfil.")
  (:export
   ;; conditions
   #:net-error
   #:net-error-message
   #:not-supported
   ;; sockets
   #:socket
   #:open-udp-socket
   #:close-socket
   #:with-udp-socket
   #:socket-local-endpoint
   #:socket-timeout
   #:send-to
   #:receive-from
   ;; multicast
   #:multicast-join
   #:multicast-leave
   #:multicast-configure
   ;; host
   #:network-interfaces
   #:ipv6-supported-p))
