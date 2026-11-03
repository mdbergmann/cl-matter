(in-package :cl-matter.net)

;;; No backend for this implementation yet: every operation signals
;;; NOT-SUPPORTED, so the systems above still load and their pure parts
;;; (the DNS codec, TLV) can be used and tested.

(macrolet ((unsupported (name lambda-list)
             `(defmethod ,name ,lambda-list
                (declare (ignorable ,@(remove-if (lambda (x) (member x lambda-list-keywords))
                                                 (mapcar (lambda (x) (if (consp x) (car x) x))
                                                         lambda-list))))
                (error 'not-supported :operation ,(string-downcase (string name))))))
  (unsupported open-udp-socket (&key port address family reuse-address))
  (unsupported close-socket (socket))
  (unsupported socket-local-endpoint (socket))
  (unsupported send-to (socket buffer host port &key start end))
  (unsupported receive-from (socket buffer &key start end))
  (unsupported multicast-join (socket group &optional interface))
  (unsupported multicast-leave (socket group &optional interface))
  (unsupported multicast-configure (socket &key hops loopback interface))
  (unsupported network-interfaces ())
  (unsupported ipv6-supported-p ()))

(defmethod (setf socket-timeout) (seconds socket)
  (declare (ignore seconds socket))
  (error 'not-supported :operation "socket-timeout"))
