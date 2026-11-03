(in-package :cl-matter.net)

;;; SBCL backend on sb-bsd-sockets.  IPv4 datagram sockets are complete;
;;; multicast membership and the interface list need setsockopt /
;;; getifaddrs through sb-alien and are the next step (NOT-SUPPORTED
;;; until then).  Its purpose is to let the protocol layers above be
;;; developed and compared on SBCL.

(defclass sbcl-socket (socket)
  ((sock :initarg :sock :reader %sock)
   (timeout :initform nil :accessor %timeout)))

(defun %parse-ipv4 (string)
  "\"192.168.1.5\" -> #(192 168 1 5)."
  (let ((parts (loop :with start := 0
                     :for dot := (position #\. string :start start)
                     :collect (parse-integer string :start start :end dot)
                     :while dot
                     :do (setf start (1+ dot)))))
    (unless (= (length parts) 4)
      (error 'net-error :message (format nil "not an IPv4 address: ~s" string)))
    (coerce parts '(vector (unsigned-byte 8) 4))))

(defun %format-ipv4 (vector)
  (format nil "~{~d~^.~}" (coerce vector 'list)))

(defun %resolve-ipv4 (host)
  (if (every (lambda (c) (or (digit-char-p c) (char= c #\.))) host)
      (%parse-ipv4 host)
      (let ((ent (sb-bsd-sockets:get-host-by-name host)))
        (sb-bsd-sockets:host-ent-address ent))))

(defmethod open-udp-socket (&key (port 0) address (family :ipv4) reuse-address)
  (unless (eq family :ipv4)
    (error 'not-supported :operation (format nil "open-udp-socket :family ~s" family)))
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (when reuse-address
      (setf (sb-bsd-sockets:sockopt-reuse-address sock) t))
    (handler-case
        (sb-bsd-sockets:socket-bind sock (if address (%parse-ipv4 address) #(0 0 0 0)) port)
      (sb-bsd-sockets:socket-error (e)
        (sb-bsd-sockets:socket-close sock)
        (error 'net-error :message (format nil "open-udp-socket: ~a" e))))
    (make-instance 'sbcl-socket :sock sock)))

(defmethod close-socket ((socket sbcl-socket))
  (ignore-errors (sb-bsd-sockets:socket-close (%sock socket)))
  t)

(defmethod socket-local-endpoint ((socket sbcl-socket))
  (multiple-value-bind (addr port) (sb-bsd-sockets:socket-name (%sock socket))
    (values (%format-ipv4 addr) port)))

(defmethod (setf socket-timeout) (seconds (socket sbcl-socket))
  (setf (%timeout socket) seconds))

(defmethod send-to ((socket sbcl-socket) buffer host port &key (start 0) end)
  (let* ((end (or end (length buffer)))
         (chunk (if (and (= start 0) (= end (length buffer))) buffer (subseq buffer start end))))
    (sb-bsd-sockets:socket-send (%sock socket) chunk (length chunk)
                                :address (list (%resolve-ipv4 host) port))))

(defmethod receive-from ((socket sbcl-socket) buffer &key (start 0) end)
  (let* ((end (or end (length buffer)))
         (sock (%sock socket))
         (timeout (%timeout socket)))
    (when (and timeout
               (not (sb-sys:wait-until-fd-usable
                     (sb-bsd-sockets:socket-file-descriptor sock) :input timeout)))
      (return-from receive-from nil))
    (let ((chunk (if (= start 0) buffer (make-array (- end start) :element-type '(unsigned-byte 8)))))
      (multiple-value-bind (buf len addr port)
          (sb-bsd-sockets:socket-receive sock chunk (- end start))
        (declare (ignore buf))
        (unless (eq chunk buffer)
          (replace buffer chunk :start1 start :end2 len))
        (values len (%format-ipv4 addr) port)))))

(defmethod multicast-join ((socket sbcl-socket) group &optional interface)
  (declare (ignore group interface))
  (error 'not-supported :operation "multicast-join"))

(defmethod multicast-leave ((socket sbcl-socket) group &optional interface)
  (declare (ignore group interface))
  (error 'not-supported :operation "multicast-leave"))

(defmethod multicast-configure ((socket sbcl-socket) &key hops loopback interface)
  (declare (ignore hops loopback interface))
  (error 'not-supported :operation "multicast-configure"))

(defmethod network-interfaces ()
  (error 'not-supported :operation "network-interfaces"))

(defmethod ipv6-supported-p ()
  nil)
