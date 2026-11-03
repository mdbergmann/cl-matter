(in-package :cl-matter.net)

;;; AmiLisp backend: a thin mapping onto the EXT package's unconnected
;;; datagram sockets (README "Networking", docs/ext.md).  Sockets are
;;; streams there, so CLOSE and the stream timeouts apply.

(defclass amilisp-socket (socket)
  ((stream :initarg :stream :reader %socket-stream)))

(defmethod open-udp-socket (&key (port 0) address (family :ipv4) reuse-address)
  (handler-case
      (make-instance 'amilisp-socket
                     :stream (ext:open-udp-socket :port port
                                                  :address address
                                                  :family family
                                                  :reuse-address reuse-address))
    (error (e)
      (error 'net-error :message (format nil "open-udp-socket: ~a" e)))))

(defmethod close-socket ((socket amilisp-socket))
  (let ((s (%socket-stream socket)))
    (when (open-stream-p s)
      (close s))
    t))

(defmethod socket-local-endpoint ((socket amilisp-socket))
  (ext:socket-stream-local-endpoint (%socket-stream socket)))

(defmethod (setf socket-timeout) (seconds (socket amilisp-socket))
  (setf (ext:socket-stream-timeout (%socket-stream socket) :input) seconds))

(defmethod send-to ((socket amilisp-socket) buffer host port &key (start 0) end)
  (let* ((end (or end (length buffer)))
         (chunk (if (and (= start 0) (= end (length buffer)))
                    buffer
                    (subseq buffer start end))))
    (ext:udp-send-to (%socket-stream socket) chunk host port)
    (- end start)))

(defmethod receive-from ((socket amilisp-socket) buffer &key (start 0) end)
  (let* ((end (or end (length buffer)))
         (chunk (if (= start 0) buffer
                    (make-array (- end start) :element-type '(unsigned-byte 8)))))
    (handler-case
        (multiple-value-bind (len host port)
            (ext:udp-receive-from (%socket-stream socket) chunk (- end start))
          (unless (eq chunk buffer)
            (replace buffer chunk :start1 start :end2 len))
          (values len host port))
      (ext:socket-timeout () nil))))

(defmethod multicast-join ((socket amilisp-socket) group &optional interface)
  (ext:udp-multicast-join (%socket-stream socket) group interface))

(defmethod multicast-leave ((socket amilisp-socket) group &optional interface)
  (ext:udp-multicast-leave (%socket-stream socket) group interface))

(defmethod multicast-configure ((socket amilisp-socket)
                                &rest args &key hops loopback interface)
  (declare (ignore hops loopback interface))
  (apply #'ext:udp-multicast-configure (%socket-stream socket) args))

(defmethod network-interfaces ()
  (ext:network-interfaces))

(defmethod ipv6-supported-p ()
  (ext:ipv6-supported-p))
