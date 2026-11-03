(defpackage :cl-matter.net.tests
  (:use :cl :fiveam :cl-matter.net))
(in-package :cl-matter.net.tests)

(def-suite net-tests :description "cl-matter/net backend" :in cl-matter.tests:test-suite)
(in-suite net-tests)

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(test bind-and-local-endpoint
  "A socket bound to port 0 on the loopback address reports a real port."
  (with-udp-socket (s :address "127.0.0.1")
    (multiple-value-bind (address port) (socket-local-endpoint s)
      (is (string= "127.0.0.1" address))
      (is (< 0 port 65536)))))

(test loopback-round-trip
  "Two sockets talk over loopback; receive-from names the sender."
  (with-udp-socket (a :address "127.0.0.1")
    (with-udp-socket (b :address "127.0.0.1")
      (setf (socket-timeout a) 5
            (socket-timeout b) 5)
      (let ((port-a (nth-value 1 (socket-local-endpoint a)))
            (port-b (nth-value 1 (socket-local-endpoint b)))
            (buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
        (is (= 5 (send-to a (octets 1 2 3 4 5) "127.0.0.1" port-b)))
        (multiple-value-bind (len host port) (receive-from b buf)
          (is (= 5 len))
          (is (string= "127.0.0.1" host))
          (is (= port-a port))
          (is (equalp (octets 1 2 3 4 5) (subseq buf 0 len)))
          ;; answer with the pair receive-from handed back
          (send-to b buf host port :end len))
        (multiple-value-bind (len host port) (receive-from a buf)
          (is (= 5 len))
          (is (string= "127.0.0.1" host))
          (is (= port-b port)))))))

(test receive-timeout
  "receive-from returns NIL, not an error, when nothing arrives in time."
  (with-udp-socket (s :address "127.0.0.1")
    (setf (socket-timeout s) 0.2)
    (let ((buf (make-array 16 :element-type '(unsigned-byte 8))))
      (is (null (receive-from s buf))))))

(test multicast-or-not-supported
  "Joining the mDNS group either works or says NOT-SUPPORTED, never anything else."
  (with-udp-socket (s :reuse-address t)
    (finishes
      (handler-case (multicast-join s "224.0.0.251")
        (not-supported () :not-supported)))))
