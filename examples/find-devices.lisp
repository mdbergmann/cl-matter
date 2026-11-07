;;;; find-devices.lisp -- the Matter nodes on the local network: the
;;;; commissionable ones (their window is open), the operational ones
;;;; (commissioned, fabric and node id in the instance name) and the
;;;; commissioners.
;;;;
;;;;   AMILISP_NO_USERINIT=1 amilisp --heap 64M --load examples/find-devices.lisp
;;;;   sbcl --load examples/find-devices.lisp          (legacy unicast queries on SBCL)
;;;;
;;;; Environment: MATTER_TIMEOUT (seconds to listen per service type, 4),
;;;; AMILISP_REPO (where lib/quicklisp-compat.lisp is; default
;;;; ../../amigasources/cl-amiga from here).

(require "asdf")
(load "~/quicklisp/setup.lisp")
#+amilisp
(let ((compat (merge-pathnames "lib/quicklisp-compat.lisp"
                               (uiop:ensure-directory-pathname
                                (or (uiop:getenv "AMILISP_REPO")
                                    (uiop:merge-pathnames* "../../amigasources/cl-amiga/"
                                                           (uiop:pathname-directory-pathname *load-truename*)))))))
  (when (probe-file compat) (load compat)))
(asdf:load-system :cl-matter)

(defpackage :find-devices (:use :cl :cl-matter))
(in-package :find-devices)

(defparameter *timeout*
  (let ((value (uiop:getenv "MATTER_TIMEOUT")))
    (if (and value (plusp (length value))) (parse-integer value) 4)))

(defun say (format &rest args)
  (format t "~&~?~%" format args)
  (finish-output))

(defun show-service (service)
  (say "  ~a~%    host ~a port ~a~%    addresses ~{~a~^, ~}"
       (getf service :name) (getf service :host) (getf service :port) (getf service :addresses))
  (let ((matter (parse-matter-txt (getf service :txt))))
    (loop :for (key value) :on matter :by #'cddr
          :do (say "    ~(~a~) ~a" key (if (vectorp value) (format nil "~{~2,'0x~}" (coerce value 'list)) value)))))

(defun browse-type (type what socket)
  (say "== ~a (~a)" type what)
  (multiple-value-bind (instances records) (dns-sd:browse type :socket socket :timeout *timeout*)
    (if (null instances)
        (say "  (none)")
        (dolist (instance instances)
          (let ((service (dns-sd:resolve instance :socket socket :records records :timeout *timeout*)))
            (if service
                (show-service service)
                (say "  ~a (did not resolve)" instance)))))))

(dns-sd:with-mdns-socket (socket)
  (say "listening ~d seconds per type, ~:[legacy unicast~;multicast~]"
       *timeout* (dns-sd::mdns-socket-multicast-p socket))
  (browse-type "_matterc._udp" "commissionable: the window is open" socket)
  (browse-type "_matter._tcp" "operational: <compressed fabric id>-<node id>" socket)
  (browse-type "_matterd._udp" "commissioners" socket))
(uiop:quit)
