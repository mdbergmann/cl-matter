;;;; control-device.lisp -- talk to a device commission-device.lisp
;;;; commissioned: find its operational advertisement, open a CASE session
;;;; from the saved commissioner state, and read it or switch it.
;;;;
;;;;   AMILISP_NO_USERINIT=1 amilisp --heap 128M --load examples/control-device.lisp
;;;;   MATTER_COMMAND=on sbcl --load examples/control-device.lisp
;;;;
;;;; Environment: MATTER_COMMAND (read -- the default --, on, off or toggle,
;;;; the On/Off cluster on MATTER_ENDPOINT, default 1), MATTER_NODE (the
;;;; device's node id; default the last one commissioned), MATTER_STORAGE
;;;; (the commissioner's state file, default ~/.cl-matter/commissioner.state),
;;;; MATTER_TRACE, AMILISP_REPO (as in commission-device.lisp).
;;;;
;;;; "read" reads Basic Information, the Descriptor of every endpoint, the
;;;; device's fabric table and its On/Off state; a command is followed by a
;;;; read of the On/Off state.

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

(defpackage :control-device (:use :cl :cl-matter))
(in-package :control-device)

(defun env (name &optional default)
  (let ((value (uiop:getenv name)))
    (if (and value (plusp (length value))) value default)))

(defparameter *command* (string-downcase (env "MATTER_COMMAND" "read")))
(defparameter *endpoint* (parse-integer (env "MATTER_ENDPOINT" "1")))
(defparameter *storage* (env "MATTER_STORAGE" (merge-pathnames ".cl-matter/commissioner.state" (user-homedir-pathname))))

(defun say (format &rest args)
  (format t "~&~?~%" format args)
  (finish-output))

(defun show-reports (reports)
  (dolist (report reports)
    (multiple-value-bind (value known) (attribute-report-value report)
      (say "    ~a = ~s~:[ (raw)~;~]" (attribute-report-path report) value known))))

(let ((state (read-state-file *storage*)))
  (unless state
    (say "no commissioner state in ~a -- run commission-device.lisp first" *storage*)
    (uiop:quit 1))
  (let* ((trace (and (env "MATTER_TRACE") (lambda (format &rest args) (apply #'say format args))))
         (transport (make-udp-transport :family :ipv6 :port 0))
         (manager (make-exchange-manager :transport transport :trace trace))
         (channel (make-secure-channel manager))
         (model (make-interaction-model manager))
         (commissioner (make-commissioner channel model :state state))
         (fabric (commissioner-fabric commissioner))
         (node-id (parse-integer (env "MATTER_NODE" (princ-to-string (1- (commissioner-next-node-id commissioner))))))
         (node (discover-operational-node fabric node-id :timeout 4)))
    (unless node
      (say "node ~d of fabric ~16,'0x is not on the air" node-id (fabric-fabric-id fabric))
      (uiop:quit 1))
    (say "node ~d at [~a]:~d" node-id (first (getf node :addresses)) (getf node :port))
    (unwind-protect
         (let ((session (establish-case-session channel (first (getf node :addresses)) (getf node :port)
                                                :fabric fabric :peer-node-id node-id)))
           (say "~a" session)
           (flet ((on-off ()
                    (say "On/Off of endpoint ~d: ~:[off~;on~]" *endpoint*
                         (attribute-report-value
                          (first (read-attributes model session (list (attribute-path *endpoint* +cluster-on-off+ 0))))))))
             (cond ((string= *command* "read")
                    (say "Basic Information:")
                    (show-reports (read-attributes model session (list (attribute-path 0 +cluster-basic-information+ nil))))
                    (say "Descriptor of every endpoint:")
                    (show-reports (read-attributes model session (list (attribute-path nil +cluster-descriptor+ nil))))
                    (say "Fabrics:")
                    (show-reports (read-attributes model session (list (attribute-path 0 +cluster-operational-credentials+ 1))))
                    (on-off))
                   ((member *command* '("on" "off" "toggle") :test #'string=)
                    (on-off)
                    (let* ((command-id (cond ((string= *command* "off") 0) ((string= *command* "on") 1) (t 2)))
                           (responses (invoke-command model session (command-path *endpoint* +cluster-on-off+ command-id) nil)))
                      (say "~a: ~a" *command* (invoke-response-value (first responses))))
                    (on-off))
                   (t (say "MATTER_COMMAND is read, on, off or toggle, not ~s" *command*))))
           (close-session channel session))
      (exchange-manager-close manager))))
(uiop:quit)
