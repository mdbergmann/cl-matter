(in-package :cl-matter.dns-sd)

;;; mDNS transport and the DNS-SD querier over CL-MATTER.NET.
;;;
;;; An MDNS-SOCKET is either a real multicast endpoint -- port 5353 shared
;;; with whatever else runs on this host, the group joined, so it hears
;;; every answer on the link -- or, where the backend cannot join a group
;;; (SBCL until its sb-alien step), a legacy querier on an ephemeral port:
;;; RFC 6762 section 6.7 obliges responders to answer those by unicast.
;;; QUERY is the one primitive; BROWSE and RESOLVE are built on it.
;;;
;;; The responder is in responder.lisp.

(defconstant +mdns-port+ 5353)
(defparameter +mdns-ipv4-group+ "224.0.0.251")
(defparameter +mdns-ipv6-group+ "ff02::fb")
(defconstant +max-datagram+ 9000 "RFC 6762 section 17: the largest mDNS message.")

(defstruct (mdns-socket (:constructor %make-mdns-socket))
  "A datagram socket set up for mDNS: SOCKET is the CL-MATTER.NET socket,
MULTICAST-P says whether it listens on the group (NIL: legacy querier),
GROUP and PORT are where queries go."
  socket
  (multicast-p nil :type boolean)
  group
  port)

(defun open-mdns-socket (&key interface address
                              (group +mdns-ipv4-group+) (port +mdns-port+)
                              (multicast :auto))
  "Open an MDNS-SOCKET.  MULTICAST T binds PORT with address reuse and joins
GROUP (on INTERFACE, when given); NIL makes a legacy querier on an ephemeral
port; :AUTO, the default, tries the first and falls back to the second when
the backend cannot (NOT-SUPPORTED) or the port cannot be shared.  ADDRESS
binds one local address instead of all."
  (flet ((legacy ()
           (%make-mdns-socket :socket (cl-matter.net:open-udp-socket :address address)
                              :group group :port port)))
    (if (null multicast)
        (legacy)
        (let ((socket (handler-case
                          (cl-matter.net:open-udp-socket :port port :address address
                                                         :reuse-address t)
                        (cl-matter.net:net-error (e)
                          (if (eq multicast :auto) nil (error e))))))
          (if (null socket)
              (legacy)
              (handler-case
                  (progn
                    (cl-matter.net:multicast-join socket group interface)
                    (when interface
                      (cl-matter.net:multicast-configure socket :interface interface))
                    (%make-mdns-socket :socket socket :multicast-p t :group group :port port))
                (cl-matter.net:net-error (e)
                  (cl-matter.net:close-socket socket)
                  (if (eq multicast :auto) (legacy) (error e)))))))))

(defun close-mdns-socket (mdns-socket)
  (cl-matter.net:close-socket (mdns-socket-socket mdns-socket))
  t)

(defmacro with-mdns-socket ((var &rest open-args) &body body)
  "Bind VAR to an MDNS-SOCKET opened with OPEN-ARGS for the extent of BODY."
  `(let ((,var (open-mdns-socket ,@open-args)))
     (unwind-protect (progn ,@body)
       (close-mdns-socket ,var))))

;;; ------------------------------------------------------------------
;;; Querying

(defun %now ()
  "Seconds, monotonic enough for timeouts."
  (/ (get-internal-real-time) (float internal-time-units-per-second 1.0d0)))

(defun %record-key (record)
  (list (string-downcase (dns-record-name record))
        (dns-record-type record)
        (dns-record-data record)))

(defun %merge-records (records new)
  "NEW appended to RECORDS without duplicates (name, type and data equal
up to case); a goodbye record (TTL 0) removes what it names instead."
  (dolist (r new records)
    (let ((key (%record-key r)))
      (setf records (remove key records :key #'%record-key :test #'equalp))
      (unless (zerop (dns-record-ttl r))
        (setf records (append records (list r)))))))

(defun %message-records (message)
  (append (dns-message-answers message)
          (dns-message-authorities message)
          (dns-message-additionals message)))

(defun query (mdns-socket questions &key (timeout 3) records until)
  "Send QUESTIONS (DNS-QUESTIONs) on MDNS-SOCKET and collect the records of
every response that arrives within TIMEOUT seconds, retransmitting the
query after one second and then at doubling intervals as RFC 6762 section
5.2 asks.  RECORDS seeds the collection (what an earlier query brought in);
UNTIL, a function of the records so far, ends the wait early when it
returns true.  Returns the records, duplicates and goodbyes removed."
  (let* ((socket (mdns-socket-socket mdns-socket))
         (buffer (make-array +max-datagram+ :element-type '(unsigned-byte 8)))
         (packet (encode-message (make-dns-message :questions questions)))
         (start (%now))
         (deadline (+ start timeout))
         (next-send start)
         (interval 1.0d0))
    (loop
      (let ((now (%now)))
        (when (and until (funcall until records))
          (return records))
        (when (>= now deadline)
          (return records))
        (when (>= now next-send)
          (cl-matter.net:send-to socket packet (mdns-socket-group mdns-socket)
                                 (mdns-socket-port mdns-socket))
          (setf next-send (+ now interval)
                interval (* 2 interval)))
        (setf (cl-matter.net:socket-timeout socket)
              (max 0.05d0 (min (- deadline now) (- next-send now))))
        (let ((length (cl-matter.net:receive-from socket buffer)))
          (when length
            (let ((message (handler-case (decode-message buffer :end length)
                             (dns-decode-error () nil))))
              ;; queries (our own echo among them) and junk are skipped
              (when (and message (dns-message-response-p message))
                (setf records (%merge-records records (%message-records message)))))))))))

(defun %records-of (records name &rest types)
  "The RECORDS named NAME (case-insensitively) whose type is one of TYPES."
  (remove-if-not (lambda (r)
                   (and (string-equal name (dns-record-name r))
                        (member (dns-record-type r) types)))
                 records))

(defun %service-name (service-type domain)
  (if (or (null domain) (zerop (length domain)))
      service-type
      (concatenate 'string service-type "." domain)))

(defun browse (service-type &key (timeout 3) (domain "local") socket records)
  "Query for instances of SERVICE-TYPE (\"_http._tcp\") in DOMAIN and
collect the PTR answers that arrive within TIMEOUT seconds.  Returns the
instance names (\"Printer._http._tcp.local\") and, as a second value, every
record received -- the SRV, TXT and address records responders add -- for
RESOLVE to start from.  SOCKET is an MDNS-SOCKET to use; NIL opens one for
the call."
  (let* ((name (%service-name service-type domain))
         (questions (list (make-dns-question :name name :type +type-ptr+))))
    (flet ((run (s)
             (let ((all (query s questions :timeout timeout :records records)))
               (values (mapcar #'dns-record-data (%records-of all name +type-ptr+))
                       all))))
      (if socket
          (run socket)
          (with-mdns-socket (s) (run s))))))

(defun parse-txt-record (strings)
  "The strings of a TXT record -> an alist of (key . value) in order,
RFC 6763 section 6: \"key=value\" gives a string value, a bare \"key\" NIL,
\"key=\" the empty string.  Keys compare with STRING-EQUAL; a repeated key
keeps its first occurrence, as the RFC asks."
  (let ((alist '()))
    (dolist (s strings (nreverse alist))
      (let* ((eq (position #\= s))
             (key (if eq (subseq s 0 eq) s))
             (value (and eq (subseq s (1+ eq)))))
        (unless (or (zerop (length key))
                    (assoc key alist :test #'string-equal))
          (push (cons key value) alist))))))

(defun txt-value (alist key)
  "The value of KEY in a PARSE-TXT-RECORD alist (NIL also when absent); the
second value says whether KEY was present."
  (let ((entry (assoc key alist :test #'string-equal)))
    (values (cdr entry) (and entry t))))

(defun %service-from-records (instance-name records)
  "The resolved service plist, or NIL while the SRV record is missing."
  (let ((srv (first (%records-of records instance-name +type-srv+))))
    (when srv
      (let* ((data (dns-record-data srv))
             (host (getf data :target))
             (txt (first (%records-of records instance-name +type-txt+))))
        (list :name instance-name
              :host host
              :port (getf data :port)
              :addresses (mapcar #'dns-record-data
                                 (%records-of records host +type-a+ +type-aaaa+))
              :txt (and txt (parse-txt-record (dns-record-data txt))))))))

(defun %srv-and-txt-p (instance-name records)
  (and (%records-of records instance-name +type-srv+)
       (%records-of records instance-name +type-txt+)
       t))

(defun resolve (instance-name &key (timeout 3) socket records)
  "Resolve a service instance (\"Printer._http._tcp.local\") to its host,
port, addresses and TXT properties.  Returns a plist (:name :host :port
:addresses :txt) -- :addresses a list of address strings, :txt a
PARSE-TXT-RECORD alist -- or NIL when no SRV record arrived within TIMEOUT
seconds.  RECORDS (BROWSE's second value) may already hold everything, in
which case nothing is sent; otherwise SRV and TXT are asked for in one
query and the host's addresses in a second one when the responder did not
add them.  SOCKET as for BROWSE."
  (flet ((run (s)
           (let* ((deadline (+ (%now) timeout))
                  (records
                    (if (%srv-and-txt-p instance-name records)
                        records
                        (query s (list (make-dns-question :name instance-name :type +type-srv+)
                                       (make-dns-question :name instance-name :type +type-txt+))
                               :timeout timeout :records records
                               :until (lambda (rs) (%srv-and-txt-p instance-name rs)))))
                  (service (%service-from-records instance-name records)))
             (when (and service
                        (null (getf service :addresses))
                        (> (- deadline (%now)) 0))
               (let ((host (getf service :host)))
                 (setf records
                       (query s (list (make-dns-question :name host :type +type-a+)
                                      (make-dns-question :name host :type +type-aaaa+))
                              :timeout (- deadline (%now)) :records records
                              :until (lambda (rs)
                                       (%records-of rs host +type-a+ +type-aaaa+)))
                       service (%service-from-records instance-name records))))
             (values service records))))
    (if socket
        (run socket)
        (with-mdns-socket (s) (run s)))))
