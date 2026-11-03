(in-package :cl-matter.dns-sd)

;;; The mDNS responder (RFC 6762 sections 6 to 10) advertising DNS-SD
;;; services (RFC 6763): it probes for its unique names, announces, answers
;;; queries for its records -- with the additionals section 12 of RFC 6763
;;; asks for, known-answer suppression, the legacy unicast format for
;;; queries from other ports -- and says goodbye on stop.
;;;
;;; The responder runs in a thread of its own; RESPONDER-POLL is one turn of
;;; that thread and can be driven by hand, which is how the tests work
;;; without a network.  Not implemented: tie-breaking between simultaneous
;;; probes (section 8.2), rate limiting of multicast responses, and
;;; answering on several interfaces with per-interface addresses.

(defconstant +ttl-service+ 4500 "PTR, SRV, TXT: 75 minutes (RFC 6762 section 10).")
(defconstant +ttl-host+ 120 "A, AAAA and the host's NSEC.")
(defparameter *services-enumeration* "_services._dns-sd._udp")

;;; ------------------------------------------------------------------
;;; Services

(defstruct (service (:constructor %make-service))
  "A DNS-SD service to advertise.  INSTANCE is the user-visible name
(\"Living Room Lamp\"), TYPE the service type (\"_matterc._udp\"), TXT a
list of \"key=value\" strings, SUBTYPES a list of subtype labels
(\"_L840\") under which the instance is also found."
  (instance "" :type string)
  (type "" :type string)
  (port 0 :type (unsigned-byte 16))
  (txt nil :type list)
  (subtypes nil :type list)
  (priority 0 :type (unsigned-byte 16))
  (weight 0 :type (unsigned-byte 16))
  (domain "local" :type string))

(defun make-service (&key instance type port txt subtypes (priority 0) (weight 0) (domain "local"))
  "TXT may hold strings (\"path=/\") or conses ((\"path\" . \"/\"), (\"flag\"))."
  (check-type instance string)
  (check-type type string)
  (check-type port (unsigned-byte 16))
  (%make-service :instance instance :type type :port port
                 :txt (mapcar (lambda (entry)
                                (cond ((stringp entry) entry)
                                      ((cdr entry) (format nil "~a=~a" (car entry) (cdr entry)))
                                      (t (string (car entry)))))
                              txt)
                 :subtypes subtypes :priority priority :weight weight :domain domain))

(defun service-type-name (service)
  "\"_matterc._udp.local\""
  (%service-name (service-type service) (service-domain service)))

(defun service-instance-name (service)
  "\"Living Room Lamp._matterc._udp.local\", the instance label escaped."
  (concatenate 'string (%labels-name (list (service-instance service)))
               "." (service-type-name service)))

(defun %subtype-name (service subtype)
  (format nil "~a._sub.~a" subtype (service-type-name service)))

;;; ------------------------------------------------------------------
;;; The responder

(defclass responder ()
  ((services :initarg :services :initform nil :accessor responder-services)
   (host :initarg :host :accessor responder-host
         :documentation "This host's name, \"box.local\".")
   (addresses :initarg :addresses :initform nil :accessor responder-addresses)
   (socket :initarg :socket :accessor responder-socket)
   (owns-socket-p :initarg :owns-socket-p :initform nil :reader %owns-socket-p)
   (records :initform nil :accessor responder-records
            :documentation "Every record advertised, as DNS-RECORDs.")
   (running-p :initform nil :accessor responder-running-p)
   (thread :initform nil :accessor responder-thread)
   (last-error :initform nil :accessor responder-last-error
               :documentation "The last error the responder thread swallowed.")
   (pending :initform nil :accessor %pending
            :documentation "Timed work: a list of (due-time . thunk).")
   (buffer :initform (make-array +max-datagram+ :element-type '(unsigned-byte 8))
           :reader %buffer))
  (:documentation "Advertises this host's services: answers queries for its
names, announces on start, sends goodbye records on stop."))

(defun %unique-p (record)
  "Shared records (PTR) may have several owners; everything else is ours alone."
  (/= +type-ptr+ (dns-record-type record)))

(defun %ipv6-p (address)
  (find #\: address))

(defun %strip-zone (address)
  "\"fe80::1%en0\" -> \"fe80::1\""
  (subseq address 0 (position #\% address)))

(defun %build-records (responder)
  "Derive the record set from the host, its addresses and the services."
  (let ((host (responder-host responder))
        (records '()))
    (flet ((add (name type data ttl)
             (push (make-dns-record :name name :type type :data data :ttl ttl) records)))
      (dolist (address (responder-addresses responder))
        (add host (if (%ipv6-p address) +type-aaaa+ +type-a+) (%strip-zone address) +ttl-host+))
      (let ((host-types (remove-duplicates (mapcar #'dns-record-type records))))
        (when host-types
          (add host +type-nsec+ (list :next-name host :types (sort host-types #'<)) +ttl-host+)))
      (dolist (service (responder-services responder))
        (let ((type-name (service-type-name service))
              (instance (service-instance-name service)))
          (add (%service-name *services-enumeration* (service-domain service))
               +type-ptr+ type-name +ttl-service+)
          (add type-name +type-ptr+ instance +ttl-service+)
          (dolist (subtype (service-subtypes service))
            (add (%subtype-name service subtype) +type-ptr+ instance +ttl-service+))
          (add instance +type-srv+
               (list :priority (service-priority service) :weight (service-weight service)
                     :port (service-port service) :target host)
               +ttl-service+)
          (add instance +type-txt+ (service-txt service) +ttl-service+)
          (add instance +type-nsec+ (list :next-name instance :types (list +type-txt+ +type-srv+))
               +ttl-service+))))
    (setf (responder-records responder) (nreverse records))))

(defun %unique-names (responder)
  (cons (responder-host responder)
        (mapcar #'service-instance-name (responder-services responder))))

(defun %host-records (responder)
  (%records-of (responder-records responder) (responder-host responder)
               +type-a+ +type-aaaa+ +type-nsec+))

(defun %additionals-for (responder record)
  "What RFC 6763 section 12 asks a responder to add for RECORD."
  (let ((records (responder-records responder))
        (type (dns-record-type record)))
    (cond ((= type +type-ptr+)
           (let* ((target (dns-record-data record))
                  (instance-records (%records-of records target +type-srv+ +type-txt+ +type-nsec+)))
             ;; a service-type enumeration PTR points at a type, not an instance
             (and instance-records (append instance-records (%host-records responder)))))
          ((or (= type +type-srv+) (= type +type-a+) (= type +type-aaaa+))
           (%host-records responder))
          (t nil))))

(defun %same-record-p (a b)
  (equalp (%record-key a) (%record-key b)))

(defun %outgoing (record &key legacy (ttl (dns-record-ttl record)))
  "RECORD as it goes on the wire: cache-flush on unique records, unless this
is a legacy unicast response, where the TTL is also capped at 10
(RFC 6762 section 6.7)."
  (make-dns-record :name (dns-record-name record)
                   :type (dns-record-type record)
                   :class +class-in+
                   :cache-flush-p (and (not legacy) (%unique-p record))
                   :ttl (if legacy (min 10 ttl) ttl)
                   :data (dns-record-data record)))

(defun responder-response (responder message &key legacy)
  "The response to the query MESSAGE, or NIL when none of it is ours.  Each
question is matched against the records by name (and type unless ANY); a
name we own but a type we lack is answered with the name's NSEC record
(RFC 6762 section 6.1); answers the querier already holds with at least
half the TTL left are suppressed (section 7.1).  LEGACY produces the
unicast format for a query from a port other than 5353 (section 6.7)."
  (let ((records (responder-records responder))
        (unique-names (%unique-names responder))
        (answers '())
        (additionals '()))
    (dolist (q (dns-message-questions message))
      (let* ((name (dns-question-name q))
             (type (dns-question-type q))
             (matches (remove-if-not
                       (lambda (r)
                         (and (string-equal name (dns-record-name r))
                              (or (= type +type-any+) (= type (dns-record-type r)))))
                       records)))
        (when (and (null matches)
                   (/= type +type-any+)
                   (member name unique-names :test #'string-equal))
          (setf matches (%records-of records name +type-nsec+)))
        (dolist (m matches)
          (pushnew m answers :test #'%same-record-p)
          (dolist (a (%additionals-for responder m))
            (pushnew a additionals :test #'%same-record-p)))))
    (setf answers
          (remove-if (lambda (r)
                       (find-if (lambda (known)
                                  (and (%same-record-p known r)
                                       (>= (dns-record-ttl known) (floor (dns-record-ttl r) 2))))
                                (dns-message-answers message)))
                     answers))
    (when answers
      (setf additionals (remove-if (lambda (a) (member a answers :test #'%same-record-p))
                                   additionals))
      (make-dns-message
       :id (if legacy (dns-message-id message) 0)
       :flags (logior +flag-response+ +flag-authoritative+)
       :questions (if legacy (dns-message-questions message) nil)
       :answers (mapcar (lambda (r) (%outgoing r :legacy legacy)) (nreverse answers))
       :additionals (mapcar (lambda (r) (%outgoing r :legacy legacy)) (nreverse additionals))))))

;;; ------------------------------------------------------------------
;;; Sending and receiving

(defun %send (responder message &key legacy host port)
  "Multicast MESSAGE, or unicast it to HOST:PORT when given."
  (let ((mdns (responder-socket responder))
        (packet (encode-message message :compress-srv-target (not legacy))))
    (cl-matter.net:send-to (mdns-socket-socket mdns) packet
                           (or host (mdns-socket-group mdns))
                           (or port (mdns-socket-port mdns)))))

(defun %all-records-response (responder &key goodbye)
  (make-dns-message
   :flags (logior +flag-response+ +flag-authoritative+)
   :answers (mapcar (lambda (r)
                      (if goodbye
                          (make-dns-record :name (dns-record-name r) :type (dns-record-type r)
                                           :ttl 0 :data (dns-record-data r))
                          (%outgoing r)))
                    (responder-records responder))))

(defun %announce (responder)
  "RFC 6762 section 8.3: the whole record set, twice, one second apart."
  (%send responder (%all-records-response responder))
  (%schedule responder 1
             (lambda () (%send responder (%all-records-response responder)))))

(defun %goodbye (responder)
  "RFC 6762 section 10.1: every record with TTL 0."
  (when (responder-records responder)
    (%send responder (%all-records-response responder :goodbye t))))

(defun %schedule (responder delay thunk)
  (push (cons (+ (%now) delay) thunk) (%pending responder)))

(defun %run-pending (responder)
  (let ((now (%now)))
    (dolist (entry (%pending responder))
      (when (>= now (car entry))
        (setf (%pending responder) (remove entry (%pending responder)))
        (funcall (cdr entry))))))

(defun %handle-query (responder message host port)
  (let* ((mdns (responder-socket responder))
         (legacy (/= port (mdns-socket-port mdns)))
         (unicast (or legacy
                      (every #'dns-question-unicast-response-p (dns-message-questions message))))
         (response (responder-response responder message :legacy legacy)))
    (when response
      ;; RFC 6762 section 6.3: shared records wait 20-120 ms so that several
      ;; responders do not answer in the same instant
      (when (and (not unicast)
                 (find +type-ptr+ (dns-message-answers response) :key #'dns-record-type))
        (sleep (+ 0.02 (/ (random 100) 1000.0))))
      (if unicast
          (%send responder response :legacy legacy :host host :port port)
          (%send responder response)))))

(defun responder-poll (responder &key (timeout 0.25))
  "One turn of the responder: run the announcement that is due, then wait up
to TIMEOUT seconds for a datagram and answer it if it is a query for our
records.  Returns true when a datagram was handled.  The responder thread
calls this in a loop; a test rig without threads may too."
  (%run-pending responder)
  (let ((socket (mdns-socket-socket (responder-socket responder)))
        (buffer (%buffer responder)))
    (setf (cl-matter.net:socket-timeout socket) timeout)
    (multiple-value-bind (length host port) (cl-matter.net:receive-from socket buffer)
      (when length
        (let ((message (handler-case (decode-message buffer :end length)
                         (dns-decode-error () nil))))
          (when (and message (not (dns-message-response-p message)))
            (%handle-query responder message host port)))
        t))))

;;; ------------------------------------------------------------------
;;; Probing (RFC 6762 section 8.1)

(defun %conflict (responder message)
  "The host (:HOST) or SERVICE whose unique name MESSAGE claims with other
data, or NIL.  NSEC records are left out: they only describe the others."
  (dolist (theirs (%message-records message))
    (dolist (mine (responder-records responder))
      (when (and (%unique-p mine)
                 (/= +type-nsec+ (dns-record-type mine))
                 (= (dns-record-type theirs) (dns-record-type mine))
                 (string-equal (dns-record-name theirs) (dns-record-name mine))
                 (not (equalp (dns-record-data theirs) (dns-record-data mine))))
        (return-from %conflict
          (if (string-equal (dns-record-name mine) (responder-host responder))
              :host
              (find (dns-record-name mine) (responder-services responder)
                    :key #'service-instance-name :test #'string-equal)))))))

(defun %probe-once (responder)
  "Three probes 250 ms apart; the conflict seen meanwhile, or NIL."
  (let* ((mdns (responder-socket responder))
         (socket (mdns-socket-socket mdns))
         (buffer (%buffer responder))
         (unique (remove-if-not #'%unique-p (responder-records responder)))
         (probe (make-dns-message
                 :questions (mapcar (lambda (name)
                                      (make-dns-question :name name :type +type-any+
                                                         :unicast-response-p t))
                                    (%unique-names responder))
                 :authorities unique))
         (start (%now)))
    (dotimes (i 3)
      (%send responder probe)
      (let ((until (+ start (* 0.25 (1+ i)))))
        (loop :for remaining := (- until (%now))
              :while (> remaining 0)
              :do (setf (cl-matter.net:socket-timeout socket) remaining)
                  (let ((length (cl-matter.net:receive-from socket buffer)))
                    (when length
                      (let ((message (handler-case (decode-message buffer :end length)
                                       (dns-decode-error () nil))))
                        (when (and message (dns-message-response-p message))
                          (let ((conflict (%conflict responder message)))
                            (when conflict (return-from %probe-once conflict))))))))))
    nil))

(defun %next-name (name separator)
  "\"Lamp\" -> \"Lamp (2)\" -> \"Lamp (3)\" with SEPARATOR \" (\"; \"box\" ->
\"box-2\" with \"-\"."
  (let* ((open (search separator name :from-end t))
         (close (if (string= separator " (") ")" ""))
         (n (and open
                 (let ((end (- (length name) (length close))))
                   (and (> end (+ open (length separator)))
                        (string= close (subseq name end))
                        (every #'digit-char-p (subseq name (+ open (length separator)) end))
                        (parse-integer name :start (+ open (length separator)) :end end))))))
    (if n
        (format nil "~a~a~d~a" (subseq name 0 open) separator (1+ n) close)
        (format nil "~a~a2~a" name separator close))))

(defun %rename (responder conflict)
  (if (eq conflict :host)
      (let* ((host (responder-host responder))
             (dot (position #\. host)))
        (setf (responder-host responder)
              (concatenate 'string (%next-name (subseq host 0 dot) "-")
                           (if dot (subseq host dot) ""))))
      (setf (service-instance conflict) (%next-name (service-instance conflict) " (")))
  (%build-records responder))

(defun %probe (responder)
  "Probe until no one objects to our unique names, renaming on conflict."
  (loop :for conflict := (%probe-once responder)
        :while conflict
        :do (%rename responder conflict)))

;;; ------------------------------------------------------------------
;;; Start and stop

(defun %default-host ()
  (let* ((machine (or (ignore-errors (machine-instance)) ""))
         (label (string-downcase (subseq machine 0 (position #\. machine)))))
    (concatenate 'string (if (zerop (length label)) "cl-matter" label) ".local")))

(defun %link-local-p (address)
  "An IPv6 address in fe80::/10."
  (and (%ipv6-p address)
       (let ((first (parse-integer address :end (position #\: address)
                                           :radix 16 :junk-allowed t)))
         (and first (= (logand first #xFFC0) #xFE80)))))

(defun %default-addresses ()
  "The addresses of the interfaces that are up and not loopback: every IPv4,
and IPv6 except link-local, zone identifiers removed."
  (let ((addresses '()))
    (dolist (interface (handler-case (cl-matter.net:network-interfaces)
                         (cl-matter.net:not-supported () nil)))
      (let ((flags (getf interface :flags)))
        (when (and (member :up flags) (not (member :loopback flags)))
          (dolist (address (getf interface :addresses))
            (let ((address (%strip-zone address)))
              (unless (%link-local-p address)
                (pushnew address addresses :test #'string-equal)))))))
    (nreverse addresses)))

(defun start-responder (&key services host addresses interface socket (probe t) (thread t))
  "Start advertising SERVICES (MAKE-SERVICE structs) for HOST (default: this
machine's name under .local) at ADDRESSES (default: the addresses of the
interfaces that are up).  INTERFACE restricts multicast to one interface.
SOCKET is an MDNS-SOCKET to use instead of opening one; PROBE NIL skips
the probing for unique names; THREAD NIL leaves RESPONDER-POLL to the
caller.  Returns the RESPONDER.  Signals NET-ERROR when there is no
address to advertise.

The default host name is the one the system's own mDNS responder uses, if
it has one; records for a name both advertise are shared, which is legal
when their data agree, but a host of its own is the cleaner choice."
  (let* ((host (or host (%default-host)))
         (addresses (or addresses (%default-addresses)))
         (owns-socket-p (null socket))
         (socket (or socket (open-mdns-socket :interface interface))))
    (when (null addresses)
      (when owns-socket-p (close-mdns-socket socket))
      (error 'cl-matter.net:net-error
             :message "start-responder: no address to advertise; pass :addresses"))
    (let ((responder (make-instance 'responder
                                    :services services :host host :addresses addresses
                                    :socket socket :owns-socket-p owns-socket-p)))
      (%build-records responder)
      (handler-case
          (progn
            (when probe (%probe responder))
            (%announce responder))
        (error (e)
          (when owns-socket-p (close-mdns-socket socket))
          (error e)))
      (setf (responder-running-p responder) t)
      (when thread
        (setf (responder-thread responder)
              (bt:make-thread
               (lambda ()
                 (loop :while (responder-running-p responder)
                       :do (handler-case (responder-poll responder)
                             (error (e) (setf (responder-last-error responder) e)))))
               :name "mdns-responder")))
      responder)))

(defun stop-responder (responder)
  "Stop the thread, say goodbye for every record, close the socket if the
responder opened it.  Stopping twice is harmless."
  (when (responder-running-p responder)
    (setf (responder-running-p responder) nil)
    (let ((thread (responder-thread responder)))
      (when thread
        (bt:join-thread thread)
        (setf (responder-thread responder) nil)))
    (unwind-protect (%goodbye responder)
      (when (%owns-socket-p responder)
        (close-mdns-socket (responder-socket responder)))))
  t)
