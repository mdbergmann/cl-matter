;;;; interaction.lisp -- the Interaction Model over exchanges (Matter Core
;;;; Specification chapter 8): Read, Write, Invoke and Subscribe, as the
;;;; server of a NODE and as a client.
;;;;
;;;; One INTERACTION-MODEL per exchange manager handles protocol 0x0001
;;;; in both roles.  As a server it answers the peer's requests from the
;;;; node's data model, chunks reports that exceed one message, honours
;;;; timed requests and data version filters, and keeps subscriptions:
;;;; a change to a subscribed attribute is reported after the minimum
;;;; interval, and an empty report keeps the subscription alive at the
;;;; maximum.  As a client it starts an interaction (START-READ, START-WRITE,
;;;; START-INVOKE, START-SUBSCRIBE), whose result arrives through
;;;; INTERACTION-WAIT or an ON-COMPLETE function, and answers the reports of
;;;; its subscriptions.
;;;;
;;;; Every read, write and invoke is checked against the node's ACL
;;;; (access.lisp): a concrete path the peer may not touch is answered
;;;; UNSUPPORTED_ACCESS, a wildcard silently leaves out what it may not
;;;; read (8.4.3.2).
;;;;
;;;; A list the server sends in pieces (8.7.3.3: the list, then one report
;;;; per element with a list index) is put together again on the client, so
;;;; a read or subscription delivers every attribute once.  As a server, an
;;;; attribute too big for one message is reported RESOURCE_EXHAUSTED.
;;;;
;;;; Not done: events (event requests are accepted and never answered),
;;;; list chunking as a server, group writes.

(in-package :cl-matter)

(defparameter *interaction-timeout* 30.0d0
  "Seconds a side waits for the peer's next message of an interaction.")

(defparameter *max-report-payload* 1100
  "Octets of attribute reports per ReportData message; the rest of the
message and the headers fit in the 1280 of a UDP datagram beside it.")

(defparameter *max-subscription-interval* 3600
  "The longest MaxInterval, seconds, we grant a subscriber (the specification's hour).")

(defparameter *subscription-grace* 5.0d0
  "Seconds past MaxInterval a subscriber waits for a report before giving up.")

(defparameter *timed-request-grace* 5.0d0
  "Seconds past its timeout the server keeps an expired timed request's
exchange, so a late action is answered TIMEOUT rather than mismatch.")

;;; ------------------------------------------------------------------
;;; The model

(defstruct (server-subscription (:constructor %make-server-subscription))
  "A peer's subscription to this node."
  (id 0) session paths (min-interval 0) (max-interval 0) (fabric-filtered nil)
  (last-report 0) (dirty '()) (exchange nil) (chunks '()))

(defmethod print-object ((s server-subscription) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "#x~8,'0x ~d path~:p ~d..~ds" (server-subscription-id s)
            (length (server-subscription-paths s))
            (server-subscription-min-interval s) (server-subscription-max-interval s))))

(defstruct (subscription (:constructor %make-subscription))
  "Our subscription to a peer.  ON-REPORT is called with the subscription
and the list of ATTRIBUTE-REPORTs of each report; ON-FAILURE with the
subscription and a reason when it ends."
  model session (id 0) paths (min-interval 0) (max-interval 0)
  on-report on-failure (state :active) (last-report 0) (primed-reports '()) (chunk '()))

(defmethod print-object ((s subscription) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "#x~8,'0x ~a max ~ds" (subscription-id s) (subscription-state s) (subscription-max-interval s))))

(defun subscription-active-p (subscription) (eq :active (subscription-state subscription)))

(defstruct (interaction-model (:constructor %make-interaction-model))
  "Protocol 0x0001 on MANAGER, serving NODE (NIL: client only)."
  manager
  node
  (subscriptions '())                   ; SERVER-SUBSCRIPTIONs
  (client-subscriptions '())            ; SUBSCRIPTIONs
  (next-subscription-id (random (ash 1 32)))
  listener
  timer)

(defun make-interaction-model (manager &key node)
  "Serve NODE's data model to the peers of MANAGER and interact with theirs."
  (let ((model (%make-interaction-model :manager manager :node node)))
    (register-protocol-handler manager +protocol-interaction-model+
                               (lambda (exchange event &rest data) (%responder-event model exchange event data)))
    (when node
      (setf (interaction-model-listener model)
            (add-node-listener node (lambda (endpoint cluster attribute)
                                      (%attribute-dirty model endpoint cluster attribute)))))
    (setf (interaction-model-timer model)
          (add-timer manager (lambda (now) (%model-timer model now))))
    model))

(defun interaction-model-now (model)
  (exchange-manager-now (interaction-model-manager model)))

(defun interaction-model-close (model)
  "Stop serving: forget every subscription both ways."
  (let ((manager (interaction-model-manager model)))
    (register-protocol-handler manager +protocol-interaction-model+ nil)
    (remove-timer manager (interaction-model-timer model))
    (when (interaction-model-listener model)
      (remove-node-listener (interaction-model-node model) (interaction-model-listener model)))
    (setf (interaction-model-subscriptions model) '()
          (interaction-model-client-subscriptions model) '())
    nil))

(defun %trace-model (model format &rest args)
  (apply #'%trace (interaction-model-manager model) format args))

(defun %send (exchange message &key (reliable t))
  (multiple-value-bind (opcode octets) (encode-interaction-message message)
    (exchange-send exchange opcode octets :reliable reliable)))

(defun %send-status (exchange status)
  (%send exchange (make-status-response :status (im-status-code status))))

;;; ------------------------------------------------------------------
;;; Server: reading the data model

(defun %readable-p (node session endpoint cluster attribute-id)
  "May the peer of SESSION read the attribute?"
  (access-granted-p node session endpoint (cluster-id cluster)
                    (attribute-definition-read-privilege (%attribute cluster attribute-id))))

(defun %path-report (node path &key session fabric-filtered expanded)
  "The ATTRIBUTE-REPORT of the concrete PATH for the peer of SESSION: its
data, or a status.  An attribute the peer may not read is reported
UNSUPPORTED_ACCESS, or when PATH came from a wildcard (EXPANDED) not at all: NIL."
  (flet ((status (status) (make-attribute-report
                           :status (make-attribute-status :path path :status (im-status status)))))
    (let* ((endpoint (find-endpoint node (attribute-path-endpoint path)))
           (cluster (and endpoint (find-cluster endpoint (attribute-path-cluster path))))
           (fabric-index (session-fabric-index session)))
      (cond ((null endpoint) (status :unsupported-endpoint))
            ((null cluster) (status :unsupported-cluster))
            ((not (attribute-present-p cluster (attribute-path-attribute path))) (status :unsupported-attribute))
            ((not (%readable-p node session endpoint cluster (attribute-path-attribute path)))
             (if expanded nil (status :unsupported-access)))
            (t (handler-case
                   (make-attribute-report
                    :data (make-attribute-data :data-version (cluster-data-version cluster)
                                               :path (attribute-path (attribute-path-endpoint path)
                                                                     (attribute-path-cluster path)
                                                                     (attribute-path-attribute path))
                                               :data (read-attribute cluster (attribute-path-attribute path)
                                                                     :fabric-index fabric-index
                                                                     :fabric-filtered fabric-filtered)))
                 (interaction-error (e) (status (interaction-error-status e)))))))))

(defun %expand-path (node pattern)
  "The concrete paths PATTERN stands for on NODE (none of them failing)."
  (loop :for endpoint :in (node-endpoints node)
        :when (or (null (attribute-path-endpoint pattern))
                  (= (attribute-path-endpoint pattern) (endpoint-id endpoint)))
          :append (loop :for cluster :in (endpoint-clusters endpoint)
                        :when (or (null (attribute-path-cluster pattern))
                                  (= (attribute-path-cluster pattern) (cluster-id cluster)))
                          :append (loop :for id :in (if (attribute-path-attribute pattern)
                                                        (and (attribute-present-p cluster (attribute-path-attribute pattern))
                                                             (list (attribute-path-attribute pattern)))
                                                        (cluster-attribute-ids cluster))
                                        :collect (attribute-path (endpoint-id endpoint) (cluster-id cluster) id)))))

(defun %filtered-out-p (node report filters)
  "Does a data version filter say the peer already has REPORT's cluster?"
  (let ((data (attribute-report-data report)))
    (and data
         (some (lambda (filter)
                 (let ((path (data-version-filter-path filter))
                       (attribute-path (attribute-data-path data)))
                   (and (eql (cluster-path-endpoint path) (attribute-path-endpoint attribute-path))
                        (eql (cluster-path-cluster path) (attribute-path-cluster attribute-path))
                        (let ((cluster (node-cluster node (attribute-path-endpoint attribute-path)
                                                     (attribute-path-cluster attribute-path))))
                          (and cluster (= (data-version-filter-data-version filter) (cluster-data-version cluster)))))))
               filters))))

(defun %collect-reports (node paths &key filters session fabric-filtered)
  "Reports for PATHS (wildcards expanded, concrete misses reported as
statuses) for the peer of SESSION."
  (let ((reports '()))
    (dolist (path paths)
      (if (attribute-path-concrete-p path)
          (push (%path-report node path :session session :fabric-filtered fabric-filtered) reports)
          (dolist (concrete (%expand-path node path))
            (let ((report (%path-report node concrete :session session :fabric-filtered fabric-filtered :expanded t)))
              (when report (push report reports))))))
    (setf reports (nreverse reports))
    (if filters
        (remove-if (lambda (report) (%filtered-out-p node report filters)) reports)
        reports)))

(defun %report-size (report)
  (length (tlv-encode (attribute-report-tlv nil report))))

(defun %chunk-reports (reports)
  "REPORTS split into lists that each fit one ReportData message."
  (let ((chunks '()) (current '()) (size 0))
    (dolist (report reports)
      (let ((n (%report-size report)))
        (when (> n *max-report-payload*)
          (setf report (make-attribute-report
                        :status (make-attribute-status :path (attribute-report-path report)
                                                       :status (im-status :resource-exhausted)))
                n (%report-size report)))
        (when (and current (> (+ size n) *max-report-payload*))
          (push (nreverse current) chunks)
          (setf current '() size 0))
        (push report current)
        (incf size n)))
    (when current (push (nreverse current) chunks))
    (nreverse chunks)))

;;; ------------------------------------------------------------------
;;; Server: writing and invoking

(defun %check-write-access (node session endpoint cluster attribute-id)
  "The peer of SESSION is about to write the attribute: it must exist, be
writable, and be theirs to write (in that order of refusal)."
  (let ((attribute (%attribute cluster attribute-id)))
    (unless (attribute-present-p cluster attribute-id)
      (%im-fail :unsupported-attribute "~a does not have the optional attribute ~a"
                cluster (attribute-definition-name attribute)))
    (unless (and (attribute-definition-writable attribute) (not (attribute-definition-computed attribute)))
      (%im-fail :unsupported-write "~a of ~a is not writable" (attribute-definition-name attribute) cluster))
    (unless (access-granted-p node session endpoint (cluster-id cluster) (attribute-definition-write-privilege attribute))
      (%im-fail :unsupported-access "~a may not write ~a of ~a: ~a needed"
                session (attribute-definition-name attribute) cluster
                (privilege-name (attribute-definition-write-privilege attribute))))))

(defun %apply-write (model data)
  "Apply one AttributeDataIB for the peer of *INTERACTION-SESSION*; returns its ATTRIBUTE-STATUS."
  (let* ((node (interaction-model-node model))
         (path (attribute-data-path data))
         (endpoint (and (attribute-path-endpoint path) (find-endpoint node (attribute-path-endpoint path))))
         (cluster (and endpoint (attribute-path-cluster path) (find-cluster endpoint (attribute-path-cluster path))))
         (status (handler-case
                     (cond ((not (attribute-path-concrete-p path))
                            (%im-fail :invalid-action "a write path must be concrete: ~a" path))
                           ((null endpoint) (im-status :unsupported-endpoint))
                           ((null cluster) (im-status :unsupported-cluster))
                           ((progn (%check-write-access node *interaction-session* endpoint cluster
                                                        (attribute-path-attribute path))
                                   nil))
                           ((and (attribute-data-data-version data)
                                 (/= (attribute-data-data-version data) (cluster-data-version cluster)))
                            (im-status :data-version-mismatch))
                           (t (write-attribute cluster (attribute-path-attribute path) (attribute-data-data data)
                                               :list-index (attribute-path-list-index path)
                                               :fabric-index (session-fabric-index *interaction-session*))
                              (im-status :success)))
                   (interaction-error (e)
                     (when (= +im-status-invalid-action+ (interaction-error-status e)) (error e))
                     (%trace-model model "write to ~a refused: ~a" path e)
                     (im-status (interaction-error-status e) (interaction-error-cluster-status e))))))
    (make-attribute-status :path path :status status)))

(defun %apply-invoke (model data timed)
  "Run one CommandDataIB for the peer of *INTERACTION-SESSION*; returns its INVOKE-RESPONSE."
  (let* ((node (interaction-model-node model))
         (path (command-data-path data))
         (ref (command-data-ref data))
         (endpoint (and (command-path-endpoint path) (find-endpoint node (command-path-endpoint path))))
         (cluster (and endpoint (find-cluster endpoint (command-path-cluster path))))
         (command (and cluster (find-command-definition (cluster-definition cluster) (command-path-command path)))))
    (flet ((status (status)
             (make-invoke-response :status (make-command-status :path path :status status :ref ref))))
      (handler-case
          (cond ((null (command-path-endpoint path))
                 (%im-fail :invalid-action "an invoke path must name its endpoint: ~a" path))
                ((null endpoint) (status (im-status :unsupported-endpoint)))
                ((null cluster) (status (im-status :unsupported-cluster)))
                ((not (and command (command-handler cluster (command-definition-id command))))
                 (status (im-status :unsupported-command)))
                ((not (access-granted-p node *interaction-session* endpoint (cluster-id cluster)
                                        (command-definition-privilege command)))
                 (%trace-model model "~a may not invoke ~a of ~a: ~a needed" *interaction-session*
                               (command-definition-name command) cluster (privilege-name (command-definition-privilege command)))
                 (status (im-status :unsupported-access)))
                ((and (command-definition-timed command) (not timed))
                 (status (im-status :needs-timed-interaction)))
                (t (multiple-value-bind (response-id result)
                       (invoke-cluster-command cluster (command-path-command path) (command-data-fields data))
                     (if response-id
                         (make-invoke-response
                          :command (make-command-data :path (command-path (command-path-endpoint path)
                                                                          (command-path-cluster path)
                                                                          response-id)
                                                      :fields result :ref ref))
                         (status result)))))
        (interaction-error (e)
          (when (= +im-status-invalid-action+ (interaction-error-status e)) (error e))
          (%trace-model model "invoke of ~a refused: ~a" path e)
          (status (im-status (interaction-error-status e) (interaction-error-cluster-status e))))))))

;;; ------------------------------------------------------------------
;;; Server: the exchange state machine

(defstruct (server-state (:constructor %make-server-state))
  "What an exchange we respond on is in the middle of."
  (kind nil)                            ; :timed :read :write :subscribe
  (chunks '())                          ; report lists still to send
  (timed-deadline nil)
  (subscription nil))

(defun %server-state (exchange)
  (or (exchange-user-data exchange)
      (setf (exchange-user-data exchange) (%make-server-state))))

(defun %responder-event (model exchange event data)
  (case event
    (:message
     (destructuring-bind (opcode payload) data
       (handler-case
           (let ((*interaction-session* (exchange-session exchange)))
             (%responder-message model exchange opcode payload))
         (interaction-error (e)
           (%trace-model model "~a: ~a" exchange e)
           (%abandon-priming model exchange)
           (when (exchange-open-p exchange)
             (%send-status exchange (interaction-error-status e))
             (exchange-close exchange))))))
    (:failure
     (%trace-model model "~a failed: ~a" exchange (first data))
     (%abandon-priming model exchange))))

(defun %abandon-priming (model exchange)
  (declare (ignore model))
  (let ((state (exchange-user-data exchange)))
    (when (and (server-state-p state) (server-state-subscription state))
      (setf (server-state-subscription state) nil))))

(defun %responder-message (model exchange opcode payload)
  (let ((message (decode-interaction-message opcode payload))
        (state (%server-state exchange)))
    (etypecase message
      (report-data (%client-report model exchange message))
      (status-response (%responder-status model exchange state message))
      (timed-request (%responder-timed model exchange state message))
      (read-request (%responder-read model exchange state message))
      (write-request (%responder-write model exchange state message))
      (invoke-request (%responder-invoke model exchange state message))
      (subscribe-request (%responder-subscribe model exchange state message))
      ((or subscribe-response write-response invoke-response-message)
       (%im-fail :invalid-action "~a is not a request" (type-of message))))))

(defun %require-node (model)
  (or (interaction-model-node model)
      (%im-fail :unsupported-node "this side has no data model")))

(defun %check-timed (model exchange state timed-flag)
  "The peer's write or invoke claims (or not) to follow a timed request."
  (let ((deadline (server-state-timed-deadline state)))
    (cond ((and timed-flag (null deadline))
           (%im-fail :timed-request-mismatch "no timed request preceded this timed action"))
          ((and deadline (not timed-flag))
           (%im-fail :timed-request-mismatch "a timed request preceded this untimed action"))
          ((and deadline (> (interaction-model-now model) deadline))
           (%im-fail :timeout "the timed request expired"))
          (t (setf (server-state-timed-deadline state) nil
                   (exchange-response-timeout exchange) nil)))))

(defun %responder-timed (model exchange state message)
  (let ((seconds (/ (timed-request-timeout message) 1000.0d0)))
    (setf (server-state-kind state) :timed
          (server-state-timed-deadline state) (+ (interaction-model-now model) seconds)
          (exchange-response-timeout exchange) (+ seconds *timed-request-grace*))
    (%send-status exchange :success)))

(defun %send-report-chunk (exchange state &key subscription-id suppress-last)
  "Send the next chunk of STATE; the exchange stays open while more follow."
  (let* ((chunk (pop (server-state-chunks state)))
         (more (and (server-state-chunks state) t))
         (suppress (and (not more) suppress-last)))
    (setf (exchange-response-timeout exchange) (if suppress nil *interaction-timeout*))
    (%send exchange (make-report-data :subscription-id subscription-id
                                      :attribute-reports chunk
                                      :more-chunked-messages more
                                      :suppress-response suppress))
    (when suppress (exchange-close exchange))
    more))

(defun %responder-read (model exchange state message)
  (let ((node (%require-node model)))
    (when (server-state-kind state) (%im-fail :invalid-action "a read cannot continue a ~a" (server-state-kind state)))
    (setf (server-state-kind state) :read
          (server-state-chunks state)
          (or (%chunk-reports (%collect-reports node (read-request-attribute-requests message)
                                                :filters (read-request-data-version-filters message)
                                                :session (exchange-session exchange)
                                                :fabric-filtered (read-request-fabric-filtered message)))
              (list '())))
    (%send-report-chunk exchange state :suppress-last t)))

(defun %responder-write (model exchange state message)
  (%require-node model)
  (progn
    (unless (member (server-state-kind state) '(nil :timed :write))
      (%im-fail :invalid-action "a write cannot continue a ~a" (server-state-kind state)))
    (unless (eq (server-state-kind state) :write) ; the first chunk
      (%check-timed model exchange state (write-request-timed-request message)))
    (setf (server-state-kind state) :write)
    (let ((responses (mapcar (lambda (data) (%apply-write model data)) (write-request-write-requests message))))
      (cond ((write-request-more-chunked-messages message)
             (setf (exchange-response-timeout exchange) *interaction-timeout*)
             (%send exchange (make-write-response :write-responses responses)))
            ((write-request-suppress-response message)
             (exchange-close exchange))
            (t
             (setf (exchange-response-timeout exchange) nil)
             (%send exchange (make-write-response :write-responses responses))
             (exchange-close exchange))))))

(defun %responder-invoke (model exchange state message)
  (%require-node model)
  (progn
    (unless (member (server-state-kind state) '(nil :timed))
      (%im-fail :invalid-action "an invoke cannot continue a ~a" (server-state-kind state)))
    (%check-timed model exchange state (invoke-request-timed-request message))
    (setf (server-state-kind state) :invoke)
    (let ((requests (invoke-request-invoke-requests message)))
      (when (/= 1 (length requests))
        (%im-fail :invalid-action "one command per invoke (MaxPathsPerInvoke), got ~d" (length requests)))
      (let ((responses (mapcar (lambda (data) (%apply-invoke model data (invoke-request-timed-request message)))
                               requests)))
        (unless (invoke-request-suppress-response message)
          (%send exchange (make-invoke-response-message :invoke-responses responses)))
        (exchange-close exchange)))))

(defun %responder-subscribe (model exchange state message)
  (let* ((node (%require-node model))
         (session (exchange-session exchange))
         (floor (subscribe-request-min-interval-floor message))
         (ceiling (subscribe-request-max-interval-ceiling message))
         (paths (subscribe-request-attribute-requests message)))
    (when (server-state-kind state) (%im-fail :invalid-action "a subscribe cannot continue a ~a" (server-state-kind state)))
    (when (> floor ceiling) (%im-fail :invalid-action "MinIntervalFloor ~d > MaxIntervalCeiling ~d" floor ceiling))
    (unless (or paths (subscribe-request-event-requests message))
      (%im-fail :invalid-action "a subscription needs attribute or event paths"))
    (unless (subscribe-request-keep-subscriptions message)
      (dolist (other (interaction-model-subscriptions model))
        (when (%same-subscriber-p (server-subscription-session other) session)
          (%drop-server-subscription model other "replaced"))))
    (let ((subscription (%make-server-subscription
                         :id (%next-subscription-id model) :session session :paths paths
                         :min-interval floor
                         :max-interval (max floor (min ceiling *max-subscription-interval*))
                         :fabric-filtered (subscribe-request-fabric-filtered message)
                         :last-report (interaction-model-now model))))
      (setf (server-state-kind state) :subscribe
            (server-state-subscription state) subscription
            (server-state-chunks state)
            (or (%chunk-reports (%collect-reports node paths
                                                  :filters (subscribe-request-data-version-filters message)
                                                  :session session
                                                  :fabric-filtered (subscribe-request-fabric-filtered message)))
                (list '())))
      (%send-report-chunk exchange state :subscription-id (server-subscription-id subscription)))))

(defun %same-subscriber-p (a b)
  (or (eq a b)
      (and (session-peer-node-id a) (eql (session-peer-node-id a) (session-peer-node-id b))
           (eq (session-fabric a) (session-fabric b)))))

(defun %next-subscription-id (model)
  (loop :for id := (interaction-model-next-subscription-id model)
        :do (setf (interaction-model-next-subscription-id model) (logand #xFFFFFFFF (1+ id)))
        :unless (find id (interaction-model-subscriptions model) :key #'server-subscription-id)
          :return id))

(defun %responder-status (model exchange state message)
  "A StatusResponse answers one of our report chunks."
  (let ((status (status-response-status message)))
    (case (server-state-kind state)
      (:read
       (cond ((/= status +im-status-success+)
              (%trace-model model "read on ~a abandoned by the peer: ~a" exchange (im-status-name status))
              (exchange-close exchange))
             ((server-state-chunks state) (%send-report-chunk exchange state :suppress-last t))
             (t (exchange-close exchange))))
      (:subscribe
       (let ((subscription (server-state-subscription state)))
         (cond ((or (/= status +im-status-success+) (null subscription))
                (%trace-model model "subscription on ~a abandoned by the peer: ~a" exchange (im-status-name status))
                (setf (server-state-subscription state) nil)
                (exchange-close exchange))
               ((server-state-chunks state)
                (%send-report-chunk exchange state :subscription-id (server-subscription-id subscription)))
               (t
                (setf (exchange-response-timeout exchange) nil)
                (%send exchange (make-subscribe-response :subscription-id (server-subscription-id subscription)
                                                         :max-interval (server-subscription-max-interval subscription)))
                (exchange-close exchange)
                (setf (server-subscription-last-report subscription) (interaction-model-now model))
                (push subscription (interaction-model-subscriptions model))
                (%trace-model model "subscribed ~a" subscription)))))
      (t (%im-fail :invalid-action "unexpected StatusResponse ~a on ~a" (im-status-name status) exchange)))))

;;; ------------------------------------------------------------------
;;; Server: reporting to subscribers

(defun %attribute-dirty (model endpoint-id cluster-id attribute-id)
  (let ((path (attribute-path endpoint-id cluster-id attribute-id))
        (any nil))
    (dolist (subscription (interaction-model-subscriptions model))
      (when (some (lambda (pattern) (attribute-path-matches-p pattern path)) (server-subscription-paths subscription))
        (pushnew path (server-subscription-dirty subscription) :test #'equalp)
        (setf any t)))
    ;; the timer sleeps until the next maximum interval: wake it for the minimum
    (when any (wake-timer (interaction-model-manager model) (interaction-model-timer model)))))

(defun %drop-server-subscription (model subscription why)
  (%trace-model model "dropped ~a: ~a" subscription why)
  (setf (interaction-model-subscriptions model) (remove subscription (interaction-model-subscriptions model)))
  (let ((exchange (server-subscription-exchange subscription)))
    (when (and exchange (not (exchange-closed-p exchange))) (exchange-abort exchange))
    (setf (server-subscription-exchange subscription) nil)))

(defun %send-subscription-report (model subscription now)
  (let* ((node (interaction-model-node model))
         (session (server-subscription-session subscription))
         (asked (server-subscription-paths subscription))
         (paths (reverse (server-subscription-dirty subscription)))
         ;; a path only a wildcard covers is left out when the peer may not read it, as at priming
         (reports (loop :for path :in paths
                        :for report := (%path-report node path :session session
                                                     :fabric-filtered (server-subscription-fabric-filtered subscription)
                                                     :expanded (not (member path asked :test #'equalp)))
                        :when report :collect report))
         (exchange (open-exchange (interaction-model-manager model) (server-subscription-session subscription)
                                  +protocol-interaction-model+
                                  :handler (lambda (exchange event &rest data)
                                             (%report-exchange-event model subscription exchange event data))
                                  :response-timeout *interaction-timeout*)))
    (setf (server-subscription-dirty subscription) '()
          (server-subscription-last-report subscription) now
          (server-subscription-exchange subscription) exchange
          (server-subscription-chunks subscription) (or (%chunk-reports reports) (list '())))
    (%trace-model model "report ~d attribute~:p to ~a" (length reports) subscription)
    (%send-next-subscription-chunk subscription exchange)))

(defun %send-next-subscription-chunk (subscription exchange)
  (let* ((chunk (pop (server-subscription-chunks subscription)))
         (more (and (server-subscription-chunks subscription) t)))
    (%send exchange (make-report-data :subscription-id (server-subscription-id subscription)
                                      :attribute-reports chunk
                                      :more-chunked-messages more))))

(defun %report-exchange-event (model subscription exchange event data)
  (case event
    (:failure
     (%drop-server-subscription model subscription (format nil "report failed: ~a" (first data))))
    (:message
     (destructuring-bind (opcode payload) data
       (let ((message (handler-case (decode-interaction-message opcode payload)
                        (interaction-error () nil))))
         (cond ((not (status-response-p message))
                (%drop-server-subscription model subscription "the subscriber answered a report with something else")
                (unless (exchange-closed-p exchange) (exchange-close exchange)))
               ((/= +im-status-success+ (status-response-status message))
                (%drop-server-subscription model subscription
                                           (format nil "the subscriber answered ~a"
                                                   (im-status-name (status-response-status message))))
                (unless (exchange-closed-p exchange) (exchange-close exchange)))
               ((server-subscription-chunks subscription)
                (%send-next-subscription-chunk subscription exchange))
               (t
                (exchange-close exchange)
                (setf (server-subscription-exchange subscription) nil))))))))

(defun %model-timer (model now)
  "Report to subscribers when due; fail our own subscriptions that fell silent."
  (let ((next nil))
    (flet ((consider (time) (when (or (null next) (< time next)) (setf next time))))
      (dolist (subscription (copy-list (interaction-model-subscriptions model)))
        (let ((session (server-subscription-session subscription)))
          (cond ((not (session-active-p session))
                 (%drop-server-subscription model subscription "session closed"))
                ((server-subscription-exchange subscription)
                 nil)                   ; a report is in flight; its exchange has the timeout
                (t
                 (let* ((last (server-subscription-last-report subscription))
                        (due (if (server-subscription-dirty subscription)
                                 (+ last (server-subscription-min-interval subscription))
                                 (+ last (server-subscription-max-interval subscription)))))
                   (if (>= now due)
                       (%send-subscription-report model subscription now)
                       (consider due)))))))
      (dolist (subscription (copy-list (interaction-model-client-subscriptions model)))
        (let ((due (+ (subscription-last-report subscription) (subscription-max-interval subscription)
                      *subscription-grace*)))
          (if (>= now due)
              (%end-subscription model subscription :timeout)
              (consider due)))))
    (or next (+ now 1.0d0))))

;;; ------------------------------------------------------------------
;;; Client: subscriptions receiving reports

(defun %end-subscription (model subscription reason)
  (when (subscription-active-p subscription)
    (setf (subscription-state subscription) :ended)
    (setf (interaction-model-client-subscriptions model)
          (remove subscription (interaction-model-client-subscriptions model)))
    (%trace-model model "~a ended: ~a" subscription reason)
    (when (subscription-on-failure subscription)
      (funcall (subscription-on-failure subscription) subscription reason))))

(defun unsubscribe (subscription)
  "Forget SUBSCRIPTION; the server learns of it when its next report is refused."
  (when (subscription-active-p subscription)
    (setf (subscription-state subscription) :ended)
    (let ((model (subscription-model subscription)))
      (setf (interaction-model-client-subscriptions model)
            (remove subscription (interaction-model-client-subscriptions model)))))
  nil)

(defun %client-report (model exchange message)
  "A ReportData on an exchange the server opened: one of our subscriptions."
  (let* ((id (report-data-subscription-id message))
         (subscription (and id (find-if (lambda (s) (and (= id (subscription-id s))
                                                        (eq (exchange-session exchange) (subscription-session s))))
                                        (interaction-model-client-subscriptions model)))))
    (cond ((null subscription)
           (%trace-model model "report for unknown subscription ~a on ~a" id exchange)
           (%send-status exchange :invalid-subscription)
           (exchange-close exchange))
          (t
           (setf (subscription-last-report subscription) (interaction-model-now model))
           (setf (subscription-chunk subscription)
                 (append (subscription-chunk subscription) (report-data-attribute-reports message)))
           (unless (report-data-suppress-response message)
             (%send-status exchange :success))
           (unless (report-data-more-chunked-messages message)
             (let ((reports (merge-chunked-reports (subscription-chunk subscription))))
               (setf (subscription-chunk subscription) '())
               (exchange-close exchange)
               (when (subscription-on-report subscription)
                 (funcall (subscription-on-report subscription) subscription reports))))))))

;;; ------------------------------------------------------------------
;;; Client: lists that arrived in pieces

(defun %same-attribute-p (a b)
  (and (eql (attribute-path-endpoint a) (attribute-path-endpoint b))
       (eql (attribute-path-cluster a) (attribute-path-cluster b))
       (eql (attribute-path-attribute a) (attribute-path-attribute b))))

(defun merge-chunked-reports (reports)
  "REPORTS with the pieces of a chunked list (8.7.3.3) folded into the
list: a data report whose path has a list index is an element -- appended
when the index is :NULL, replacing the element at the index otherwise -- of
the last report of the same attribute whose data is a whole list.  Reports
keep their order; an element without such a list stays as it came."
  (let ((merged '()))
    (dolist (report reports)
      (let* ((data (attribute-report-data report))
             (path (and data (attribute-data-path data)))
             (index (and path (attribute-path-list-index path)))
             (whole (and index
                         (find-if (lambda (r)
                                    (let ((d (attribute-report-data r)))
                                      (and d (null (attribute-path-list-index (attribute-data-path d)))
                                           (%same-attribute-p (attribute-data-path d) path)
                                           (eq :array (tlv-element-type (attribute-data-data d))))))
                                  merged))))
        (cond ((null whole) (push report merged))
              (t (let* ((list (attribute-report-data whole))
                        (items (tlv-element-value (attribute-data-data list)))
                        (item (let ((element (attribute-data-data data)))
                                (make-tlv-element nil (tlv-element-type element) (tlv-element-value element)))))
                   (setf (attribute-data-data list)
                         (make-tlv-element (tlv-element-tag (attribute-data-data list)) :array
                                           (cond ((eq index :null) (append items (list item)))
                                                 ((< -1 index (length items))
                                                  (let ((new (copy-list items))) (setf (nth index new) item) new))
                                                 (t (%im-fail :invalid-action "list index ~d of ~a is out of range (~d items)"
                                                              index path (length items)))))))))))
    (nreverse merged)))

(defun find-attribute-report (reports endpoint cluster attribute)
  "The report in REPORTS for the concrete path ENDPOINT/CLUSTER/ATTRIBUTE, or NIL."
  (find-if (lambda (report)
             (let ((path (attribute-report-path report)))
               (and (eql endpoint (attribute-path-endpoint path))
                    (eql cluster (attribute-path-cluster path))
                    (eql attribute (attribute-path-attribute path)))))
           reports))

;;; ------------------------------------------------------------------
;;; Client: interactions

(defstruct (interaction (:constructor %make-interaction))
  "One client action in progress.  STATE is :RUNNING, :COMPLETE (RESULT
holds the outcome) or :FAILED (CONDITION holds the error)."
  model kind exchange (state :running) result condition on-complete
  (reports '()) (timed nil) (request nil) (subscription nil))

(defmethod print-object ((i interaction) stream)
  (print-unreadable-object (i stream :type t)
    (format stream "~a ~a" (interaction-kind i) (interaction-state i))))

(defun interaction-running-p (interaction) (eq :running (interaction-state interaction)))
(defun interaction-complete-p (interaction) (eq :complete (interaction-state interaction)))
(defun interaction-failed-p (interaction) (eq :failed (interaction-state interaction)))

(defun %interaction-done (interaction state)
  (setf (interaction-state interaction) state)
  (let ((exchange (interaction-exchange interaction)))
    (when (and exchange (exchange-open-p exchange)) (exchange-close exchange)))
  (when (interaction-on-complete interaction)
    (funcall (interaction-on-complete interaction) interaction)))

(defun %interaction-complete (interaction result)
  (setf (interaction-result interaction) result)
  (%interaction-done interaction :complete))

(defun %interaction-fail (interaction error)
  (setf (interaction-condition interaction) error)
  (%trace-model (interaction-model interaction) "~a failed: ~a" interaction error)
  (%interaction-done interaction :failed))

(defun %client-event (interaction exchange event data)
  (when (interaction-running-p interaction)
    (case event
      (:failure
       (%interaction-fail interaction (make-condition 'interaction-error :status +im-status-timeout+
                                                      :message (format nil "exchange failed: ~a" (first data)))))
      (:message
       (destructuring-bind (opcode payload) data
         (handler-case (%client-message interaction exchange opcode payload)
           (interaction-error (e)
             (when (exchange-open-p exchange)
               (%send-status exchange (interaction-error-status e)))
             (%interaction-fail interaction e))))))))

(defun %expect (interaction message type)
  (cond ((typep message type) message)
        ((status-response-p message)
         (%im-fail (status-response-status message) "the server answered ~a with ~a"
                   (interaction-kind interaction) (im-status-name (status-response-status message))))
        (t (%im-fail :invalid-action "the server answered ~a with ~a"
                     (interaction-kind interaction) (type-of message)))))

(defun %client-message (interaction exchange opcode payload)
  (let ((message (decode-interaction-message opcode payload)))
    (when (interaction-timed interaction)
      ;; the StatusResponse to our TimedRequest: now the real request
      (%expect interaction message 'status-response)
      (unless (= +im-status-success+ (status-response-status message))
        (%im-fail (status-response-status message) "the timed request was refused"))
      (setf (interaction-timed interaction) nil)
      (%send exchange (interaction-request interaction))
      (return-from %client-message))
    (ecase (interaction-kind interaction)
      (:read
       (%expect interaction message 'report-data)
       (setf (interaction-reports interaction)
             (append (interaction-reports interaction) (report-data-attribute-reports message)))
       (cond ((report-data-more-chunked-messages message)
              (%send-status exchange :success))
             (t
              (unless (report-data-suppress-response message) (%send-status exchange :success))
              (%interaction-complete interaction (merge-chunked-reports (interaction-reports interaction))))))
      (:write
       (%expect interaction message 'write-response)
       (%interaction-complete interaction (write-response-write-responses message)))
      (:invoke
       (%expect interaction message 'invoke-response-message)
       (setf (interaction-reports interaction)
             (append (interaction-reports interaction) (invoke-response-message-invoke-responses message)))
       (cond ((invoke-response-message-more-chunked-messages message)
              (%send-status exchange :success))
             (t (%interaction-complete interaction (interaction-reports interaction)))))
      (:subscribe
       (let ((subscription (interaction-subscription interaction)))
         (cond ((report-data-p message)
                (unless (report-data-subscription-id message)
                  (%im-fail :invalid-action "a priming report without a subscription id"))
                (setf (subscription-id subscription) (report-data-subscription-id message))
                (setf (interaction-reports interaction)
                      (append (interaction-reports interaction) (report-data-attribute-reports message)))
                (%send-status exchange :success))
               (t
                (%expect interaction message 'subscribe-response)
                (unless (= (subscribe-response-subscription-id message) (subscription-id subscription))
                  (%im-fail :invalid-action "SubscribeResponse names subscription ~d, the reports ~d"
                            (subscribe-response-subscription-id message) (subscription-id subscription)))
                (setf (subscription-max-interval subscription) (subscribe-response-max-interval message)
                      (subscription-primed-reports subscription) (merge-chunked-reports (interaction-reports interaction))
                      (subscription-last-report subscription) (interaction-model-now (interaction-model interaction)))
                (push subscription (interaction-model-client-subscriptions (interaction-model interaction)))
                (%interaction-complete interaction subscription))))))))

(defun %start-interaction (model session kind request &key on-complete timed subscription)
  (let* ((interaction (%make-interaction :model model :kind kind :on-complete on-complete
                                         :request request :timed (and timed t) :subscription subscription))
         (exchange (open-exchange (interaction-model-manager model) session +protocol-interaction-model+
                                  :handler (lambda (exchange event &rest data)
                                             (%client-event interaction exchange event data))
                                  :response-timeout *interaction-timeout*)))
    (setf (interaction-exchange interaction) exchange)
    (if timed
        (%send exchange (make-timed-request :timeout (round (* 1000 timed))))
        (%send exchange request))
    interaction))

(defun start-read (model session paths &key fabric-filtered data-version-filters on-complete)
  "Read the attribute PATHS of the peer of SESSION.  The result is the
list of ATTRIBUTE-REPORTs."
  (%start-interaction model session :read
                      (make-read-request :attribute-requests paths :fabric-filtered fabric-filtered
                                         :data-version-filters data-version-filters)
                      :on-complete on-complete))

(defun start-write (model session writes &key timed on-complete)
  "Write WRITES, a list of ATTRIBUTE-DATA, to the peer of SESSION; TIMED
seconds makes it a timed interaction.  The result is the list of
ATTRIBUTE-STATUSes."
  (%start-interaction model session :write
                      (make-write-request :write-requests writes :timed-request (and timed t))
                      :timed timed :on-complete on-complete))

(defun start-invoke (model session path fields &key timed on-complete)
  "Invoke the command at PATH with FIELDS (a TLV structure element or NIL)
on the peer of SESSION.  The result is the list of INVOKE-RESPONSEs."
  (%start-interaction model session :invoke
                      (make-invoke-request :invoke-requests (list (make-command-data :path path :fields fields))
                                           :timed-request (and timed t))
                      :timed timed :on-complete on-complete))

(defun start-subscribe (model session paths &key (min-interval 0) (max-interval 60) on-report on-failure
                                               fabric-filtered data-version-filters keep-subscriptions on-complete)
  "Subscribe to the attribute PATHS of the peer of SESSION, reporting at
least every MAX-INTERVAL and at most every MIN-INTERVAL seconds.  The
result is the SUBSCRIPTION; its priming reports are in
SUBSCRIPTION-PRIMED-REPORTS, later ones go to ON-REPORT."
  (%start-interaction model session :subscribe
                      (make-subscribe-request :keep-subscriptions keep-subscriptions
                                              :min-interval-floor min-interval
                                              :max-interval-ceiling max-interval
                                              :attribute-requests paths
                                              :fabric-filtered fabric-filtered
                                              :data-version-filters data-version-filters)
                      :on-complete on-complete
                      :subscription (%make-subscription :model model :session session :paths paths
                                                        :min-interval min-interval :max-interval max-interval
                                                        :on-report on-report :on-failure on-failure)))

(defun interaction-abort (interaction)
  "Give up on INTERACTION; no completion is delivered."
  (when (interaction-running-p interaction)
    (setf (interaction-state interaction) :failed
          (interaction-condition interaction) (make-condition 'interaction-error :status +im-status-timeout+
                                                                                 :message "aborted"))
    (let ((exchange (interaction-exchange interaction)))
      (when (and exchange (not (exchange-closed-p exchange))) (exchange-abort exchange))))
  interaction)

(defun interaction-wait (interaction &key (timeout *interaction-timeout*))
  "Run the manager until INTERACTION is done; its result, or the error signalled."
  (let ((model (interaction-model interaction)))
    (exchange-manager-run (interaction-model-manager model)
                          :until (lambda () (not (interaction-running-p interaction)))
                          :timeout timeout)
    (when (interaction-running-p interaction)
      (interaction-abort interaction)
      (error 'interaction-error :status +im-status-timeout+
                                :message (format nil "~a got no answer in ~a seconds" interaction timeout)))
    (if (interaction-failed-p interaction)
        (error (interaction-condition interaction))
        (interaction-result interaction))))

(defun read-attributes (model session paths &rest args &key (timeout *interaction-timeout*) &allow-other-keys)
  "START-READ and wait: the list of ATTRIBUTE-REPORTs."
  (interaction-wait (apply #'start-read model session paths :allow-other-keys t args) :timeout timeout))

(defun write-attributes (model session writes &rest args &key (timeout *interaction-timeout*) &allow-other-keys)
  "START-WRITE and wait: the list of ATTRIBUTE-STATUSes."
  (interaction-wait (apply #'start-write model session writes :allow-other-keys t args) :timeout timeout))

(defun invoke-command (model session path fields &rest args &key (timeout *interaction-timeout*) &allow-other-keys)
  "START-INVOKE and wait: the list of INVOKE-RESPONSEs."
  (interaction-wait (apply #'start-invoke model session path fields :allow-other-keys t args) :timeout timeout))

(defun subscribe-attributes (model session paths &rest args &key (timeout *interaction-timeout*) &allow-other-keys)
  "START-SUBSCRIBE and wait: the SUBSCRIPTION."
  (interaction-wait (apply #'start-subscribe model session paths :allow-other-keys t args) :timeout timeout))

;;; ------------------------------------------------------------------
;;; Client conveniences over the cluster definitions

(defun %attribute-type (cluster-id attribute-id)
  "The type of a known attribute, or NIL."
  (let ((definition (find-cluster-definition cluster-id nil)))
    (when definition
      (let ((attribute (or (find-attribute-definition definition attribute-id)
                           (find attribute-id *global-attribute-definitions* :key #'attribute-definition-id))))
        (and attribute (attribute-definition-type attribute))))))

(defun attribute-report-value (report)
  "The Lisp value of a data REPORT when its cluster and attribute are
defined here (second value T), else the TLV element; a status report
gives its IM-STATUS and :STATUS.  A report of one list element (a path
with a list index, see MERGE-CHUNKED-REPORTS) gives the element's value."
  (let ((data (attribute-report-data report)))
    (if (null data)
        (values (attribute-status-status (attribute-report-status report)) :status)
        (let* ((path (attribute-data-path data))
               (type (%attribute-type (attribute-path-cluster path) (attribute-path-attribute path))))
          (when (and type (attribute-path-list-index path))
            (let ((resolved (resolve-type type)))
              (setf type (and (eq :list (%type-kind resolved)) (second resolved)))))
          (if type
              (values (tlv-value type (attribute-data-data data)) t)
              (values (attribute-data-data data) nil))))))

(defun attribute-write (endpoint cluster attribute value &key data-version)
  "An ATTRIBUTE-DATA for WRITE-ATTRIBUTES: VALUE of a defined attribute
as a Lisp value, or a TLV element."
  (let ((type (and (not (tlv-element-p value)) (%attribute-type cluster attribute))))
    (unless (or type (tlv-element-p value))
      (error "attribute #x~4,'0x/#x~4,'0x is not defined here; pass a TLV element" cluster attribute))
    (make-attribute-data :path (attribute-path endpoint cluster attribute)
                         :data-version data-version
                         :data (if type (value-tlv type nil value) value))))

(defun command-fields (cluster command plist)
  "PLIST as the TLV field structure of a defined command (NIL for none)."
  (let* ((definition (find-cluster-definition cluster))
         (command (or (find-command-definition definition command)
                      (error "~a has no command ~s" definition command))))
    (when (command-definition-fields command)
      (value-tlv (cons :struct (command-definition-fields command)) nil plist))))

(defun invoke-response-value (response)
  "A response command's fields as a plist when the command is defined here
(second value T), else its TLV element; a status gives its IM-STATUS and :STATUS."
  (let ((command (invoke-response-command response)))
    (if (null command)
        (values (command-status-status (invoke-response-status response)) :status)
        (let* ((path (command-data-path command))
               (definition (find-cluster-definition (command-path-cluster path) nil))
               (response-command (and definition (find-command-definition definition (command-path-command path)))))
          (if response-command
              (values (tlv-value (cons :struct (command-definition-fields response-command))
                                 (or (command-data-fields command) (tlv nil :structure nil)))
                      t)
              (values (command-data-fields command) nil))))))
