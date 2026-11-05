(defpackage :cl-matter.dns-sd
  (:use :cl)
  (:nicknames :dns-sd)
  (:documentation "mDNS (RFC 6762) and DNS-SD (RFC 6763) in pure Common Lisp
over CL-MATTER.NET: the DNS message codec, a resolver and service browser,
and a responder that advertises this host's services.")
  (:export
   ;; constants
   #:+mdns-port+
   #:+mdns-ipv4-group+
   #:+mdns-ipv6-group+
   ;; message codec (message.lisp)
   #:+type-a+
   #:+type-cname+
   #:+type-ptr+
   #:+type-txt+
   #:+type-aaaa+
   #:+type-srv+
   #:+type-nsec+
   #:+type-any+
   #:+class-in+
   #:+flag-response+
   #:+flag-authoritative+
   #:+flag-truncated+
   #:+flag-rcode-mask+
   #:dns-message
   #:make-dns-message
   #:dns-message-id
   #:dns-message-flags
   #:dns-message-questions
   #:dns-message-answers
   #:dns-message-authorities
   #:dns-message-additionals
   #:dns-message-response-p
   #:dns-message-truncated-p
   #:dns-question
   #:make-dns-question
   #:dns-question-name
   #:dns-question-type
   #:dns-question-class
   #:dns-question-unicast-response-p
   #:dns-record
   #:make-dns-record
   #:dns-record-name
   #:dns-record-type
   #:dns-record-class
   #:dns-record-cache-flush-p
   #:dns-record-ttl
   #:dns-record-data
   #:encode-message
   #:decode-message
   #:dns-decode-error
   #:dns-decode-error-message
   #:dns-decode-error-offset
   #:dns-encode-error
   #:dns-encode-error-message
   ;; mDNS (mdns.lisp)
   #:mdns-socket
   #:mdns-socket-p
   #:mdns-socket-multicast-p
   #:mdns-socket-socket
   #:mdns-socket-group
   #:mdns-socket-port
   #:open-mdns-socket
   #:close-mdns-socket
   #:with-mdns-socket
   #:query
   #:browse
   #:resolve
   #:parse-txt-record
   #:txt-value
   ;; responder (responder.lisp)
   #:service
   #:make-service
   #:service-p
   #:service-instance
   #:service-type
   #:service-port
   #:service-txt
   #:service-subtypes
   #:service-priority
   #:service-weight
   #:service-domain
   #:service-type-name
   #:service-instance-name
   #:responder
   #:responder-services
   #:responder-host
   #:responder-addresses
   #:responder-records
   #:responder-socket
   #:responder-running-p
   #:responder-thread
   #:responder-last-error
   #:responder-response
   #:responder-poll
   #:start-responder
   #:stop-responder
   #:responder-set-services))
