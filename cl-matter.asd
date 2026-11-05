;;;; cl-matter.asd -- Matter (CSA) over IPv6 for Common Lisp, with the
;;;; mDNS / DNS-SD discovery layer it is built on.
;;;;
;;;; Systems
;;;;   cl-matter/net     datagram socket backend protocol, one backend per
;;;;                     implementation (AmiLisp on EXT, SBCL on sb-bsd-sockets)
;;;;   cl-matter/dns-sd  DNS message codec, mDNS resolver/browser/responder
;;;;   cl-matter         Matter core: TLV, sessions, interaction model
;;;;   cl-matter/tests   fiveam suite over all of the above

(defsystem "cl-matter/net"
  :version "0.1.0"
  :author "Manfred Bergmann"
  :license "Apache-2"
  :description "Unconnected UDP sockets, multicast and interface enumeration behind one protocol, one backend per Lisp implementation."
  :depends-on ("alexandria"
               #+sbcl "sb-bsd-sockets")
  :components ((:module "src/net"
                :serial t
                :components
                ((:file "package")
                 (:file "protocol")
                 #+amilisp (:file "backend-amilisp")
                 #+sbcl (:file "backend-sbcl")
                 #-(or amilisp sbcl) (:file "backend-unsupported")))))

(defsystem "cl-matter/dns-sd"
  :version "0.1.0"
  :author "Manfred Bergmann"
  :license "Apache-2"
  :description "mDNS (RFC 6762) and DNS-SD (RFC 6763): resolver, browser and responder in pure Common Lisp."
  :depends-on ("alexandria"
               "bordeaux-threads"
               "cl-matter/net")
  :components ((:module "src/dns-sd"
                :serial t
                :components
                ((:file "package")
                 (:file "message")
                 (:file "mdns")
                 (:file "responder")))))

(defsystem "cl-matter"
  :version "0.1.0"
  :author "Manfred Bergmann"
  :license "Apache-2"
  :description "Matter (CSA) protocol for Common Lisp: TLV, secure sessions and the interaction model over IPv6, discovery via mDNS/DNS-SD."
  :depends-on ("alexandria"
               "ironclad"
               "cl-matter/net"
               "cl-matter/dns-sd")
  :components ((:module "src/matter"
                :serial t
                :components
                ((:file "package")
                 (:file "tlv")
                 (:file "message")
                 (:file "crypto")
                 (:file "p256")
                 (:file "spake2p")
                 (:file "pase")
                 (:file "asn1")
                 (:file "der")
                 (:file "certificate")
                 (:file "fabric")
                 (:file "attestation")
                 (:file "case")
                 (:file "session")
                 (:file "exchange")
                 (:file "secure-channel")
                 (:file "interaction-codec")
                 (:file "data-model")
                 (:file "clusters")
                 (:file "access")
                 (:file "interaction")
                 (:file "commissioning")
                 (:file "persistence")
                 (:file "discovery"))))
  :in-order-to ((test-op (test-op "cl-matter/tests"))))

(defsystem "cl-matter/tests"
  :author "Manfred Bergmann"
  :depends-on ("cl-matter"
               "fiveam")
  :components ((:module "test"
                :serial t
                :components
                ((:file "test-all")
                 (:file "net-test")
                 (:file "dns-sd-test")
                 (:file "tlv-test")
                 (:file "message-test")
                 (:file "crypto-test")
                 (:file "spake2p-test")
                 (:file "pase-test")
                 (:file "sdk-certificates")
                 (:file "certificate-test")
                 (:file "case-test")
                 (:file "exchange-test")
                 (:file "data-model-test")
                 (:file "interaction-test")
                 (:file "access-test")
                 (:file "sdk-attestation")
                 (:file "attestation-test")
                 (:file "commissioning-test")
                 (:file "persistence-test")
                 (:file "discovery-test"))))
  :description "Test system for cl-matter"
  :perform (test-op (op c) (symbol-call :fiveam :run!
                                        (find-symbol "TEST-SUITE" "CL-MATTER.TESTS"))))
