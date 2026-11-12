(defpackage :cl-matter
  (:use :cl)
  (:documentation "Matter protocol core.  First the TLV codec (Matter Core
Specification, Appendix A), then message framing and the secure session
layer (PASE/CASE), then the interaction model.  Operational discovery uses
CL-MATTER.DNS-SD.  Matter runs over IPv6 only, so controller and device
roles are host-side; AmigaOS stacks are IPv4 and get the discovery layer.")
  (:export
   ;; TLV (tlv.lisp)
   #:tlv-element
   #:tlv-element-p
   #:make-tlv-element
   #:tlv-element-tag
   #:tlv-element-type
   #:tlv-element-value
   #:tlv
   #:tlv-structure
   #:tlv-array
   #:tlv-list
   #:tlv-container-p
   #:tlv-ref
   #:tlv-get
   #:tlv-encode
   #:tlv-decode
   #:tlv-error
   #:tlv-error-message
   #:tlv-encode-error
   #:tlv-decode-error
   #:tlv-decode-error-offset
   #:*tlv-max-depth*
   ;; message framing (message.lisp)
   #:message-error
   #:message-error-message
   #:message-encode-error
   #:message-decode-error
   #:message-decode-error-offset
   #:+protocol-secure-channel+
   #:+protocol-interaction-model+
   #:+protocol-bdx+
   #:+protocol-user-directed-commissioning+
   #:+opcode-msg-counter-sync-req+
   #:+opcode-msg-counter-sync-rsp+
   #:+opcode-standalone-ack+
   #:+opcode-pbkdf-param-request+
   #:+opcode-pbkdf-param-response+
   #:+opcode-pase-pake1+
   #:+opcode-pase-pake2+
   #:+opcode-pase-pake3+
   #:+opcode-case-sigma1+
   #:+opcode-case-sigma2+
   #:+opcode-case-sigma3+
   #:+opcode-case-sigma2-resume+
   #:+opcode-status-report+
   #:+opcode-im-status-response+
   #:+opcode-im-read-request+
   #:+opcode-im-subscribe-request+
   #:+opcode-im-subscribe-response+
   #:+opcode-im-report-data+
   #:+opcode-im-write-request+
   #:+opcode-im-write-response+
   #:+opcode-im-invoke-request+
   #:+opcode-im-invoke-response+
   #:+opcode-im-timed-request+
   #:+status-success+
   #:+status-failure+
   #:+status-bad-precondition+
   #:+status-out-of-range+
   #:+status-bad-request+
   #:+status-unsupported+
   #:+status-unexpected+
   #:+status-resource-exhausted+
   #:+status-busy+
   #:+status-timeout+
   #:+status-continue+
   #:+status-aborted+
   #:+status-invalid-argument+
   #:+status-not-found+
   #:+status-already-exists+
   #:+status-permission-denied+
   #:+status-data-loss+
   #:+mic-length+
   #:+unsecured-session-id+
   #:message-header
   #:make-message-header
   #:message-header-p
   #:message-header-session-id
   #:message-header-session-type
   #:message-header-privacy-p
   #:message-header-control-p
   #:message-header-message-counter
   #:message-header-source-node-id
   #:message-header-destination-node-id
   #:message-header-destination-group-id
   #:message-header-extensions
   #:protocol-header
   #:make-protocol-header
   #:protocol-header-p
   #:protocol-header-initiator-p
   #:protocol-header-reliability-p
   #:protocol-header-ack-counter
   #:protocol-header-vendor-id
   #:protocol-header-protocol-id
   #:protocol-header-opcode
   #:protocol-header-exchange-id
   #:protocol-header-secured-extensions
   #:protocol-header-payload
   #:protocol-header-secure-channel-p
   #:message-header-security-flags
   #:encode-message-header
   #:decode-message-header
   #:encode-protocol-header
   #:decode-protocol-header
   #:encode-unsecured-message
   #:decode-unsecured-message
   #:status-report
   #:make-status-report
   #:status-report-general-code
   #:status-report-protocol-id
   #:status-report-protocol-code
   #:status-report-data
   #:encode-status-report
   #:decode-status-report
   #:+counter-window-size+
   #:random-message-counter
   #:message-counter
   #:make-message-counter
   #:message-counter-value
   #:next-message-counter
   #:counter-window
   #:make-counter-window
   #:counter-window-newest
   #:counter-window-accept
   #:*mrp-max-transmissions*
   #:*mrp-standalone-ack-timeout*
   #:*mrp-default-idle-interval*
   #:*mrp-default-active-interval*
   #:*mrp-default-active-threshold*
   #:mrp-backoff
   #:pending-message
   #:pending-message-counter
   #:pending-message-octets
   #:pending-message-transmissions
   #:pending-message-next-at
   #:pending-message-context
   #:retransmission-table
   #:make-retransmission-table
   #:retransmission-table-pending
   #:retransmission-table-idle-interval
   #:retransmission-table-active-interval
   #:mrp-track
   #:mrp-acknowledge
   #:mrp-due
   #:mrp-next-deadline
   ;; crypto (crypto.lisp)
   #:crypto-error
   #:crypto-error-message
   #:aead-authentication-error
   #:sha256
   #:hmac-sha256
   #:pbkdf2-sha256
   #:hkdf-sha256
   #:random-octets
   #:aes-ccm-encrypt
   #:aes-ccm-decrypt
   #:message-nonce
   #:message-header-nonce
   #:encode-secured-message
   #:decode-secured-message
   ;; SPAKE2+ (spake2p.lisp)
   #:spake2p-error
   #:spake2p-confirmation-error
   #:+p256-point-length+
   #:+spake2p-verifier-length+
   #:*spake2p-m*
   #:*spake2p-n*
   #:random-p256-scalar
   #:passcode-octets
   #:spake2p-w0w1
   #:spake2p-l
   #:spake2p-verifier
   #:spake2p-verifier-parts
   #:spake2p
   #:spake2p-p
   #:spake2p-role
   #:spake2p-state
   #:spake2p-start
   #:spake2p-share
   #:spake2p-peer-share
   #:spake2p-derive
   #:spake2p-confirm
   #:spake2p-shared-key
   #:spake2p-z
   #:spake2p-v
   #:spake2p-transcript
   #:spake2p-ka
   #:spake2p-ke
   #:spake2p-kca
   #:spake2p-kcb
   #:spake2p-confirmation
   #:spake2p-expected-confirmation
   ;; PASE (pase.lisp)
   #:pase-error
   #:pase-error-message
   #:pase-error-protocol-code
   #:pase-peer-failure
   #:pase-peer-failure-report
   #:+pase-passcode-id+
   #:+pase-min-salt-length+
   #:+pase-max-salt-length+
   #:+pase-min-iterations+
   #:+pase-max-iterations+
   #:+secure-channel-status-session-establishment-success+
   #:+secure-channel-status-no-shared-trust-roots+
   #:+secure-channel-status-invalid-parameter+
   #:+secure-channel-status-close-session+
   #:+secure-channel-status-busy+
   #:+secure-channel-status-session-not-found+
   #:pase-status-report
   #:valid-passcode-p
   #:session-parameters
   #:make-session-parameters
   #:session-parameters-p
   #:session-parameters-idle-interval
   #:session-parameters-active-interval
   #:session-parameters-active-threshold
   #:session-parameters-data-model-revision
   #:session-parameters-interaction-model-revision
   #:session-parameters-specification-version
   #:session-parameters-max-paths-per-invoke
   #:session-parameters-supported-transports
   #:session-parameters-max-tcp-payload-size
   #:default-session-parameters
   #:session-parameters-tlv
   #:tlv-session-parameters
   #:pbkdf-param-request
   #:make-pbkdf-param-request
   #:pbkdf-param-request-initiator-random
   #:pbkdf-param-request-initiator-session-id
   #:pbkdf-param-request-passcode-id
   #:pbkdf-param-request-has-pbkdf-parameters-p
   #:pbkdf-param-request-session-parameters
   #:encode-pbkdf-param-request
   #:decode-pbkdf-param-request
   #:pbkdf-param-response
   #:make-pbkdf-param-response
   #:pbkdf-param-response-initiator-random
   #:pbkdf-param-response-responder-random
   #:pbkdf-param-response-responder-session-id
   #:pbkdf-param-response-iterations
   #:pbkdf-param-response-salt
   #:pbkdf-param-response-session-parameters
   #:encode-pbkdf-param-response
   #:decode-pbkdf-param-response
   #:pake1
   #:make-pake1
   #:pake1-pa
   #:encode-pake1
   #:decode-pake1
   #:pake2
   #:make-pake2
   #:pake2-pb
   #:pake2-cb
   #:encode-pake2
   #:decode-pake2
   #:pake3
   #:make-pake3
   #:pake3-ca
   #:encode-pake3
   #:decode-pake3
   #:session-keys
   #:session-keys-p
   #:session-keys-i2r
   #:session-keys-r2i
   #:session-keys-attestation-challenge
   #:derive-session-keys
   #:pase
   #:pase-p
   #:pase-role
   #:pase-state
   #:pase-local-session-id
   #:pase-peer-session-id
   #:pase-local-session-parameters
   #:pase-peer-session-parameters
   #:pase-salt
   #:pase-iterations
   #:pase-initiator-random
   #:pase-responder-random
   #:pase-spake2p
   #:pase-session-keys
   #:make-pase-initiator
   #:make-pase-responder
   #:pase-complete-p
   #:pase-start
   #:pase-handle
   ;; P-256 (p256.lisp)
   #:p256-error
   #:+p256-scalar-length+
   #:+p256-signature-length+
   #:+p256-shared-secret-length+
   #:*p256-order*
   #:p256-decode-point
   #:p256-encode-point
   #:p256-point-p
   #:p256-keypair
   #:p256-keypair-p
   #:p256-keypair-private
   #:p256-keypair-public
   #:p256-public-key
   #:make-p256-keypair
   #:generate-p256-keypair
   #:p256-keypair-octets
   #:p256-keypair-from-octets
   #:p256-ecdh
   #:p256-sign-digest
   #:p256-sign
   #:p256-verify-digest
   #:p256-verify
   ;; DER (asn1.lisp)
   #:der
   #:der-sequence
   #:der-set
   #:der-integer
   #:der-integer-octets
   #:der-unsigned-octets
   #:der-boolean
   #:der-null
   #:der-octet-string
   #:der-bit-string
   #:der-bit-string-flags
   #:der-oid
   #:der-utf8-string
   #:der-printable-string
   #:der-ia5-string
   #:der-utc-time
   #:der-generalized-time
   #:der-context
   ;; DER decoding, base64, PEM (der.lisp)
   #:der-error #:der-error-message #:der-node #:der-node-p #:der-node-tag #:der-node-octets
   #:der-node-start #:der-node-content-start #:der-node-end #:der-node-children #:der-node-constructed-p
   #:der-node-class #:der-node-number #:der-node-content #:der-node-whole #:der-node-length
   #:der-decode #:*der-max-depth* #:der-context-tag #:der-expect #:der-children #:der-child #:der-optional-child
   #:der-node-integer #:der-node-unsigned-octets #:der-node-boolean #:der-node-oid #:der-node-string
   #:der-node-bit-string #:der-node-bit-string-flags #:der-node-octet-string #:der-node-time
   #:+der-boolean+ #:+der-integer+ #:+der-bit-string+ #:+der-octet-string+ #:+der-null+ #:+der-oid+
   #:+der-utf8-string+ #:+der-printable-string+ #:+der-ia5-string+ #:+der-utc-time+ #:+der-generalized-time+
   #:+der-sequence+ #:+der-set+
   #:base64-encode #:base64-decode #:pem-encode #:pem-decode #:pem-block #:read-pem-file
   ;; certificates (certificate.lisp)
   #:certificate-error
   #:certificate-error-message
   #:+key-identifier-length+
   #:*dn-attribute-types*
   #:*key-usage-bits*
   #:*key-purposes*
   #:operational-node-id-p
   #:fabric-id-p
   #:case-auth-tag-p
   #:matter-time
   #:matter-time-universal
   #:dn-attribute
   #:dn-attributes
   #:dn-equal
   #:certificate
   #:make-certificate
   #:certificate-p
   #:certificate-serial-number
   #:certificate-signature-algorithm
   #:certificate-issuer
   #:certificate-not-before
   #:certificate-not-after
   #:certificate-subject
   #:certificate-public-key-algorithm
   #:certificate-curve
   #:certificate-public-key
   #:certificate-extensions
   #:certificate-signature
   #:certificate-octets
   #:certificate-octets*
   #:certificate-extension
   #:certificate-ca-p
   #:certificate-path-length
   #:certificate-key-usage
   #:certificate-extended-key-usage
   #:certificate-subject-key-id
   #:certificate-authority-key-id
   #:certificate-node-id
   #:certificate-fabric-id
   #:certificate-case-auth-tags
   #:certificate-type
   #:certificate-valid-at-p
   #:encode-certificate
   #:decode-certificate
   #:certificate-tbs-der
   #:certificate-der
   #:ecdsa-signature-der
   #:certificate-tbs-digest
   #:verify-certificate-signature
   #:sign-certificate
   #:subject-key-identifier
   #:validate-rcac
   #:validate-certificate-chain
   #:make-root-certificate
   #:make-ica-certificate
   #:make-node-certificate
   #:decode-certificate-der #:decode-certificate-pem #:certificate-from-octets
   #:ecdsa-signature-from-der #:certificate-vendor-id #:certificate-product-id
   #:decode-ec-private-key #:decode-ec-private-key-pem #:encode-ec-private-key
   ;; fabrics (fabric.lisp)
   #:+compressed-fabric-id-length+
   #:+epoch-key-length+
   #:+ipk-length+
   #:compressed-fabric-id
   #:operational-group-key
   #:group-session-id
   #:case-destination-id
   #:fabric
   #:fabric-p
   #:fabric-rcac
   #:fabric-icac
   #:fabric-noc
   #:fabric-operational-keypair
   #:fabric-node-id
   #:fabric-fabric-id
   #:fabric-case-auth-tags
   #:fabric-root-public-key
   #:fabric-compressed-fabric-id
   #:fabric-epoch-key
   #:fabric-ipk
   #:fabric-vendor-id
   #:fabric-label
   #:make-fabric
   #:fabric-operational-instance-name
   #:fabric-destination-id
   #:make-test-fabric
   #:fabric-add-node #:fabric-index
   ;; device attestation and the CSR (attestation.lisp)
   #:attestation-error #:attestation-error-reason #:attestation-error-message
   #:+attestation-nonce-length+ #:+attestation-elements-max-length+ #:+certificate-chain-dac+ #:+certificate-chain-pai+
   #:encode-attestation-elements #:decode-attestation-elements #:encode-nocsr-elements #:decode-nocsr-elements
   #:attestation-tbs #:sign-attestation #:verify-attestation-signature
   #:*csr-default-subject* #:make-certificate-signing-request #:decode-certificate-signing-request
   #:*cd-signing-keys* #:add-cd-signing-key
   #:encode-certification-declaration-tlv #:decode-certification-declaration-tlv
   #:encode-certification-declaration #:decode-certification-declaration
   #:*paa-trust-store* #:add-trusted-paa #:find-trusted-paa #:validate-paa #:validate-attestation-chain
   #:verify-device-attestation #:verify-nocsr
   #:attestation-credentials #:attestation-credentials-p #:make-attestation-credentials
   #:attestation-credentials-dac #:attestation-credentials-pai #:attestation-credentials-keypair
   #:attestation-credentials-certification-declaration #:attestation-credentials-firmware-info
   #:attestation-credentials-vendor-id #:attestation-credentials-product-id
   #:*test-dac-pem* #:*test-dac-key-pem* #:*test-pai-pem* #:*test-paa-pems* #:*test-certification-declaration*
   #:test-attestation-credentials
   ;; CASE (case.lisp)
   #:case-error
   #:case-error-message
   #:case-error-protocol-code
   #:case-peer-failure
   #:case-peer-failure-report
   #:+case-random-length+
   #:+case-resumption-id-length+
   #:case-status-report
   #:sigma1
   #:make-sigma1
   #:sigma1-initiator-random
   #:sigma1-initiator-session-id
   #:sigma1-destination-id
   #:sigma1-initiator-eph-pub-key
   #:sigma1-session-parameters
   #:sigma1-resumption-id
   #:sigma1-resume-mic
   #:encode-sigma1
   #:decode-sigma1
   #:sigma2
   #:make-sigma2
   #:sigma2-responder-random
   #:sigma2-responder-session-id
   #:sigma2-responder-eph-pub-key
   #:sigma2-encrypted
   #:sigma2-session-parameters
   #:encode-sigma2
   #:decode-sigma2
   #:sigma2-resume
   #:make-sigma2-resume
   #:sigma2-resume-resumption-id
   #:sigma2-resume-resume-mic
   #:sigma2-resume-responder-session-id
   #:sigma2-resume-session-parameters
   #:encode-sigma2-resume
   #:decode-sigma2-resume
   #:sigma3
   #:make-sigma3
   #:sigma3-encrypted
   #:encode-sigma3
   #:decode-sigma3
   #:sigma-tbe
   #:make-sigma-tbe
   #:sigma-tbe-noc
   #:sigma-tbe-icac
   #:sigma-tbe-signature
   #:sigma-tbe-resumption-id
   #:encode-sigma-tbs
   #:encode-sigma-tbe
   #:decode-sigma-tbe
   #:sigma2-key
   #:sigma3-key
   #:derive-case-session-keys
   #:derive-case-resumed-session-keys
   #:sigma-resume-mic
   #:case-resumption
   #:make-case-resumption
   #:case-resumption-p
   #:case-resumption-resumption-id
   #:case-resumption-shared-secret
   #:case-resumption-fabric
   #:case-resumption-peer-node-id
   #:case-resumption-peer-case-auth-tags
   #:case-session
   #:case-session-p
   #:case-role
   #:case-state
   #:case-fabric
   #:case-local-session-id
   #:case-peer-session-id
   #:case-local-session-parameters
   #:case-peer-session-parameters
   #:case-peer-node-id
   #:case-peer-case-auth-tags
   #:case-shared-secret
   #:case-resumed-p
   #:case-session-keys
   #:make-case-initiator
   #:make-case-responder
   #:case-complete-p
   #:case-resumption-state
   #:case-start
   #:case-handle
   ;; sessions (session.lisp)
   #:session-error
   #:session-error-message
   #:+max-message-size+
   #:session
   #:session-p
   #:session-type
   #:session-role
   #:session-local-session-id
   #:session-peer-session-id
   #:session-local-node-id
   #:session-peer-node-id
   #:session-fabric
   #:session-peer-case-auth-tags
   #:session-keys
   #:session-encrypt-key
   #:session-decrypt-key
   #:session-peer-host
   #:session-peer-port
   #:session-message-counter
   #:session-counter-window
   #:session-local-session-parameters
   #:session-peer-session-parameters
   #:session-peer-parameters
   #:session-retransmissions
   #:session-last-received
   #:session-resumption
   #:session-state
   #:session-secured-p
   #:session-active-p
   #:session-idle-interval
   #:session-active-interval
   #:session-active-threshold
   #:session-peer-active-p
   #:make-unsecured-session
   #:make-secured-session
   #:session-attestation-challenge
   #:session-encode
   #:session-decode
   #:session-accept-counter
   #:session-note-received
   #:session-manager
   #:session-manager-p
   #:make-session-manager
   #:session-manager-sessions
   #:session-manager-unsecured
   #:session-manager-unsecured-counter
   #:session-manager-session-parameters
   #:find-session
   #:allocate-session-id
   #:release-session-id
   #:add-session
   #:remove-session
   #:random-ephemeral-node-id
   #:open-unsecured-session
   #:find-unsecured-session
   ;; exchanges and MRP (exchange.lisp)
   #:exchange-error
   #:exchange-error-message
   #:*unsecured-session-lifetime*
   #:transport-send
   #:transport-receive
   #:transport-close
   #:transport-local-endpoint
   #:udp-transport
   #:udp-transport-socket
   #:make-udp-transport
   #:exchange
   #:exchange-p
   #:exchange-manager
   #:exchange-session
   #:exchange-id
   #:exchange-initiator-p
   #:exchange-protocol-id
   #:exchange-vendor-id
   #:exchange-handler
   #:exchange-state
   #:exchange-pending-ack
   #:exchange-outstanding
   #:exchange-response-timeout
   #:exchange-user-data
   #:exchange-open-p
   #:exchange-closed-p
   #:exchange-manager-p
   #:make-exchange-manager
   #:exchange-manager-transport
   #:exchange-manager-session-manager
   #:exchange-manager-exchanges
   #:exchange-manager-clock
   #:exchange-manager-trace
   #:exchange-manager-received
   #:exchange-manager-sent
   #:exchange-manager-now
   #:exchange-manager-close
   #:register-protocol-handler
   #:find-protocol-handler
   #:find-exchange
   #:open-exchange
   #:exchange-send
   #:exchange-close
   #:exchange-abort
   #:exchange-manager-poll
   #:exchange-manager-run
   ;; Secure Channel over exchanges (secure-channel.lisp)
   #:*handshake-timeout*
   #:handshake
   #:handshake-p
   #:handshake-kind
   #:handshake-role
   #:handshake-machine
   #:handshake-exchange
   #:handshake-state
   #:handshake-session
   #:handshake-error
   #:handshake-running-p
   #:handshake-complete-p
   #:handshake-failed-p
   #:secure-channel
   #:secure-channel-p
   #:make-secure-channel
   #:secure-channel-manager
   #:secure-channel-session-manager
   #:secure-channel-fabrics
   #:secure-channel-resumptions
   #:secure-channel-handshakes
   #:secure-channel-on-session
   #:secure-channel-on-session-closed
   #:secure-channel-on-handshake-failed
   #:secure-channel-sessions
   #:set-pase-verifier #:secure-channel-pase-verifier #:secure-channel-pase-salt #:secure-channel-pase-iterations
   #:find-resumption
   #:start-pase
   #:start-case
   #:handshake-abort
   #:handshake-wait
   #:establish-pase-session
   #:establish-case-session
   #:close-session
   ;; timers (exchange.lisp)
   #:add-timer
   #:wake-timer
   #:remove-timer
   #:exchange-manager-timers
   ;; Interaction Model codec (interaction-codec.lisp)
   #:*interaction-model-revision*
   #:+im-status-success+ #:+im-status-failure+ #:+im-status-invalid-subscription+
   #:+im-status-unsupported-access+ #:+im-status-unsupported-endpoint+ #:+im-status-invalid-action+
   #:+im-status-unsupported-command+ #:+im-status-invalid-command+ #:+im-status-unsupported-attribute+
   #:+im-status-constraint-error+ #:+im-status-unsupported-write+ #:+im-status-resource-exhausted+
   #:+im-status-not-found+ #:+im-status-unreportable-attribute+ #:+im-status-invalid-data-type+
   #:+im-status-unsupported-read+ #:+im-status-data-version-mismatch+ #:+im-status-timeout+
   #:+im-status-unsupported-node+ #:+im-status-busy+ #:+im-status-access-restricted+
   #:+im-status-unsupported-cluster+ #:+im-status-no-upstream-subscription+
   #:+im-status-needs-timed-interaction+ #:+im-status-unsupported-event+ #:+im-status-paths-exhausted+
   #:+im-status-timed-request-mismatch+ #:+im-status-failsafe-required+ #:+im-status-invalid-in-state+
   #:+im-status-no-command-response+
   #:im-status-name #:im-status-code
   #:interaction-error #:interaction-error-message #:interaction-error-status #:interaction-error-cluster-status
   #:attribute-path #:make-attribute-path #:attribute-path-p #:attribute-path-node #:attribute-path-endpoint
   #:attribute-path-cluster #:attribute-path-attribute #:attribute-path-list-index #:attribute-path-tag-compression
   #:attribute-path-concrete-p #:attribute-path-matches-p #:attribute-path-tlv #:tlv-attribute-path
   #:cluster-path-tlv #:tlv-cluster-path #:command-path-tlv #:tlv-command-path #:event-path-tlv #:tlv-event-path
   #:im-status-tlv #:tlv-im-status #:attribute-report-tlv #:tlv-attribute-report
   #:cluster-path #:make-cluster-path #:cluster-path-p #:cluster-path-node #:cluster-path-endpoint #:cluster-path-cluster
   #:command-path #:make-command-path #:command-path-p #:command-path-endpoint #:command-path-cluster #:command-path-command
   #:event-path #:make-event-path #:event-path-p #:event-path-node #:event-path-endpoint #:event-path-cluster
   #:event-path-event #:event-path-urgent
   #:im-status #:make-im-status #:im-status-p #:im-status-status #:im-status-cluster-status #:im-status-success-p
   #:attribute-data #:make-attribute-data #:attribute-data-p #:attribute-data-data-version #:attribute-data-path
   #:attribute-data-data
   #:attribute-status #:make-attribute-status #:attribute-status-p #:attribute-status-path #:attribute-status-status
   #:attribute-report #:make-attribute-report #:attribute-report-p #:attribute-report-status #:attribute-report-data
   #:attribute-report-path
   #:data-version-filter #:make-data-version-filter #:data-version-filter-p #:data-version-filter-path
   #:data-version-filter-data-version
   #:event-filter #:make-event-filter #:event-filter-p #:event-filter-node #:event-filter-event-min
   #:event-data #:make-event-data #:event-data-p #:event-data-path #:event-data-event-number #:event-data-priority
   #:event-data-epoch-timestamp #:event-data-system-timestamp #:event-data-delta-epoch-timestamp
   #:event-data-delta-system-timestamp #:event-data-data
   #:event-status #:make-event-status #:event-status-p #:event-status-path #:event-status-status
   #:event-report #:make-event-report #:event-report-p #:event-report-status #:event-report-data
   #:command-data #:make-command-data #:command-data-p #:command-data-path #:command-data-fields #:command-data-ref
   #:command-status #:make-command-status #:command-status-p #:command-status-path #:command-status-status
   #:command-status-ref
   #:invoke-response #:make-invoke-response #:invoke-response-p #:invoke-response-command #:invoke-response-status
   #:invoke-response-path
   #:status-response #:make-status-response #:status-response-p #:status-response-status
   #:read-request #:make-read-request #:read-request-p #:read-request-attribute-requests #:read-request-event-requests
   #:read-request-event-filters #:read-request-fabric-filtered #:read-request-data-version-filters
   #:report-data #:make-report-data #:report-data-p #:report-data-subscription-id #:report-data-attribute-reports
   #:report-data-event-reports #:report-data-more-chunked-messages #:report-data-suppress-response
   #:subscribe-request #:make-subscribe-request #:subscribe-request-p #:subscribe-request-keep-subscriptions
   #:subscribe-request-min-interval-floor #:subscribe-request-max-interval-ceiling
   #:subscribe-request-attribute-requests #:subscribe-request-event-requests #:subscribe-request-event-filters
   #:subscribe-request-fabric-filtered #:subscribe-request-data-version-filters
   #:subscribe-response #:make-subscribe-response #:subscribe-response-p #:subscribe-response-subscription-id
   #:subscribe-response-max-interval
   #:write-request #:make-write-request #:write-request-p #:write-request-suppress-response
   #:write-request-timed-request #:write-request-write-requests #:write-request-more-chunked-messages
   #:write-response #:make-write-response #:write-response-p #:write-response-write-responses
   #:invoke-request #:make-invoke-request #:invoke-request-p #:invoke-request-suppress-response
   #:invoke-request-timed-request #:invoke-request-invoke-requests
   #:invoke-response-message #:make-invoke-response-message #:invoke-response-message-p
   #:invoke-response-message-suppress-response #:invoke-response-message-invoke-responses
   #:invoke-response-message-more-chunked-messages
   #:timed-request #:make-timed-request #:timed-request-p #:timed-request-timeout
   #:encode-interaction-message #:decode-interaction-message
   ;; data model (data-model.lisp)
   #:*interaction-session* #:*type-aliases* #:resolve-type #:value-tlv #:tlv-value
   #:attribute-definition #:make-attribute-definition #:attribute-definition-p #:attribute-definition-name
   #:attribute-definition-id #:attribute-definition-type #:attribute-definition-writable
   #:attribute-definition-default #:attribute-definition-computed #:attribute-definition-optional
   #:attribute-definition-fabric-scoped #:attribute-definition-fabric-sensitive #:attribute-definition-check
   #:attribute-definition-read-privilege #:attribute-definition-write-privilege
   #:+privilege-view+ #:+privilege-proxy-view+ #:+privilege-operate+ #:+privilege-manage+ #:+privilege-administer+
   #:*privileges* #:privilege-value #:privilege-name #:privilege-grants-p
   #:command-definition #:make-command-definition #:command-definition-p #:command-definition-name
   #:command-definition-id #:command-definition-fields #:command-definition-response
   #:command-definition-generated #:command-definition-timed #:command-definition-privilege
   #:cluster-definition #:make-cluster-definition #:cluster-definition-p #:cluster-definition-name
   #:cluster-definition-id #:cluster-definition-revision #:cluster-definition-attributes
   #:cluster-definition-commands
   #:register-cluster-definition #:find-cluster-definition #:find-attribute-definition #:find-command-definition
   #:define-cluster
   #:+attribute-cluster-revision+ #:+attribute-feature-map+ #:+attribute-attribute-list+
   #:+attribute-accepted-command-list+ #:+attribute-generated-command-list+
   #:global-attribute-p #:*global-attribute-definitions*
   #:cluster #:cluster-p #:make-cluster #:cluster-endpoint #:cluster-data-version #:cluster-feature-map
   #:cluster-handlers #:cluster-id #:cluster-name #:cluster-revision
   #:attribute-present-p #:cluster-attribute-ids #:cluster-accepted-command-ids #:cluster-generated-command-ids
   #:attribute-value #:read-attribute #:write-attribute #:command-handler #:invoke-cluster-command
   #:attribute-write-handler
   #:endpoint #:endpoint-p #:make-endpoint #:endpoint-id #:endpoint-device-types #:endpoint-clusters #:endpoint-node
   #:endpoint-parent
   #:add-cluster #:find-cluster
   #:node #:node-p #:make-node #:node-endpoints #:node-listeners
   #:add-endpoint #:remove-endpoint #:find-endpoint #:endpoint-parts #:node-cluster
   #:add-node-listener #:remove-node-listener
   #:+endpoint-root+ #:+cluster-descriptor+ #:+attribute-parts-list+
   ;; clusters (clusters.lisp)
   #:+cluster-basic-information+ #:+cluster-bridged-device-basic-information+
   #:+cluster-identify+ #:+cluster-on-off+ #:+cluster-boolean-state+ #:+cluster-temperature-measurement+
   #:+cluster-window-covering+ #:+cluster-thermostat+
   #:+device-type-root-node+ #:+device-type-aggregator+ #:+device-type-bridged-node+
   #:+device-type-on-off-light+ #:+device-type-on-off-plug-in-unit+ #:+device-type-on-off-light-switch+
   #:+device-type-contact-sensor+ #:+device-type-temperature-sensor+
   #:+device-type-window-covering+ #:+device-type-thermostat+
   #:+data-model-revision+ #:+specification-version+
   #:make-identify-cluster #:make-on-off-cluster #:make-basic-node
   #:make-boolean-state-cluster #:make-temperature-measurement-cluster #:temperature-hundredths
   #:make-window-covering-cluster #:percent-hundredths #:window-covering-features
   #:make-thermostat-cluster
   #:make-aggregator-endpoint #:make-bridged-endpoint #:bridged-device-basic-information
   ;; access control (access.lisp)
   #:+cluster-access-control+ #:+auth-mode-pase+ #:+auth-mode-case+ #:+auth-mode-group+ #:+cat-subject-prefix+
   #:cat-subject #:cat-subject-p #:session-subjects #:acl-entry-grants-p #:node-access-control-entries
   #:access-granted-p
   ;; the Interaction Model over exchanges (interaction.lisp)
   #:*interaction-timeout* #:*max-report-payload* #:*max-subscription-interval* #:*subscription-grace*
   #:*timed-request-grace*
   #:server-subscription #:server-subscription-p #:server-subscription-id #:server-subscription-session
   #:server-subscription-paths #:server-subscription-min-interval #:server-subscription-max-interval
   #:server-subscription-last-report #:server-subscription-dirty
   #:subscription #:subscription-p #:subscription-model #:subscription-session #:subscription-id
   #:subscription-paths #:subscription-min-interval #:subscription-max-interval #:subscription-on-report
   #:subscription-on-failure #:subscription-state #:subscription-last-report #:subscription-primed-reports
   #:subscription-active-p #:unsubscribe
   #:interaction-model #:interaction-model-p #:make-interaction-model #:interaction-model-manager
   #:interaction-model-node #:interaction-model-subscriptions #:interaction-model-client-subscriptions
   #:interaction-model-max-subscription-interval #:interaction-model-on-subscription
   #:interaction-model-now #:interaction-model-close
   #:interaction #:interaction-p #:interaction-kind #:interaction-exchange #:interaction-state
   #:interaction-result #:interaction-condition #:interaction-running-p #:interaction-complete-p
   #:interaction-failed-p
   #:start-read #:start-write #:start-invoke #:start-subscribe #:interaction-abort #:interaction-wait
   #:read-attributes #:write-attributes #:invoke-command #:subscribe-attributes
   #:attribute-report-value #:attribute-write #:command-fields #:invoke-response-value
   #:merge-chunked-reports #:find-attribute-report
   #:session-fabric-index
   ;; commissioning (commissioning.lisp)
   #:+cluster-general-commissioning+ #:+cluster-network-commissioning+
   #:+cluster-operational-credentials+ #:+cluster-administrator-commissioning+
   #:+commissioning-ok+ #:+commissioning-value-outside-range+ #:+commissioning-invalid-authentication+
   #:+commissioning-no-fail-safe+ #:+commissioning-busy-with-other-admin+
   #:+regulatory-indoor+ #:+regulatory-outdoor+ #:+regulatory-indoor-outdoor+
   #:+noc-status-ok+ #:+noc-status-invalid-public-key+ #:+noc-status-invalid-node-op-id+ #:+noc-status-invalid-noc+
   #:+noc-status-missing-csr+ #:+noc-status-table-full+ #:+noc-status-invalid-admin-subject+
   #:+noc-status-fabric-conflict+ #:+noc-status-label-conflict+ #:+noc-status-invalid-fabric-index+
   #:+network-commissioning-feature-ethernet+
   #:+administrator-commissioning-feature-basic+ #:+window-not-open+ #:+enhanced-window-open+ #:+basic-window-open+
   #:+administrator-commissioning-busy+ #:+administrator-commissioning-pake-parameter-error+
   #:+administrator-commissioning-window-not-open+ #:+min-commissioning-timeout+ #:+max-commissioning-timeout+
   #:+max-fabric-index+ #:+max-cumulative-fail-safe-seconds+ #:*fabric-removal-delay*
   #:*subjects-per-acl-entry* #:*targets-per-acl-entry* #:*acl-entries-per-fabric*
   #:make-ethernet-network-commissioning-cluster #:acl-entry
   #:commissioning-error #:commissioning-error-step #:commissioning-error-message
   #:fail-safe #:fail-safe-p #:fail-safe-session #:fail-safe-fabric #:fail-safe-expiry #:fail-safe-armed-at
   #:fail-safe-root #:fail-safe-keypair #:fail-safe-added-fabric
   #:device #:device-p #:make-device #:device-node #:device-channel #:device-model #:device-manager
   #:device-credentials #:device-vendor-id #:device-product-id #:device-fabrics #:device-max-fabrics
   #:device-fail-safe #:device-general-commissioning #:device-operational-credentials
   #:device-network-commissioning #:device-access-control #:device-administrator-commissioning
   #:device-window-mode #:device-window-expiry #:device-window-discriminator #:device-window-fabric
   #:device-on-commissioned #:device-on-fabric-removed #:device-on-state-change #:device-storage
   #:device-now #:device-acl #:find-device-fabric #:remove-device-fabric
   #:open-commissioning-window #:close-commissioning-window #:commissioning-window-open-p
   #:commissioner #:commissioner-p #:make-commissioner #:commissioner-channel #:commissioner-model
   #:commissioner-fabric #:commissioner-root-keypair #:commissioner-ica-keypair #:commissioner-vendor-id
   #:commissioner-next-node-id #:commissioner-trust-store #:commissioner-cd-signing-keys #:commissioner-issue-noc
   #:commissioning #:commissioning-p #:commissioning-commissioner #:commissioning-host #:commissioning-port
   #:commissioning-node-id #:commissioning-state #:commissioning-step #:commissioning-result
   #:commissioning-condition #:commissioning-pase-session #:commissioning-case-session
   #:commissioning-running-p #:commissioning-complete-p #:commissioning-failed-p
   #:start-commissioning #:commissioning-wait #:commission
   ;; persistence (persistence.lisp)
   #:+state-format+ #:state-error #:state-error-message #:write-state-file #:read-state-file
   #:fabric-state #:fabric-from-state #:device-state #:restore-device-state #:commissioner-state
   #:device-discriminator #:device-on-advertising-change #:random-discriminator
   ;; discovery (discovery.lisp)
   #:*commissionable-service-type* #:*operational-service-type* #:*commissioner-service-type*
   #:+commissioning-mode-none+ #:+commissioning-mode-basic+ #:+commissioning-mode-enhanced+
   #:+discovery-soft-ap+ #:+discovery-ble+ #:+discovery-on-network+
   #:+commissioning-flow-standard+ #:+commissioning-flow-user-intent+ #:+commissioning-flow-custom+
   #:discovery-error #:discovery-error-message
   #:random-instance-name #:random-host-name
   #:commissionable-service #:operational-service #:commissioner-service #:parse-matter-txt
   #:*forbidden-passcodes* #:passcode-valid-p #:random-passcode
   #:onboarding-payload #:onboarding-payload-p #:make-onboarding-payload #:onboarding-payload-version
   #:onboarding-payload-vendor-id #:onboarding-payload-product-id #:onboarding-payload-commissioning-flow
   #:onboarding-payload-discovery-capabilities #:onboarding-payload-discriminator
   #:onboarding-payload-short-discriminator-p #:onboarding-payload-short-discriminator
   #:onboarding-payload-passcode #:onboarding-payload-tlv-data
   #:verhoeff-check-digit #:verhoeff-valid-p
   #:encode-manual-pairing-code #:decode-manual-pairing-code
   #:base38-encode #:base38-decode #:encode-qr-code #:decode-qr-code
   #:device-advertiser #:device-advertiser-p #:device-advertiser-device #:device-advertiser-responder
   #:device-advertiser-instance #:device-advertiser-services
   #:device-services #:start-device-advertising #:stop-device-advertising #:device-advertised-services
   #:device-onboarding-payload
   #:discover-commissionable-nodes #:discover-operational-node
   #:start-commissioning-window-request #:request-commissioning-window))
