# cl-matter

Matter (the CSA smart-home standard) for Common Lisp, built bottom-up:

| System | What |
|---|---|
| `cl-matter/net` | Unconnected UDP sockets, multicast, interface list — one protocol, one backend per implementation (AmiLisp on `EXT`, SBCL on `sb-bsd-sockets`) |
| `cl-matter/dns-sd` | mDNS (RFC 6762) and DNS-SD (RFC 6763): DNS message codec, resolver, service browser, responder |
| `cl-matter` | Matter core: TLV codec, message framing, PASE/CASE sessions, interaction model, commissioning, discovery |
| `cl-matter/tests` | fiveam suite over all of the above |

The discovery layer works on IPv4 and IPv6 and therefore on AmigaOS and
MorphOS too. Matter itself runs over IPv6 only, so the controller and device
roles are for the hosts (macOS, Linux, Windows); a Thread border router
makes Thread devices reachable as ordinary IPv6 nodes.

## Status

Early, but a cl-matter lamp is commissioned, controlled and
re-administered by chip-tool, and comes back commissioned after a restart.
Layer by layer, bottom up; every layer's test file is its specification
and the place to see it used.

- **Sockets** (`cl-matter/net`): unconnected UDP, multicast and interface
  enumeration behind one protocol. Complete on AmiLisp; SBCL has IPv4
  datagrams only, multicast and interfaces pending. `test/net-test.lisp`.
- **DNS messages** (`src/dns-sd/message.lisp`): the codec with name
  compression, the QU and cache-flush bits, typed record data for PTR, SRV,
  TXT, A, AAAA and NSEC. `test/dns-sd-test.lisp` decodes packets captured
  from a real mDNS responder.
- **mDNS querier** (`src/dns-sd/mdns.lisp`): `browse` lists a service
  type's instances, `resolve` turns one into host, port, addresses and TXT
  properties; a shared port 5353 with the group joined where the backend
  can, legacy unicast queries where it cannot (SBCL).
- **mDNS responder** (`src/dns-sd/responder.lisp`): advertises this host's
  services; probes and renames on conflict, announces, answers with the
  additionals DNS-SD asks for, suppresses known answers, uses the legacy
  unicast format for other ports, says goodbye on stop.
- **TLV** (`src/matter/tlv.lisp`): every tag form and element type of
  Appendix A, verified against the specification's examples.
  `test/tlv-test.lisp`.
- **Message framing** (`src/matter/message.lisp`): message and protocol
  headers, unsecured messages, the status report, outgoing counters, the
  receive window, the MRP retransmission schedule. `test/message-test.lisp`.
- **Crypto** (`src/matter/crypto.lisp`, `src/matter/p256.lisp`): SHA-256,
  HMAC, HKDF, PBKDF2 (the runtime's native digests on AmiLisp, Ironclad on
  SBCL), AES-CCM built on Ironclad's AES, the message nonce, secured
  messages with the 16-octet MIC; P-256 key pairs, ECDH and ECDSA. Checked
  against RFC 3610, SP 800-38C and OpenSSL vectors. `test/crypto-test.lisp`.
- **PASE** (`src/matter/spake2p.lisp`, `src/matter/pase.lisp`): SPAKE2+
  per RFC 9383 with Matter's key schedule, verified against the RFC's and
  the SDK's vectors; the five-message handshake as an initiator and a
  responder driven with (opcode, payload) pairs, so it runs without a
  socket. `test/spake2p-test.lisp`, `test/pase-test.lisp`.
- **Certificates and fabrics** (`src/matter/certificate.lisp`,
  `src/matter/der.lisp`, `src/matter/fabric.lisp`): Matter operational
  certificates and their X.509 DER mapping both ways, PEM, chain
  validation, our own RCAC/ICAC/NOC chains; byte-exact against the SDK's
  test certificates. Fabrics with the compressed fabric id, the IPK and
  the CASE destination id. `test/certificate-test.lisp`.
- **CASE** (`src/matter/case.lisp`): the Sigma handshake with session
  resumption, driven like PASE. `test/case-test.lisp`.
- **Sessions and exchanges** (`src/matter/session.lisp`,
  `src/matter/exchange.lisp`, `src/matter/secure-channel.lisp`): the
  session layer frames, encrypts and counter-checks per peer; the exchange
  manager pairs requests with responses and runs MRP (acknowledgements,
  retransmission on the backoff, duplicate suppression) from one poll loop
  over a transport; the Secure Channel carries PASE and CASE on it,
  installs the sessions, remembers resumption state, answers BUSY, closes
  sessions. Application protocols are handler functions per protocol id.
  `test/exchange-test.lisp` drives two nodes over an in-memory network
  with a stepped clock and over loopback UDP.
- **Interaction Model** (`src/matter/interaction-codec.lisp`,
  `src/matter/data-model.lisp`, `src/matter/clusters.lisp`,
  `src/matter/interaction.lisp`): every message of chapter 10;
  `define-cluster` for attributes and commands with their types, nodes of
  endpoints of cluster instances; Descriptor, Basic Information, Identify
  and On/Off; Read, Write, Invoke and Subscribe served from a node and
  performed against a peer, with wildcard paths, per-path statuses,
  chunked reports, data version filters, timed requests and subscriptions.
  `test/data-model-test.lisp`, `test/interaction-test.lisp`.
- **Attestation** (`src/matter/attestation.lisp`): attestation and NOCSR
  elements, the DAC-signed signature, PKCS#10 CSRs, the certification
  declaration in its CMS envelope, the PAA trust store, and the
  commissioner's checks of section 6.2.3, against the SDK's vectors.
  `test/attestation-test.lisp`.
- **Commissioning** (`src/matter/commissioning.lisp`): General
  Commissioning, Operational Credentials, Network Commissioning (Ethernet),
  Access Control and Administrator Commissioning; a `device` with its
  fabric table, fail-safe and commissioning window (basic with its own
  passcode, or enhanced, opened by an administrator for the next one); a
  `commissioner` running the flow of section 5.5 over PASE through to CASE
  and CommissioningComplete; fabric-scoped attributes.
  `test/commissioning-test.lisp` runs it on the rig and over UDP and
  brings a second administrator in through a window.
- **Access control** (`src/matter/access.lisp`): every attribute and
  command carries the privilege it takes; a CASE session gets what its
  fabric's ACL entries grant its node id or CATs; PASE administers.
  `test/access-test.lisp`.
- **Persistence** (`src/matter/persistence.lisp`): the fabric table with
  its keys, the ACL, the resumption records and the attributes
  administrators wrote, kept in a state file the device rewrites by itself,
  committed at CommissioningComplete; a commissioner likewise.
  `test/persistence-test.lisp` restarts both and resumes their session.
- **Discovery** (`src/matter/discovery.lisp`): the commissionable and
  operational advertisements that follow the window and the fabric table,
  the onboarding payload with QR and manual pairing codes, the
  commissioner's search. `test/discovery-test.lisp`.
- **Interop**: `examples/lamp-device.lisp` on the real network, driven by
  chip-tool (pairing, On/Off, ACL writes, a second administrator through
  an opened window, unpair, restart).

The API in sketches, bottom up (each one is a call sequence from the
layer's test file):

```lisp
;; the commissionee stores a verifier, never the passcode
(cl-matter:spake2p-verifier 20202021 salt 1000)        ; => 97 octets, w0 || L
(cl-matter:make-pase-responder :verifier * :salt salt :iterations 1000 :local-session-id 2)
;; the commissioner knows the passcode
(cl-matter:make-pase-initiator :passcode 20202021 :local-session-id 1)
(cl-matter:pase-start initiator)                       ; => #x20, PBKDFParamRequest octets
(cl-matter:pase-handle responder #x20 octets)          ; => #x21, PBKDFParamResponse octets
;; ... Pake1, Pake2, Pake3, StatusReport; then on both sides
(cl-matter:pase-session-keys initiator)                ; => I2R, R2I, attestation challenge
```

```lisp
;; a fabric: the credentials, the key pair the NOC certifies, the IPK epoch key
(cl-matter:make-fabric :rcac rcac :icac icac :noc noc
                       :operational-keypair keypair :epoch-key epoch-key)
(cl-matter:make-test-fabric :fabric-id #x1D :node-id 1 :icac t)   ; generated credentials
;; CASE between two nodes of the fabric
(cl-matter:make-case-initiator :fabric a :peer-node-id 2 :local-session-id 1)
(cl-matter:make-case-responder :fabrics (list b) :local-session-id 2)
(cl-matter:case-start initiator)                       ; => #x30, Sigma1 octets
(cl-matter:case-handle responder #x30 octets)          ; => #x31, Sigma2 octets
;; ... Sigma3, StatusReport; then on both sides
(cl-matter:case-session-keys initiator)                ; => I2R, R2I, attestation challenge
(cl-matter:case-resumption-state initiator)            ; keep it: the next session resumes
```

```lisp
;; a node: a UDP transport, an exchange manager over it, the Secure Channel on that
(defvar *m* (cl-matter:make-exchange-manager
             :transport (cl-matter:make-udp-transport :family :ipv6 :port 5540)))
(defvar *sc* (cl-matter:make-secure-channel *m* :fabrics (list fabric)
                                                :pase-passcode 20202021 :pase-salt salt
                                                :pase-iterations 1000))
;; as a commissioner / controller: a handshake over the wire
(cl-matter:establish-pase-session *sc* "fe80::1%en0" 5540 :passcode 20202021)
(cl-matter:establish-case-session *sc* "fe80::1%en0" 5540 :fabric fabric :peer-node-id 2)
;; => a SESSION; the next CASE to that node resumes
;; an application protocol on a session
(cl-matter:register-protocol-handler *m* 1 (lambda (exchange event &rest data) ...))
(let ((ex (cl-matter:open-exchange *m* session 1 :handler #'my-handler)))
  (cl-matter:exchange-send ex #x02 payload))        ; reliable; acked, retransmitted
(cl-matter:exchange-manager-run *m* :until #'done-p) ; or EXCHANGE-MANAGER-POLL, one turn
```

```lisp
;; a light: the root endpoint with Basic Information, endpoint 1 with On/Off
(defvar *light* (cl-matter:make-on-off-cluster
                 :on-change (lambda (cluster on) (declare (ignore cluster)) (set-relay on))))
(defvar *node* (cl-matter:make-basic-node
                :vendor-name "ACME" :vendor-id #xFFF1 :product-name "Lamp" :product-id 1
                :endpoints (list (cl-matter:make-endpoint
                                  1 :device-types (list (cons cl-matter:+device-type-on-off-light+ 3))
                                    :clusters (list (cl-matter:make-identify-cluster) *light*)))))
(defvar *im* (cl-matter:make-interaction-model *m* :node *node*))   ; serves it to every session
(setf (cl-matter:attribute-value *light* 'on-off) t)   ; a local change: subscribers hear of it
;; as a controller, on a session from the Secure Channel
(cl-matter:read-attributes *im* session (list (cl-matter:attribute-path 1 #x0006 0)
                                              (cl-matter:attribute-path nil #x001D nil)))
;; => ATTRIBUTE-REPORTs; ATTRIBUTE-REPORT-VALUE decodes a defined cluster's value
(cl-matter:write-attributes *im* session (list (cl-matter:attribute-write 0 #x0028 5 "Kitchen")))
(cl-matter:invoke-command *im* session (cl-matter:command-path 1 #x0006 2) nil)   ; Toggle
(cl-matter:subscribe-attributes *im* session (list (cl-matter:attribute-path 1 #x0006 0))
                                :min-interval 1 :max-interval 60
                                :on-report (lambda (subscription reports) ...))
;; START-READ ... START-SUBSCRIBE are the non-blocking forms (:on-complete), for a
;; node that polls its own manager; a new cluster is a DEFINE-CLUSTER plus handlers
```

```lisp
;; a commissionable device: the node from above, its Secure Channel and Interaction Model
(defvar *device* (cl-matter:make-device :node *node* :channel *sc* :model *im*
                                        :credentials (cl-matter:test-attestation-credentials) ; the SDK's example DAC
                                        :passcode 20202021 :salt salt :iterations 1000        ; opens the window
                                        :on-commissioned (lambda (device fabric) ...)))
(cl-matter:device-fabrics *device*)                    ; the fabric table, FABRICs with their indices
;; a commissioner: its own fabric, rooted here
(defvar *admin* (cl-matter:make-commissioner *m-sc* *m-im* :fabric-id 1 :vendor-id #xFFF1))
(cl-matter:commission *admin* "fe80::1%en0" 5540 :passcode 20202021 :country-code "DE")
;; => (:node-id 2 :fabric #<FABRIC> :session #<SESSION CASE ...> :attestation (...) ...)
;; START-COMMISSIONING is the non-blocking form; :attestation :ignore skips the trust store
;; for development devices (the signature must still be the DAC's)
;; multi-admin: the administrator opens a window for the next one (Administrator
;; Commissioning, timed, Administer); the payload's codes go to the other commissioner
(defvar *next* (cl-matter:request-commissioning-window *admin* (getf result :session) :timeout 300))
(cl-matter:encode-manual-pairing-code *next*)          ; => "02757-612-6473" style, 11 digits
;; the device's side: (open-commissioning-window *device* :timeout 300) re-opens the basic
;; window; :mode :enhanced with :verifier/:salt/:iterations/:discriminator is what the cluster does
;; across a restart: the fabric table with its keys, the ACL, the resumption records and the
;; attributes administrators wrote live in a state file the device keeps by itself
(cl-matter:make-device ... :storage "~/.cl-matter/lamp.state")   ; restored when it exists, rewritten on change
(cl-matter:device-state *device*)                      ; the committed state, a plist of plain data
(cl-matter:write-state-file (cl-matter:commissioner-state *admin*) path)   ; a commissioner's too
(cl-matter:make-commissioner *m-sc* *m-im* :state (cl-matter:read-state-file path))  ; resumes its sessions
```

```lisp
;; the device on the air: _matterc._udp while the window is open (discriminator, VP, CM
;; in subtypes and TXT), _matter._tcp per fabric from AddNOC on; follows the device by itself
(cl-matter:start-device-advertising *device* :device-name "Lamp"
                                             :device-type cl-matter:+device-type-on-off-light+)
(cl-matter:device-advertised-services *device*)        ; the DNS-SD:SERVICEs on the air right now
(cl-matter:stop-device-advertising *device*)
;; what the user types into the commissioner
(defvar *payload* (cl-matter:device-onboarding-payload *device* 20202021))
(cl-matter:encode-qr-code *payload*)                   ; => "MT:-24J0AFN00KA0648G00"
(cl-matter:encode-manual-pairing-code *payload*)       ; => "34970112332"
;; ... and the commissioner's side of both
(cl-matter:decode-manual-pairing-code "3497-011-2332") ; => #<ONBOARDING-PAYLOAD ... discriminator 3840 (short) ...>
(cl-matter:discover-commissionable-nodes :short-discriminator 15)
;; => ((:instance "8DEADBEEFCAFE001._matterc._udp.local" :host "..." :port 5540
;;      :addresses ("fe80::1") :discriminator 3840 :vendor-id 65521 :product-id 32768
;;      :commissioning-mode 1 :idle-interval 0.5d0 ...))
(cl-matter:discover-operational-node fabric node-id)   ; the same plist for a commissioned node
```

`test/discovery-test.lisp` is the reference: the TXT keys and subtypes of
section 4.3, the SDK's example QR and manual codes, and a device whose
advertisement follows its window and fabric table over a loopback
responder.  `examples/lamp-device.lisp` puts all of it on the real network:
a lamp on port 5540 that chip-tool commissions with
`chip-tool pairing code 1 34970112332` and switches with
`chip-tool onoff toggle 1 1`.

```lisp
(dns-sd:browse "_http._tcp")
;; => ("Printer._http._tcp.local" ...), <all records received>
(dns-sd:resolve "Printer._http._tcp.local")
;; => (:name "Printer._http._tcp.local" :host "printer.local" :port 80
;;     :addresses ("192.168.1.9" "fe80::1") :txt (("path" . "/")))
(defvar *r* (dns-sd:start-responder
             :services (list (dns-sd:make-service :instance "Lamp" :type "_matterc._udp"
                                                  :port 5540 :txt '(("D" . "840"))
                                                  :subtypes '("_L840")))))
(dns-sd:stop-responder *r*)
```

The responder needs a backend that can join the multicast group (AmiLisp
today); it runs in a thread of its own, or without one through
`responder-poll`, which is how `test/dns-sd-test.lisp` drives it on
loopback.

```lisp
(cl-matter:tlv-encode
 (cl-matter:tlv-structure nil (cl-matter:tlv 1 :unsigned 42)
                              (cl-matter:tlv 2 :string "Hello!")))
;; => #(21 36 1 42 44 2 6 72 101 108 108 111 33 24)
(cl-matter:tlv-get (cl-matter:tlv-decode *) 1)
;; => 42, T
```

## What's missing

Nothing talks to a real Matter device yet. In the order it will be built:

- **Running a node**: the exchange manager is single-threaded and
  polled (`exchange-manager-poll` / `exchange-manager-run`); there is no
  thread wrapper yet, no TCP transport, no message-counter
  synchronisation for group messages, and sessions never expire on their
  own.
- **Certificates**: the PAA trust store starts with the SDK's test PAAs
  only; the CSA's production roots (the Distributed Compliance Ledger)
  must be added with `add-trusted-paa`. Revocation is not checked.
- **Message privacy** (the P flag, privacy keys): not implemented; group
  messages and group keys likewise.
- **Interaction model**: events are accepted in requests and never
  reported; no list chunking (an attribute too big for one message is
  reported RESOURCE_EXHAUSTED) and no group writes or invokes. Beyond
  the commissioning clusters only Descriptor, Basic Information, Identify
  and On/Off are defined.
- **Access control**: the Group auth mode never matches (there are no
  group sessions), the ACL's Extension attribute is not served, and
  Matter 1.4's Access Restriction List is not implemented.
- **Commissioning**: the Network Commissioning cluster is Ethernet only
  (no Wi-Fi or Thread configuration), and group key sets are neither
  served nor kept.
- **Discovery**: the advertisements are made and read, but the device does
  not keep advertising with `CM=0` after commissioning (extended
  discovery), the rotating device identifier is passed in rather than
  derived, and the responder answers on one interface's addresses.
- **SBCL backend**: multicast membership and interface enumeration are
  still missing, so on SBCL the querier uses legacy unicast and the
  responder cannot run.
- **Interop**: chip-tool (the Matter SDK's reference controller) commissions
  `examples/lamp-device.lisp`, toggles and reads it, and removes its fabric
  again (2026-11-05, SDK master on macOS).  No other controller and no real
  device has been tried yet; cl-matter's own commissioner has only
  commissioned cl-matter devices.

## Build and test

```
ln -s "$PWD" ~/quicklisp/local-projects/cl-matter   # once
scripts/run-tests.sh          # AmiLisp
scripts/run-tests.sh --sbcl   # SBCL
```

or from a REPL: `(asdf:test-system :cl-matter)`.

## Plan

1. ~~DNS message codec with tests against captured mDNS packets.~~ Done.
2. ~~Querier: `browse` and `resolve` over the mDNS group.~~ Done.
3. ~~Responder: announce, answer, goodbye.~~ Done.
4. SBCL backend: multicast membership and `getifaddrs` through `sb-alien`.
5. ~~Matter TLV~~ Done. ~~Message framing~~ Done. ~~AES-CCM, nonce, secured messages, SHA-256/HMAC/HKDF/PBKDF2~~ Done. ~~PASE (SPAKE2+ on Ironclad's P-256)~~ Done. ~~CASE: certificates, fabrics, the Sigma handshake~~ Done. ~~Exchanges, MRP and the session manager over the net backend~~ Done. ~~The interaction model: Read/Write/Invoke/Subscribe and the first clusters~~ Done. ~~Commissioning: DER import, CSR, device attestation, the commissioning clusters, the device and the commissioner~~ Done. ~~Discovery: the commissionable and operational advertisements, the onboarding payload (QR and manual pairing code), the commissioner's search~~ Done. ~~An interop test against chip-tool~~ Done. ~~ACL enforcement~~ Done. ~~Administrator Commissioning~~ Done. ~~Fabric persistence~~ Done.
