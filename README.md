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

Early. `cl-matter/net` is functional on AmiLisp (all operations) and on
SBCL (IPv4 datagrams; multicast and interfaces pending). The DNS message
codec is complete: `encode-message` / `decode-message` with name
compression, the QU and cache-flush bits, and typed record data for PTR,
SRV, TXT, A, AAAA and NSEC (see `test/dns-sd-test.lisp`, which decodes
packets captured from a real mDNS responder). The querier works:
`browse` lists the instances of a service type and `resolve` turns one
into host, port, addresses and TXT properties, over a shared port 5353
with the group joined where the backend can (AmiLisp), and as legacy
unicast queries where it cannot (SBCL for now). The responder advertises
this host's services: it probes for its names and renames on conflict,
announces, answers queries with the additionals DNS-SD asks for, suppresses
known answers, uses the legacy unicast format for queries from other ports,
and says goodbye on stop. The Matter TLV codec is complete:
`tlv-encode` / `tlv-decode` over `tlv-element` structs with every tag form
and element type of Appendix A, verified against the specification's
examples (`test/tlv-test.lisp`). Message framing is in place: the message
and protocol headers, whole unsecured messages, the Secure Channel status
report, outgoing counters, the receive window that rejects duplicate and
stale counters, and the MRP retransmission schedule (`test/message-test.lisp`).
The crypto primitives of the secure channel are in (`src/matter/crypto.lisp`):
SHA-256, HMAC, HKDF and PBKDF2 (the runtime's native digests on AmiLisp,
Ironclad on SBCL), AES-CCM built on Ironclad's AES since Ironclad has no CCM
mode, the 13-octet message nonce, and `encode-secured-message` /
`decode-secured-message` with the header as additional data and the 16-octet
MIC, checked against RFC 3610, SP 800-38C and OpenSSL vectors
(`test/crypto-test.lisp`). PASE is done: SPAKE2+ on P-256
(`src/matter/spake2p.lisp`, the RFC 9383 construction with Matter's key
schedule, verified against the RFC's and the Matter SDK's vectors,
`test/spake2p-test.lisp`) and the five-message handshake
(`src/matter/pase.lisp`): the PBKDFParam and Pake message codecs, session
parameters, and an initiator and a responder driven by `pase-handle` with
(opcode, payload) pairs, so a whole handshake runs without a socket
(`test/pase-test.lisp`). CASE is done too: P-256 key pairs, ECDH and ECDSA
(`src/matter/p256.lisp`), Matter operational certificates with their
mapping to X.509 DER, chain validation and the generation of an
RCAC/ICAC/NOC chain of our own (`src/matter/certificate.lisp`, byte-exact
against the SDK's test certificates in `test/sdk-certificates.lisp`),
fabrics with the compressed fabric id, the IPK and the CASE destination id
(`src/matter/fabric.lisp`, the specification's vectors), and the Sigma
handshake with session resumption (`src/matter/case.lisp`), driven like
PASE by `case-handle` (`test/case-test.lisp`). Both handshakes now run over
UDP: the session layer (`src/matter/session.lisp`) frames, encrypts and
counter-checks messages per peer and keeps the sessions of a node; the
exchange manager (`src/matter/exchange.lisp`) pairs requests with responses
on exchanges and runs the Message Reliability Protocol for all of them
(piggybacked and standalone acknowledgements, retransmission on the
specification's backoff, duplicate suppression, one reliable message in
flight per exchange) from a single poll loop over a transport; and the
Secure Channel driver (`src/matter/secure-channel.lisp`) carries PASE and
CASE on it, installs the session each one yields, remembers CASE
resumption state for the next time, answers BUSY while a PASE handshake is
running, and does CloseSession. Application protocols plug in as handler
functions per protocol id. `test/exchange-test.lisp` drives two nodes over
an in-memory network with a stepped clock (lossy links, retransmission
schedules, timeouts) and over real loopback UDP sockets. The Interaction
Model runs on that: its message codec (`src/matter/interaction-codec.lisp`,
every path, information block and message of chapter 10), a data model
(`src/matter/data-model.lisp`: `define-cluster` describes a cluster's
attributes and commands with their types, a node is endpoints of cluster
instances with values, data versions and command handlers, and the global
attributes are computed), the first clusters (`src/matter/clusters.lisp`:
Descriptor, Basic Information, Identify, On/Off), and the engine
(`src/matter/interaction.lisp`) that serves Read, Write, Invoke and
Subscribe from a node and performs them against a peer: wildcard paths,
per-path statuses, chunked reports, data version filters, timed requests,
and subscriptions that report changes after the minimum interval and keep
alive at the maximum, in both directions. `test/data-model-test.lisp` and
`test/interaction-test.lisp` cover it, the last one with a server thread
over UDP after a PASE handshake. Commissioning is in: X.509 DER is read as
well as written (`src/matter/der.lisp`, with base64 and PEM), so device
attestation certificates and PAA roots import into the same `certificate`
struct (`decode-certificate-der`, `decode-certificate-pem`, EC private keys
from PEM); `src/matter/attestation.lisp` has the attestation and NOCSR
elements, the DAC-signed attestation signature, PKCS#10 certificate
signing requests, the certification declaration in its CMS envelope
(signed by the CSA's keys or the SDK's test key), the PAA trust store, and
`verify-device-attestation` / `verify-nocsr`, the commissioner's checks of
section 6.2.3, verified against the Matter SDK's vectors
(`test/sdk-attestation.lisp`, `test/attestation-test.lisp`);
`src/matter/commissioning.lisp` defines General Commissioning,
Operational Credentials, Network Commissioning (Ethernet) and Access
Control, a `device` that serves them from a fabric table with the
fail-safe and its reverts, and a `commissioner` that runs the flow of
section 5.5 over PASE: arm the fail-safe, regulatory configuration,
attestation, CSR, root and NOC, CASE as the new administrator,
CommissioningComplete. Attributes can be fabric-scoped (`define-cluster`'s
`:fabric-scoped` and `:fabric-sensitive`): the NOCs, Fabrics and ACL
lists show each fabric its own entries. `test/commissioning-test.lisp`
runs the flow on the in-memory rig and over UDP, drives every cluster
command by hand, and lets fail-safes expire.

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
responder.

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
  reported; the ACL is kept and checked but not enforced (any session may
  do what the definitions allow); no list chunking (an attribute too big
  for one message is reported RESOURCE_EXHAUSTED) and no group writes or
  invokes. Beyond the commissioning clusters only Descriptor, Basic
  Information, Identify and On/Off are defined.
- **Commissioning**: the fabric table lives in memory (the application
  keeps and restores `device-fabrics`); there is no Administrator
  Commissioning cluster (a window opened by an existing admin, with the
  enhanced commissioning mode in the advertisement), and the Network
  Commissioning cluster is Ethernet only (no Wi-Fi or Thread
  configuration).
- **Discovery**: the advertisements are made and read, but the device does
  not keep advertising with `CM=0` after commissioning (extended
  discovery), the rotating device identifier is passed in rather than
  derived, and the responder answers on one interface's addresses.
- **SBCL backend**: multicast membership and interface enumeration are
  still missing, so on SBCL the querier uses legacy unicast and the
  responder cannot run.
- **Interop**: nothing has been tried against chip-tool or a real device.
  Everything so far is verified against specification and RFC vectors and
  against the Matter SDK's test vectors only.

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
5. ~~Matter TLV~~ Done. ~~Message framing~~ Done. ~~AES-CCM, nonce, secured messages, SHA-256/HMAC/HKDF/PBKDF2~~ Done. ~~PASE (SPAKE2+ on Ironclad's P-256)~~ Done. ~~CASE: certificates, fabrics, the Sigma handshake~~ Done. ~~Exchanges, MRP and the session manager over the net backend~~ Done. ~~The interaction model: Read/Write/Invoke/Subscribe and the first clusters~~ Done. ~~Commissioning: DER import, CSR, device attestation, the commissioning clusters, the device and the commissioner~~ Done. ~~Discovery: the commissionable and operational advertisements, the onboarding payload (QR and manual pairing code), the commissioner's search~~ Done. Next: an interop test against chip-tool.
