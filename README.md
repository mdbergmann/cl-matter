# cl-matter

Matter (the CSA smart-home standard) for Common Lisp, built bottom-up:

| System | What |
|---|---|
| `cl-matter/net` | Unconnected UDP sockets, multicast, interface list — one protocol, one backend per implementation (AmiLisp on `EXT`, SBCL on `sb-bsd-sockets`) |
| `cl-matter/dns-sd` | mDNS (RFC 6762) and DNS-SD (RFC 6763): DNS message codec, resolver, service browser, responder |
| `cl-matter` | Matter core: TLV codec, message framing, PASE/CASE sessions, interaction model |
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
Encryption and sessions come next.

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
5. ~~Matter TLV~~ Done. ~~Message framing~~ Done. Then the session layer with Ironclad: PASE, CASE.
