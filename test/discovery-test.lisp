;;;; discovery-test.lisp -- the _matterc/_matter advertisements, the
;;;; onboarding payload, and a device advertising over a loopback responder.

(defpackage :cl-matter.discovery.tests
  (:use :cl :fiveam :cl-matter)
  (:import-from :cl-matter.exchange.tests #:make-rig #:rig-b #:rig-b-port #:octets-from #:zeros #:*salt* #:*passcode*)
  (:import-from :cl-matter.commissioning.tests
                #:make-commissioning-rig #:cr-device #:cr-rig #:cr-commissioner #:commission-on-rig #:device-fabric
                #:light-node)
  (:import-from :cl-matter.dns-sd.tests #:lamp-service))
(in-package :cl-matter.discovery.tests)

;;; Discovery (Core Specification 4.3 and 5.1): the advertisements a node
;;; makes, the onboarding payload, and a device keeping its advertisement in
;;; step with its window and fabric table over a loopback mDNS responder.
;;; Vectors are the SDK's examples: discriminator 3840, passcode 20202021,
;;; vendor 0xFFF1, product 0x8000 / 0x8001.

(def-suite discovery-tests :description "Discovery: _matterc/_matter advertisements, onboarding payloads, device advertising"
  :in cl-matter.tests:test-suite)
(in-suite discovery-tests)

;;; ------------------------------------------------------------------
;;; Services

(test commissionable-service-records
  (let ((s (commissionable-service :discriminator 3840 :port 5540 :instance "8DEADBEEFCAFE001"
                                   :vendor-id #xFFF1 :product-id #x8000 :device-type #x0100 :device-name "Lamp"
                                   :rotating-id (octets-from 0 4) :pairing-hint 33 :pairing-instruction "10")))
    (is (string= "_matterc._udp" (dns-sd:service-type s)))
    (is (string= "8DEADBEEFCAFE001" (dns-sd:service-instance s)))
    (is (string= "8DEADBEEFCAFE001._matterc._udp.local" (dns-sd:service-instance-name s)))
    (is (= 5540 (dns-sd:service-port s)))
    (is (equal '("_L3840" "_S15" "_V65521" "_CM" "_T256") (dns-sd:service-subtypes s)))
    (is (equal '("D=3840" "VP=65521+32768" "CM=1" "DT=256" "DN=Lamp" "RI=00010203" "PH=33" "PI=10"
                 "SII=500" "SAI=300" "SAT=4000" "T=0" "ICD=0")
               (dns-sd:service-txt s))))
  ;; the minimum: discriminator and port
  (let ((s (commissionable-service :discriminator 0 :port 1)))
    (is (= 16 (length (dns-sd:service-instance s))))
    (is (every (lambda (c) (or (digit-char-p c) (char<= #\A c #\F))) (dns-sd:service-instance s)))
    (is (equal '("_L0" "_S0" "_CM") (dns-sd:service-subtypes s)))
    (is (equal '("D=0" "CM=1" "SII=500" "SAI=300" "SAT=4000" "T=0" "ICD=0") (dns-sd:service-txt s))))
  ;; vendor without product, mode 0 has no _CM, mode 2, the intervals
  (let ((s (commissionable-service :discriminator #xABC :port 5540 :vendor-id 7 :commissioning-mode 0
                                   :idle-interval 5d0 :active-interval 0.3d0 :active-threshold 4d0 :tcp 6 :icd 1)))
    (is (equal '("_L2748" "_S10" "_V7") (dns-sd:service-subtypes s)))
    (is (equal '("D=2748" "VP=7" "CM=0" "SII=5000" "SAI=300" "SAT=4000" "T=6" "ICD=1") (dns-sd:service-txt s))))
  (is (member "_CM" (dns-sd:service-subtypes (commissionable-service :discriminator 1 :port 2 :commissioning-mode 2)) :test #'string=))
  (is (member "CM=2" (dns-sd:service-txt (commissionable-service :discriminator 1 :port 2 :commissioning-mode 2)) :test #'string=)))

(test commissionable-service-checks
  (signals error (commissionable-service :discriminator 4096 :port 5540))
  (signals error (commissionable-service :discriminator -1 :port 5540))
  (signals error (commissionable-service :discriminator 1 :port 0))
  (signals error (commissionable-service :discriminator 1 :port 65536))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :commissioning-mode 3))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :product-id 1))
  (signals error (commissionable-service :discriminator 1 :port 1 :vendor-id 65536))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :device-name (make-string 33 :initial-element #\a)))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :device-name (make-string 17 :initial-element (code-char 228))))
  (finishes (commissionable-service :discriminator 1 :port 1 :device-name (make-string 16 :initial-element (code-char 228))))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :rotating-id (octets-from 0 51)))
  (finishes (commissionable-service :discriminator 1 :port 1 :rotating-id (octets-from 0 50)))
  (signals discovery-error (commissionable-service :discriminator 1 :port 1 :pairing-instruction (make-string 129 :initial-element #\x)))
  (signals discovery-error (operational-service (make-test-fabric) :port 0)))

(test operational-service-records
  (let* ((fabric (make-test-fabric :fabric-id #x1D :node-id #xBEEF))
         (s (operational-service fabric :port 5540))
         (compressed (string-upcase (with-output-to-string (out)
                                      (loop :for b :across (fabric-compressed-fabric-id fabric) :do (format out "~2,'0x" b))))))
    (is (string= "_matter._tcp" (dns-sd:service-type s)))
    (is (= 33 (length (dns-sd:service-instance s))))
    (is (string= (format nil "~a-000000000000BEEF" compressed) (dns-sd:service-instance s)))
    (is (string= (string-upcase (dns-sd:service-instance s)) (dns-sd:service-instance s)))
    (is (equal (list (format nil "_I~a" compressed)) (dns-sd:service-subtypes s)))
    (is (equal '("SII=500" "SAI=300" "SAT=4000" "T=0" "ICD=0") (dns-sd:service-txt s)))
    ;; another node of the same fabric
    (is (string= (format nil "~a-0000000000000002" compressed)
                 (dns-sd:service-instance (operational-service fabric :node-id 2 :port 5540))))))

(test commissioner-service-records
  (let ((s (commissioner-service :port 5550 :instance "0000000000000001" :vendor-id #xFFF1 :product-id 1 :device-type #x0100 :device-name "Hub")))
    (is (string= "_matterd._udp" (dns-sd:service-type s)))
    (is (equal '("_V65521" "_T256") (dns-sd:service-subtypes s)))
    (is (equal '("VP=65521+1" "DT=256" "DN=Hub" "SII=500" "SAI=300" "SAT=4000" "T=0" "ICD=0") (dns-sd:service-txt s))))
  (signals discovery-error (commissioner-service :port 1 :product-id 1)))

(test parse-matter-txt-reads-the-keys
  (let ((plist (parse-matter-txt '("D=3840" "VP=65521+32768" "CM=1" "DT=256" "DN=Lamp" "RI=00010203" "PH=33" "PI=10"
                                   "SII=5000" "SAI=300" "SAT=4000" "T=0" "ICD=0" "X=ignored"))))
    (is (equalp '(:discriminator 3840 :vendor-id 65521 :product-id 32768 :commissioning-mode 1 :device-type 256
                  :device-name "Lamp" :rotating-id #(0 1 2 3) :pairing-hint 33 :pairing-instruction "10"
                  :idle-interval 5d0 :active-interval 0.3d0 :active-threshold 4d0 :tcp 0 :icd 0)
                plist)))
  ;; a service's TXT round-trips
  (is (equal '(:discriminator 2748 :vendor-id 7 :commissioning-mode 0 :idle-interval 0.5d0 :active-interval 0.3d0
               :active-threshold 4d0 :tcp 0 :icd 0)
             (parse-matter-txt (dns-sd:service-txt (commissionable-service :discriminator #xABC :port 5540 :vendor-id 7
                                                                           :commissioning-mode 0)))))
  ;; the alist form, bare keys, junk values, nothing at all
  (is (equal '(:discriminator 12) (parse-matter-txt (dns-sd:parse-txt-record '("D=12")))))
  (is (equal '(:vendor-id 5) (parse-matter-txt '("VP=5" "D" "CM=x" "RI=abc" "SII="))))
  (is (null (parse-matter-txt nil)))
  (is (null (parse-matter-txt '("path=/")))))

;;; ------------------------------------------------------------------
;;; The onboarding payload

(test passcodes
  (is (passcode-valid-p 20202021))
  (is (passcode-valid-p 1))
  (is (passcode-valid-p 99999998))
  (is (not (passcode-valid-p 0)))
  (is (not (passcode-valid-p 99999999)))
  (is (not (passcode-valid-p 11111111)))
  (is (not (passcode-valid-p 12345678)))
  (is (not (passcode-valid-p 87654321)))
  (is (not (passcode-valid-p "1")))
  (loop :repeat 50 :do (is (passcode-valid-p (random-passcode))))
  (loop :repeat 50 :do (is (<= 0 (random-discriminator) 4095)))
  (signals discovery-error (make-onboarding-payload :discriminator 1 :passcode 11111111))
  (signals error (make-onboarding-payload :discriminator 4096 :passcode 1)))

(test verhoeff
  (is (= 2 (verhoeff-check-digit "3497011233")))
  (is (= 4 (verhoeff-check-digit "74970112336552132769")))
  (is (= 3 (verhoeff-check-digit "236")))              ; the textbook example
  (is (verhoeff-valid-p "2363"))
  (is (not (verhoeff-valid-p "2364")))
  (is (not (verhoeff-valid-p "2633")))                 ; transposition caught
  (is (not (verhoeff-valid-p "3"))))

(test manual-pairing-code
  ;; the SDK's example device: discriminator 3840, passcode 20202021
  (let ((payload (make-onboarding-payload :discriminator 3840 :passcode 20202021 :vendor-id #xFFF1 :product-id #x8001)))
    (is (string= "34970112332" (encode-manual-pairing-code payload)))
    (is (string= "749701123365521327694" (encode-manual-pairing-code payload :with-vendor-product t)))
    (is (string= "749701123365521327694"
                 (encode-manual-pairing-code (make-onboarding-payload :discriminator 3840 :passcode 20202021
                                                                      :vendor-id #xFFF1 :product-id #x8001
                                                                      :commissioning-flow +commissioning-flow-custom+)))))
  (let ((p (decode-manual-pairing-code "34970112332")))
    (is (= 20202021 (onboarding-payload-passcode p)))
    (is (= 3840 (onboarding-payload-discriminator p)))
    (is (= 15 (onboarding-payload-short-discriminator p)))
    (is (onboarding-payload-short-discriminator-p p))
    (is (= 0 (onboarding-payload-vendor-id p)))
    (is (= +commissioning-flow-standard+ (onboarding-payload-commissioning-flow p))))
  (let ((p (decode-manual-pairing-code "7497-011-2336-5521-3276-94")))
    (is (= 20202021 (onboarding-payload-passcode p)))
    (is (= 3840 (onboarding-payload-discriminator p)))
    (is (= #xFFF1 (onboarding-payload-vendor-id p)))
    (is (= #x8001 (onboarding-payload-product-id p)))
    (is (= +commissioning-flow-custom+ (onboarding-payload-commissioning-flow p))))
  ;; every short discriminator and the passcode extremes round-trip
  (dotimes (short 16)
    (dolist (passcode '(1 16383 16384 99999998))
      (let ((p (decode-manual-pairing-code
                (encode-manual-pairing-code (make-onboarding-payload :discriminator (ash short 8) :passcode passcode)))))
        (is (= short (onboarding-payload-short-discriminator p)))
        (is (= passcode (onboarding-payload-passcode p))))))
  ;; errors
  (signals discovery-error (decode-manual-pairing-code "3497011233"))      ; too short
  (signals discovery-error (decode-manual-pairing-code "34970112331"))     ; check digit
  (signals discovery-error (decode-manual-pairing-code "74970112332"))     ; says vid/pid, 11 digits
  (signals discovery-error (decode-manual-pairing-code "349701123365521327693")) ; 21 digits, no vid/pid flag
  (signals discovery-error (decode-manual-pairing-code "abc")))

(test qr-code
  ;; the SDK's example device (vendor 0xFFF1, product 0x8001, on the network already)
  (let ((p (decode-qr-code "MT:-24J0AFN00KA0648G00")))
    (is (= 0 (onboarding-payload-version p)))
    (is (= #xFFF1 (onboarding-payload-vendor-id p)))
    (is (= #x8001 (onboarding-payload-product-id p)))
    (is (= +commissioning-flow-standard+ (onboarding-payload-commissioning-flow p)))
    (is (= +discovery-on-network+ (onboarding-payload-discovery-capabilities p)))
    (is (= 3840 (onboarding-payload-discriminator p)))
    (is (not (onboarding-payload-short-discriminator-p p)))
    (is (= 20202021 (onboarding-payload-passcode p)))
    (is (null (onboarding-payload-tlv-data p)))
    (is (string= "MT:-24J0AFN00KA0648G00" (encode-qr-code p)))
    (is (string= "MT:-24J0AFN00KA0648G00" (encode-qr-code (decode-qr-code "mt:-24j0afn00ka0648g00")))))
  ;; our own payloads round-trip, TLV data included
  (let* ((tlv (tlv-encode (tlv-structure nil (tlv (list :profile #xFFF1 1 0) :string "serial"))))
         (p (make-onboarding-payload :vendor-id 1 :product-id 2 :discovery-capabilities (logior +discovery-ble+ +discovery-on-network+)
                                     :discriminator #xABC :passcode 12341234 :tlv-data tlv))
         (text (encode-qr-code p))
         (back (decode-qr-code text)))
    (is (string= "MT:" text :end2 3))
    (is (equalp p back))
    (is (equalp tlv (onboarding-payload-tlv-data back))))
  ;; base-38 groups
  (is (string= "" (base38-encode (zeros 0))))
  (is (string= "00" (base38-encode (zeros 1))))
  (is (string= "0000" (base38-encode (zeros 2))))
  (is (string= "00000" (base38-encode (zeros 3))))
  (is (string= "10" (base38-encode (octets-from 1 2))))
  (is (string= "JD00" (base38-encode (octets-from 1 3))))              ; 1 + 2*256 = 513 = 13*38 + 19
  (is (equalp (octets-from 1 3) (base38-decode "JD00")))
  (dolist (n '(1 2 3 4 5 11 12 13))
    (let ((octets (octets-from 200 (+ 200 n))))
      (is (equalp octets (base38-decode (base38-encode octets))))))
  (signals discovery-error (base38-decode "0"))                 ; a group of 1
  (signals discovery-error (base38-decode "000"))               ; a group of 3
  (signals discovery-error (base38-decode "0000*"))
  (signals discovery-error (base38-decode "....."))             ; does not fit three octets
  (signals discovery-error (decode-qr-code "XX:-24J0AFN00KA0648G00"))
  (signals discovery-error (decode-qr-code "MT:"))
  (signals discovery-error (decode-qr-code "MT:00000000000000"))  ; passcode 0
  (signals discovery-error (decode-qr-code "MT:-24J0AFN00KA0648G0")))

;;; ------------------------------------------------------------------
;;; A device advertising over a loopback mDNS responder

(defun local-port (mdns-socket)
  (nth-value 1 (cl-matter.net:socket-local-endpoint (dns-sd:mdns-socket-socket mdns-socket))))

(defmacro with-loopback-mdns ((querier responder-socket) &body body)
  "Two legacy mDNS sockets on 127.0.0.1 that take each other for the group:
what QUERIER sends arrives at RESPONDER-SOCKET as if multicast, and back."
  `(dns-sd:with-mdns-socket (,querier :address "127.0.0.1" :multicast nil :group "127.0.0.1" :port 1)
     (dns-sd:with-mdns-socket (,responder-socket :address "127.0.0.1" :multicast nil :group "127.0.0.1"
                                                :port (local-port ,querier))
       (setf (dns-sd:mdns-socket-port ,querier) (local-port ,responder-socket))
       ,@body)))

(defun same-set-p (a b) (null (set-exclusive-or a b :test #'equal)))

(test device-advertising-follows-window-and-fabrics
  "The commissionable service while the window is open, found by discriminator;
the operational service from AddNOC on; nothing after the fabric is gone."
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr))
         (port (rig-b-port (cr-rig cr)))
         (discriminator (device-discriminator device)))
    (with-loopback-mdns (querier rs)
      (let ((advertiser (start-device-advertising device :socket rs :probe nil :host "box.local"
                                                         :addresses '("10.0.0.9" "fd00::9")
                                                         :device-type +device-type-on-off-light+ :device-name "Lamp")))
        (unwind-protect
             (progn
               (is (eq advertiser (device-advertiser device)))
               (is (dns-sd:responder-running-p (device-advertiser-responder advertiser)))
               (signals error (start-device-advertising device :socket rs))
               ;; on the air: the commissionable service
               (let ((services (device-advertised-services device)))
                 (is (= 1 (length services)))
                 (let ((s (first services)))
                   (is (string= "_matterc._udp" (dns-sd:service-type s)))
                   (is (= port (dns-sd:service-port s)))
                   (is (string= (device-advertiser-instance advertiser) (dns-sd:service-instance s)))
                   (is (= 16 (length (dns-sd:service-instance s))))
                   (is (equal (list (format nil "_L~d" discriminator) (format nil "_S~d" (ash discriminator -8))
                                    "_V65521" "_CM" "_T256")
                              (dns-sd:service-subtypes s)))
                   (is (equal (list :discriminator discriminator :vendor-id #xFFF1 :product-id #x8000 :commissioning-mode 1
                                    :device-type 256 :device-name "Lamp" :idle-interval 0.5d0 :active-interval 0.3d0
                                    :active-threshold 4d0 :tcp 0 :icd 0)
                              (parse-matter-txt (dns-sd:service-txt s))))))
               ;; a commissioner finds it by its discriminator, and not by another
               (let ((found (discover-commissionable-nodes :discriminator discriminator :socket querier :timeout 0.6)))
                 (is (= 1 (length found)))
                 (let ((node (first found)))
                   (is (string= (format nil "~a._matterc._udp.local" (device-advertiser-instance advertiser)) (getf node :instance)))
                   (is (string= "box.local" (getf node :host)))
                   (is (= port (getf node :port)))
                   (is (same-set-p '("10.0.0.9" "fd00::9") (getf node :addresses)))
                   (is (= discriminator (getf node :discriminator)))
                   (is (= 1 (getf node :commissioning-mode)))
                   (is (string= "Lamp" (getf node :device-name)))))
               (is (null (discover-commissionable-nodes :discriminator (logxor discriminator 1) :socket querier :timeout 0.3)))
               (is (= 1 (length (discover-commissionable-nodes :short-discriminator (ash discriminator -8) :socket querier :timeout 0.4))))
               (is (= 1 (length (discover-commissionable-nodes :vendor-id #xFFF1 :socket querier :timeout 0.4))))
               (is (= 1 (length (discover-commissionable-nodes :socket querier :timeout 0.4))))
               ;; commissioning: the operational service appears with AddNOC, the commissionable one leaves
               (let* ((result (commission-on-rig cr))
                      (fabric (device-fabric cr))
                      (services (device-advertised-services device)))
                 (is (not (commissioning-window-open-p device)))
                 (is (= 1 (length services)))
                 (let ((s (first services)))
                   (is (string= "_matter._tcp" (dns-sd:service-type s)))
                   (is (string= (fabric-operational-instance-name fabric) (dns-sd:service-instance s)))
                   (is (= port (dns-sd:service-port s)))
                   (is (= 1 (length (dns-sd:service-subtypes s))))
                   (is (string= "_I" (first (dns-sd:service-subtypes s)) :end2 2)))
                 (let ((node (discover-operational-node (commissioner-fabric (cr-commissioner cr)) (getf result :node-id)
                                                        :socket querier :timeout 0.6)))
                   (is (not (null node)))
                   (when node
                     (is (= port (getf node :port)))
                     (is (string= "box.local" (getf node :host)))
                     (is (= 0.5d0 (getf node :idle-interval)))
                     (is (null (getf node :discriminator)))))
                 (is (null (discover-commissionable-nodes :socket querier :timeout 0.3)))
                 (is (null (discover-operational-node (commissioner-fabric (cr-commissioner cr)) 99 :socket querier :timeout 0.3)))
                 ;; the fabric goes: nothing is advertised
                 (remove-device-fabric device fabric)
                 (is (null (device-advertised-services device)))
                 (is (= 3 (length (dns-sd:responder-records (device-advertiser-responder advertiser))))) ; the host's
                 ;; a new window: the commissionable service again, under the same instance name
                 (open-commissioning-window device :passcode *passcode* :salt *salt* :iterations 1000)
                 (is (equal '("_matterc._udp") (mapcar #'dns-sd:service-type (device-advertised-services device))))
                 (is (string= (device-advertiser-instance advertiser)
                              (dns-sd:service-instance (first (device-advertised-services device)))))
                 (is (= 1 (length (discover-commissionable-nodes :discriminator discriminator :socket querier :timeout 0.4))))))
          (is (stop-device-advertising device)))
        (is (null (device-advertiser device)))
        (is (null (device-on-advertising-change device)))
        (is (not (dns-sd:responder-running-p (device-advertiser-responder advertiser))))
        (is (null (stop-device-advertising device)))
        ;; without an advertiser the window still opens and closes
        (finishes (close-commissioning-window device))))))

(test device-advertising-on-a-shared-responder
  "The device's services join a responder the application runs, and leave it again."
  (let* ((cr (make-commissioning-rig))
         (device (cr-device cr)))
    (with-loopback-mdns (querier rs)
      (is (dns-sd:mdns-socket-p querier))
      (let ((responder (dns-sd:start-responder :socket rs :probe nil :thread nil :host "box.local"
                                               :addresses '("10.0.0.9") :services (list (lamp-service)))))
        (unwind-protect
             (progn
               (start-device-advertising device :responder responder :port 5540)
               (is (equal '("_matterc._udp" "_matterc._udp") (mapcar #'dns-sd:service-type (dns-sd:responder-services responder))))
               (is (eq (lamp-service-p (first (dns-sd:responder-services responder))) t))
               (is (= 5540 (dns-sd:service-port (second (dns-sd:responder-services responder)))))
               (is (not (null (dns-sd::%records-of (dns-sd:responder-records responder)
                                                   (dns-sd:service-instance-name (first (device-advertised-services device)))
                                                   dns-sd:+type-srv+))))
               (close-commissioning-window device)
               (is (= 1 (length (dns-sd:responder-services responder))))
               (open-commissioning-window device :passcode *passcode* :salt *salt* :iterations 1000)
               (is (= 2 (length (dns-sd:responder-services responder))))
               (stop-device-advertising device)
               (is (dns-sd:responder-running-p responder))
               (is (= 1 (length (dns-sd:responder-services responder))))
               (is (= 9 (length (dns-sd:responder-records responder)))))   ; host A + NSEC, the lamp's 7
          (dns-sd:stop-responder responder))))))

(defun lamp-service-p (service) (and (string= "Lamp" (dns-sd:service-instance service)) t))

(test device-discriminator-and-payload
  (let ((rig (make-rig)))
    (let ((device (make-device :node (light-node) :channel (make-secure-channel (rig-b rig)) :discriminator 3840
                               :passcode *passcode* :salt *salt* :iterations 1000)))
      (is (= 3840 (device-discriminator device)))
      (let ((payload (device-onboarding-payload device *passcode*)))
        (is (= #xFFF1 (onboarding-payload-vendor-id payload)))
        (is (= #x8000 (onboarding-payload-product-id payload)))
        (is (= +discovery-on-network+ (onboarding-payload-discovery-capabilities payload)))
        (is (= 3840 (onboarding-payload-discriminator payload)))
        (is (equalp payload (decode-qr-code (encode-qr-code payload))))
        (is (string= "34970112332" (encode-manual-pairing-code payload))))
      (signals discovery-error (device-onboarding-payload device 11111111)))
    (is (<= 0 (device-discriminator (make-device :node (light-node) :channel (make-secure-channel (rig-b rig)))) 4095))
    (signals error (make-device :node (light-node) :channel (make-secure-channel (rig-b rig)) :discriminator 4096))))
