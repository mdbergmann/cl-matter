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
   #:*tlv-max-depth*))
