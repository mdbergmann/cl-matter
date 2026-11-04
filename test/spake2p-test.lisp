(defpackage :cl-matter.spake2p.tests
  (:use :cl :fiveam :cl-matter))
(in-package :cl-matter.spake2p.tests)

(def-suite spake2p-tests :description "SPAKE2+ on P-256 (RFC 9383, Matter key schedule)"
  :in cl-matter.tests:test-suite)
(in-suite spake2p-tests)

(defun hex (string)
  (let* ((digits (remove-if (lambda (c) (member c '(#\Space #\Newline))) string))
         (out (make-array (floor (length digits) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer digits :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun unhex (octets)
  (format nil "~(~{~2,'0x~}~)" (coerce octets 'list)))

(defun ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

;;; ------------------------------------------------------------------
;;; RFC 9383 Appendix C, P-256-SHA256-HKDF-SHA256-HMAC-SHA256.  The shares,
;;; Z, V and the transcript are what Matter uses; the RFC's final key
;;; schedule (K_main, K_confirmP/V, K_shared) is checked here from the
;;; transcript, next to Matter's Ka || Ke split of the same hash.

(defparameter *rfc-context* "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors")
(defparameter *rfc-w0* "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3")
(defparameter *rfc-w1* "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba")
(defparameter *rfc-l* "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd")
(defparameter *rfc-x* "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539")
(defparameter *rfc-share-p* "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727")
(defparameter *rfc-y* "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3")
(defparameter *rfc-share-v* "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048")
(defparameter *rfc-z* "04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839")
(defparameter *rfc-v* "0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68")
(defparameter *rfc-tt*
  "38000000000000005350414b45322b2d503235362d5348413235362d484b44462d5348413235362d484d41432d534841323536205465737420566563746f7273
   0600000000000000636c69656e7406000000000000007365727665724100000000000000
   04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20
   4100000000000000
   04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7
   4100000000000000
   04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727
   4100000000000000
   04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048
   4100000000000000
   04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839
   4100000000000000
   0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68
   2000000000000000
   bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3")
(defparameter *rfc-k-main* "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29")
(defparameter *rfc-k-confirm-p* "871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a")
(defparameter *rfc-k-confirm-v* "ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680")
(defparameter *rfc-mac-p* "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527")
(defparameter *rfc-mac-v* "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68")
(defparameter *rfc-k-shared* "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7")

(test rfc9383-registration
  (is (= 56 (length *rfc-context*)))
  (is (string= *rfc-l* (unhex (spake2p-l (hex *rfc-w1*)))))
  (is (string= "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
               (unhex (concatenate 'vector (vector (+ 2 (logand 1 (aref *spake2p-m* 64)))) (subseq *spake2p-m* 1 33)))))
  (is (string= "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
               (unhex (concatenate 'vector (vector (+ 2 (logand 1 (aref *spake2p-n* 64)))) (subseq *spake2p-n* 1 33))))))

(test rfc9383-shares-and-transcript
  (let ((prover (spake2p-start :prover :context (ascii *rfc-context*)
                                       :id-prover (ascii "client") :id-verifier (ascii "server")
                                       :w0 (hex *rfc-w0*) :w1 (hex *rfc-w1*) :scalar (hex *rfc-x*)))
        (verifier (spake2p-start :verifier :context (ascii *rfc-context*)
                                           :id-prover (ascii "client") :id-verifier (ascii "server")
                                           :w0 (hex *rfc-w0*) :l (hex *rfc-l*) :scalar (hex *rfc-y*))))
    (is (string= *rfc-share-p* (unhex (spake2p-share prover))))
    (is (string= *rfc-share-v* (unhex (spake2p-share verifier))))
    (is (eq :started (spake2p-state prover)))
    (spake2p-derive prover (spake2p-share verifier))
    (spake2p-derive verifier (spake2p-share prover))
    (is (eq :derived (spake2p-state prover)))
    (dolist (s (list prover verifier))
      (is (string= *rfc-z* (unhex (spake2p-z s))))
      (is (string= *rfc-v* (unhex (spake2p-v s))))
      (is (equalp (hex *rfc-tt*) (spake2p-transcript s)))
      ;; the RFC's key schedule from the shared transcript
      (let* ((k-main (sha256 (spake2p-transcript s)))
             (confirm (hkdf-sha256 k-main nil (ascii "ConfirmationKeys") 64))
             (k-confirm-p (subseq confirm 0 32))
             (k-confirm-v (subseq confirm 32)))
        (is (string= *rfc-k-main* (unhex k-main)))
        (is (string= *rfc-k-confirm-p* (unhex k-confirm-p)))
        (is (string= *rfc-k-confirm-v* (unhex k-confirm-v)))
        (is (string= *rfc-mac-p* (unhex (hmac-sha256 k-confirm-p (hex *rfc-share-v*)))))
        (is (string= *rfc-mac-v* (unhex (hmac-sha256 k-confirm-v (hex *rfc-share-p*)))))
        (is (string= *rfc-k-shared* (unhex (hkdf-sha256 k-main nil (ascii "SharedKey") 32))))
        ;; Matter's split of the same hash
        (is (equalp (subseq k-main 0 16) (spake2p-ka s)))
        (is (equalp (subseq k-main 16) (spake2p-ke s)))))
    ;; and the two sides confirm each other under Matter's schedule
    (is (spake2p-confirm prover (spake2p-confirmation verifier)))
    (is (spake2p-confirm verifier (spake2p-confirmation prover)))
    (is (equalp (spake2p-shared-key prover) (spake2p-shared-key verifier)))))

;;; ------------------------------------------------------------------
;;; The Matter SDK's vectors (src/crypto/tests/SPAKE2P_RFC_test_vectors.h,
;;; from draft-bar-cfrg-spake2plus-01): the same construction with the
;;; Ka || Ke schedule, with every combination of present and empty identities.

(defparameter *sdk-vectors*
  '(
    (:context "SPAKE2+-P256-SHA256-HKDF draft-01" :id-prover "client" :id-verifier "server"
     :w0 "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"
     :w1 "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"
     :l "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
     :x "8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6"
     :share-p "04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e"
     :y "2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91"
     :share-v "04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4"
     :z "0471a35282d2026f36bf3ceb38fcf87e3112a4452f46e9f7b47fd769cfb570145b62589c76b7aa1eb6080a832e5332c36898426912e29c40ef9e9c742eee82bf30"
     :v "046718981bf15bc4db538fc1f1c1d058cb0eececf1dbe1b1ea08a4e25275d382e82b348c8131d8ed669d169c2e03a858db7cf6ca2853a4071251a39fbe8cfc39bc"
     :ka "f9cab9adcc0ed8e5a4db11a8505914b2"
     :ke "801db297654816eb4f02868129b9dc89"
     :kca "0d248d7d19234f1486b2efba5179c52d"
     :kcb "556291df26d705a2caedd6474dd0079b"
     :mac-kca "d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd"
     :mac-kcb "0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e"
     )
    (:context "SPAKE2+-P256-SHA256-HKDF draft-01" :id-prover "client" :id-verifier ""
     :w0 "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"
     :w1 "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"
     :l "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
     :x "ec82d9258337f61239c9cd68e8e532a3a6b83d12d2b1ca5d543f44def17dfb8d"
     :share-p "04230779960824076d3666a7418e4d433e2fa15b06176eabdd572f43a32ecc79a192b243d2624310a7356273b86e5fd9bd627d3ade762baeff1a320d4ad7a4e47f"
     :y "eac3f7de4b198d5fe25c443c0cd4963807add767815dd02a6f0133b4bc2c9eb0"
     :share-v "044558642e71b616b248c9583bd6d7aa1b3952c6df6a9f7492a06035ca5d92522d84443de7aa20a59380fa4de6b7438d925dbfb7f1cfe60d79acf961ee33988c7d"
     :z "04b4e8770f19f58ddf83f9220c3a9305792665e0c60989e6ee9d7fa449c775d6395f6f25f307e3903ac045a013fbb5a676e872a6abfcf4d7bb5aac69efd6140eed"
     :v "04141db83bc7d96f41b636622e7a5c552ad83211ff55319ac25ed0a09f0818bd942e8150319bfbfa686183806dc61911183f6a0f5956156023d96e0f93d275bf50"
     :ka "e2cbee3ae19a4dbe9f146be6bee9bfa1"
     :ke "6989d8f9177ef7df67da437987f07255"
     :kca "2f9e0bb669d2c22645bce34da04ac16a"
     :kcb "eb7a35168759dd8e9ce44e4dc51277ce"
     :mac-kca "e1b9258807ba4750dae1d7f3c3c294f13dc4fa60cde346d5de7d200e2f8fd3fc"
     :mac-kcb "b9c39dfa49c47757de778d9bedeaca2448b905be19a43b94ee24b770208135e3"
     )
    (:context "SPAKE2+-P256-SHA256-HKDF draft-01" :id-prover "" :id-verifier "server"
     :w0 "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"
     :w1 "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"
     :l "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
     :x "ba0f0f5b78ef23fd07868e46aeca63b51fda519a3420501acbe23d53c2918748"
     :share-p "04c14d28f4370fea20745106cea58bcfb60f2949fa4e131b9aff5ea13fd5aa79d507ae1d229e447e000f15eb78a9a32c2b88652e3411642043c1b2b7992cf2d4de"
     :y "39397fbe6db47e9fbd1a263d79f5d0aaa44df26ce755f78e092644b434533a42"
     :share-v "04d1bee3120fd87e86fe189cb952dc688823080e62524dd2c08dffe3d22a0a8986aa64c9fe0191033cafbc9bcaefc8e2ba8ba860cd127af9efdd7f1c3a41920fe8"
     :z "04aac71cf4c8df8181b867c9ecbee9d0963caf51f1534a823429c26fe5248313ffc5c5e44ea8162161ab6b3d73b87704a45889bf6343d96fa96cd1641efa71607c"
     :v "04c7c9505365f7ce57293c92a37f1bbdc68e0322901e61edef59fee7876b17b063e0fa4a126eae0a671b37f1464cf1ccad591c33ae944e3b1f318d76e36fea9966"
     :ka "ec8d19b807ffb1d1eea81a93ba35cdfe"
     :ke "2ea40e4badfa5452b5744dc5983e99ba"
     :kca "66de534d9bf1e44e96a53a4b48d6b353"
     :kcb "4945c38bb476cb0f347f3222be9b64a2"
     :mac-kca "e564c93b3015efb946dc16d642bbe7d1c8da5be164ed9fc3bae4e0ff86e1bd3c"
     :mac-kcb "072a94d9a54edc201d8891534c2317cadf3ea3792827f479e873f93e90f21552"
     )
    (:context "SPAKE2+-P256-SHA256-HKDF draft-01" :id-prover "" :id-verifier ""
     :w0 "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"
     :w1 "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"
     :l "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
     :x "5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786"
     :share-p "04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd"
     :y "766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e"
     :share-v "04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947"
     :z "040a150d9a62f514c9a1fedd782a0240a342721046cefb1111c3adb3be893ce9fcd2ffa137922fcf8a588d0f76ba9c55c85da2af3f1c789ca17976810387fb1d7e"
     :v "04f8e247cc263a1846272f5a3b61b68aa60a5a2665d10cd22c89cd6bad05dc0e5e650f21ff017186cc92651a4cd7e66ce88f529299f340ea80fb90a9bad094e1a6"
     :ka "5929a3ce9822c81401bf0f764f69af08"
     :ke "ea3276d68334576097e04b19ee5a3a8b"
     :kca "7f84b939d600117256b0c8a6d40cf181"
     :kcb "f7d7547ced93f681e8df4c258c4516fd"
     :mac-kca "71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea"
     :mac-kcb "095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3"
     )))

(defun check-sdk-vector (v)
  (flet ((f (key) (getf v key)))
    (let ((prover (spake2p-start :prover :context (ascii (f :context))
                                         :id-prover (ascii (f :id-prover)) :id-verifier (ascii (f :id-verifier))
                                         :w0 (hex (f :w0)) :w1 (hex (f :w1)) :scalar (hex (f :x))))
          (verifier (spake2p-start :verifier :context (ascii (f :context))
                                             :id-prover (ascii (f :id-prover)) :id-verifier (ascii (f :id-verifier))
                                             :w0 (hex (f :w0)) :l (hex (f :l)) :scalar (hex (f :y)))))
      (is (string= (f :l) (unhex (spake2p-l (hex (f :w1))))))
      (is (string= (f :share-p) (unhex (spake2p-share prover))))
      (is (string= (f :share-v) (unhex (spake2p-share verifier))))
      (let ((ca (spake2p-derive prover (spake2p-share verifier)))
            (cb (spake2p-derive verifier (spake2p-share prover))))
        (dolist (s (list prover verifier))
          (is (string= (f :z) (unhex (spake2p-z s))))
          (is (string= (f :v) (unhex (spake2p-v s))))
          (is (string= (f :ka) (unhex (spake2p-ka s))))
          (is (string= (f :ke) (unhex (spake2p-ke s))))
          (is (string= (f :kca) (unhex (spake2p-kca s))))
          (is (string= (f :kcb) (unhex (spake2p-kcb s)))))
        (is (string= (f :mac-kca) (unhex ca)))
        (is (string= (f :mac-kcb) (unhex cb)))
        (is (spake2p-confirm prover cb))
        (is (spake2p-confirm verifier ca))
        (is (string= (f :ke) (unhex (spake2p-shared-key prover))))
        (is (string= (f :ke) (unhex (spake2p-shared-key verifier))))))))

(test sdk-draft01-vectors
  (dolist (v *sdk-vectors*)
    (check-sdk-vector v)))

;;; ------------------------------------------------------------------
;;; Registration: the SDK's well-known test verifier
;;; (spake2p gen-verifier -i 1000 -s "U1BBS0UyUCBLZXkgU2FsdA==" -p 20202021)

(defparameter *sdk-salt* (ascii "SPAKE2P Key Salt"))
(defparameter *sdk-verifier*
  (concatenate 'string
               "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb35"
               "0457f8ab79ee253ab6a8e46bb09e543ae422736de501e3db37d441fe344920d09548e4c18240630c4ff4913c53513839b7c07fcc0627a1b8573a149fcd1fa466cf"))

(test passcode-octets-little-endian
  (is (equalp (hex "25423401") (passcode-octets 20202021)))   ; 20202021 = #x01344225
  (is (equalp (hex "00000000") (passcode-octets 0)))
  (is (equalp (hex "ffffffff") (passcode-octets #xffffffff)))
  (signals spake2p-error (passcode-octets (ash 1 32)))
  (signals spake2p-error (passcode-octets -1))
  (signals spake2p-error (passcode-octets "20202021")))

(test sdk-test-verifier
  (let ((verifier (spake2p-verifier 20202021 *sdk-salt* 1000)))
    (is (= +spake2p-verifier-length+ (length verifier)))
    (is (string= *sdk-verifier* (unhex verifier)))
    (multiple-value-bind (w0 l) (spake2p-verifier-parts verifier)
      (is (= 32 (length w0)))
      (is (= 65 (length l)))
      (is (equalp verifier (concatenate 'vector w0 l)))
      ;; w0 and L are what spake2p-w0w1 and spake2p-l give
      (multiple-value-bind (w0-int w1-int) (spake2p-w0w1 20202021 *sdk-salt* 1000)
        (is (= w0-int (reduce (lambda (a b) (+ (* 256 a) b)) w0)))
        (is (equalp l (spake2p-l w1-int)))))
    ;; another passcode or salt gives another verifier
    (is (not (equalp verifier (spake2p-verifier 20202022 *sdk-salt* 1000))))
    (is (not (equalp verifier (spake2p-verifier 20202021 (ascii "SPAKE2P Key Salt!") 1000)))))
  (signals spake2p-error (spake2p-verifier-parts (hex "0102")))
  (signals crypto-error (spake2p-verifier 20202021 "SPAKE2P Key Salt" 1000)))

;;; ------------------------------------------------------------------
;;; Random runs and the failure paths

(defparameter *context* (sha256 (ascii "CHIP PAKE V1 Commissioning")))

(defun run-exchange (w0 w1 l &key (context *context*))
  "A whole exchange with fresh scalars; both parties, confirmed."
  (let ((prover (spake2p-start :prover :context context :w0 w0 :w1 w1))
        (verifier (spake2p-start :verifier :context context :w0 w0 :l l)))
    (let ((ca (spake2p-derive prover (spake2p-share verifier)))
          (cb (spake2p-derive verifier (spake2p-share prover))))
      (spake2p-confirm prover cb)
      (spake2p-confirm verifier ca))
    (values prover verifier)))

(test random-exchanges-agree
  (multiple-value-bind (w0 w1) (spake2p-w0w1 12341234 *sdk-salt* 1000)
    (let ((l (spake2p-l w1))
          (keys '()))
      (dotimes (i 3)
        (multiple-value-bind (prover verifier) (run-exchange w0 w1 l)
          (is (eq :confirmed (spake2p-state prover)))
          (is (eq :confirmed (spake2p-state verifier)))
          (is (equalp (spake2p-shared-key prover) (spake2p-shared-key verifier)))
          (is (equalp (spake2p-transcript prover) (spake2p-transcript verifier)))
          (is (not (equalp (spake2p-share prover) (spake2p-share verifier))))
          (push (spake2p-shared-key prover) keys)))
      ;; fresh scalars, fresh keys
      (is (= 3 (length (remove-duplicates keys :test #'equalp)))))))

(test wrong-passcode-fails-confirmation
  (multiple-value-bind (w0 w1) (spake2p-w0w1 12341234 *sdk-salt* 1000)
    (multiple-value-bind (w0-wrong w1-wrong) (spake2p-w0w1 12341235 *sdk-salt* 1000)
      (declare (ignore w1-wrong))
      (let* ((l (spake2p-l w1))
             (prover (spake2p-start :prover :context *context* :w0 w0-wrong :w1 w1))
             (verifier (spake2p-start :verifier :context *context* :w0 w0 :l l))
             (ca (spake2p-derive prover (spake2p-share verifier)))
             (cb (spake2p-derive verifier (spake2p-share prover))))
        (signals spake2p-confirmation-error (spake2p-confirm prover cb))
        (signals spake2p-confirmation-error (spake2p-confirm verifier ca))
        (is (eq :derived (spake2p-state prover)))
        (signals spake2p-error (spake2p-shared-key prover))))
    ;; a verifier for another passcode's L: prover's V differs
    (let* ((l-wrong (spake2p-l (nth-value 1 (spake2p-w0w1 12341235 *sdk-salt* 1000))))
           (prover (spake2p-start :prover :context *context* :w0 w0 :w1 w1))
           (verifier (spake2p-start :verifier :context *context* :w0 w0 :l l-wrong)))
      (spake2p-derive prover (spake2p-share verifier))
      (let ((cb (spake2p-derive verifier (spake2p-share prover))))
        (signals spake2p-confirmation-error (spake2p-confirm prover cb))))))

(test tampered-confirmation-and-context
  (multiple-value-bind (w0 w1) (spake2p-w0w1 12341234 *sdk-salt* 1000)
    (let* ((l (spake2p-l w1))
           (prover (spake2p-start :prover :context *context* :w0 w0 :w1 w1))
           (verifier (spake2p-start :verifier :context *context* :w0 w0 :l l)))
      (spake2p-derive prover (spake2p-share verifier))
      (let ((cb (copy-seq (spake2p-derive verifier (spake2p-share prover)))))
        (setf (aref cb 31) (logxor 1 (aref cb 31)))
        (signals spake2p-confirmation-error (spake2p-confirm prover cb))
        (signals spake2p-confirmation-error (spake2p-confirm prover (subseq cb 0 31)))
        (signals crypto-error (spake2p-confirm prover "not octets"))))
    ;; different contexts: everything else equal, the MACs differ
    (let* ((l (spake2p-l w1))
           (prover (spake2p-start :prover :context *context* :w0 w0 :w1 w1))
           (verifier (spake2p-start :verifier :context (sha256 (ascii "other")) :w0 w0 :l l)))
      (spake2p-derive prover (spake2p-share verifier))
      (signals spake2p-confirmation-error
        (spake2p-confirm prover (spake2p-derive verifier (spake2p-share prover)))))))

(test invalid-peer-shares
  (multiple-value-bind (w0 w1) (spake2p-w0w1 12341234 *sdk-salt* 1000)
    (let ((l (spake2p-l w1)))
      (flet ((prover () (spake2p-start :prover :context *context* :w0 w0 :w1 w1))
             (verifier () (spake2p-start :verifier :context *context* :w0 w0 :l l)))
        ;; wrong length, wrong prefix, off the curve
        (signals spake2p-error (spake2p-derive (prover) (subseq (spake2p-share (verifier)) 0 64)))
        (signals spake2p-error (spake2p-derive (prover) (subseq (spake2p-share (verifier)) 1)))
        (let ((share (copy-seq (spake2p-share (verifier)))))
          (setf (aref share 0) 2)
          (signals spake2p-error (spake2p-derive (prover) share)))
        (let ((share (copy-seq (spake2p-share (verifier)))))
          (setf (aref share 64) (logxor 1 (aref share 64)))
          (signals spake2p-error (spake2p-derive (prover) share)))
        (signals crypto-error (spake2p-derive (prover) "pB"))
        ;; pB = w0*N makes pB - w0*N the point at infinity: Z is rejected
        (let ((blinding-only (ironclad:ec-encode-point
                              (ironclad:ec-scalar-mult (ironclad:ec-decode-point :secp256r1 *spake2p-n*) w0))))
          (signals spake2p-error (spake2p-derive (prover) blinding-only)))
        (let ((blinding-only (ironclad:ec-encode-point
                              (ironclad:ec-scalar-mult (ironclad:ec-decode-point :secp256r1 *spake2p-m*) w0))))
          (signals spake2p-error (spake2p-derive (verifier) blinding-only)))
        ;; a rejected share leaves the party able to take a good one
        (let ((p (prover)))
          (handler-case (spake2p-derive p (subseq (spake2p-share (verifier)) 0 64))
            (spake2p-error () nil))
          (is (eq :started (spake2p-state p)))
          (spake2p-derive p (spake2p-share (verifier)))
          (is (eq :derived (spake2p-state p))))))))

(test parameter-and-state-errors
  (multiple-value-bind (w0 w1) (spake2p-w0w1 12341234 *sdk-salt* 1000)
    (let ((l (spake2p-l w1)))
      (signals spake2p-error (spake2p-start :client :w0 w0 :w1 w1))
      (signals spake2p-error (spake2p-start :prover :w0 w0))            ; no w1
      (signals spake2p-error (spake2p-start :verifier :w0 w0))          ; no L
      (signals spake2p-error (spake2p-start :prover :w0 0 :w1 w1))
      (signals spake2p-error (spake2p-start :prover :w0 w0 :w1 115792089210356248762697446949407573529996955224135760342422259061068512044369))
      (signals spake2p-error (spake2p-start :prover :w0 (hex "0102") :w1 w1))
      (signals spake2p-error (spake2p-start :prover :w0 "w0" :w1 w1))
      (signals spake2p-error (spake2p-start :verifier :w0 w0 :l (subseq l 0 33)))
      (signals spake2p-error (spake2p-start :prover :w0 w0 :w1 w1 :scalar 0))
      (signals crypto-error (spake2p-start :prover :w0 w0 :w1 w1 :context "ctx"))
      (let ((p (spake2p-start :prover :w0 w0 :w1 w1))
            (v (spake2p-start :verifier :w0 w0 :l l)))
        (signals spake2p-error (spake2p-confirm p (make-array 32 :element-type '(unsigned-byte 8))))
        (signals spake2p-error (spake2p-shared-key p))
        (spake2p-derive p (spake2p-share v))
        (signals spake2p-error (spake2p-derive p (spake2p-share v)))
        (is (search "PROVER DERIVED" (princ-to-string p)))))))

(test random-scalars-in-range
  (dotimes (i 20)
    (let ((k (random-p256-scalar)))
      (is (< 0 k 115792089210356248762697446949407573529996955224135760342422259061068512044369)))))

(test spake2p-l-matches-generator-multiplication
  ;; L of w1 = 1 is the base point G
  (is (string= "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
               (unhex (spake2p-l 1))))
  (signals spake2p-error (spake2p-l 0)))
