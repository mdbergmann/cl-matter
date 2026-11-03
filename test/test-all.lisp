(defpackage :cl-matter.tests
  (:use :cl :fiveam)
  (:export #:run!
           #:all-tests
           #:test-suite))

(in-package :cl-matter.tests)

(def-suite test-suite
  :description "All catching test suite.")

(in-suite test-suite)

(test scaffold
  "The three packages exist."
  (is (find-package :cl-matter.net))
  (is (find-package :cl-matter.dns-sd))
  (is (find-package :cl-matter)))
