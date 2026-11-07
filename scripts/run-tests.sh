#!/bin/sh
# Run the cl-matter test suite.
#
#   scripts/run-tests.sh          # under AmiLisp (host build of ../amigasources/cl-amiga)
#   scripts/run-tests.sh --sbcl   # under SBCL
#
# Both need the project visible to ASDF: a symlink in ~/quicklisp/local-projects
# (ln -s "$PWD" ~/quicklisp/local-projects/cl-matter) or a source-registry entry.
# AMILISP_REPO / AMILISP override where the AmiLisp checkout and binary are.
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
AMILISP_REPO=${AMILISP_REPO:-$HERE/../amigasources/cl-amiga}
AMILISP=${AMILISP:-$AMILISP_REPO/build/host/amilisp}
LOG=${TMPDIR:-/tmp}/cl-matter-tests.log

if [ "$1" = "--sbcl" ]; then
  sbcl --non-interactive \
       --eval '(load "~/quicklisp/setup.lisp")' \
       --eval '(ql:quickload :cl-matter/tests :silent t)' \
       --eval '(unless (fiveam:run! (quote cl-matter.tests:test-suite)) (sb-ext:exit :code 1))'
else
  AMILISP_NO_USERINIT=1 "$AMILISP" --heap 64M \
      --eval '(require "asdf")' \
      --eval '(load "~/quicklisp/setup.lisp")' \
      --eval "(load \"$AMILISP_REPO/lib/quicklisp-compat.lisp\")" \
      --eval '(handler-case (asdf:load-system :cl-matter/tests) (error (e) (format t "~%CL-MATTER-TESTS: LOAD FAILED: ~a~%" e) (quit 1)))' \
      --eval '(format t "~%CL-MATTER-TESTS: ~a~%" (if (fiveam:run! (quote cl-matter.tests:test-suite)) "PASSED" "FAILED"))' \
      --eval '(quit)' </dev/null 2>&1 | tee "$LOG"
  grep -q "CL-MATTER-TESTS: PASSED" "$LOG"
fi
