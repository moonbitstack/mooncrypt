#!/bin/sh
# The constant-time measurement the README quotes, at the sample counts those
# numbers were taken with. The quick pass is what CI runs; this is the slow one:
#
#     scripts/run_dudect.sh
#
# Any argument is passed on, so `--full` (already the default here) and nothing
# else are the two modes the harness knows.
set -eu
cd "$(dirname "$0")/.."
exec moon run src/examples/timing --target native --release -- --full "$@"
