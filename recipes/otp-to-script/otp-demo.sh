#!/usr/bin/env bash
# Pass a one-time code from your phone to a script running somewhere else.
#
# Three ways, from simplest to most contained:
set -euo pipefail

# 1. Capture it. stdout carries only the value; status lines go to stderr.
#    Exit code 3 means nobody answered before the timeout.
code="$(tailslip receive \
  --label "6-digit code from your authenticator" \
  --pattern '[0-9]{6}' \
  --timeout 5m)"
echo "got a ${#code}-character code" >&2
# ... use "$code" (prefer stdin or a 0600 file over command-line arguments)

# 2. Hand it straight to a command's stdin, never touching a shell variable.
#    Replace the python one-liner with e.g. `some-cli login --otp-stdin`.
tailslip exec --stdin \
  --label "Code for the release step" --pattern '[0-9]{6}' \
  -- python3 -c 'import sys; print("received", len(sys.stdin.read().strip()), "digits")'

# 3. Put it in one environment variable of one command.
tailslip exec --env RELEASE_OTP \
  --label "Code for the release step" --pattern '[0-9]{6}' \
  -- sh -c 'echo "RELEASE_OTP has ${#RELEASE_OTP} characters"'
