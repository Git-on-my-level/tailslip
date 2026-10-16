#!/usr/bin/env bash
# Hand a file (a key, a license, a small config) to a headless box from your phone
# or laptop browser, without scp access, a shared drive or pasting it into a chat.
#
# The file is written atomically with mode 0600. Default size limit is 16 MB;
# raise it with --max-bytes (e.g. --max-bytes 64M).
set -euo pipefail

dest="${1:-$HOME/incoming/upload.bin}"
mkdir -p "$(dirname "$dest")"

tailslip receive --file \
  --label "Upload the deploy key for $(hostname -s)" \
  --prompt "Pick the file from your device. It is stored with owner-only permissions." \
  --timeout 10m \
  --out "$dest"

echo "saved $(wc -c < "$dest" | tr -d ' ') bytes to $dest" >&2

# Long text (a multi-line config or PEM) works the same way without a file picker:
#   tailslip receive --text --label "Paste the PEM" --out key.pem
