#!/usr/bin/env bash
# Offline end-to-end demo on the bundled synthetic images in examples/firmware.
# Every image was produced by `make fixtures` (src/fwaudit/synth); nothing here is real
# vendor firmware and nothing touches the network.
set -euo pipefail
cd "$(dirname "$0")/.."

FW="uv run --frozen fwaudit"
EX=examples/firmware
OUT=build/demo
IMG=$EX/dev-0023-flash-squashfs-xz.bin
REF=2026-01-01T00:00:00+00:00   # fixed reference time so certificate verdicts are stable

rm -rf "$OUT"
mkdir -p "$OUT"

banner() { printf '\n==== %s ====\n' "$1"; }

banner "1. identify: validated signatures in the flash image"
$FW identify "$IMG"

banner "2. entropy map (4 KiB blocks)"
$FW entropy "$IMG" --width 64

banner "3. scan: extract + audit, write JSON and Markdown reports, materialise the rootfs"
$FW scan "$IMG" --reference-time "$REF" \
    --json "$OUT/report.json" --markdown "$OUT/report.md" --extract-to "$OUT/extracted"
echo
echo "reports: $OUT/report.json ($(wc -c < "$OUT/report.json" | tr -d ' ') bytes), $OUT/report.md"
echo "extracted files: $(find "$OUT/extracted" -type f | wc -l | tr -d ' ') (symlinks/devices recorded in .fwaudit-manifest.json, never created)"

banner "4. ground truth for this image vs. the report"
uv run --frozen python - "$EX/dev-0023-flash-squashfs-xz.truth.json" "$OUT/report.json" <<'PY'
import json, sys
from collections import Counter
truth = json.load(open(sys.argv[1]))
report = json.load(open(sys.argv[2]))
want = Counter((e["rule_id"], e["path"]) for e in truth["expected"])
got = Counter((f["rule_id"], f["path"]) for f in report["findings"])
print(f"planted: {sum(want.values())}  reported: {sum(got.values())}  "
      f"missed: {sum((want - got).values())}  unexpected: {sum((got - want).values())}")
PY

banner "5. hostile inputs: traversal, bombs, nesting, tampered header"
for f in "$EX"/hostile-*.bin; do
    $FW scan "$f" --json "$OUT/$(basename "$f" .bin).json" > /dev/null
done
uv run --frozen python - "$OUT"/hostile-*.json <<'PY'
import json, sys
for path in sys.argv[1:]:
    r = json.load(open(path))
    rules = ", ".join(sorted({f["rule_id"] for f in r["findings"]}))
    name, extracted = r["image"]["name"], r["summary"]["extracted_bytes"]
    print(f"{name:<32} extracted {extracted:>7} bytes -> {rules}")
PY
test ! -e /tmp/fwaudit-pwned && echo "traversal target /tmp/fwaudit-pwned was not created"

banner "6. CI gating: --fail-on high returns exit status 1 when HIGH+ findings exist"
set +e
$FW scan "$IMG" --reference-time "$REF" --fail-on high > /dev/null
status=$?
set -e
echo "exit status: $status"
