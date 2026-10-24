# Decisions

Rulings made while building fwaudit, in the form
`Ruling: <what> — <why> — <cost if wrong>`.

## Architecture

- Ruling: Mount every archive and filesystem into an in-memory `VirtualFS`; never unpack to disk while auditing — removes the whole class of path-traversal and symlink-following bugs from the audit path and makes the audit side-effect free — memory use scales with extracted data (bounded by `max_total_bytes`, 768 MiB default); multi-GiB images need a streaming design.
- Ruling: One `Budget` shared by every decoder and parser for one audit — limits must hold across nesting, otherwise a bomb split over many layers passes each local check — a single legitimately huge image hits the global cap and needs `--max-total-mb`.
- Ruling: Greedy left-to-right carve (skip hits inside already-consumed regions) — same strategy as binwalk, O(h) after the scan, and avoids double-counting nested streams — a container whose declared length is wrong can hide a following container; gaps are still scanned for keys and entropy.
- Ruling: Reject any `..` member component, even when it stays inside the root — legitimate firmware never needs it and order-independent checks are easier to trust — a strange but benign archive loses those members (reported, not silent).
- Ruling: Only `..` and writes through a symlinked parent are `FWA-EXT-001` (traversal); other inconsistent members (file under a file, hard link to a missing target) are notes — keeps the HIGH rule meaningful — some malformed-but-harmless archives produce notes only.
- Ruling: A failing check is caught, logged and listed in `check_errors`; the audit continues — one bug must not hide every other finding — a crashing check could go unnoticed if nobody reads `check_errors` (tests assert it is empty).

## Formats

- Ruling: SquashFS through PySquashfsImage 0.9.0 (pure Python, LGPL) with bounded compressors and superblock validation, not `unsquashfs` — no external binary is installed on the build machine or guaranteed in CI, and a library call keeps everything in memory — slower than native tools on big images; LGPL dependency (used unmodified via import).
- Ruling: Support gzip and xz SquashFS only; LZO/LZ4/ZSTD reported as `FWA-EXT-005` — these need third-party native packages; reporting the gap is better than a silent skip — many real vendor images use LZO or XZ-with-BCJ variants we have not tested.
- Ruling: tar headers decoded by the stdlib `tarfile`, but never its extraction functions — reuses a mature header parser (GNU/pax long names) while keeping writes impossible — inherits any `tarfile` header-parsing bug; data is still bounded.
- Ruling: LZMA-alone streams are trusted only when they decode to completion, and are never used to classify files inside a filesystem — the 3-byte magic occurs by chance in binaries — a truncated genuine LZMA stream is not explored (uImage-declared LZMA payloads are still decoded).
- Ruling: Accept a uImage with a bad header CRC if its OS/arch fields are known values — tampered images are what an auditor needs to look inside — slightly more false-positive uImage hits in random data (they then fail payload validation).

## Detection

- Ruling: Implement md5-crypt, apr1 and sha256/512-crypt in pure Python; do not implement DES crypt — the stdlib `crypt` module is removed in Python 3.13 and DES needs a full DES implementation for a scheme already flagged weak — default passwords behind DES hashes are not reported as `FWA-CRED-004`.
- Ruling: Skip hashes with more than 50,000 sha-crypt rounds — an image can set `rounds=999999999` to stall the audit — a default password behind a very high round count is missed.
- Ruling: Default credentials are a 28-pair list of widely published embedded defaults (vendor manuals, IoT botnet research), plus "password equals user name" — enough to show the mechanism without shipping a cracking dictionary — real images with other defaults are missed.
- Ruling: Version detection only in ELF files, first match per component per file — documentation and scripts mention versions that do not run (the generator plants exactly that as a negative control) — a version only present in a non-ELF file (e.g. a Lua module) is missed.
- Ruling: CVE matching uses OSV-style ranges and NVD's machine-readable CPE configuration where it disagrees with the free-text description (CVE-2022-48174: description says "before 1.35", CPE says through 1.36.1; we use the CPE range) — the CPE data is what tooling and scanners consume, and it is what `scripts/verify_cvedb.py` can check — may over-report busybox 1.35-1.36.1 if NVD's CPE data is too broad.
- Ruling: Component CVE findings take the severity of the worst CVSS v3 score in the subset — matches common scanner practice — CVSS overstates risk for features a device may not use (e.g. the busybox ash bug needs local shell input).
- Ruling: Certificate expiry is evaluated against an explicit `reference_time` (default: now; tests and demo use 2026-01-01) — deterministic reports and reproducible tests — a user who forgets the flag sees verdicts relative to today, which is the intended default.
- Ruling: Telnet/dropbear daemons count only when started in command position (line start, inittab process field, after exec/nohup/start-stop-daemon) — avoids false positives from comments, `echo` lines and `killall telnetd` — a daemon started indirectly (via a variable or a helper function) is missed.
- Ruling: Secrets are masked to a 2-character hint plus length unless `--show-secrets` — reports end up in CI logs and tickets — the hint and length leak a little information.

## Evaluation and honesty

- Ruling: Ground truth is synthetic and built in-repo by a seeded generator; expected CVE ids are written by hand from NVD ranges, not computed with fwaudit's matcher — real firmware with labelled findings does not exist under a redistributable licence, and computing expectations with the code under test would make the CVE evaluation circular — perfect scores only show coverage of the generator's forms, which the README states.
- Ruling: Two splits: `dev` forms used while writing detectors, `holdout` adds forms fixed before evaluation (CRLF, JSON, xinetd, DER, vendor paths, tab UCI, rc.local, /etc/httpd) — measures generalisation to unseen shapes within the synthetic world — the forms are still chosen by the same author.
- Ruling: Report the first held-out run (seeds 0-99, recall 0.985, 27 misses in two forms) as the generalisation number, fix both misses, and report the post-fix run on fresh seeds 100-199 with the caveat that the fixed forms are no longer unseen — the contract forbids tuning and reporting on the same split — the post-fix 1.000 could be misread if quoted without the caveat; the README table labels both rows.
- Ruling: The CVE subset `source` field says "cross-checked against the live API on 2026-10-25 with scripts/verify_cvedb.py" because that script was run on that date and reported 20/20 agreement (output in the build report) — an unverifiable "retrieved from" claim would be weaker — NVD records change; re-run `make verify-cvedb` before relying on it.
- Ruling: Benchmarks report medians on a shared laptop and are labelled order-of-magnitude — six other builds were running concurrently — absolute numbers will differ elsewhere; the bomb peak-memory numbers are allocation counts and are stable.

## Tooling

- Ruling: Coverage gate at 90 % branch coverage over the whole package (measured 96.3-96.5 %), including the synthetic generator — the contract asks for ≥ 80 % on core logic; the stricter whole-package gate is simpler to state — a future large generator change could block CI on coverage of test-only code.
- Ruling: Bundle 8 small synthetic images (332 KiB) in `examples/firmware` and assert in tests that they equal the generator output — the demo should run from committed fixtures, and drift is caught — regenerating requires `make fixtures`.
- Ruling: `scripts/` is on the pytest `pythonpath` so helper scripts are unit-tested without being part of the package — keeps the published package free of evaluation code — scripts are not importable from an installed wheel.
