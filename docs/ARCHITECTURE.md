# fwaudit architecture

This document describes how an image flows through fwaudit, the algorithms used at each
stage, and their cost. Sizes: `n` = image bytes, `k` = number of signatures (14),
`h` = validated signature hits, `m` = extracted bytes, `f` = files in a mounted
filesystem.

## Module map

| Module | Responsibility |
|---|---|
| `limits.py` | `Limits` (frozen ceilings) and `Budget` (running totals shared by every decoder) |
| `errors.py` | `FwauditError` hierarchy: `FormatError`, `TruncatedError`, `UnsupportedFormatError`, `LimitExceededError`, `UnsafePathError`, `CveDatabaseError` |
| `model.py` | `Severity`, `Category`, the 30-rule catalogue, `Finding` (stable id = SHA-256 of rule, location and discriminator), `ExtractionNode` |
| `signatures.py` | Magic database, header validators, `scan()` and `match_at_start()` |
| `entropy.py` | Block entropy, region classification, sparkline |
| `formats/` | `uimage`, `compression` (bounded gzip/zlib/xz/lzma/bzip2), `cpio`, `tar`, `squashfs` readers; `entries.ArchiveEntry` is the format-neutral member |
| `extract/engine.py` | Recursive carving and mounting; converts every failure into a note or finding |
| `extract/pathsafe.py` | Member-name normalisation and chroot-style symlink joining |
| `vfs.py` | In-memory `VirtualFS` with safe insertion, symlink resolution and globbing |
| `extract/disk.py` | Optional hardened materialisation (`--extract-to`) |
| `audit/` | Checks (`accounts`, `configs`, `keys`, `components`, `services`, `permissions`), `cryptpw` (crypt(3) implementations), `versions` + `cvedb` (offline CVE matching), `base` (config, masking, text helpers) |
| `pipeline.py` | `audit_bytes()` / `audit_file()`: entropy, extraction, checks, raw-region key scan, de-duplication |
| `report/` | JSON report (`fwaudit-report/1`, validated against `schema.json` in tests) and Markdown report |
| `synth/` | Seeded ground-truth generator, deterministic SquashFS writer, deterministic PKI, hostile samples |
| `evaluation.py` | Multiset matching of findings against ground truth |
| `cli.py` | `scan`, `identify`, `entropy`, `synth`, `rules` |

## Pipeline

```
audit_bytes(data)
  ├─ size check against max_image_bytes
  ├─ entropy_map(data)                         O(n)
  ├─ Extractor(limits).run(data)               see below
  ├─ for each mounted VirtualFS: run_checks()  a crashing check is recorded, not fatal
  ├─ KeyAnalyzer over raw unclaimed regions    keys hidden in NVRAM/padding
  └─ dedupe(findings) and sort by severity     O(F log F)
```

## Identification: `signatures.scan`

For each signature, `bytes.find` walks the buffer for the magic (C speed), and the
signature's validator inspects only the header at each candidate: uImage header CRC (or
known OS/arch values when the CRC is wrong, so tampered images are still opened), gzip
flag/OS bytes, xz stream-flag CRC32, LZMA properties/dictionary plausibility, tar header
checksum (signed and unsigned variants), SquashFS superblock fields, cpio hex/octal
fields. Cost is O(k·n) for the searches plus O(c) validator work for c candidates; hits are
capped at 100,000 so a pathological file of repeated magics cannot blow up memory.

LZMA-alone has a 3-byte magic (`5d 00 00`) that occurs by chance in binary data, so it is
only trusted when the stream decodes completely, and it is never used to classify a file
inside a filesystem.

## Extraction: `extract/engine.py`

`_explore(blob)` is a greedy left-to-right carve, the strategy binwalk uses:

1. scan the blob, sorted by offset;
2. skip hits that start before the cursor (inside something already consumed);
3. decode the hit; the handler returns how many bytes the container occupied, and the
   cursor jumps past it;
4. bytes no container claimed become `RawRegion`s; any high-entropy run of 8 KiB or more
   in them is reported as `FWA-EXT-006`.

Handlers:

* **Streams** (gzip, xz, lzma, bzip2): decompress under the budget, then recurse into the
  output at depth + 1. Truncated streams are explored partially and noted.
* **uImage**: verify header and data CRC (mismatch is a finding, not an abort), split
  multi-file payloads (type 4), decode LZMA payloads that the header declares, recurse.
* **cpio / tar / SquashFS**: parse members into `ArchiveEntry` objects and mount them into
  a new `VirtualFS`. Every regular file whose first bytes match an extractable signature
  is explored again (this is how `defaults.tar.gz` inside the rootfs is reached).

Each recursion level charges the depth limit; each carve charges the carve limit; each
member charges the entry limit; each materialised byte charges the global byte limit.
`LimitExceededError` becomes `FWA-EXT-002` / `FWA-EXT-003` for that region, and the rest of
the image is still audited.

Cost: O(n) bytes scanned per level plus the decoders' linear cost in their output; total
work is bounded by `max_total_bytes` and `max_depth`.

## Bounded decompression: `formats/compression.py`

All decoders are incremental (`zlib.decompressobj`, `lzma.LZMADecompressor`,
`bz2.BZ2Decompressor`) and are fed 64 KiB of input at a time. Each call is asked for at
most

```
min(per-stream cap, remaining global budget, ratio_allowance(fed)) + 1 - produced
```

bytes, where `ratio_allowance(fed) = max(grace, max_ratio * fed)`. The `+1` makes crossing
a limit observable, after which `LimitExceededError` is raised. Peak memory is therefore
O(max_ratio x input fed) rather than O(per-stream cap): a 64 MiB gzip bomb (66 KB on disk)
peaks at 25 MiB of traced allocations instead of 141 MiB before this cap was introduced
(`scripts/bench.py`). The LZMA decoders also get a 256 MiB `memlimit` for their
dictionaries. The decoders report `consumed` input bytes from `unused_data`, which the
carver uses to continue after the stream.

## SquashFS: `formats/squashfs.py`

PySquashfsImage does the directory and inode walking. fwaudit subclasses its image class
to replace the compressors with ones that never produce more than one block (block size
for data, 8 KiB for metadata), validates the superblock first (version 4.0, block size a
power of two between 4 KiB and 1 MiB matching `block_log`, `bytes_used` within the input,
gzip or xz compressor), charges every member against the budget, and converts any library
exception (including `RecursionError` from cyclic directory tables) into `FormatError`.
Big-endian and pre-4.0 images raise `UnsupportedFormatError` and appear as `FWA-EXT-005`.

The test-suite builds SquashFS images with an independent in-repo writer
(`synth/squashfs_writer.py`) and reads them back through the library, so neither side can
silently drift.

## Virtual filesystem and path safety

`pathsafe.normalize_member` rejects empty names, NUL bytes, names longer than 4096 bytes
and **any** `..` component (even `a/../b`, which would stay inside the root, because
legitimate firmware never needs it and allowing it makes the check order-dependent). A
leading `/` is stripped and noted, like GNU tar.

`VirtualFS.add_entry` then creates missing parents and refuses to write through a symlinked
parent (the classic `link -> /etc` then `link/cron.d/x` attack); only that and `..` are
reported as traversal (`FWA-EXT-001`). Symlinks are stored, never followed at insertion.
`resolve()` follows them component by component with chroot semantics (an absolute target
restarts at the virtual root; `..` cannot climb above it) and stops after 40 hops, so
loops terminate. Lookups are O(depth) dictionary operations.

`extract/disk.py` (only for `--extract-to`) writes regular files and directories with
`O_CREAT | O_EXCL | O_NOFOLLOW`, strips setuid/setgid/sticky and group/world-write bits,
re-checks that every parent resolves inside the destination, and records symlinks and
device nodes in `.fwaudit-manifest.json` instead of creating them.

## Entropy map: `entropy.py`

For each chunk of up to 4 MiB the bytes are turned into indices `block * 256 + byte`, and
one `numpy.bincount` produces all per-block histograms at once; entropy is
`-Σ p log2 p` per row. Time O(n), memory O(chunk + n / block). Adjacent blocks of the same
class (`high` ≥ 7.2 bits/byte, `low` ≤ 1.0, else `mixed`) merge into regions.

## Checks

| Check | Approach | Cost |
|---|---|---|
| accounts | Parse passwd/shadow; passwd field overrides shadow; per hash: scheme, weak flag, then try each default password for that user (`crack`) | O(users x defaults x hash cost); sha-crypt rounds capped at 50,000 per guess |
| config secrets | Text files under system prefixes, ≤ 256 KiB, ≥ 90 % printable; per line: chpasswd, URL credentials, UCI `option`, key=value / quoted JSON-YAML keys; placeholders, booleans and policy keys (`password_min_len`) excluded | O(total text) |
| keys | Linear PEM scanner (BEGIN headers matched in one pass, END markers indexed once, paired by binary search; body ≤ 64 KiB) parsed with `cryptography`; dropbear binary host keys decoded from their SSH-string layout; DER certificates by extension; certificate expiry against `reference_time` | O(file bytes · log) |
| components | Four compiled regexes over ELF files only; each (component, version) is matched against OSV-style ranges (`introduced <= v < fixed` or `<= last_affected`) | O(ELF bytes + CVEs) |
| services | Startup files by glob; commands only count in command position (start of line, inittab process field, after exec / nohup / start-stop-daemon); inetd and xinetd service blocks; htpasswd / htdigest / BusyBox httpd.conf credentials checked against defaults; vsftpd, snmpd, sshd_config | O(config text x defaults) |
| permissions | Mode bits from the archive metadata | O(f) |

Version ordering (`audit/versions.py`) maps OpenSSL letter releases to extra tuple
elements (`1.0.2` < `1.0.2a` < `1.0.2z` < `1.0.2za`) and Dropbear's `YYYY.NN` to a numeric
tuple, so plain tuple comparison works for all four components.

## Reports

Findings are de-duplicated by an identity key (rule, filesystem id, path, offset,
discriminator) and sorted by severity, rule and location. The JSON report sorts keys and
contains no wall-clock time, so the same image and settings give a byte-identical report
(`tests/test_golden.py`). Secrets are masked to a two-character hint plus length unless
`show_secrets` is set; the raw value never enters evidence otherwise.

## Synthetic ground truth

`synth/firmware.py` builds every image in memory from a `random.Random(f"{split}:{seed}")`,
so a sample is reproducible from its name. Keys come from seeded primes (RSA) or
`derive_private_key` (EC), and certificates use deterministic signatures (PKCS#1 v1.5 or
RFC 6979 ECDSA), so images are byte-identical across runs and machines. The generator
records an `Expected` entry for every planted weakness at the moment it plants it.
