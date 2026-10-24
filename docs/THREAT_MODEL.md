# Threat model

## Scope and intended use

fwaudit is a defensive, offline analysis tool. It reads a firmware image that the operator
already has (their own product build, or an image obtained for an authorised assessment),
and reports weaknesses in it. It never connects to a device, never uses discovered
credentials against anything, and has no network code (the only network access in the
repository is the optional `scripts/verify_cvedb.py`, which queries the public NVD API for
the bundled CVE ids).

All test and demo images are synthetic and built by this repository. The "hostile" samples
are benign data shaped like unpacker attacks (traversal names, compression bombs); they
contain no executable payloads.

## Assets

1. The analyst's host: filesystem integrity, memory and CPU.
2. Secrets recovered from the image (passwords, keys) once they are in a report.
3. The correctness of the report (a missed finding or a wrong CVE match misleads).

## Adversary

The image author. Firmware under audit is attacker-controlled input: the adversary can
choose every byte, including container headers, member names, compression streams,
filesystem tables and file contents, and may craft the image specifically to attack
analysis tools or to hide weaknesses from them.

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Path traversal while unpacking (`../`, absolute names, writes through a planted symlink) | No disk writes while auditing: everything is mounted into an in-memory `VirtualFS`. Names with `..` are rejected; writes through symlinked parents are rejected; both are reported as `FWA-EXT-001`. `--extract-to` writes with `O_EXCL | O_NOFOLLOW`, re-checks containment, never creates symlinks or device nodes | `extract/pathsafe.py`, `vfs.py`, `extract/disk.py` |
| Symlink loops / deep chains used to hang resolution | Resolution capped at 40 hops; chroot semantics | `vfs.py` |
| Decompression bombs (single stream, nested, or squashfs blocks) | Per-call output cap at the ratio allowance, per-stream cap (256 MiB), global cap (768 MiB), ratio cap (200:1 after 4 MiB grace), LZMA `memlimit`; squashfs blocks capped at block size | `formats/compression.py`, `limits.py`, `formats/squashfs.py` |
| Nesting bombs (gzip of gzip of ...) | Depth limit 8 (`FWA-EXT-003`) | `extract/engine.py` |
| Entry / carve floods | 200,000 entries, 512 carves, 100,000 signature hits | `limits.py`, `signatures.py` |
| Oversized inputs | Image size checked against `max_image_bytes` before reading | `pipeline.py` |
| Parser crashes (malformed headers, truncation, cyclic squashfs directories) | Every parser raises `FormatError`; the engine turns it into a note and continues; library exceptions and `RecursionError` are converted. Hypothesis property tests feed random and mutated images and assert no exception and no check errors | `formats/*`, `tests/test_fuzz.py`, `tests/test_formats.py` |
| CPU exhaustion through crypt rounds (`$6$rounds=999999999$`) | Hashes with more than 50,000 rounds are not tried | `audit/cryptpw.py` |
| Regex denial of service | PEM body match bounded to 64 KiB; config scanning restricted to text files ≤ 256 KiB and applied line by line | `audit/keys.py`, `audit/configs.py` |
| A broken check aborting the audit | Checks run under a per-check exception boundary; failures are listed in `check_errors` | `audit/__init__.py` |
| Tampered CVE database making old components look clean | SHA-256 pin of `cve_subset.json` compiled into the code and checked on load | `audit/cvedb.py` |
| Secret leakage via reports or CI logs | Secrets masked (2-character hint and length) unless `--show-secrets` | `audit/base.py` |
| Hiding weaknesses: tampered uImage headers | Header CRC mismatch is reported and the payload is still opened (validator accepts known OS/arch values) | `formats/uimage.py`, `signatures.py` |
| Hiding weaknesses: secrets in nested archives or raw partitions | Files that are containers are explored; unclaimed regions are scanned for keys; unexplained high entropy is reported | `extract/engine.py`, `pipeline.py` |

## Residual risks

* **Evasion is easy** for a motivated author: unsupported formats (UBIFS, JFFS2, LZ4
  SquashFS), encryption, custom headers, obfuscated config files or stripped version
  strings all reduce what fwaudit can see. Unsupported-but-recognised containers and
  high-entropy regions are reported, but an absence of findings is never evidence of
  safety.
* **Third-party parsers:** PySquashfsImage, `tarfile`, `zlib`, `lzma`, `bz2` and
  `cryptography` parse attacker bytes. They are wrapped and bounded, but a memory-safety
  bug in a C extension would be outside fwaudit's control. Run audits of untrusted images
  in a disposable container or VM.
* **Memory:** limits bound extracted data (768 MiB by default) but the image itself is read
  fully into memory (up to `max_image_bytes`, 1 GiB by default).
* **Masked secrets** still reveal two characters and the length.
