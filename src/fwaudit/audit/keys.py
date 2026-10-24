"""Embedded key material: private keys and X.509 certificates.

PEM blocks are located in linear time (BEGIN headers matched in one pass, END markers
indexed in one pass and paired by binary search) and parsed with ``cryptography``; DER
certificates are recognised by extension, and dropbear's binary host-key format is decoded
directly. The same analysis runs on files inside mounted filesystems and on raw image
regions that no container claimed (e.g. a key sitting in an NVRAM partition).

Each private key is fingerprinted (SHA-256 of its SubjectPublicKeyInfo) so the report can
show when one key is reused across several locations.
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from fwaudit.audit.base import AuditConfig
from fwaudit.model import Finding, JsonValue, Severity, make_finding
from fwaudit.vfs import VirtualFS

PEM_MAX_BODY = 65536
_PEM_BEGIN_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")
# Lookahead so END markers that overlap (``-----END A-----END B-----``) are all indexed.
_PEM_END_RE = re.compile(rb"(?=-----END ([A-Z0-9 ]{3,40})-----)")


@dataclass(frozen=True)
class PemBlock:
    start: int
    label: bytes
    block: bytes
    body: bytes


def iter_pem_blocks(data: bytes, max_body: int = PEM_MAX_BODY) -> Iterator[PemBlock]:
    """Yield PEM blocks in order, in O(n log n) time for adversarial input.

    Same blocks as the backtracking pattern
    ``-----BEGIN (L)-----(.{1,65536}?)-----END (?P=L)-----`` (DOTALL) under ``finditer``:
    each BEGIN pairs with the first END of the same label whose body is 1..``max_body``
    bytes,
    the scan resumes after a matched END, and a BEGIN without a partner is skipped by one
    byte. That pattern costs O(n x 64 KiB) on a flood of unmatched BEGIN headers; here every
    END marker is indexed once and each BEGIN is a binary search.
    """
    if b"-----BEGIN " not in data:
        return
    ends: dict[bytes, list[int]] = {}
    for end_match in _PEM_END_RE.finditer(data):
        ends.setdefault(end_match.group(1), []).append(end_match.start())
    pos = 0
    while (m := _PEM_BEGIN_RE.search(data, pos)) is not None:
        label = m.group(1)
        positions = ends.get(label)
        if positions:
            body_start = m.end()
            i = bisect.bisect_left(positions, body_start + 1)
            if i < len(positions) and positions[i] <= body_start + max_body:
                end = positions[i]
                stop = end + len(b"-----END ") + len(label) + len(b"-----")
                yield PemBlock(m.start(), label, data[m.start() : stop], data[body_start:end])
                pos = stop
                continue
        pos = m.start() + 1


PRIVATE_LABELS = {
    b"RSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
}
CERT_LABELS = {b"CERTIFICATE", b"X509 CERTIFICATE"}
DER_EXTENSIONS = (".der", ".cer", ".crt")
WEAK_BITS = 2048
WEAK_SIG_HASHES = {"md5", "sha1"}

PublicKey = (
    rsa.RSAPublicKey
    | dsa.DSAPublicKey
    | ec.EllipticCurvePublicKey
    | ed25519.Ed25519PublicKey
    | ed448.Ed448PublicKey
)


@dataclass(frozen=True)
class KeyInfo:
    algorithm: str
    bits: int | None
    fingerprint: str | None


def describe_public(key: object) -> KeyInfo:
    """Algorithm, size and SPKI SHA-256 fingerprint of a public key."""
    fp: str | None = None
    if isinstance(key, PublicKey):
        der = key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fp = "sha256:" + hashlib.sha256(der).hexdigest()
    if isinstance(key, rsa.RSAPublicKey):
        return KeyInfo("rsa", key.key_size, fp)
    if isinstance(key, dsa.DSAPublicKey):
        return KeyInfo("dsa", key.key_size, fp)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return KeyInfo(f"ec-{key.curve.name}", key.curve.key_size, fp)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return KeyInfo("ed25519", 256, fp)
    if isinstance(key, ed448.Ed448PublicKey):
        return KeyInfo("ed448", 456, fp)
    return KeyInfo("unknown", None, fp)


def _openssh_encrypted(body: bytes) -> bool:
    try:
        blob = base64.b64decode(b"".join(body.split()), validate=False)
    except ValueError:
        return False
    magic = b"openssh-key-v1\x00"
    if not blob.startswith(magic) or len(blob) < len(magic) + 4:
        return False
    (n,) = struct.unpack_from(">I", blob, len(magic))
    cipher = blob[len(magic) + 4 : len(magic) + 4 + n]
    return cipher != b"none"


def _load_private(label: bytes, pem: bytes) -> KeyInfo | None:
    try:
        if label == b"OPENSSH PRIVATE KEY":
            return describe_public(serialization.load_ssh_private_key(pem, None).public_key())
        return describe_public(serialization.load_pem_private_key(pem, None).public_key())
    except (ValueError, TypeError, NotImplementedError, UnsupportedAlgorithm):
        return None


def _ssh_strings(blob: bytes, count: int) -> list[bytes]:
    out: list[bytes] = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(blob):
            raise ValueError("truncated ssh string")
        (n,) = struct.unpack_from(">I", blob, pos)
        pos += 4
        if n > 16384 or pos + n > len(blob):
            raise ValueError("implausible ssh string length")
        out.append(blob[pos : pos + n])
        pos += n
    return out


def parse_dropbear_key(blob: bytes) -> KeyInfo | None:
    """Decode the key type and size of a dropbear binary host key."""
    try:
        (ktype,) = _ssh_strings(blob, 1)
        if ktype == b"ssh-rsa":
            _, _e, n = _ssh_strings(blob, 3)
            return KeyInfo("rsa", int.from_bytes(n, "big").bit_length(), None)
        if ktype == b"ssh-dss":
            _, p, *_ = _ssh_strings(blob, 2)
            return KeyInfo("dsa", int.from_bytes(p, "big").bit_length(), None)
        if ktype.startswith(b"ecdsa-sha2-"):
            curve = ktype.decode()[len("ecdsa-sha2-") :]
            bits = {"nistp256": 256, "nistp384": 384, "nistp521": 521}.get(curve)
            return KeyInfo(f"ec-{curve}", bits, None)
        if ktype == b"ssh-ed25519":
            return KeyInfo("ed25519", 256, None)
    except ValueError:
        return None
    return None


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    return name.rfc4514_string()


class KeyAnalyzer:
    """Turns key material found in a byte buffer into findings."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    def analyze(
        self,
        data: bytes,
        *,
        filesystem: str,
        path: str | None,
        base_offset: int | None = None,
    ) -> list[Finding]:
        out: list[Finding] = []
        for index, pem in enumerate(iter_pem_blocks(data)):
            loc = _Loc(filesystem, path, base_offset, pem.start, index)
            if pem.label in PRIVATE_LABELS:
                out += self._private(pem.label, pem.block, pem.body, loc)
            elif pem.label in CERT_LABELS:
                try:
                    cert = x509.load_pem_x509_certificate(pem.block)
                except ValueError:
                    continue
                out += self._certificate(cert, loc)
        return out

    def analyze_der_certificate(self, data: bytes, *, filesystem: str, path: str) -> list[Finding]:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError:
            return []
        return self._certificate(cert, _Loc(filesystem, path, None, 0, 0))

    def analyze_dropbear(self, data: bytes, *, filesystem: str, path: str) -> list[Finding]:
        info = parse_dropbear_key(data)
        if info is None:
            return []
        loc = _Loc(filesystem, path, None, 0, 0)
        out = [
            loc.finding(
                "FWA-KEY-001",
                f"dropbear host private key ({info.algorithm}, {info.bits} bits) in the image",
                {
                    "format": "dropbear",
                    "algorithm": info.algorithm,
                    "bits": info.bits,
                    "encrypted": False,
                },
            )
        ]
        out += self._weak_size(info, loc, "dropbear host key")
        return out

    # ---------------------------------------------------------------- internals
    def _private(self, label: bytes, pem: bytes, body: bytes, loc: _Loc) -> list[Finding]:
        encrypted = (
            label == b"ENCRYPTED PRIVATE KEY"
            or b"Proc-Type: 4,ENCRYPTED" in body
            or (label == b"OPENSSH PRIVATE KEY" and _openssh_encrypted(body))
        )
        info = None if encrypted else _load_private(label, pem)
        algo = info.algorithm if info else label.decode().replace(" PRIVATE KEY", "").lower()
        evidence: dict[str, JsonValue] = {
            "format": "pem",
            "label": label.decode(),
            "algorithm": algo or "pkcs8",
            "bits": info.bits if info else None,
            "encrypted": encrypted,
            "fingerprint": info.fingerprint if info else None,
            "parsed": info is not None,
        }
        detail = f"{label.decode()} ({'passphrase-protected' if encrypted else 'unencrypted'}"
        detail += f", {info.algorithm} {info.bits} bits)" if info else ")"
        out = [
            loc.finding(
                "FWA-KEY-001",
                detail,
                evidence,
                severity=Severity.MEDIUM if encrypted else None,
            )
        ]
        if info is not None:
            out += self._weak_size(info, loc, "private key")
        return out

    def _weak_size(self, info: KeyInfo, loc: _Loc, what: str) -> list[Finding]:
        if info.algorithm in ("rsa", "dsa") and info.bits is not None and info.bits < WEAK_BITS:
            return [
                loc.finding(
                    "FWA-KEY-004",
                    f"{what} is {info.algorithm.upper()}-{info.bits}",
                    {"algorithm": info.algorithm, "bits": info.bits, "subject": what},
                )
            ]
        return []

    def _certificate(self, cert: x509.Certificate, loc: _Loc) -> list[Finding]:
        ref = self.config.reference_time
        not_after = cert.not_valid_after_utc
        subject, issuer = _cn(cert.subject), _cn(cert.issuer)
        info = describe_public(cert.public_key())
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"
        days_left = (not_after - ref).days
        evidence: dict[str, JsonValue] = {
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "self_signed": cert.subject == cert.issuer,
            "key_algorithm": info.algorithm,
            "key_bits": info.bits,
            "signature_hash": sig_hash,
            "serial": format(cert.serial_number, "x"),
        }
        out = [
            loc.finding(
                "FWA-KEY-006",
                f"certificate CN={subject} issued by CN={issuer}, valid until {not_after.date()}",
                evidence,
            )
        ]
        if not_after < ref:
            out.append(
                loc.finding(
                    "FWA-KEY-002",
                    f"certificate CN={subject} expired on {not_after.date()} "
                    f"({-days_left} days before the reference time)",
                    {"subject": subject, "not_after": not_after.isoformat()},
                )
            )
        elif not_after - ref <= timedelta(days=self.config.expiry_warning_days):
            out.append(
                loc.finding(
                    "FWA-KEY-003",
                    f"certificate CN={subject} expires on {not_after.date()} "
                    f"({days_left} days left)",
                    {"subject": subject, "not_after": not_after.isoformat()},
                )
            )
        if sig_hash in WEAK_SIG_HASHES:
            out.append(
                loc.finding(
                    "FWA-KEY-005",
                    f"certificate CN={subject} is signed with {sig_hash.upper()}",
                    {"subject": subject, "signature_hash": sig_hash},
                )
            )
        out += self._weak_size(info, loc, f"certificate CN={subject} key")
        return out


@dataclass(frozen=True)
class _Loc:
    filesystem: str
    path: str | None
    base_offset: int | None
    offset: int
    index: int

    def finding(
        self,
        rule_id: str,
        detail: str,
        evidence: dict[str, JsonValue],
        *,
        severity: Severity | None = None,
    ) -> Finding:
        ev = dict(evidence)
        ev["key"] = str(self.index)
        abs_offset = None if self.base_offset is None else self.base_offset + self.offset
        if self.path is not None:
            ev["block_offset"] = self.offset
        return make_finding(
            rule_id,
            detail,
            filesystem=self.filesystem,
            path=self.path,
            offset=abs_offset,
            severity=severity,
            evidence=ev,
        )


class KeysCheck:
    name = "keys"

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        analyzer = KeyAnalyzer(config)
        out: list[Finding] = []
        for node in fs.files():
            if not node.data or len(node.data) > config.max_scan_file_bytes:
                continue
            base = node.path.rsplit("/", 1)[-1]
            if base.startswith("dropbear_") and base.endswith("_host_key"):
                out += analyzer.analyze_dropbear(node.data, filesystem=fs.fs_id, path=node.path)
            elif base.endswith(DER_EXTENSIONS) and node.data[:2] == b"\x30\x82":
                out += analyzer.analyze_der_certificate(
                    node.data, filesystem=fs.fs_id, path=node.path
                )
            else:
                out += analyzer.analyze(node.data, filesystem=fs.fs_id, path=node.path)
        return out
