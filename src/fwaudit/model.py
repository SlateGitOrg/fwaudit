"""Core data model: severities, rules, findings and the extraction tree."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

JsonValue = str | int | float | bool | None | list[Any] | dict[str, Any]


class Severity(IntEnum):
    """Ordered severity scale; comparisons work numerically (CRITICAL > HIGH)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {text!r}") from None


class Category(StrEnum):
    EXTRACTION = "extraction"
    CREDENTIALS = "credentials"
    CRYPTO = "crypto"
    COMPONENT = "component"
    SERVICE = "service"
    PERMISSIONS = "permissions"


@dataclass(frozen=True)
class Rule:
    """Static description of one kind of finding."""

    rule_id: str
    category: Category
    severity: Severity
    title: str
    remediation: str


_RULE_LIST: tuple[Rule, ...] = (
    Rule("FWA-EXT-001", Category.EXTRACTION, Severity.HIGH,
         "Archive member path escapes the extraction root",
         "Treat the image as hostile; never unpack it with tools that honour '..' or "
         "write through symlinks."),
    Rule("FWA-EXT-002", Category.EXTRACTION, Severity.MEDIUM,
         "Decompression safety limit reached (possible decompression bomb)",
         "Inspect the stream manually; raise limits only if the data is trusted."),
    Rule("FWA-EXT-003", Category.EXTRACTION, Severity.LOW,
         "Container nesting deeper than the configured limit",
         "Raise --max-depth if the nesting is legitimate."),
    Rule("FWA-EXT-004", Category.EXTRACTION, Severity.MEDIUM,
         "Image integrity check failed (CRC mismatch)",
         "Obtain the image from a trusted source; a CRC mismatch indicates corruption "
         "or tampering."),
    Rule("FWA-EXT-005", Category.EXTRACTION, Severity.INFO,
         "Container recognised but could not be fully decoded",
         "Extract this region with a specialised tool; findings inside it are missing."),
    Rule("FWA-EXT-006", Category.EXTRACTION, Severity.INFO,
         "Unidentified high-entropy region (encrypted or unknown compression)",
         "Determine whether the region is encrypted; encrypted firmware cannot be "
         "audited without the vendor key."),
    Rule("FWA-CRED-001", Category.CREDENTIALS, Severity.CRITICAL,
         "Login account with an empty password",
         "Set a password or lock the account ('!' in /etc/shadow)."),
    Rule("FWA-CRED-002", Category.CREDENTIALS, Severity.HIGH,
         "Password hash stored in world-readable /etc/passwd",
         "Move hashes to /etc/shadow with mode 0600/0640."),
    Rule("FWA-CRED-003", Category.CREDENTIALS, Severity.MEDIUM,
         "Password hashed with a weak algorithm (DES or MD5 crypt)",
         "Use sha512-crypt, bcrypt or yescrypt."),
    Rule("FWA-CRED-004", Category.CREDENTIALS, Severity.CRITICAL,
         "Hardcoded default password (hash cracked with the offline default list)",
         "Remove factory-default passwords; force a unique password at first boot."),
    Rule("FWA-CRED-005", Category.CREDENTIALS, Severity.HIGH,
         "Non-root account with UID 0",
         "Remove the account or give it an unprivileged UID."),
    Rule("FWA-CRED-006", Category.CREDENTIALS, Severity.HIGH,
         "Hardcoded credential in configuration or script",
         "Provision secrets per device at runtime instead of baking them into the image."),
    Rule("FWA-CRED-007", Category.CREDENTIALS, Severity.MEDIUM,
         "Shadow password file is world-readable",
         "chmod 0600 /etc/shadow (or 0640 root:shadow)."),
    Rule("FWA-KEY-001", Category.CRYPTO, Severity.HIGH,
         "Embedded private key",
         "Generate keys per device at first boot; never ship a shared private key."),
    Rule("FWA-KEY-002", Category.CRYPTO, Severity.MEDIUM,
         "Expired certificate",
         "Replace the certificate; clients may be trained to ignore TLS errors."),
    Rule("FWA-KEY-003", Category.CRYPTO, Severity.LOW,
         "Certificate expires within 90 days of the reference time",
         "Plan certificate rotation before expiry."),
    Rule("FWA-KEY-004", Category.CRYPTO, Severity.MEDIUM,
         "Weak key size (RSA/DSA below 2048 bits)",
         "Use RSA >= 2048 bits or an elliptic-curve key."),
    Rule("FWA-KEY-005", Category.CRYPTO, Severity.LOW,
         "Certificate signed with a weak hash (MD5 or SHA-1)",
         "Re-issue the certificate with SHA-256 or better."),
    Rule("FWA-KEY-006", Category.CRYPTO, Severity.INFO,
         "Certificate inventory",
         "Informational: track certificate expiry and ownership."),
    Rule("FWA-CMP-001", Category.COMPONENT, Severity.INFO,
         "Third-party component version identified",
         "Informational: keep an SBOM of shipped components."),
    Rule("FWA-CMP-002", Category.COMPONENT, Severity.HIGH,
         "Component version affected by known CVEs (offline subset)",
         "Upgrade the component to a fixed release."),
    Rule("FWA-SVC-001", Category.SERVICE, Severity.HIGH,
         "Telnet service enabled",
         "Remove telnetd from init scripts and inetd; use SSH with key authentication."),
    Rule("FWA-SVC-002", Category.SERVICE, Severity.CRITICAL,
         "Web interface protected by default credentials",
         "Force the user to set a unique password on first login."),
    Rule("FWA-SVC-003", Category.SERVICE, Severity.MEDIUM,
         "Anonymous FTP enabled",
         "Set anonymous_enable=NO unless anonymous access is required."),
    Rule("FWA-SVC-004", Category.SERVICE, Severity.MEDIUM,
         "SNMP default community string",
         "Use SNMPv3 with authentication or unique community strings."),
    Rule("FWA-SVC-005", Category.SERVICE, Severity.LOW,
         "SSH permits root password login",
         "Disable password authentication for root (dropbear -g/-s, PermitRootLogin no)."),
    Rule("FWA-PERM-001", Category.PERMISSIONS, Severity.CRITICAL,
         "World-writable setuid/setgid file",
         "Remove the world-writable bit; any local user can replace the binary."),
    Rule("FWA-PERM-002", Category.PERMISSIONS, Severity.INFO,
         "setuid-root executable",
         "Informational: review whether the binary needs setuid."),
    Rule("FWA-PERM-003", Category.PERMISSIONS, Severity.MEDIUM,
         "World-writable file in a system directory",
         "Remove the world-writable bit."),
    Rule("FWA-PERM-004", Category.PERMISSIONS, Severity.LOW,
         "World-writable directory without the sticky bit",
         "Set the sticky bit (chmod +t) or remove world-write."),
)  # fmt: skip

RULES: dict[str, Rule] = {r.rule_id: r for r in _RULE_LIST}


def rule(rule_id: str) -> Rule:
    try:
        return RULES[rule_id]
    except KeyError:
        raise KeyError(f"unknown rule id {rule_id!r}") from None


@dataclass(frozen=True)
class Finding:
    """One concrete issue located in the image.

    ``filesystem`` is the extraction-node id of the filesystem the path lives in, or the
    id of the raw blob for image-level findings (then ``path`` is ``None`` and ``offset``
    is set). ``evidence`` must never contain unmasked secrets.
    """

    rule_id: str
    severity: Severity
    title: str
    detail: str
    filesystem: str
    path: str | None = None
    offset: int | None = None
    evidence: dict[str, JsonValue] = field(default_factory=dict)

    @property
    def category(self) -> Category:
        return rule(self.rule_id).category

    @property
    def key(self) -> str:
        """Identity used for de-duplication and for the stable finding id."""
        discriminator = self.evidence.get("key", "")
        return "|".join(
            (
                self.rule_id,
                self.filesystem,
                self.path or "",
                "" if self.offset is None else str(self.offset),
                str(discriminator),
            )
        )

    @property
    def finding_id(self) -> str:
        return "F-" + hashlib.sha256(self.key.encode()).hexdigest()[:12]

    def sort_key(self) -> tuple[int, str, str, str, int, str]:
        return (
            -int(self.severity),
            self.rule_id,
            self.filesystem,
            self.path or "",
            self.offset if self.offset is not None else -1,
            self.key,
        )


def make_finding(
    rule_id: str,
    detail: str,
    *,
    filesystem: str,
    path: str | None = None,
    offset: int | None = None,
    severity: Severity | None = None,
    evidence: dict[str, JsonValue] | None = None,
) -> Finding:
    """Build a finding using the rule's default title and severity."""
    r = rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=r.severity if severity is None else severity,
        title=r.title,
        detail=detail,
        filesystem=filesystem,
        path=path,
        offset=offset,
        evidence=dict(evidence or {}),
    )


@dataclass
class ExtractionNode:
    """A region of bytes that was identified, decoded or mounted during extraction."""

    node_id: str
    kind: str
    offset: int
    length: int
    depth: int
    parent: str | None
    meta: dict[str, JsonValue] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "offset": self.offset,
            "length": self.length,
            "depth": self.depth,
            "parent": self.parent,
            "meta": dict(sorted(self.meta.items())),
            "notes": list(self.notes),
            "children": list(self.children),
        }
