"""fwaudit: offline firmware image auditor.

Typical use::

    from fwaudit import AuditOptions, audit_file
    result = audit_file("firmware.bin")
    for finding in result.findings:
        print(finding.severity.name, finding.rule_id, finding.path, finding.detail)
"""

__version__ = "0.1.0"

from fwaudit.audit.base import AuditConfig
from fwaudit.limits import Limits
from fwaudit.model import Finding, Severity
from fwaudit.pipeline import AuditOptions, AuditResult, audit_bytes, audit_file

__all__ = [
    "AuditConfig",
    "AuditOptions",
    "AuditResult",
    "Finding",
    "Limits",
    "Severity",
    "__version__",
    "audit_bytes",
    "audit_file",
]
