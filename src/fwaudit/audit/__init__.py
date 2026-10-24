"""Filesystem checks and the runner that applies them to every mounted filesystem."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from fwaudit.audit.accounts import AccountsCheck
from fwaudit.audit.base import AuditConfig, Check
from fwaudit.audit.components import ComponentsCheck
from fwaudit.audit.configs import ConfigSecretsCheck
from fwaudit.audit.keys import KeysCheck
from fwaudit.audit.permissions import PermissionsCheck
from fwaudit.audit.services import ServicesCheck
from fwaudit.model import Finding
from fwaudit.vfs import VirtualFS

log = logging.getLogger(__name__)

__all__ = ["AuditConfig", "Check", "CheckRun", "default_checks", "run_checks"]


def default_checks() -> list[Check]:
    return [
        AccountsCheck(),
        ConfigSecretsCheck(),
        KeysCheck(),
        ComponentsCheck(),
        ServicesCheck(),
        PermissionsCheck(),
    ]


@dataclass
class CheckRun:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def run_checks(fs: VirtualFS, config: AuditConfig, checks: list[Check]) -> CheckRun:
    """Run every check on ``fs``; a check that crashes is recorded, not fatal."""
    run = CheckRun()
    for check in checks:
        try:
            run.findings.extend(check.run(fs, config))
        except Exception as exc:  # noqa: BLE001 - one broken check must not abort the audit
            log.exception("check %s failed on %s", check.name, fs.fs_id)
            run.errors.append(f"{check.name} on {fs.fs_id}: {type(exc).__name__}: {exc}")
    return run
