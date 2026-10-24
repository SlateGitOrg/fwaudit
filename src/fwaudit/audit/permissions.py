"""File permission checks on the mounted filesystem metadata.

Archive and filesystem formats preserve mode bits, so dangerous permissions shipped in
the image are visible without running it: world-writable setuid/setgid files (local
privilege escalation), setuid-root inventory, world-writable files in system
directories, and world-writable directories without the sticky bit.
"""

from __future__ import annotations

from fwaudit.audit.base import SYSTEM_DIRS, AuditConfig
from fwaudit.formats.entries import EntryKind
from fwaudit.model import Finding, make_finding
from fwaudit.vfs import VirtualFS


def _in_system_dir(path: str) -> bool:
    return any(path == d or path.startswith(d + "/") for d in SYSTEM_DIRS)


class PermissionsCheck:
    name = "permissions"

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        out: list[Finding] = []
        for node in fs.nodes():
            mode = node.mode_string()
            if node.kind is EntryKind.FILE:
                special = node.is_setuid or node.is_setgid
                if special and node.world_writable:
                    bits = "setuid" if node.is_setuid else "setgid"
                    out.append(
                        make_finding(
                            "FWA-PERM-001",
                            f"{bits} file is world-writable ({mode}, owner uid {node.uid})",
                            filesystem=fs.fs_id,
                            path=node.path,
                            evidence={"mode": oct(node.mode), "uid": node.uid},
                        )
                    )
                    continue
                if node.is_setuid and node.uid == 0:
                    out.append(
                        make_finding(
                            "FWA-PERM-002",
                            f"setuid-root executable ({mode})",
                            filesystem=fs.fs_id,
                            path=node.path,
                            evidence={"mode": oct(node.mode)},
                        )
                    )
                if node.world_writable and _in_system_dir(node.path):
                    out.append(
                        make_finding(
                            "FWA-PERM-003",
                            f"world-writable file in a system directory ({mode})",
                            filesystem=fs.fs_id,
                            path=node.path,
                            evidence={"mode": oct(node.mode)},
                        )
                    )
            elif node.kind is EntryKind.DIR and node.world_writable and not node.sticky:
                out.append(
                    make_finding(
                        "FWA-PERM-004",
                        f"world-writable directory without sticky bit ({mode})",
                        filesystem=fs.fs_id,
                        path=node.path,
                        evidence={"mode": oct(node.mode)},
                    )
                )
        return out
