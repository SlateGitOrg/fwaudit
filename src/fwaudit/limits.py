"""Extraction safety limits and the shared budget that enforces them.

Firmware images are attacker-controlled input. Every decompressor and archive parser
draws from a single :class:`Budget` so that a decompression bomb, a deeply nested
archive or an archive with millions of entries cannot exhaust memory or time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fwaudit.errors import LimitExceededError

MiB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """Hard ceilings applied during extraction. All sizes are in bytes."""

    max_image_bytes: int = 1024 * MiB
    max_total_bytes: int = 768 * MiB
    max_stream_bytes: int = 256 * MiB
    max_file_bytes: int = 64 * MiB
    max_ratio: int = 200
    ratio_grace_bytes: int = 4 * MiB
    max_depth: int = 8
    max_entries: int = 200_000
    max_carves: int = 512
    max_path_len: int = 4096

    def __post_init__(self) -> None:
        for name in (
            "max_image_bytes",
            "max_total_bytes",
            "max_stream_bytes",
            "max_file_bytes",
            "max_ratio",
            "max_depth",
            "max_entries",
            "max_carves",
            "max_path_len",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass
class Budget:
    """Mutable running totals for one audit, checked against :class:`Limits`."""

    limits: Limits
    total_bytes: int = 0
    entries: int = 0
    carves: int = 0
    events: list[str] = field(default_factory=list)

    def charge_bytes(self, n: int, what: str) -> None:
        """Account for ``n`` newly materialised bytes; raise if the global cap is hit."""
        if n < 0:
            raise ValueError("cannot charge a negative byte count")
        if self.total_bytes + n > self.limits.max_total_bytes:
            raise LimitExceededError(
                "max_total_bytes",
                f"{what}: total extracted bytes would exceed {self.limits.max_total_bytes}",
            )
        self.total_bytes += n

    def remaining_bytes(self) -> int:
        return self.limits.max_total_bytes - self.total_bytes

    def charge_entry(self, what: str) -> None:
        if self.entries + 1 > self.limits.max_entries:
            raise LimitExceededError(
                "max_entries", f"{what}: more than {self.limits.max_entries} archive entries"
            )
        self.entries += 1

    def charge_carve(self) -> None:
        if self.carves + 1 > self.limits.max_carves:
            raise LimitExceededError(
                "max_carves", f"more than {self.limits.max_carves} carved regions"
            )
        self.carves += 1

    def ratio_allowance(self, consumed: int) -> int:
        """Most output bytes that ``consumed`` input bytes may produce without tripping
        :meth:`check_ratio`."""
        return max(self.limits.ratio_grace_bytes, self.limits.max_ratio * max(consumed, 1))

    def check_ratio(self, produced: int, consumed: int, what: str) -> None:
        """Reject streams whose expansion ratio is implausible for real firmware."""
        if produced <= self.limits.ratio_grace_bytes:
            return
        if produced > self.limits.max_ratio * max(consumed, 1):
            raise LimitExceededError(
                "max_ratio",
                f"{what}: expansion ratio {produced // max(consumed, 1)}:1 exceeds "
                f"{self.limits.max_ratio}:1",
            )
