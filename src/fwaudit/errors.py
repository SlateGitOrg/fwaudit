"""Exception hierarchy for fwaudit.

Every error raised deliberately by the library derives from :class:`FwauditError`, so
callers can catch one type. Format parsers raise :class:`FormatError` when bytes do not
match the claimed structure; the extraction engine converts those into findings instead
of aborting the whole audit.
"""

from __future__ import annotations


class FwauditError(Exception):
    """Base class for all fwaudit errors."""


class FormatError(FwauditError):
    """Input bytes are not a valid instance of the format being parsed."""


class TruncatedError(FormatError):
    """The structure starts correctly but the input ends before it does."""


class UnsupportedFormatError(FormatError):
    """The format was recognised but this build cannot decode it (e.g. LZO squashfs)."""


class LimitExceededError(FwauditError):
    """An extraction safety limit (size, ratio, entries, depth) was hit."""

    def __init__(self, limit: str, message: str) -> None:
        super().__init__(message)
        self.limit = limit


class UnsafePathError(FwauditError):
    """An archive member path would escape the extraction root."""


class CveDatabaseError(FwauditError):
    """The pinned CVE subset failed to load or its integrity pin does not match."""
