"""Pure-Python implementations of the Unix ``crypt(3)`` schemes found in firmware.

* ``$1$`` MD5-crypt (Poul-Henning Kamp) and ``$apr1$`` (Apache's variant, same algorithm
  with a different magic string);
* ``$5$`` / ``$6$`` SHA-256/SHA-512-crypt (Ulrich Drepper's specification), including the
  ``rounds=N`` parameter.

The standard-library ``crypt`` module is deprecated (removed in Python 3.13) and on many
platforms only supports DES, so these are implemented directly. They are used solely to
test a hash against a short offline list of factory-default passwords; nothing here is
suitable for *creating* password hashes.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Literal

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SHA_DEFAULT_ROUNDS = 5000
SHA_MIN_ROUNDS = 1000
SHA_MAX_ROUNDS = 999_999_999
# Cap the work an attacker-supplied "rounds=" can make us do per guess.
AUDIT_MAX_ROUNDS = 50_000

Scheme = Literal["md5", "apr1", "sha256", "sha512", "des", "bcrypt", "yescrypt", "unknown"]


@dataclass(frozen=True)
class ParsedHash:
    scheme: Scheme
    salt: str
    rounds: int | None
    raw: str

    @property
    def weak(self) -> bool:
        """DES and MD5-based schemes are considered weak for password storage."""
        return self.scheme in ("des", "md5", "apr1")

    @property
    def crackable(self) -> bool:
        return self.scheme in ("md5", "apr1", "sha256", "sha512") and (
            self.rounds is None or self.rounds <= AUDIT_MAX_ROUNDS
        )


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(ITOA64[w & 0x3F])
        w >>= 6
    return "".join(out)


def md5_crypt(password: bytes, salt: str, magic: str = "$1$") -> str:
    """MD5-crypt; ``magic`` is ``"$1$"`` or ``"$apr1$"``."""
    salt = salt[:8]
    salt_b = salt.encode()
    magic_b = magic.encode()
    alt = hashlib.md5(password + salt_b + password).digest()
    ctx = hashlib.md5(password + magic_b + salt_b)
    for i in range(len(password), 0, -16):
        ctx.update(alt[: min(16, i)])
    i = len(password)
    while i:
        ctx.update(b"\x00" if i & 1 else password[:1])
        i >>= 1
    final = ctx.digest()
    for r in range(1000):
        c = hashlib.md5()
        c.update(password if r & 1 else final)
        if r % 3:
            c.update(salt_b)
        if r % 7:
            c.update(password)
        c.update(final if r & 1 else password)
        final = c.digest()
    f = final
    encoded = (
        _b64_from_24bit(f[0], f[6], f[12], 4)
        + _b64_from_24bit(f[1], f[7], f[13], 4)
        + _b64_from_24bit(f[2], f[8], f[14], 4)
        + _b64_from_24bit(f[3], f[9], f[15], 4)
        + _b64_from_24bit(f[4], f[10], f[5], 4)
        + _b64_from_24bit(0, 0, f[11], 2)
    )
    return f"{magic}{salt}${encoded}"


_SHA256_ORDER = [
    (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
    (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
]  # fmt: skip
_SHA512_ORDER = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
    (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
    (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
    (62, 20, 41),
]  # fmt: skip


def sha_crypt(password: bytes, salt: str, *, bits: int = 512, rounds: int | None = None) -> str:
    """SHA-crypt per Drepper's specification (``bits`` is 256 or 512)."""
    if bits not in (256, 512):
        raise ValueError("bits must be 256 or 512")
    h = hashlib.sha256 if bits == 256 else hashlib.sha512
    size = 32 if bits == 256 else 64
    explicit_rounds = rounds is not None
    n = SHA_DEFAULT_ROUNDS if rounds is None else max(SHA_MIN_ROUNDS, min(rounds, SHA_MAX_ROUNDS))
    salt = salt[:16]
    salt_b = salt.encode()
    pw = password

    db = h(pw + salt_b + pw).digest()
    a = h(pw + salt_b)
    plen = len(pw)
    while plen > size:
        a.update(db)
        plen -= size
    a.update(db[:plen])
    i = len(pw)
    while i:
        a.update(db if i & 1 else pw)
        i >>= 1
    da = a.digest()

    dp_full = h(pw * len(pw)).digest()
    p = (dp_full * (len(pw) // size + 1))[: len(pw)]
    ds_full = h(salt_b * (16 + da[0])).digest()
    s = (ds_full * (len(salt_b) // size + 1))[: len(salt_b)]

    c = da
    for r in range(n):
        ctx = h()
        ctx.update(p if r & 1 else c)
        if r % 3:
            ctx.update(s)
        if r % 7:
            ctx.update(p)
        ctx.update(c if r & 1 else p)
        c = ctx.digest()

    order = _SHA256_ORDER if bits == 256 else _SHA512_ORDER
    encoded = "".join(_b64_from_24bit(c[x], c[y], c[z], 4) for x, y, z in order)
    if bits == 256:
        encoded += _b64_from_24bit(0, c[31], c[30], 3)
        magic = "$5$"
    else:
        encoded += _b64_from_24bit(0, 0, c[63], 2)
        magic = "$6$"
    rounds_part = f"rounds={n}$" if explicit_rounds else ""
    return f"{magic}{rounds_part}{salt}${encoded}"


def parse_hash(value: str) -> ParsedHash:
    """Identify the scheme of a crypt(3) string."""
    if value.startswith("$1$"):
        return ParsedHash("md5", value[3:].split("$", 1)[0], None, value)
    if value.startswith("$apr1$"):
        return ParsedHash("apr1", value[6:].split("$", 1)[0], None, value)
    if value.startswith(("$5$", "$6$")):
        scheme: Scheme = "sha256" if value[1] == "5" else "sha512"
        rest = value[3:]
        rounds = None
        if rest.startswith("rounds="):
            spec, _, rest = rest.partition("$")
            try:
                rounds = int(spec[len("rounds=") :])
            except ValueError:
                return ParsedHash("unknown", "", None, value)
        return ParsedHash(scheme, rest.split("$", 1)[0], rounds, value)
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return ParsedHash("bcrypt", "", None, value)
    if value.startswith(("$y$", "$7$")):
        return ParsedHash("yescrypt", "", None, value)
    if len(value) == 13 and all(ch in ITOA64 for ch in value):
        return ParsedHash("des", value[:2], None, value)
    return ParsedHash("unknown", "", None, value)


def verify(password: str, parsed: ParsedHash) -> bool | None:
    """Return True/False if ``password`` matches, or ``None`` if the scheme is unsupported."""
    if not parsed.crackable:
        return None
    pw = password.encode()
    if parsed.scheme in ("md5", "apr1"):
        magic = "$1$" if parsed.scheme == "md5" else "$apr1$"
        candidate = md5_crypt(pw, parsed.salt, magic)
    else:
        bits = 256 if parsed.scheme == "sha256" else 512
        candidate = sha_crypt(pw, parsed.salt, bits=bits, rounds=parsed.rounds)
    return hmac.compare_digest(candidate, parsed.raw)


def crack(parsed: ParsedHash, candidates: list[str]) -> str | None:
    """Return the first candidate password that matches ``parsed``, if any."""
    if not parsed.crackable:
        return None
    for guess in candidates:
        if verify(guess, parsed):
            return guess
    return None
