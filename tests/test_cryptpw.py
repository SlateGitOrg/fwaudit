"""crypt(3) implementations checked against vectors produced by OpenSSL 3.6 ``passwd``."""

from __future__ import annotations

import pytest

from fwaudit.audit.cryptpw import crack, md5_crypt, parse_hash, sha_crypt, verify

VECTORS = [
    ("Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
    ("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
    ("password", "$1$saltstri$qQY4WxjABChYG1ccLpfkz/"),
    ("password", "$apr1$saltstri$KbmdckUzuN1qd7Gpo8DEL."),
    ("Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
    ("", "$1$abc$Or2rbeUYTvt12aiVzMuS/."),
    ("admin", "$6$xY12$vJIe8ZaGkMNf8YUG31Q9gEUgUbox1qPDcquW/aAgGZtRuHMEG.r2pb5SlPHBONLL5XiJtZIKGvcvQYJDEG.ET1"),
]  # fmt: skip


@pytest.mark.parametrize(("password", "expected"), VECTORS)
def test_openssl_vectors(password: str, expected: str) -> None:
    parsed = parse_hash(expected)
    assert verify(password, parsed) is True
    assert verify(password + "x", parsed) is False


def test_direct_functions() -> None:
    assert md5_crypt(b"password", "saltstri") == VECTORS[2][1]
    assert sha_crypt(b"Hello world!", "saltstring", bits=256) == VECTORS[1][1]
    long_pw = b"x" * 100
    assert sha_crypt(long_pw, "s", bits=512).startswith("$6$s$")
    with pytest.raises(ValueError):
        sha_crypt(b"a", "s", bits=384)


def test_parse_hash_schemes() -> None:
    assert parse_hash("$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012").scheme == "bcrypt"
    assert parse_hash("$y$j9T$salt$hash").scheme == "yescrypt"
    des = parse_hash("abJnggxhB/yWI")
    assert des.scheme == "des"
    assert des.weak
    assert not des.crackable
    assert parse_hash("$6$rounds=abc$salt$x").scheme == "unknown"
    assert parse_hash("plaintext!").scheme == "unknown"
    huge = parse_hash("$6$rounds=900000$salt$hash")
    assert huge.rounds == 900000
    assert not huge.crackable
    assert verify("x", huge) is None
    assert crack(huge, ["x"]) is None


def test_crack_finds_candidate() -> None:
    target = parse_hash(md5_crypt(b"vizxv", "ab12cd34"))
    assert crack(target, ["root", "admin", "vizxv"]) == "vizxv"
    assert crack(target, ["nope"]) is None
