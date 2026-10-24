"""Deterministic test keys and certificates for synthetic firmware images.

Byte-identical fixtures make golden tests possible, so every key here is derived from a
seed: RSA primes come from a seeded PRNG plus Miller-Rabin, EC keys from
``derive_private_key``, and certificates are signed with deterministic schemes only
(RSA PKCS#1 v1.5 or RFC 6979 ECDSA). These keys are throwaway test material and are
never suitable for real use.
"""

from __future__ import annotations

import base64
import random
import struct
from datetime import datetime
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

_SHA256_RSA_OID = bytes.fromhex("06092a864886f70d01010b")
_SHA1_RSA_OID = bytes.fromhex("06092a864886f70d010105")
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71)


def _is_probable_prime(n: int, rng: random.Random, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random, e: int) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if (candidate - 1) % e and _is_probable_prime(candidate, rng):
            return candidate


@lru_cache(maxsize=32)
def rsa_key(seed: int, bits: int = 2048) -> rsa.RSAPrivateKey:
    """Deterministic RSA key for ``seed``."""
    rng = random.Random(f"rsa:{seed}:{bits}")
    e = 65537
    while True:
        p = _prime(bits // 2, rng, e)
        q = _prime(bits - bits // 2, rng, e)
        if p != q and (p * q).bit_length() == bits:
            break
    d = pow(e, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(e, p * q),
    )
    return numbers.private_key()


def ec_key(seed: int) -> ec.EllipticCurvePrivateKey:
    """Deterministic P-256 key for ``seed``."""
    rng = random.Random(f"ec:{seed}")
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return ec.derive_private_key(rng.randrange(1, order), ec.SECP256R1())


def private_pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    fmt = (
        serialization.PrivateFormat.TraditionalOpenSSL
        if isinstance(key, rsa.RSAPrivateKey)
        else serialization.PrivateFormat.PKCS8
    )
    return key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption())


def fake_encrypted_pem(seed: int) -> bytes:
    """A legacy passphrase-protected PEM *envelope* with random ciphertext.

    It is structurally identical to ``openssl genrsa -aes128`` output but the body is
    random bytes, so it is not a decryptable key; fwaudit only inspects the envelope.
    """
    rng = random.Random(f"enc:{seed}")
    iv = rng.randbytes(16).hex().upper()
    body = base64.encodebytes(rng.randbytes(1216)).replace(b"\n", b"")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return (
        b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
        + f"DEK-Info: AES-128-CBC,{iv}\n\n".encode()
        + b"\n".join(lines)
        + b"\n-----END RSA PRIVATE KEY-----\n"
    )


def certificate(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    common_name: str,
    not_before: datetime,
    not_after: datetime,
    *,
    hash_name: str = "sha256",
    serial: int = 1,
) -> x509.Certificate:
    """Self-signed certificate with deterministic signature bytes."""
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "fwaudit synthetic test CA"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if hash_name != "sha256":
            raise ValueError("EC test certificates are SHA-256 only")
        return builder.sign(key, hashes.SHA256(), ecdsa_deterministic=True)
    cert = builder.sign(key, hashes.SHA256())
    if hash_name == "sha1":
        return _resign_sha1(cert, key)
    return cert


def _resign_sha1(cert: x509.Certificate, key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Re-sign an RSA/SHA-256 certificate as RSA/SHA-1.

    Modern OpenSSL refuses to *issue* SHA-1 certificates, but firmware still ships them,
    so the auditor must be tested against one. The sha256WithRSAEncryption and
    sha1WithRSAEncryption OIDs differ only in their final byte (0x0b vs 0x05), so the
    DER can be patched in place without changing any lengths, then the patched TBS is
    signed with SHA-1.
    """
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    tbs = bytearray(cert.tbs_certificate_bytes)
    tbs_at = der.find(tbs)
    if tbs_at < 0 or der.count(_SHA256_RSA_OID) != 2 or tbs.count(_SHA256_RSA_OID) != 1:
        raise ValueError("unexpected certificate layout")
    tbs = tbs.replace(_SHA256_RSA_OID, _SHA1_RSA_OID)
    der[tbs_at : tbs_at + len(tbs)] = tbs
    der = bytearray(der.replace(_SHA256_RSA_OID, _SHA1_RSA_OID))
    signature = key.sign(bytes(tbs), padding.PKCS1v15(), hashes.SHA1())
    if len(signature) != len(cert.signature):
        raise ValueError("signature length changed")
    der[-len(signature) :] = signature
    return x509.load_der_x509_certificate(bytes(der))


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def dropbear_rsa_host_key(key: rsa.RSAPrivateKey) -> bytes:
    """Serialise an RSA key in dropbear's binary host-key format."""

    def ssh_string(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    def mpint(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 8) // 8, "big")
        return ssh_string(raw)

    nums = key.private_numbers()
    pub = nums.public_numbers
    return (
        ssh_string(b"ssh-rsa")
        + mpint(pub.e)
        + mpint(pub.n)
        + mpint(nums.d)
        + mpint(nums.p)
        + mpint(nums.q)
    )
