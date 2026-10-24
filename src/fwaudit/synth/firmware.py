"""Seeded generator of synthetic firmware images with known planted findings.

Every image is built from scratch in memory: a small embedded-Linux root filesystem is
assembled, a random subset of *plants* (deliberate weaknesses) is added, the rootfs is
packed into one of several realistic container layouts, and the list of findings the
auditor *should* report is recorded as ground truth.

Two splits exist. ``dev`` samples use one set of surface forms (paths, file formats,
line endings) and were used while writing the detectors. ``holdout`` samples
additionally draw from forms that were fixed before the evaluation was first run and
were not used to tune detectors (CRLF configs, JSON configs, xinetd telnet, DER
certificates, vendor paths); they measure how detectors generalise to unseen shapes.

Expected CVE identifiers for each component version were derived by hand from the NVD
ranges, not by calling fwaudit's own matcher, so the evaluation checks the matcher.
"""

from __future__ import annotations

import gzip
import io
import json
import lzma
import random
import struct
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from fwaudit.audit.cryptpw import md5_crypt, sha_crypt
from fwaudit.formats import cpio, uimage
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.synth import pki, squashfs_writer

REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
LAYOUTS = ("uimage-multi-cpio", "uimage-lzma-cpio", "flash-squashfs-gzip", "flash-squashfs-xz",
           "tar-xz-update")  # fmt: skip
ERASE_BLOCK = 0x10000

# component -> version -> CVE ids affected (hand-derived from the NVD ranges)
COMPONENT_VERSIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "busybox": {
        "1.24.1": ("CVE-2016-2147", "CVE-2016-2148", "CVE-2017-16544", "CVE-2022-48174"),
        "1.27.2": ("CVE-2017-16544", "CVE-2021-42374", "CVE-2022-48174"),
        "1.33.1": ("CVE-2021-42374", "CVE-2022-48174"),
        "1.36.1": (),
    },
    "openssl": {
        "1.0.1f": ("CVE-2014-0160", "CVE-2014-0224", "CVE-2016-0800", "CVE-2016-2107",
                   "CVE-2016-2108"),
        "1.0.2k": ("CVE-2022-0778", "CVE-2023-0286"),
        "1.1.1k": ("CVE-2022-0778", "CVE-2023-0286"),
        "3.0.13": (),
    },
    "dropbear": {
        "2016.72": ("CVE-2016-7406", "CVE-2016-7407", "CVE-2017-9078", "CVE-2018-15599",
                    "CVE-2020-36254"),
        "2018.76": ("CVE-2018-15599", "CVE-2020-36254"),
        "2022.83": (),
    },
    "dnsmasq": {
        "2.75": ("CVE-2017-14491", "CVE-2017-14492", "CVE-2020-25681"),
        "2.80": ("CVE-2020-25681",),
        "2.89": (),
    },
}  # fmt: skip
_VERSION_STRINGS = {
    "busybox": "BusyBox v{v} (2019-06-01 08:00:00 UTC) multi-call binary.",
    "openssl": "OpenSSL {v}  11 Feb 2021",
    "dropbear": "SSH-2.0-dropbear_{v}",
    "dnsmasq": "dnsmasq-{v}",
}
_KERNEL_WORDS = (b"sched", b"irq", b"mtd", b"spi", b"nand", b"eth0", b"probe", b"init", b"usb",
                 b"gpio", b"clk", b"regulator", b"wdt", b"rtc", b"uart", b"dma")  # fmt: skip


@dataclass(frozen=True)
class Expected:
    """One finding the auditor must report.

    ``where`` is ``"extracted"`` (inside the container tree carved from the image, e.g.
    the root filesystem), ``"nested"`` (inside a filesystem that was itself found in a
    *file* of another filesystem) or ``"image"`` (the raw image level, no path).
    """

    rule_id: str
    path: str | None
    where: str
    note: str
    cves: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, "path": self.path, "where": self.where,
                "note": self.note, "cves": list(self.cves)}  # fmt: skip


@dataclass
class Sample:
    name: str
    seed: int
    split: str
    layout: str
    image: bytes
    expected: list[Expected]
    plants: list[str] = field(default_factory=list)

    def manifest(self) -> dict[str, object]:
        return {
            "name": self.name,
            "seed": self.seed,
            "split": self.split,
            "layout": self.layout,
            "size": len(self.image),
            "plants": self.plants,
            "reference_time": REFERENCE_TIME.isoformat(),
            "expected": [e.to_json() for e in self.expected],
        }


class Rootfs:
    """Ordered collection of archive entries keyed by path (no leading slash)."""

    def __init__(self) -> None:
        self._entries: dict[str, ArchiveEntry] = {}

    def _parents(self, path: str) -> None:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            d = "/".join(parts[:i])
            if d not in self._entries:
                self._entries[d] = ArchiveEntry(d.encode(), EntryKind.DIR, 0o755)

    def dir(self, path: str, mode: int = 0o755) -> None:
        self._parents(path)
        self._entries[path] = ArchiveEntry(path.encode(), EntryKind.DIR, mode)

    def file(self, path: str, data: bytes | str, mode: int = 0o644, uid: int = 0, gid: int = 0) -> None:
        self._parents(path)
        raw = data.encode() if isinstance(data, str) else data
        self._entries[path] = ArchiveEntry(path.encode(), EntryKind.FILE, mode, uid, gid, raw)

    def link(self, path: str, target: str) -> None:
        self._parents(path)
        self._entries[path] = ArchiveEntry(path.encode(), EntryKind.SYMLINK, 0o777,
                                           link_target=target.encode())  # fmt: skip

    def chardev(self, path: str, major: int, minor: int, mode: int = 0o600) -> None:
        self._parents(path)
        self._entries[path] = ArchiveEntry(path.encode(), EntryKind.CHARDEV, mode,
                                           rdev=(major, minor))  # fmt: skip

    def read(self, path: str) -> bytes:
        return self._entries[path].data

    def entries(self) -> list[ArchiveEntry]:
        return [self._entries[p] for p in sorted(self._entries)]


def fake_elf(rng: random.Random, strings: list[str], size: int = 6144) -> bytes:
    """A benign stand-in binary: an ELF header, version strings and random filler."""
    header = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HHI", 2, 8, 1)
    header = header.ljust(52, b"\x00")
    body = b"\x00".join(s.encode() for s in strings) + b"\x00"
    return header + rng.randbytes(size // 2) + body + rng.randbytes(size // 2)


def tar_bytes(entries: list[ArchiveEntry]) -> bytes:
    """Deterministic GNU tar of ``entries``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for e in entries:
            info = tarfile.TarInfo(e.name.decode())
            info.mode, info.uid, info.gid, info.mtime = e.mode, e.uid, e.gid, 0
            if e.kind is EntryKind.FILE:
                info.size = len(e.data)
                tf.addfile(info, io.BytesIO(e.data))
                continue
            if e.kind is EntryKind.DIR:
                info.type = tarfile.DIRTYPE
            elif e.kind is EntryKind.SYMLINK:
                info.type = tarfile.SYMTYPE
                info.linkname = (e.link_target or b"").decode()
            elif e.kind is EntryKind.CHARDEV:
                info.type = tarfile.CHRTYPE
                info.devmajor, info.devminor = e.rdev or (0, 0)
            tf.addfile(info)
    return buf.getvalue()


def lzma_alone(data: bytes) -> bytes:
    """LZMA-alone stream with the uncompressed size in the header (as U-Boot expects)."""
    raw = lzma.compress(data, format=lzma.FORMAT_ALONE)
    return raw[:5] + struct.pack("<Q", len(data)) + raw[13:]


def pad_to(data: bytes, boundary: int, fill: bytes = b"\xff") -> bytes:
    return data + fill * (-len(data) % boundary)


class _Generator:
    def __init__(self, seed: int, split: str) -> None:
        if split not in ("dev", "holdout"):
            raise ValueError("split must be 'dev' or 'holdout'")
        self.seed = seed
        self.split = split
        self.holdout = split == "holdout"
        self.rng = random.Random(f"{split}:{seed}")
        self.fs = Rootfs()
        self.expected: list[Expected] = []
        self.plants: list[str] = []
        self.passwd: list[str] = []
        self.shadow: list[str] = []
        self.startup: list[str] = []

    # ---------------------------------------------------------------- helpers
    def expect(self, rule: str, path: str | None, note: str, *, where: str = "extracted",
               cves: tuple[str, ...] = ()) -> None:  # fmt: skip
        self.expected.append(Expected(rule, path, where, note, cves))

    def chance(self, p: float = 0.55) -> bool:
        return self.rng.random() < p

    def text(self, body: str) -> str:
        """Config text; holdout samples sometimes use CRLF line endings."""
        if self.holdout and self.rng.random() < 0.4:
            return body.replace("\n", "\r\n")
        return body

    def pick(self, dev: list[str], holdout_extra: list[str]) -> str:
        return self.rng.choice(dev + holdout_extra if self.holdout else dev)

    # ---------------------------------------------------------------- base system
    def base(self) -> None:
        fs, rng = self.fs, self.rng
        for d in ("bin", "sbin", "lib", "usr/bin", "usr/sbin", "usr/lib", "etc/init.d",
                  "var/run", "proc", "sys", "root", "www"):  # fmt: skip
            fs.dir(d, 0o700 if d == "root" else 0o755)
        fs.dir("tmp", 0o1777)
        fs.chardev("dev/console", 5, 1)
        fs.chardev("dev/null", 1, 3, 0o666)
        bb_version = rng.choice(list(COMPONENT_VERSIONS["busybox"]))
        setuid = self.chance(0.5)
        fs.file("bin/busybox", fake_elf(rng, [_VERSION_STRINGS["busybox"].format(v=bb_version),
                                              "Usage: busybox [function [arguments]...]"]),
                mode=0o4755 if setuid else 0o755)  # fmt: skip
        for applet in ("bin/sh", "bin/ls", "bin/mount", "sbin/init", "sbin/reboot", "usr/bin/wget"):
            target = "busybox" if applet.startswith("bin/") else "../" * applet.count("/") + "bin/busybox"
            fs.link(applet, target)
        self._component("busybox", bb_version, "/bin/busybox")
        if setuid:
            self.plants.append("setuid-busybox")
            self.expect("FWA-PERM-002", "/bin/busybox", "busybox installed setuid root")
        self.passwd += [
            "root:x:0:0:root:/root:/bin/sh",
            "daemon:x:1:1:daemon:/usr/sbin:/bin/false",
            "nobody:x:65534:65534:nobody:/nonexistent:/bin/false",
        ]
        self.shadow += ["daemon:*:18000:0:99999:7:::", "nobody:!:18000:0:99999:7:::"]
        strong = "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(16))
        self.passwd.append("operator:x:1000:1000:Operator:/home/operator:/bin/sh")
        self.shadow.append(f"operator:{sha_crypt(strong.encode(), self._salt())}:18000:0:99999:7:::")
        fs.file("etc/hostname", "synth-router\n")
        fs.file("etc/group", "root:x:0:\ndaemon:x:1:\nnogroup:x:65534:\n")
        fs.file("etc/init.d/S40network",
                self.text("#!/bin/sh\nifconfig eth0 up\n# telnetd -l /bin/sh   (debug only, "
                          "disabled)\nudhcpc -i eth0 &\n"), mode=0o755)  # fmt: skip
        fs.file("etc/default/security.conf",
                self.text("password_min_len=8\nPASSWORD_HASH_TYPE=sha512\n"
                          "admin_password=${ADMIN_PASSWORD}\nsession_timeout=300\n"))  # fmt: skip
        fs.file("usr/share/doc/openssl/README", "Built against OpenSSL 1.0.1f  6 Jan 2014\n")
        fs.file("www/index.html", "<html><body>Router</body></html>\n")
        fs.dir("var/log", 0o755)

    def _salt(self) -> str:
        return "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))

    def _component(self, name: str, version: str, path: str) -> None:
        self.expect("FWA-CMP-001", path, f"{name} {version}")
        cves = COMPONENT_VERSIONS[name][version]
        if cves:
            self.expect("FWA-CMP-002", path, f"{name} {version}", cves=tuple(sorted(cves)))

    # ---------------------------------------------------------------- plants
    def plant_root_password(self) -> None:
        choice = self.rng.choice(["empty-shadow", "empty-passwd", "default-md5", "default-sha512",
                                  "strong"])  # fmt: skip
        if choice == "strong":
            pw = "".join(self.rng.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(14))
            self.shadow.insert(0, f"root:{sha_crypt(pw.encode(), self._salt())}:18000:0:99999:7:::")
            return
        self.plants.append(f"root-{choice}")
        if choice == "empty-shadow":
            self.shadow.insert(0, "root::18000:0:99999:7:::")
            self.expect("FWA-CRED-001", "/etc/shadow", "root has empty shadow password")
        elif choice == "empty-passwd":
            self.passwd[0] = "root::0:0:root:/root:/bin/sh"
            self.shadow.insert(0, "root:*:18000:0:99999:7:::")
            self.expect("FWA-CRED-001", "/etc/passwd", "root has empty passwd field")
        else:
            pw = self.rng.choice(["admin", "root", "12345", "password", "xc3511", "vizxv"])
            if choice == "default-md5":
                h = md5_crypt(pw.encode(), self._salt())
                self.expect("FWA-CRED-003", "/etc/shadow", "root uses md5-crypt")
            else:
                h = sha_crypt(pw.encode(), self._salt())
            self.shadow.insert(0, f"root:{h}:18000:0:99999:7:::")
            self.expect("FWA-CRED-004", "/etc/shadow", f"root password is default '{pw}'")

    def plant_passwd_hash(self) -> None:
        self.plants.append("hash-in-passwd")
        if self.chance(0.5):
            des = "".join(self.rng.choice("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
                          for _ in range(13))  # fmt: skip
            self.passwd.append(f"support:{des}:1001:1001:Support:/home/support:/bin/sh")
        else:
            h = md5_crypt(b"support", self._salt())
            self.passwd.append(f"support:{h}:1001:1001:Support:/home/support:/bin/sh")
            self.expect("FWA-CRED-004", "/etc/passwd", "support/support")
        self.expect("FWA-CRED-002", "/etc/passwd", "hash stored in passwd")
        self.expect("FWA-CRED-003", "/etc/passwd", "weak scheme (des or md5)")

    def plant_uid0(self) -> None:
        self.plants.append("uid0-backdoor")
        name = self.rng.choice(["admin1", "toor", "sysadm"])
        self.passwd.append(f"{name}:x:0:0::/root:/bin/sh")
        self.shadow.append(f"{name}:!:18000:0:99999:7:::")
        self.expect("FWA-CRED-005", "/etc/passwd", f"{name} has uid 0")

    def plant_config_secret(self) -> None:
        self.plants.append("config-secret")
        kind = self.pick(["kv", "uci", "chpasswd", "url"], ["json", "uci-tab"])
        secret = "".join(self.rng.choice("abcdefghijkmnopqrstuvwxyzABCDEFGH23456789") for _ in range(12))
        base = self.pick(["/etc/config"], ["/usr/local/etc", "/opt/vendor/etc"])
        if kind == "kv":
            path = f"{base}/cloud.conf"
            body = f"server=iot.example.invalid\nport=8883\ncloud_api_key = \"{secret}\"\n"
        elif kind in ("uci", "uci-tab"):
            path = f"{base}/system"
            indent = "\t" if kind == "uci-tab" else "  "
            body = (f"config system\n{indent}option hostname 'router'\n"
                    f"{indent}option password '{secret}'\n")  # fmt: skip
        elif kind == "chpasswd":
            path = "/etc/init.d/S10setup"
            body = f"#!/bin/sh\necho \"root:{secret}\" | chpasswd\n"
        elif kind == "url":
            path = "/usr/bin/backup.sh"
            body = f"#!/bin/sh\nwget -q ftp://backup:{secret}@10.0.0.2/cfg.tgz -O /tmp/c\n"
        else:
            path = f"{base}/app.json"
            body = json.dumps({"mqtt": {"host": "10.0.0.5", "admin_password": secret}}, indent=2) + "\n"
        self.fs.file(path.lstrip("/"), self.text(body), mode=0o755 if path.endswith(".sh") or "init.d" in path else 0o644)
        self.expect("FWA-CRED-006", path, f"{kind} secret")

    def plant_keys(self) -> None:
        self.plants.append("private-key")
        base = self.pick(["/etc/ssl/private"], ["/opt/vendor/keys"])
        if self.chance(0.5):
            key = pki.rsa_key(self.seed % 7, 1024)
            self.fs.file(f"{base.lstrip('/')}/server.key", pki.private_pem(key), mode=0o600)
            self.expect("FWA-KEY-001", f"{base}/server.key", "RSA private key")
            self.expect("FWA-KEY-004", f"{base}/server.key", "RSA-1024")
        else:
            key_ec = pki.ec_key(self.seed)
            self.fs.file(f"{base.lstrip('/')}/server.key", pki.private_pem(key_ec), mode=0o600)
            self.expect("FWA-KEY-001", f"{base}/server.key", "EC private key")
        if self.chance(0.4):
            self.plants.append("encrypted-key")
            self.fs.file("etc/ssl/private/backup.key", pki.fake_encrypted_pem(self.seed), mode=0o600)
            self.expect("FWA-KEY-001", "/etc/ssl/private/backup.key", "encrypted key envelope")

    def plant_dropbear(self) -> None:
        version = self.rng.choice(list(COMPONENT_VERSIONS["dropbear"]))
        self.fs.file("usr/sbin/dropbear", fake_elf(self.rng, [_VERSION_STRINGS["dropbear"].format(v=version)]),
                     mode=0o755)  # fmt: skip
        self._component("dropbear", version, "/usr/sbin/dropbear")
        if self.chance(0.6):
            self.plants.append("dropbear-host-key")
            bits = self.rng.choice([1024, 2048])
            key = pki.rsa_key(100 + self.seed % 5, bits)
            self.fs.file("etc/dropbear/dropbear_rsa_host_key", pki.dropbear_rsa_host_key(key), mode=0o600)
            self.expect("FWA-KEY-001", "/etc/dropbear/dropbear_rsa_host_key", "dropbear host key")
            if bits < 2048:
                self.expect("FWA-KEY-004", "/etc/dropbear/dropbear_rsa_host_key", "RSA-1024 host key")
        if self.chance(0.5):
            self.plants.append("dropbear-root-password")
            self.startup.append("/usr/sbin/dropbear -p 22 &")
            self.expect("FWA-SVC-005", "/etc/init.d/rcS", "dropbear without -s/-g")
        else:
            self.startup.append("/usr/sbin/dropbear -s -g -p 22 &")

    def plant_libs(self) -> None:
        if self.chance(0.7):
            version = self.rng.choice(list(COMPONENT_VERSIONS["openssl"]))
            self.fs.file("usr/lib/libcrypto.so.1.0.0", fake_elf(self.rng, [_VERSION_STRINGS["openssl"].format(v=version)]))
            self._component("openssl", version, "/usr/lib/libcrypto.so.1.0.0")
        if self.chance(0.5):
            version = self.rng.choice(list(COMPONENT_VERSIONS["dnsmasq"]))
            self.fs.file("usr/sbin/dnsmasq", fake_elf(self.rng, [_VERSION_STRINGS["dnsmasq"].format(v=version)]),
                         mode=0o755)  # fmt: skip
            self._component("dnsmasq", version, "/usr/sbin/dnsmasq")

    def plant_certs(self) -> None:
        ref = REFERENCE_TIME
        key = pki.ec_key(500 + self.seed)
        valid = pki.certificate(key, "device.local", ref - timedelta(days=400), ref + timedelta(days=3650))
        if self.holdout and self.chance(0.4):
            path = "/opt/vendor/certs/device.crt"
            self.fs.file(path.lstrip("/"), pki.cert_der(valid))
        else:
            path = "/etc/ssl/certs/device.pem"
            self.fs.file(path.lstrip("/"), pki.cert_pem(valid))
        self.expect("FWA-KEY-006", path, "valid certificate inventory")
        if self.chance(0.5):
            self.plants.append("expired-cert")
            expired = pki.certificate(pki.ec_key(600 + self.seed), "cloud.example.invalid",
                                      datetime(2015, 1, 1, tzinfo=UTC), datetime(2020, 1, 1, tzinfo=UTC))  # fmt: skip
            self.fs.file("etc/ssl/certs/cloud.pem", pki.cert_pem(expired))
            self.expect("FWA-KEY-006", "/etc/ssl/certs/cloud.pem", "inventory")
            self.expect("FWA-KEY-002", "/etc/ssl/certs/cloud.pem", "expired 2020")
        if self.chance(0.4):
            self.plants.append("sha1-cert")
            rsa_key = pki.rsa_key(200 + self.seed % 5, 2048)
            weak = pki.certificate(rsa_key, "legacy.local", ref - timedelta(days=100),
                                   ref + timedelta(days=30), hash_name="sha1")  # fmt: skip
            self.fs.file("etc/ssl/certs/legacy.pem", pki.cert_pem(weak))
            self.expect("FWA-KEY-006", "/etc/ssl/certs/legacy.pem", "inventory")
            self.expect("FWA-KEY-005", "/etc/ssl/certs/legacy.pem", "SHA-1 signature")
            self.expect("FWA-KEY-003", "/etc/ssl/certs/legacy.pem", "expires in 30 days")

    def plant_telnet(self) -> None:
        self.plants.append("telnet")
        form = self.pick(["rcS-shell", "inittab", "inetd"], ["xinetd", "rc.local"])
        if form == "rcS-shell":
            self.startup.append("telnetd -l /bin/sh &")
            self.expect("FWA-SVC-001", "/etc/init.d/rcS", "telnetd -l /bin/sh (critical)")
        elif form == "inittab":
            self.fs.file("etc/inittab", self.text("::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/telnetd -F\n"
                                                  "::askfirst:-/bin/sh\n"))  # fmt: skip
            self.expect("FWA-SVC-001", "/etc/inittab", "telnetd from inittab")
        elif form == "inetd":
            self.fs.file("etc/inetd.conf", self.text("telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n"))
            self.expect("FWA-SVC-001", "/etc/inetd.conf", "inetd telnet")
        elif form == "xinetd":
            self.fs.file("etc/xinetd.d/telnet", self.text(
                "service telnet\n{\n    disable = no\n    socket_type = stream\n"
                "    server = /usr/sbin/in.telnetd\n}\n"))  # fmt: skip
            self.expect("FWA-SVC-001", "/etc/xinetd.d/telnet", "xinetd telnet")
        else:
            self.fs.file("etc/rc.local", self.text("#!/bin/sh\n/usr/sbin/telnetd -p 2323\nexit 0\n"), mode=0o755)
            self.expect("FWA-SVC-001", "/etc/rc.local", "telnetd from rc.local")

    def plant_web(self) -> None:
        self.plants.append("web-creds")
        form = self.rng.choice(["busybox-default", "htpasswd-default", "plaintext-unique"])
        conf = self.pick(["/etc/httpd.conf"], ["/etc/httpd/httpd.conf"])
        if form == "busybox-default":
            user, pw = self.rng.choice([("admin", "admin"), ("admin", "1234"), ("root", "root")])
            self.fs.file(conf.lstrip("/"), self.text(f"H:/www\nA:*\n/cgi-bin:{user}:{pw}\n"))
            self.expect("FWA-SVC-002", conf, f"busybox httpd {user}/{pw}")
        elif form == "htpasswd-default":
            user, pw = self.rng.choice([("admin", "admin"), ("admin", "password")])
            line = f"{user}:{md5_crypt(pw.encode(), self._salt(), '$apr1$')}\n"
            self.fs.file("www/.htpasswd", line)
            self.expect("FWA-SVC-002", "/www/.htpasswd", f"htpasswd {user}/{pw}")
        else:
            pw = "".join(self.rng.choice("bcdfghjkmnpqrstvwxz2345678") for _ in range(10))
            self.fs.file(conf.lstrip("/"), self.text(f"H:/www\n/cgi-bin:webadmin:{pw}\n"))
            self.expect("FWA-CRED-006", conf, "plaintext unique web password")

    def plant_ftp_snmp(self) -> None:
        if self.chance(0.5):
            self.plants.append("ftp-anon")
            self.fs.file("etc/vsftpd.conf", self.text("listen=YES\nanonymous_enable=YES\nlocal_enable=YES\n"))
            self.expect("FWA-SVC-003", "/etc/vsftpd.conf", "anonymous ftp")
        else:
            self.fs.file("etc/vsftpd.conf", self.text("listen=YES\nanonymous_enable=NO\n"))
        if self.chance(0.5):
            self.plants.append("snmp-default")
            rw = self.chance(0.5)
            line = "rwcommunity private\n" if rw else "rocommunity public default\n"
            self.fs.file("etc/snmp/snmpd.conf", self.text("sysLocation lab\n" + line))
            self.expect("FWA-SVC-004", "/etc/snmp/snmpd.conf", "rw private" if rw else "ro public")
        else:
            self.fs.file("etc/snmp/snmpd.conf", self.text("sysLocation lab\nrocommunity Xk29fQ 10.0.0.0/8\n"))

    def plant_permissions(self) -> None:
        if self.chance(0.5):
            self.plants.append("setuid-world-writable")
            self.fs.file("usr/bin/fw_updater", fake_elf(self.rng, ["fw_updater 1.0"]), mode=0o4777)
            self.expect("FWA-PERM-001", "/usr/bin/fw_updater", "4777 updater")
        if self.chance(0.5):
            self.plants.append("world-writable-script")
            self.fs.file("etc/init.d/S99custom", "#!/bin/sh\necho custom hooks\n", mode=0o777)
            self.expect("FWA-PERM-003", "/etc/init.d/S99custom", "0777 init script")
        if self.chance(0.5):
            self.plants.append("world-writable-dir")
            self.fs.dir("var/upload", 0o777)
            self.expect("FWA-PERM-004", "/var/upload", "0777 dir without sticky")

    def plant_nested_backup(self) -> None:
        self.plants.append("nested-config-backup")
        secret = "".join(self.rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(12))
        inner = Rootfs()
        inner.file("etc/config/admin.conf", f"admin_user=admin\nadmin_password={secret}\n")
        self.fs.file("etc/config/defaults.tar.gz", gzip.compress(tar_bytes(inner.entries()), mtime=0))
        self.expect("FWA-CRED-006", "/etc/config/admin.conf", "secret in nested tar.gz", where="nested")

    # ---------------------------------------------------------------- assembly
    def finish_rootfs(self) -> list[ArchiveEntry]:
        shadow_mode = 0o600
        if self.chance(0.3):
            self.plants.append("shadow-world-readable")
            shadow_mode = 0o644
            self.expect("FWA-CRED-007", "/etc/shadow", "shadow is 0644")
        self.fs.file("etc/passwd", "\n".join(self.passwd) + "\n")
        self.fs.file("etc/shadow", "\n".join(self.shadow) + "\n", mode=shadow_mode)
        rcs = "#!/bin/sh\nmount -a\n" + "".join(f"{line}\n" for line in self.startup)
        self.fs.file("etc/init.d/rcS", rcs, mode=0o755)
        return self.fs.entries()

    def build(self) -> Sample:
        self.base()
        self.plant_root_password()
        for plant, p in ((self.plant_passwd_hash, 0.35), (self.plant_uid0, 0.35),
                         (self.plant_config_secret, 0.6), (self.plant_keys, 0.6),
                         (self.plant_dropbear, 0.7), (self.plant_certs, 1.0),
                         (self.plant_telnet, 0.55), (self.plant_web, 0.55),
                         (self.plant_ftp_snmp, 1.0), (self.plant_permissions, 1.0),
                         (self.plant_nested_backup, 0.35)):  # fmt: skip
            if self.chance(p):
                plant()
        self.plant_libs()
        entries = self.finish_rootfs()
        layout = LAYOUTS[self.seed % len(LAYOUTS)]
        image = self.pack(layout, entries)
        name = f"{self.split}-{self.seed:04d}-{layout}"
        return Sample(name, self.seed, self.split, layout, image, self.expected, self.plants)

    def kernel(self) -> bytes:
        lines = [b"Linux version 4.14.180 (builder@synth) (gcc 8.4) #1 SMP"]
        for i in range(1500):
            words = b" ".join(self.rng.choice(_KERNEL_WORDS) for _ in range(6))
            lines.append(b"[%8d.%06d] " % (i // 100, i * 37 % 1000000) + words)
        return b"\n".join(lines) + b"\n"

    def pack(self, layout: str, entries: list[ArchiveEntry]) -> bytes:
        kernel = self.kernel()
        if layout == "uimage-multi-cpio":
            payload = uimage.build_multi_payload(
                [gzip.compress(kernel, mtime=0), gzip.compress(cpio.build_newc(entries), mtime=0)]
            )
            corrupt = self.chance(0.4)
            if corrupt:
                self.plants.append("uimage-data-crc")
                self.expect("FWA-EXT-004", None, "data CRC corrupted", where="image")
            return uimage.build(payload, name="synth multi", image_type=4, corrupt_data_crc=corrupt)
        if layout == "uimage-lzma-cpio":
            k = uimage.build(gzip.compress(kernel, mtime=0), name="synth kernel", compression=1)
            r = uimage.build(lzma_alone(cpio.build_newc(entries)), name="synth ramdisk",
                             image_type=3, compression=3)  # fmt: skip
            return pad_to(k, 4096) + r
        if layout == "tar-xz-update":
            return lzma.compress(tar_bytes(entries), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
        compression = "gzip" if layout == "flash-squashfs-gzip" else "xz"
        k = uimage.build(gzip.compress(kernel, mtime=0), name="synth kernel", compression=1)
        image = pad_to(k, ERASE_BLOCK)
        image += pad_to(squashfs_writer.build(entries, compression=compression), ERASE_BLOCK)
        image += pad_to(self.nvram(), ERASE_BLOCK)
        if self.chance(0.5):
            self.plants.append("encrypted-blob")
            image += self.rng.randbytes(64 * 1024)
            self.expect("FWA-EXT-006", None, "64 KiB random partition", where="image")
        return image

    def nvram(self) -> bytes:
        settings = "lan_ipaddr=192.168.1.1\nwan_proto=dhcp\nwl0_ssid=synth\nfw_version=1.0.3\n"
        blob = b"NVRM" + settings.encode()
        if self.chance(0.5):
            self.plants.append("nvram-key")
            blob += b"\x00" + pki.private_pem(pki.ec_key(900 + self.seed))
            self.expect("FWA-KEY-001", None, "PEM key in raw NVRAM partition", where="image")
        return blob


def generate(seed: int, split: str = "dev") -> Sample:
    """Build one synthetic firmware sample (deterministic for a given seed and split)."""
    return _Generator(seed, split).build()
