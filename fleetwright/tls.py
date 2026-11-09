"""
tls.py
~~~~~~
FleetWright's HTTPS certificate.

On first start a self-signed certificate is generated, naming the host in
FLEETWRIGHT_PUBLIC_URL plus FLEETWRIGHT_TLS_NAMES. An admin can upload their
own certificate and key under Settings → HTTPS; the previous pair is kept
as *.prev and restored if the new one won't load.

Agents trust the exact certificate they were enrolled with (it's their trust
anchor), plus the system CAs. When the certificate changes, connected agents
are sent the new one first over their existing, already-trusted connection.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import config

CERT = "cert.pem"
KEY = "key.pem"


def tls_dir() -> Path:
    return Path(config.TLS_DIR)


def cert_path() -> Path:
    return tls_dir() / CERT


def key_path() -> Path:
    return tls_dir() / KEY


def names() -> list[str]:
    out = []
    host = urlsplit(config.PUBLIC_URL).hostname
    if host:
        out.append(host)
    out += [n.strip() for n in config.TLS_NAMES.split(",") if n.strip()]
    # Not socket.gethostname(): in a container that's just the container ID.
    out += ["localhost", "127.0.0.1"]
    seen, uniq = set(), []
    for n in out:
        if n.lower() not in seen:
            seen.add(n.lower())
            uniq.append(n)
    return uniq


def generate_self_signed(extra_names: Optional[list[str]] = None) -> None:
    all_names = names() + [n for n in (extra_names or []) if n]
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for n in dict.fromkeys(all_names):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, all_names[0][:64]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FleetWright (self-signed)")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    _write(cert.public_bytes(serialization.Encoding.PEM),
           key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()))


def _write(cert_pem: bytes, key_pem: bytes) -> None:
    d = tls_dir()
    d.mkdir(parents=True, exist_ok=True)
    for name in (CERT, KEY):
        if (d / name).exists():
            os.replace(d / name, d / f"{name}.prev")
    fd = os.open(d / KEY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)
    (d / CERT).write_bytes(cert_pem)


def ensure() -> None:
    """Make sure a loadable certificate is there: roll back a bad upload, or generate one."""
    if cert_path().exists() and key_path().exists():
        try:
            ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(cert_path(), key_path())
            return
        except (ssl.SSLError, OSError):
            prev_c, prev_k = tls_dir() / f"{CERT}.prev", tls_dir() / f"{KEY}.prev"
            if prev_c.exists() and prev_k.exists():
                os.replace(prev_c, cert_path())
                os.replace(prev_k, key_path())
                return ensure()
    generate_self_signed()


class CertProblem(Exception):
    pass


def install_uploaded(cert_pem: str, key_pem: str) -> None:
    """Check an uploaded certificate (with any chain) and key, then make them current."""
    try:
        certs = x509.load_pem_x509_certificates(cert_pem.encode())
    except ValueError as e:
        raise CertProblem("The certificate isn't readable PEM.") from e
    if not certs:
        raise CertProblem("No certificate found in what was pasted.")
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError) as e:
        raise CertProblem("The key isn't a readable, unencrypted PEM private key.") from e
    leaf = certs[0]
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub(leaf.public_key()) != pub(key.public_key()):
        raise CertProblem("The key doesn't belong to the first certificate.")
    if leaf.not_valid_after_utc < datetime.now(timezone.utc):
        raise CertProblem("That certificate has already expired.")
    # Last check: does it load the way the server will load it?
    tmp = tls_dir() / "check"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / CERT).write_text(cert_pem)
    (tmp / KEY).write_text(key_pem)
    try:
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(tmp / CERT, tmp / KEY)
    except ssl.SSLError as e:
        raise CertProblem(f"The server can't load that pair: {e}") from e
    finally:
        for p in tmp.iterdir():
            p.unlink()
        tmp.rmdir()
    _write(cert_pem.encode(), key_pem.encode())


@dataclass
class CertInfo:
    subject: str
    issuer: str
    names: list[str]
    not_after: datetime
    self_signed: bool
    sha256: str          # certificate fingerprint, as browsers show it
    spki_pin: str        # base64 SHA-256 of the public key, for curl --pinnedpubkey
    pem: str


def current() -> Optional[CertInfo]:
    if not cert_path().exists():
        return None
    pem = cert_path().read_text()
    leaf = x509.load_pem_x509_certificates(pem.encode())[0]
    try:
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_names = [str(v) for v in sans.get_values_for_type(x509.DNSName)] + \
                    [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san_names = []
    spki = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = leaf.fingerprint(hashes.SHA256()).hex().upper()
    return CertInfo(subject=leaf.subject.rfc4514_string(), issuer=leaf.issuer.rfc4514_string(),
                    names=san_names, not_after=leaf.not_valid_after_utc,
                    self_signed=leaf.issuer == leaf.subject,
                    sha256=":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
                    spki_pin=base64.b64encode(hashlib.sha256(spki).digest()).decode(), pem=pem)


def leaf_pem() -> str:
    """The server certificate alone (no chain), which agents add to their trust store."""
    info = current()
    if not info:
        return ""
    leaf = x509.load_pem_x509_certificates(info.pem.encode())[0]
    return leaf.public_bytes(serialization.Encoding.PEM).decode()
