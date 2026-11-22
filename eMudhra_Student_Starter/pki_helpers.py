"""Supplied plumbing for a deliberately restricted, offline certificate lab.

This is not a production certificate validator or TLS implementation.
Nothing here uses a network, installs trust anchors, or loads a system store.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECK_TIME = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
START = datetime(2026, 11, 1, tzinfo=timezone.utc)
END = datetime(2027, 11, 1, tzinfo=timezone.utc)
HOSTNAME = "grades.crypto.test"


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def load_cert(filename):
    return x509.load_pem_x509_certificate((FIXTURES / filename).read_bytes())


def load_public(filename):
    return serialization.load_pem_public_key((FIXTURES / filename).read_bytes())


def spki_bytes(public_key):
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_sha256(cert):
    return hashlib.sha256(spki_bytes(cert.public_key())).hexdigest()


def certificate_sha256(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def point_of(public_key):
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected an EC public key")
    if public_key.curve.name != "secp384r1":
        raise ValueError("Expected P-384")
    p = public_key.public_numbers()
    return p.x, p.y


def save_cert(cert, path):
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def leaf_template(issuer, leaf_public_key, *, hostname=HOSTNAME, serial=9001,
                  start=START, end=END, server_auth=True, digital_signature=True):
    """Unsigned test certificate. Students must supply the recovered signing key."""
    if not hostname.endswith(".test"):
        raise ValueError("This laboratory only issues .test names")
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server_auth else ExtendedKeyUsageOID.CODE_SIGNING
    return (x509.CertificateBuilder()
            .subject_name(name(hostname)).issuer_name(issuer.subject)
            .public_key(leaf_public_key).serial_number(serial)
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=digital_signature,
                           content_commitment=False, key_encipherment=False,
                           data_encipherment=False, key_agreement=False,
                           key_cert_sign=False, crl_sign=False,
                           encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))


def load_impl(path=None):
    target = Path(path) if path else Path(__file__).with_name("student.py")
    spec = importlib.util.spec_from_file_location("lab_implementation", target.resolve())
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_manifest():
    return json.loads((FIXTURES / "manifest.json").read_text())


def test_cases(forged):
    """Four explicit paths. A path builder may discover either weak path."""
    a, b = load_cert("root_a.pem"), load_cert("root_b.pem")
    return {
        "forged_via_a": [forged, load_cert("weak_a.pem"), a],
        "forged_via_b": [forged, load_cert("weak_b.pem"), b],
        "healthy_via_a": [load_cert("healthy_a_leaf.pem"), load_cert("healthy_a.pem"), a],
        "healthy_via_b": [load_cert("healthy_b_leaf.pem"), load_cert("healthy_b.pem"), b],
    }


def policies():
    a, b, weak = load_cert("root_a.pem"), load_cert("root_b.pem"), load_cert("weak_a.pem")
    both = {certificate_sha256(a), certificate_sha256(b)}
    return {
        "baseline": {"trust_anchors": both},
        "revoke_a_only": {"trust_anchors": both,
                          "revoked": {(spki_sha256(a), weak.serial_number)}},
        "block_weak_spki": {"trust_anchors": both,
                            "blocked_spki": {spki_sha256(weak)}},
        "remove_root_a": {"trust_anchors": {certificate_sha256(b)}},
    }
