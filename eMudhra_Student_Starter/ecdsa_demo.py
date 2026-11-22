"""Part C experiments: ECDSA in both directions, then a test leaf certificate.

    python ecdsa_demo.py        # prints results, writes results/forged_lab_leaf.pem
"""
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtensionOID

from pki_helpers import load_cert, point_of, save_cert, spki_sha256
import student


def library_accepts(public_key, message, r, s):
    try:
        public_key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False


def main():
    weak_a, weak_b = load_cert("weak_a.pem"), load_cert("weak_b.pem")
    q = point_of(weak_a.public_key())
    d = student.recover_small_scalar(q)
    print(f"Recovered scalar for weak_a.pem: d = {d}\n")

    # --- Experiment 1: possession of the signing key -------------------------
    message = b"Cryptography class proof of possession for grades.crypto.test"
    changed = message + b"!"

    r, s = student.sign_message(d, message)
    print("Our signature -> library verify:   ", library_accepts(weak_a.public_key(), message, r, s))
    print("Our signature -> our verify:       ", student.verify_message(q, message, (r, s)))
    print("  changed message, library:        ", library_accepts(weak_a.public_key(), changed, r, s))
    print("  changed message, ours:           ", student.verify_message(q, changed, (r, s)))

    ca_key = ec.derive_private_key(d, ec.SECP384R1())
    lr, ls = utils.decode_dss_signature(ca_key.sign(message, ec.ECDSA(hashes.SHA384())))
    print("Library signature -> our verify:   ", student.verify_message(q, message, (lr, ls)))
    print("  changed message, ours:           ", student.verify_message(q, changed, (lr, ls)))

    r2, _ = student.sign_message(d, message)
    print("Same message signed twice, r differs (fresh nonce):", r != r2, "\n")

    # --- Experiment 2: a test leaf certificate --------------------------------
    leaf = student.forge_lab_certificate(d, weak_a)
    out = Path("results")
    out.mkdir(exist_ok=True)
    save_cert(leaf, out / "forged_lab_leaf.pem")

    print("Leaf subject:  ", leaf.subject.rfc4514_string())
    print("Leaf issuer:   ", leaf.issuer.rfc4514_string())
    print("Validity:      ", leaf.not_valid_before_utc, "to", leaf.not_valid_after_utc)
    for oid in [ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.EXTENDED_KEY_USAGE]:
        ext = leaf.extensions.get_extension_for_oid(oid)
        print(f"  {oid._name:24} critical={ext.critical!s:5}  {ext.value}")
    print("Leaf key differs from CA key:", point_of(leaf.public_key()) != q, "\n")

    # Verify the certificate signature under each intermediate's public key,
    # with the library and with our own verifier.
    sig_r, sig_s = utils.decode_dss_signature(leaf.signature)
    for name, inter in [("weak_a.pem", weak_a), ("weak_b.pem", weak_b)]:
        lib = library_accepts(inter.public_key(), leaf.tbs_certificate_bytes, sig_r, sig_s)
        ours = student.verify_message(point_of(inter.public_key()),
                                      leaf.tbs_certificate_bytes, (sig_r, sig_s))
        print(f"Leaf signature under {name}: library={lib}  ours={ours}")

    print("\nWhy weak_b also works:")
    print("  leaf issuer == weak_b subject:", leaf.issuer == weak_b.subject)
    print("  weak_a SPKI == weak_b SPKI:   ", spki_sha256(weak_a) == spki_sha256(weak_b))
    print("  weak_b issuer:                ", weak_b.issuer.rfc4514_string())


if __name__ == "__main__":
    main()
