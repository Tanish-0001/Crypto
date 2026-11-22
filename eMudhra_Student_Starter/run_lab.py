"""Run completed functions and write machine-readable results. No network IO."""
import argparse
import json
from pathlib import Path
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from pki_helpers import (FIXTURES, load_impl, load_cert, load_public, point_of,
                         read_manifest, test_cases, policies, save_cert,
                         certificate_sha256, spki_sha256)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--impl", help="Implementation .py path; default student.py")
    parser.add_argument("--out", default="results", help="Output directory")
    args = parser.parse_args()
    impl = load_impl(args.impl)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = {"inventory": []}
    for filename in read_manifest()["inventory"]:
        cert = load_cert(filename)
        start = time.perf_counter()
        d = impl.recover_small_scalar(point_of(cert.public_key()), 256)
        elapsed = time.perf_counter() - start
        matches = (None if d is None else point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key())
                   == point_of(cert.public_key()))
        if matches is False:
            raise RuntimeError(f"Recovered scalar does not reproduce the public key: {filename}")
        report["inventory"].append({"file": filename, "recovered_scalar": d,
            "public_key_match": matches,
            "finding": "RECOVERED_IN_SEARCH_SET" if d is not None else "NOT_RECOVERED_IN_SEARCH_SET",
            "seconds": elapsed, "certificate_sha256": certificate_sha256(cert),
            "spki_sha256": spki_sha256(cert)})
    issuer = load_cert("weak_a.pem")
    d = impl.recover_small_scalar(point_of(issuer.public_key()), 256)
    if d is None:
        raise RuntimeError("Weak lab scalar was not recovered")
    message = b"Cryptography class proof of possession for grades.crypto.test"
    r, s = impl.sign_message(d, message)
    signature = utils.encode_dss_signature(r, s)
    issuer.public_key().verify(signature, message, ec.ECDSA(hashes.SHA384()))
    report["signature"] = {"library_verified": True,
        "student_verified": impl.verify_message(point_of(issuer.public_key()), message, (r, s)),
        "tampered_message_accepted": impl.verify_message(point_of(issuer.public_key()), message+b"!", (r, s))}
    forged = impl.forge_lab_certificate(d, issuer)
    save_cert(forged, out / "forged_lab_leaf.pem")
    report["policy_matrix"] = {}
    for label, chain in test_cases(forged).items():
        report["policy_matrix"][label] = {}
        for policy_name, kwargs in policies().items():
            accepted, reason = impl.validate_chain(chain, **kwargs)
            report["policy_matrix"][label][policy_name] = {"accepted": accepted, "reason": reason}
    report["structured_scalar"] = impl.recover_from_candidates(
        point_of(load_public("structured_public.pem")),
        [int(x) for x in read_manifest()["structured_candidates_decimal"]])
    report["ceremony"] = {
        "mismatched": impl.ceremony_consistent((FIXTURES / "ceremony_expected_spki.pem").read_bytes(),
            (FIXTURES / "weak_request.csr.pem").read_bytes(), (FIXTURES / "weak_a.pem").read_bytes()),
        "consistent": impl.ceremony_consistent((FIXTURES / "ceremony_good_spki.pem").read_bytes(),
            (FIXTURES / "healthy_request.csr.pem").read_bytes(), (FIXTURES / "healthy_a.pem").read_bytes())}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
