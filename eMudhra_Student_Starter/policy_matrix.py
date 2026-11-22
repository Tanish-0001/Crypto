"""Part D experiment: every path under every policy in pki_helpers.policies().

    python policy_matrix.py      # prints a table, writes results/policy_matrix.json

Each policy is a separate set of arguments built from the baseline, so the
policies are applied independently, never cumulatively.
"""
import json
from pathlib import Path

from pki_helpers import load_cert, point_of, test_cases, policies, certificate_sha256, spki_sha256
import student


def main():
    weak_a = load_cert("weak_a.pem")
    d = student.recover_small_scalar(point_of(weak_a.public_key()))
    paths = test_cases(student.forge_lab_certificate(d, weak_a))
    rules = policies()

    matrix = {}
    for path_name, chain in paths.items():
        matrix[path_name] = {}
        for policy_name, kwargs in rules.items():
            accepted, reason = student.validate_chain(chain, **kwargs)
            matrix[path_name][policy_name] = {"accepted": accepted, "reason": reason}

    print(f"{'path':15}" + "".join(f"{p:17}" for p in rules))
    for path_name, row in matrix.items():
        print(f"{path_name:15}" + "".join(f"{('ACCEPT' if c['accepted'] else 'REJECT'):17}"
                                          for c in row.values()))
    print("\nRejection reasons:")
    for path_name, row in matrix.items():
        for policy_name, cell in row.items():
            if not cell["accepted"]:
                print(f"  {path_name:15} {policy_name:17} {cell['reason']}")

    print("\nCertificate vs key fingerprints of the intermediates:")
    for f in ["weak_a.pem", "weak_b.pem", "healthy_a.pem", "healthy_b.pem"]:
        c = load_cert(f)
        print(f"  {f:14} cert {certificate_sha256(c)[:16]}...  SPKI {spki_sha256(c)[:16]}...  "
              f"issuer {c.issuer.rfc4514_string()}")

    Path("results").mkdir(exist_ok=True)
    Path("results/policy_matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")


if __name__ == "__main__":
    main()
