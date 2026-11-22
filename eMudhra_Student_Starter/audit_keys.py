"""Key audit for the four intermediate certificates and structured_public.pem.

    python audit_keys.py            # prints a report and writes results/audit.json

Builds on inspect_fixtures.py: same inventory fields, plus the small-scalar
search result, an independent recomputation of each recovered key, and timings.
"""
import json
import platform
import statistics
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from curve_params import P384
from pki_helpers import (load_cert, load_public, point_of, read_manifest,
                         certificate_sha256, spki_sha256)
import student

RUNS = 5  # each timing is the median of this many runs


def median_seconds(fn):
    times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        result = fn()
        times.append(time.perf_counter() - start)
    return result, statistics.median(times)


def library_point(d):
    return point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key())


def finding(d):
    """Report only what the search showed; never call a key 'secure'."""
    return "RECOVERED_IN_SEARCH_SET" if d is not None else "NOT_RECOVERED_IN_SEARCH_SET"


def audit_certificate(filename, bound):
    cert = load_cert(filename)
    q = point_of(cert.public_key())

    valid, t_validate = median_seconds(lambda: student.is_valid_public_key(q))
    d, t_total = median_seconds(lambda: student.recover_small_scalar(q, bound))

    record = {
        "file": filename,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": cert.serial_number,
        "curve": cert.public_key().curve.name,
        "certificate_sha256": certificate_sha256(cert),
        "spki_sha256": spki_sha256(cert),
        "valid_public_key": valid,
        "search_set": f"1 <= d < {bound}",
        "finding": finding(d),
        "recovered_scalar": d,
        "seconds_validation": t_validate,
        "seconds_recover_total": t_total,
    }
    if d is not None:
        # Two independent recomputations of d*G: our scalar_mul and the library.
        record["recomputed_by_scalar_mul"] = student.scalar_mul(d, P384.g) == q
        record["recomputed_by_library"] = library_point(d) == q
    return record


def audit_structured(candidates):
    q = point_of(load_public("structured_public.pem"))
    expected_family = [2 ** 383 + j for j in range(1, 9)]
    d, t_total = median_seconds(lambda: student.recover_from_candidates(q, candidates))
    small = student.recover_small_scalar(q, 256)
    return {
        "file": "structured_public.pem",
        "candidates_are_2^383+j_for_j_1..8": candidates == expected_family,
        "small_search": {"search_set": "1 <= d < 256", "finding": finding(small)},
        "candidate_search": {"search_set": "2^383 + j, 1 <= j <= 8", "finding": finding(d)},
        "recovered_scalar": d,
        "j": None if d is None else d - 2 ** 383,
        "bit_length": None if d is None else d.bit_length(),
        "recomputed_by_library": d is not None and library_point(d) == q,
        "seconds_recover_total": t_total,
    }


def main():
    manifest = read_manifest()
    bound = manifest["small_bound_exclusive"]
    report = {
        "machine": {
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "bound_exclusive": bound,
        "timing": f"median of {RUNS} runs, time.perf_counter",
        "interpretation": ("NOT_RECOVERED_IN_SEARCH_SET means only that no scalar in the "
                           "stated search set matches the public key. It is not evidence "
                           "that the key was generated securely."),
        "intermediates": [audit_certificate(f, bound) for f in manifest["inventory"]],
        "structured": audit_structured([int(x) for x in manifest["structured_candidates_decimal"]]),
    }

    # Group certificates by key: same SPKI hash means the same public key.
    by_spki = {}
    for rec in report["intermediates"]:
        by_spki.setdefault(rec["spki_sha256"], []).append(rec["file"])
    report["shared_keys"] = [files for files in by_spki.values() if len(files) > 1]

    out = Path("results")
    out.mkdir(exist_ok=True)
    (out / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
