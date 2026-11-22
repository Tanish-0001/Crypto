"""Read-only inventory; works before students implement any algorithms."""
import json
from pki_helpers import load_cert, read_manifest, spki_sha256, certificate_sha256


def main():
    records = []
    for filename in read_manifest()["inventory"]:
        cert = load_cert(filename)
        records.append({"file": filename, "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(), "serial": cert.serial_number,
                        "curve": cert.public_key().curve.name,
                        "certificate_sha256": certificate_sha256(cert),
                        "spki_sha256": spki_sha256(cert)})
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
