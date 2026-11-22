eMudhra inspired cryptography programming assignment
==================================================

Start with Assignment.pdf. The editable source is Assignment.tex.
This student bundle intentionally contains incomplete functions in student.py.
The test suite is expected to fail until those functions are implemented.

Environment
-----------
Python 3.11 or later. Tested with Python 3.12.14 and cryptography 50.0.0.
Create a virtual environment if desired, then install the pinned dependency:

    python -m pip install -r requirements.txt

Once the dependency is installed, all laboratory work is offline.
No pytest, OpenSSL command-line utility, server or network access is required.

Commands (run from this student directory)
----------------------------------------
    python inspect_fixtures.py
    python test_lab.py ArithmeticTests -v
    python test_lab.py RecoveryTests -v
    python test_lab.py SignatureTests -v
    python test_lab.py TrustTests -v
    python test_lab.py CeremonyTests -v
    python test_lab.py -v
    python run_lab.py --out results

Files
-----
student.py: functions to complete; return types and bounds are documented.
curve_params.py: P-384, small-curve and order-two test parameters.
pki_helpers.py: certificate parsing, hashing, unsigned templates and policies.
inspect_fixtures.py: working public certificate inventory.
test_lab.py: public behavioral tests, including invalid certificate cases.
run_lab.py: calls completed functions, writes report.json and a test certificate.
fixtures/: public certificates, public keys and certificate signing requests.
SOURCES.txt: primary incident reports, mathematical and API references.

Important interpretations
-------------------------
None from a bounded key search means 'not recovered in this search set'.
It never certifies that the key is secure or was generated randomly.
The two weak intermediate certificates have distinct certificate fingerprints
but the same public-key fingerprint. The structured candidate list is a
separate pedagogical example, not a claimed detail of eMudhra's implementation.

The trust validator implements the explicit three-certificate teaching profile
in the handout. It is not a browser, full RFC 5280 validator, or TLS stack.
The in-memory revocation tuples are not signed CRLs or OCSP responses.
The test clock is fixed at 2026-11-09 12:00 UTC so later grading is reproducible.
All hostnames end in .test. Do not install these roots in a system or browser.
Do not use real eMudhra certificates or keys in this exercise.

Submit
------
student.py, your additional tests, results/report.json, the test leaf certificate,
and a report of at most four pages. Include measurements, the acceptance matrix,
your mathematical reasoning, limitations, and a short tool-use declaration.
Do not submit a virtual environment or edit supplied fixtures to force a pass.
