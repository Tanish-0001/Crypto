"""Behavioral tests with independent cryptography-library oracles.

    python test_lab.py -v
    python test_lab.py --impl ../instructor/solution.py -v
    python test_lab.py ArithmeticTests -v
"""
import argparse
from dataclasses import replace
import sys
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from curve_params import P384, TOY, ORDER_TWO
from pki_helpers import (FIXTURES, load_impl, load_cert, load_public, point_of,
                         read_manifest, test_cases, policies, certificate_sha256, spki_sha256)

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--impl")
options, remaining = parser.parse_known_args()
impl = load_impl(options.impl)


class ArithmeticTests(unittest.TestCase):
    def test_inverse(self):
        self.assertEqual(impl.inverse_mod(3, 17), 6)
        self.assertEqual(impl.inverse_mod(-3, 17), 11)
        for a, p in [(0, 17), (6, 15)]:
            with self.subTest(a=a, p=p), self.assertRaises(ValueError):
                impl.inverse_mod(a, p)

    def test_curve_membership(self):
        self.assertTrue(impl.is_on_curve(None))
        self.assertTrue(impl.is_on_curve(P384.g))
        self.assertFalse(impl.is_on_curve((0, 0)))
        self.assertFalse(impl.is_on_curve((P384.g[0]+P384.p, P384.g[1])))

    def test_identity_inverse_and_order_two(self):
        g = TOY.g
        self.assertEqual(impl.point_add(None, g, TOY), g)
        self.assertEqual(impl.point_add(g, None, TOY), g)
        self.assertIsNone(impl.point_add(g, (g[0], (-g[1]) % TOY.p), TOY))
        self.assertIsNone(impl.point_add(ORDER_TWO.g, ORDER_TWO.g, ORDER_TWO))

    def test_small_curve_known_points(self):
        self.assertEqual(impl.scalar_mul(2, TOY.g, TOY), (6, 3))
        self.assertEqual(impl.scalar_mul(3, TOY.g, TOY), (10, 6))
        self.assertEqual(impl.scalar_mul(7, TOY.g, TOY), (0, 6))
        self.assertIsNone(impl.scalar_mul(19, TOY.g, TOY))

    def test_scalar_corner_cases(self):
        self.assertIsNone(impl.scalar_mul(0, P384.g))
        self.assertIsNone(impl.scalar_mul(P384.n, P384.g))
        self.assertEqual(impl.scalar_mul(P384.n+1, P384.g), P384.g)
        with self.assertRaises(ValueError):
            impl.scalar_mul(-1, P384.g)

    def test_no_automatic_scalar_reduction(self):
        altered = replace(TOY, n=2)
        self.assertEqual(impl.scalar_mul(2, TOY.g, altered), (6, 3))

    def test_p384_against_library(self):
        for d in [1, 2, 17, 257, (1 << 300)+13579, P384.n-1]:
            with self.subTest(d=d):
                expected = point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key())
                self.assertEqual(impl.scalar_mul(d, P384.g), expected)

    def test_group_law(self):
        for a, b in [(1, 3), (8, 11), (18, 18), (7, 4)]:
            self.assertEqual(impl.point_add(impl.scalar_mul(a, TOY.g, TOY),
                impl.scalar_mul(b, TOY.g, TOY), TOY), impl.scalar_mul(a+b, TOY.g, TOY))


class RecoveryTests(unittest.TestCase):
    def test_exclusive_bound(self):
        for d in [1, 2, 255, 256, 257]:
            q = point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key())
            self.assertEqual(impl.recover_small_scalar(q, 256), d if d < 256 else None)

    def test_recovery_by_public_key_equality(self):
        for f in ["weak_a.pem", "weak_b.pem"]:
            q = point_of(load_cert(f).public_key())
            d = impl.recover_small_scalar(q)
            self.assertIsInstance(d, int)
            self.assertTrue(1 <= d < 256)
            self.assertEqual(point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key()), q)
        for f in ["healthy_a.pem", "healthy_b.pem"]:
            self.assertIsNone(impl.recover_small_scalar(point_of(load_cert(f).public_key())))

    def test_recovery_invalid_input(self):
        for q in [None, (0, 0)]:
            with self.assertRaises(ValueError):
                impl.recover_small_scalar(q)
        with self.assertRaises(ValueError):
            impl.recover_small_scalar(P384.g, 1)

    def test_structured_full_length_key(self):
        q = point_of(load_public("structured_public.pem"))
        candidates = [int(x) for x in read_manifest()["structured_candidates_decimal"]]
        self.assertIsNone(impl.recover_small_scalar(q))
        d = impl.recover_from_candidates(q, candidates)
        self.assertIn(d, candidates)
        self.assertEqual(d.bit_length(), 384)
        self.assertEqual(point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key()), q)
        self.assertIsNone(impl.recover_from_candidates(q, [1, 2, 3]))
        with self.assertRaises(ValueError):
            impl.recover_from_candidates(q, [0])


class SignatureTests(unittest.TestCase):
    def test_manual_signature_accepted_by_library(self):
        d, msg = 123456789, b"Test ECDSA implementation"
        q = ec.derive_private_key(d, ec.SECP384R1()).public_key()
        r, s = impl.sign_message(d, msg)
        q.verify(utils.encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA384()))
        self.assertTrue(impl.verify_message(point_of(q), msg, (r, s)))
        self.assertFalse(impl.verify_message(point_of(q), msg+b"!", (r, s)))

    def test_library_signature_accepted_by_manual_verifier(self):
        key = ec.generate_private_key(ec.SECP384R1())
        msg = b"An independent signature implementation"
        sig = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA384())))
        self.assertTrue(impl.verify_message(point_of(key.public_key()), msg, sig))

    def test_reject_invalid_signature_values(self):
        for sig in [(0, 1), (1, 0), (P384.n, 1), (1, P384.n), (-1, 1)]:
            self.assertFalse(impl.verify_message(P384.g, b"x", sig))
        self.assertFalse(impl.verify_message(None, b"x", (1, 1)))
        self.assertFalse(impl.verify_message((0, 0), b"x", (1, 1)))
        for d in [0, P384.n]:
            with self.assertRaises(ValueError):
                impl.sign_message(d, b"x")

    def test_forged_leaf_has_valid_ca_signature(self):
        issuer = load_cert("weak_a.pem")
        d = impl.recover_small_scalar(point_of(issuer.public_key()))
        cert = impl.forge_lab_certificate(d, issuer)
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                   ec.ECDSA(hashes.SHA384()))
        self.assertNotEqual(point_of(cert.public_key()), point_of(issuer.public_key()))
        with self.assertRaises(ValueError):
            impl.forge_lab_certificate(d+1, issuer)


class TrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        issuer = load_cert("weak_a.pem")
        d = impl.recover_small_scalar(point_of(issuer.public_key()))
        cls.cases = test_cases(impl.forge_lab_certificate(d, issuer))
        cls.rules = policies()

    def test_policy_matrix(self):
        expected = {
            "forged_via_a": [True, False, False, False],
            "forged_via_b": [True, True, False, True],
            "healthy_via_a": [True, True, True, False],
            "healthy_via_b": [True, True, True, True],
        }
        for case, chain in self.cases.items():
            for (policy, kwargs), accepted in zip(self.rules.items(), expected[case]):
                with self.subTest(case=case, policy=policy):
                    actual, reason = impl.validate_chain(chain, **kwargs)
                    self.assertEqual(actual, accepted, reason)
                    self.assertIsInstance(reason, str)

    def test_certificate_identity_versus_key_identity(self):
        a, b = load_cert("weak_a.pem"), load_cert("weak_b.pem")
        self.assertNotEqual(certificate_sha256(a), certificate_sha256(b))
        self.assertEqual(spki_sha256(a), spki_sha256(b))

    def test_wrong_hostname(self):
        self.assertFalse(impl.validate_chain(self.cases["healthy_via_a"],
            **self.rules["baseline"], hostname="other.crypto.test")[0])

    def test_malformed_path(self):
        for chain in [None, [], [None, None, None], self.cases["healthy_via_a"][:2]]:
            with self.subTest(chain=chain):
                self.assertFalse(impl.validate_chain(chain, **self.rules["baseline"])[0])

    def test_bad_signature_expiry_and_leaf_usage(self):
        for fname in ["bad_signature_leaf.pem", "expired_leaf.pem", "not_yet_valid_leaf.pem",
                      "wrong_eku_leaf.pem", "wrong_ku_leaf.pem"]:
            chain = [load_cert(fname), *self.cases["healthy_via_a"][1:]]
            with self.subTest(fname=fname):
                self.assertFalse(impl.validate_chain(chain, **self.rules["baseline"])[0])

    def test_invalid_ca_and_unknown_extension(self):
        for fname in ["not_ca_intermediate.pem", "no_certsign_intermediate.pem",
                      "unknown_extension_intermediate.pem"]:
            chain = list(self.cases["healthy_via_a"])
            chain[1] = load_cert(fname)
            with self.subTest(fname=fname):
                self.assertFalse(impl.validate_chain(chain, **self.rules["baseline"])[0])

    def test_root_constraints_and_identity(self):
        chain = list(self.cases["healthy_via_a"])
        root = load_cert("root_a_pathlen_zero.pem")
        chain[-1] = root
        self.assertFalse(impl.validate_chain(chain, {certificate_sha256(root)})[0])
        self.assertFalse(impl.validate_chain(self.cases["healthy_via_a"], set())[0])
        chain = list(self.cases["healthy_via_a"])
        chain[-1] = load_cert("root_b.pem")
        self.assertFalse(impl.validate_chain(chain, **self.rules["baseline"])[0])

    def test_leaf_revocation_and_wrong_issuer_revocation(self):
        chain = self.cases["healthy_via_a"]
        revocation = {(spki_sha256(chain[1]), chain[0].serial_number)}
        self.assertFalse(impl.validate_chain(chain, **self.rules["baseline"], revoked=revocation)[0])
        wrong = {(spki_sha256(load_cert("root_b.pem")), chain[0].serial_number)}
        self.assertTrue(impl.validate_chain(chain, **self.rules["baseline"], revoked=wrong)[0])


class CeremonyTests(unittest.TestCase):
    def test_good_and_mismatched(self):
        good = [(FIXTURES / f).read_bytes() for f in
                ["ceremony_good_spki.pem", "healthy_request.csr.pem", "healthy_a.pem"]]
        bad = [(FIXTURES / f).read_bytes() for f in
               ["ceremony_expected_spki.pem", "weak_request.csr.pem", "weak_a.pem"]]
        self.assertTrue(impl.ceremony_consistent(*good))
        self.assertFalse(impl.ceremony_consistent(*bad))

    def test_invalid_csr_signature(self):
        csr = x509.load_pem_x509_csr((FIXTURES / "healthy_request.csr.pem").read_bytes())
        raw = bytearray(csr.public_bytes(serialization.Encoding.DER))
        raw[-1] ^= 1
        tampered = x509.load_der_x509_csr(bytes(raw)).public_bytes(serialization.Encoding.PEM)
        self.assertFalse(impl.ceremony_consistent((FIXTURES / "ceremony_good_spki.pem").read_bytes(),
            tampered, (FIXTURES / "healthy_a.pem").read_bytes()))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *remaining])
