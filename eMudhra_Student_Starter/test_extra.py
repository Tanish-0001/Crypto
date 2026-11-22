"""Additional tests for Parts A/B arithmetic, beyond those in test_lab.py.

    python test_extra.py -v
    python test_extra.py --impl ../instructor/solution.py -v

Oracles are independent of student.py: brute-force enumeration on the toy
curves, Python's built-in pow(a, -1, m), and the cryptography package's
ec.derive_private_key for P-384.
"""
import argparse
from dataclasses import replace
import math
import random
import secrets
import sys
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from curve_params import P384, TOY, ORDER_TWO
from pki_helpers import load_impl, load_cert, load_public, point_of

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--impl")
options, remaining = parser.parse_known_args()
impl = load_impl(options.impl)

rng = random.Random(20261121)  # fixed seed: reproducible toy/fuzz cases


def library_point(d):
    """Public point d*G computed by the cryptography package (0 < d < n)."""
    return point_of(ec.derive_private_key(d, ec.SECP384R1()).public_key())


def brute_force_points(curve):
    """Every finite affine point, by direct search over F_p x F_p."""
    p = curve.p
    return [(x, y) for x in range(p) for y in range(p)
            if (y * y - x ** 3 - curve.a * x - curve.b) % p == 0]


def negate(point, curve):
    return None if point is None else (point[0], (-point[1]) % curve.p)


class InverseTests(unittest.TestCase):
    def test_inverse_matches_builtin_pow(self):
        for m in [2, 15, 17, 97, 360, P384.p, P384.n]:
            for _ in range(200):
                a = rng.randrange(-10 ** 120, 10 ** 120)
                with self.subTest(a=a, m=m):
                    if math.gcd(a, m) == 1:
                        inv = impl.inverse_mod(a, m)
                        self.assertTrue(0 < inv < m, "inverse not canonical")
                        self.assertEqual(inv, pow(a, -1, m))
                    else:
                        with self.assertRaises(ValueError):
                            impl.inverse_mod(a, m)


class ToyCurveTests(unittest.TestCase):
    def test_membership_agrees_with_enumeration(self):
        for curve in [TOY, ORDER_TWO]:
            points = set(brute_force_points(curve))
            for x in range(-1, curve.p + 1):
                for y in range(-1, curve.p + 1):
                    with self.subTest(curve=curve, x=x, y=y):
                        self.assertEqual(impl.is_on_curve((x, y), curve), (x, y) in points)

    def test_toy_group_is_cyclic_of_order_19(self):
        # The brute-force count (18 finite points + O) must equal TOY.n, and
        # repeated addition of g must visit each of them exactly once.
        finite = set(brute_force_points(TOY))
        self.assertEqual(len(finite) + 1, TOY.n)
        multiples, acc = [], None
        for _ in range(TOY.n):
            acc = impl.point_add(acc, TOY.g, TOY)
            multiples.append(acc)
        self.assertIsNone(multiples[-1])
        self.assertEqual(set(multiples[:-1]), finite)

    def test_scalar_mul_matches_repeated_addition_past_n(self):
        expected = None
        for k in range(3 * TOY.n + 1):
            with self.subTest(k=k):
                self.assertEqual(impl.scalar_mul(k, TOY.g, TOY), expected)
            expected = impl.point_add(expected, TOY.g, TOY)

    def test_group_axioms_on_all_toy_points(self):
        elements = [None] + brute_force_points(TOY)
        for a in elements:
            self.assertIsNone(impl.point_add(a, negate(a, TOY), TOY))
            for b in elements:
                ab = impl.point_add(a, b, TOY)
                self.assertTrue(impl.is_on_curve(ab, TOY))
                self.assertEqual(ab, impl.point_add(b, a, TOY))
        for _ in range(300):
            a, b, c = (rng.choice(elements) for _ in range(3))
            self.assertEqual(impl.point_add(impl.point_add(a, b, TOY), c, TOY),
                             impl.point_add(a, impl.point_add(b, c, TOY), TOY))

    def test_every_y_zero_point_doubles_to_identity(self):
        # y^2 = x^3 + x over F_17 has three points of order two: x in {0, 4, 13}.
        order_two = [pt for pt in brute_force_points(ORDER_TWO) if pt[1] == 0]
        self.assertEqual(sorted(order_two), [(0, 0), (4, 0), (13, 0)])
        for pt in order_two:
            self.assertIsNone(impl.point_add(pt, pt, ORDER_TWO))
            self.assertIsNone(impl.scalar_mul(2, pt, ORDER_TWO))
            self.assertEqual(impl.scalar_mul(3, pt, ORDER_TWO), pt)

    def test_order_check_is_not_a_tautology(self):
        # Under a falsely declared n, n*Q must be computed literally, not as 0*Q.
        for fake_n in [2, 3, 18, 20]:
            with self.subTest(fake_n=fake_n):
                self.assertIsNotNone(impl.scalar_mul(fake_n, TOY.g, replace(TOY, n=fake_n)))
        # On ORDER_TWO, points whose order does not divide 2 give 2*Q != O.
        bigger = [pt for pt in brute_force_points(ORDER_TWO) if pt[1] != 0]
        self.assertTrue(bigger)
        for pt in bigger:
            self.assertIsNotNone(impl.scalar_mul(ORDER_TWO.n, pt, ORDER_TWO))


class P384LibraryCrossCheck(unittest.TestCase):
    def test_random_full_length_scalars(self):
        for _ in range(10):
            d = secrets.randbelow(P384.n - 1) + 1
            with self.subTest(d=hex(d)):
                self.assertEqual(impl.scalar_mul(d, P384.g), library_point(d))

    def test_structured_scalars(self):
        # Hamming-weight extremes and every power of two exercise doubling-only
        # paths and long runs of additions.
        scalars = [3, 2 ** 383 - 1, P384.n - 2, (P384.n - 1) // 2]
        scalars += [1 << i for i in range(0, 384, 37)]
        for d in scalars:
            with self.subTest(d=hex(d)):
                self.assertEqual(impl.scalar_mul(d, P384.g), library_point(d))

    def test_point_add_and_doubling_against_library(self):
        for _ in range(5):
            a = secrets.randbelow(P384.n - 1) + 1
            b = secrets.randbelow(P384.n - 1) + 1
            qa, qb = library_point(a), library_point(b)
            s = (a + b) % P384.n
            self.assertEqual(impl.point_add(qa, qb), library_point(s) if s else None)
            self.assertEqual(impl.point_add(qa, qa), library_point(2 * a % P384.n))
            self.assertEqual(impl.point_add(qa, library_point(P384.n - a)), None)

    def test_scalar_mul_of_arbitrary_base_point(self):
        # a*(b*G) == (a*b mod n)*G with the inner point coming from the library.
        for _ in range(3):
            a = secrets.randbelow(P384.n - 1) + 1
            b = secrets.randbelow(P384.n - 1) + 1
            self.assertEqual(impl.scalar_mul(a, library_point(b)), library_point(a * b % P384.n))

    def test_fixture_public_keys_are_on_curve(self):
        points = [point_of(load_cert(f).public_key()) for f in
                  ["root_a.pem", "healthy_a.pem", "weak_a.pem", "weak_b.pem"]]
        points.append(point_of(load_public("structured_public.pem")))
        for q in points:
            self.assertTrue(impl.is_on_curve(q))
            self.assertIsNone(impl.scalar_mul(P384.n, q))


class RejectInvalidPoints(unittest.TestCase):
    def test_off_curve_and_noncanonical_points_raise(self):
        g = P384.g
        bad = [(0, 0), (g[0], g[1] + 1), (g[0] + P384.p, g[1]),
               (g[0], g[1] - P384.p), (g[0], P384.p + g[1])]
        for q in bad:
            with self.subTest(q=q):
                self.assertFalse(impl.is_on_curve(q))
                with self.assertRaises(ValueError):
                    impl.point_add(q, g)
                with self.assertRaises(ValueError):
                    impl.point_add(g, q)
                with self.assertRaises(ValueError):
                    impl.scalar_mul(2, q)

    def test_zero_scalar_still_validates_point(self):
        with self.assertRaises(ValueError):
            impl.scalar_mul(0, (0, 0))


class SignatureExtraTests(unittest.TestCase):
    def test_fresh_nonce_per_signature(self):
        # A constant or derived-from-d nonce would repeat r for the same message.
        rs = {impl.sign_message(173, b"same message")[0] for _ in range(5)}
        self.assertEqual(len(rs), 5)

    def test_signature_components_must_be_canonical(self):
        d, msg = 123456789, b"canonical"
        q = impl.scalar_mul(d, P384.g)
        r, s = impl.sign_message(d, msg)
        self.assertTrue(impl.verify_message(q, msg, (r, s)))
        # r + n and s + n are congruent mod n but outside 1 <= r, s < n.
        self.assertFalse(impl.verify_message(q, msg, (r + P384.n, s)))
        self.assertFalse(impl.verify_message(q, msg, (r, s + P384.n)))

    def test_test_leaf_verifies_under_weak_b_key(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        weak_a, weak_b = load_cert("weak_a.pem"), load_cert("weak_b.pem")
        d = impl.recover_small_scalar(point_of(weak_a.public_key()))
        leaf = impl.forge_lab_certificate(d, weak_a)
        sig = utils.decode_dss_signature(leaf.signature)
        self.assertEqual(leaf.issuer, weak_b.subject)
        self.assertTrue(impl.verify_message(point_of(weak_b.public_key()),
                                            leaf.tbs_certificate_bytes, sig))
        # The leaf must not simply reuse the CA key.
        self.assertNotEqual(point_of(leaf.public_key()), point_of(weak_a.public_key()))


def build_chain(root_ext=(), inter_ext=(), leaf_ext=None, inter_bc_critical=True,
                leaf_ku=None, san=("grades.crypto.test",), root_name="T Root"):
    """Fresh root -> intermediate -> leaf with one tweak per test. Returns (chain, anchors)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from pki_helpers import name, START, END, certificate_sha256
    from cryptography.x509.oid import ExtendedKeyUsageOID as EKU

    def ku(cert_sign, digital=True):
        return x509.KeyUsage(digital, False, False, False, False, cert_sign, cert_sign, False, False)

    def issue(subject, issuer, pub, signer, exts):
        b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
             .public_key(pub).serial_number(x509.random_serial_number())
             .not_valid_before(START).not_valid_after(END))
        for ext, critical in exts:
            b = b.add_extension(ext, critical)
        return b.sign(signer, hashes.SHA384())

    keys = [ec.generate_private_key(ec.SECP384R1()) for _ in range(3)]
    root = issue(root_name, root_name, keys[0].public_key(), keys[0],
                 [(x509.BasicConstraints(True, 1), True), (ku(True), True), *root_ext])
    inter = issue("T Inter", root_name, keys[1].public_key(), keys[0],
                  [(x509.BasicConstraints(True, 0), inter_bc_critical), (ku(True), True), *inter_ext])
    leaf_exts = leaf_ext if leaf_ext is not None else [
        (x509.BasicConstraints(False, None), True), (leaf_ku or ku(False), True),
        (x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), False),
        (x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), False)]
    leaf = issue("grades.crypto.test", "T Inter", keys[2].public_key(), keys[1], leaf_exts)
    return [leaf, inter, root], {certificate_sha256(root)}


class ProfileRuleTests(unittest.TestCase):
    def test_well_formed_chain_accepted(self):
        chain, anchors = build_chain()
        self.assertEqual(impl.validate_chain(chain, anchors), (True, "accepted"))

    def test_profile_violations_rejected(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
        ski = lambda: x509.SubjectKeyIdentifier(b"\x01" * 20)
        cases = {
            "non-critical extension outside profile": dict(inter_ext=[(ski(), False)]),
            "intermediate BasicConstraints not critical": dict(inter_bc_critical=False),
            "issuer EKU without serverAuth": dict(inter_ext=[(x509.ExtendedKeyUsage([EKU.CODE_SIGNING]), False)]),
            "leaf has keyCertSign": dict(leaf_ku=x509.KeyUsage(True, False, False, False, False,
                                                               True, False, False, False)),
            "wildcard SAN only": dict(san=("*.crypto.test",)),
            "no SAN, hostname only in CN": dict(san=()),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                chain, anchors = build_chain(**kwargs)
                self.assertFalse(impl.validate_chain(chain, anchors)[0])

    def test_issuer_eku_with_server_auth_is_allowed(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
        chain, anchors = build_chain(inter_ext=[(x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), False)])
        self.assertTrue(impl.validate_chain(chain, anchors)[0])


class TrustPolicyOverridesSignature(unittest.TestCase):
    """Every signature in these paths is valid; trust policy must still reject."""

    def test_impostor_root_with_trusted_name_rejected(self):
        # Same subject name as Root A, but a different (attacker-made) certificate.
        from pki_helpers import policies
        chain, _ = build_chain(root_name="BITS Crypto Lab Root A")
        leaf, inter, root = chain
        leaf.verify_directly_issued_by(inter)       # all signatures verify...
        inter.verify_directly_issued_by(root)
        root.verify_directly_issued_by(root)
        self.assertEqual(root.subject, load_cert("root_a.pem").subject)
        accepted, reason = impl.validate_chain(chain, **policies()["baseline"])
        self.assertFalse(accepted)                  # ...but the root is not an anchor
        self.assertIn("trust anchor", reason)

    def test_test_leaf_with_valid_signature_rejected_by_policy(self):
        from pki_helpers import policies, test_cases
        weak_a = load_cert("weak_a.pem")
        d = impl.recover_small_scalar(point_of(weak_a.public_key()))
        paths = test_cases(impl.forge_lab_certificate(d, weak_a))
        rules = policies()
        for path in ["forged_via_a", "forged_via_b"]:
            leaf, inter, _ = paths[path]
            leaf.verify_directly_issued_by(inter)   # the CA signature is genuine
            self.assertFalse(impl.validate_chain(paths[path], **rules["block_weak_spki"])[0])
        self.assertFalse(impl.validate_chain(paths["forged_via_a"], **rules["revoke_a_only"])[0])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *remaining])
