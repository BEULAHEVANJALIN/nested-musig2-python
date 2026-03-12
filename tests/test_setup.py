"""
Smoke test: verify that secp256k1lab is installed and functional.

This test checks the following operations that MuSig2 depends on:
1. Scalar arithmetic modulo the group order n
2. Point multiplication
3. Point addition (the group operation)
4. The distributive property: (a + b)·G = a·G + b·G

If any of these operations fail, the MuSig2 implementation will not work.
"""

from secp256k1lab.secp256k1 import GE, Scalar, G

def test_secp256k1lab_imports():
    """Verify core imports work."""
    assert G is not None
    assert not G.infinity
    print("Generator point G loaded")

def test_scalar_arithmetic():
    """
    Verify scalar operations modulo the group order n.
    """
    a = Scalar(7)
    b = Scalar(13)
    # Addition mod n
    c = a + b
    assert int(c) == 20
    # Multiplication mod n
    d = a * b
    assert int(d) == 91
    # Division = multiplication by modular inverse
    # a / b means a · b^-1 mod n
    a_inv = Scalar(1) / a
    assert int(a * a_inv) == 1
    # Negation mod n
    # -a mod n = n - a
    neg_a = -a
    assert int(a + neg_a) == 0
    print("Scalar arithmetic works (add, mul, div, neg)")

def test_point_operations():
    """
    Verify elliptic curve point operations.
    """
    # Scalar multiplication: private_key · G = public_key
    sk = Scalar(42)
    pk = sk * G
    assert not pk.infinity
    # Point addition
    another = Scalar(100) * G
    combined = pk + another
    assert not combined.infinity
    # Point equality
    pk2 = Scalar(42) * G
    assert pk == pk2
    # Identity element: 0 · G = point at infinity
    zero_point = Scalar(0) * G
    assert zero_point.infinity
    print("Point operations working (scalar mul, add, equality, infinity)")

def test_distributive_property():
    """
    Verify that (a + b)·G = a·G + b·G.
    """
    a = Scalar(42)
    b = Scalar(100)
    left = (a + b) * G        # (a + b) · G
    right = a * G + b * G     # a·G + b·G
    assert left == right
    print("Distributive property verified. (a+b)·G = a·G + b·G")

def test_serialization():
    """
    Verify point serialization and deserialization.
    """
    sk = Scalar(12345)
    P = sk * G
    # x-only serialization (32 bytes)
    xonly = P.to_bytes_xonly()
    assert len(xonly) == 32
    # Compressed serialization (33 bytes)
    compressed = P.to_bytes_compressed()
    assert len(compressed) == 33
    assert compressed[0] in (0x02, 0x03)  # prefix byte: 02=even y, 03=odd y
    # Round-trip: serialize then deserialize must give the same point
    P_recovered = GE.from_bytes_compressed(compressed)
    assert P == P_recovered
    # x-only round-trip (implicit even y, BIP 340 convention)
    P_xonly_recovered = GE.from_bytes_xonly(xonly)
    # x-only always lifts to even y
    assert P_xonly_recovered.x == P.x
    print("Serialization round-trips work (compressed, x-only)")

if __name__ == "__main__":
    test_secp256k1lab_imports()
    test_scalar_arithmetic()
    test_point_operations()
    test_distributive_property()
    test_serialization()
    print("\nAll setup tests passed. secp256k1lab is working correctly.\n")