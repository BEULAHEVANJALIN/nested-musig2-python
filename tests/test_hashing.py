from secp256k1lab.util import tagged_hash
from common.hashing import (
    tagged_hash_to_scalar,
    hash_keyagg_list,
    hash_keyagg_coef,
    hash_nonce,
    hash_nonce_nested,
    hash_sig,
)
from secp256k1lab.secp256k1 import Scalar, G

def test_tagged_hash_determinism():
    """Same tag + same message = same output, always."""
    h1 = tagged_hash("test", b"hello")
    h2 = tagged_hash("test", b"hello")
    assert h1 == h2
    assert len(h1) == 32
    print("Tagged hash is deterministic, outputs 32 bytes")

def test_tagged_hash_domain_separation():
    """
    Different tags MUST produce different outputs for the same message.
    """
    h1 = tagged_hash("KeyAgg coefficient", b"same input")
    h2 = tagged_hash("BIP0340/challenge", b"same input")
    h3 = tagged_hash("MuSig/noncecoef", b"same input")
    assert h1 != h2
    assert h2 != h3
    assert h1 != h3
    print("Domain separation: different tags produce different outputs")

def test_tagged_hash_to_scalar():
    """Output should be a valid Scalar (reduced mod n)."""
    s = tagged_hash_to_scalar("test", b"hello")
    assert isinstance(s, Scalar)
    # The scalar should be nonzero (overwhelmingly likely for a hash)
    assert int(s) != 0
    print("tagged_hash_to_scalar returns a valid Scalar")

def test_hash_keyagg():
    """Test key aggregation hashing."""
    # Simulate two compressed public keys (33 bytes each)
    pk1 = (Scalar(111) * G).to_bytes_compressed()
    pk2 = (Scalar(222) * G).to_bytes_compressed()
    # Key list hash
    L = hash_keyagg_list(pk1 + pk2)
    assert len(L) == 32
    # Coefficients should differ for different keys
    a1 = hash_keyagg_coef(L, pk1)
    a2 = hash_keyagg_coef(L, pk2)
    assert int(a1) != int(a2)
    # Changing the key list changes the coefficients
    pk3 = (Scalar(333) * G).to_bytes_compressed()
    L_different = hash_keyagg_list(pk1 + pk3)
    a1_different = hash_keyagg_coef(L_different, pk1)
    assert int(a1) != int(a1_different)
    print("H_agg: coefficients depend on ALL keys (rogue-key prevention)")

def test_hash_nonce_includes_message():
    """
    H_non must produce different outputs for different messages.
    This is the defense against Wagner's attack.
    """
    dummy_pk = (Scalar(1) * G).to_bytes_compressed()
    dummy_nonces = (Scalar(2) * G).to_bytes_compressed()
    b1 = hash_nonce(dummy_pk, dummy_nonces, b"message A")
    b2 = hash_nonce(dummy_pk, dummy_nonces, b"message B")
    assert int(b1) != int(b2)
    print("H_non: different messages produce different nonce binding")

def test_hash_nonce_nested_excludes_message():
    """
    H̄_non takes no message argument.
    Verify that it produces consistent output from just key + nonces,
    and that it differs from H_non (different tags).
    """
    dummy_pk = (Scalar(1) * G).to_bytes_compressed()
    dummy_nonces = (Scalar(2) * G).to_bytes_compressed()
    # H̄_non with same inputs should be deterministic
    b1 = hash_nonce_nested(dummy_pk, dummy_nonces)
    b2 = hash_nonce_nested(dummy_pk, dummy_nonces)
    assert int(b1) == int(b2)
    # H̄_non and H_non with same key+nonces (and empty message) should differ
    # because they use different tags
    b_top = hash_nonce(dummy_pk, dummy_nonces, b"")
    assert int(b1) != int(b_top)
    print("H̄_non: no message input, differs from H_non (domain separation)")

def test_hash_sig_bip340_order():
    """
    H_sig input order must be R || X̃ || m (BIP 340 convention).
    We verify that swapping the order changes the output.
    """
    R = (Scalar(10) * G).to_bytes_xonly()
    X = (Scalar(20) * G).to_bytes_xonly()
    m = b"test message"
    c1 = hash_sig(X, R, m)  # correct: agg_pk_xonly, nonce_xonly, msg
    # Manually compute with swapped order to verify it differs
    swapped = tagged_hash_to_scalar("BIP0340/challenge", X + R + m)
    assert int(c1) != int(swapped)
    print("H_sig: follows BIP 340 input order (R || X̃ || m)")

if __name__ == "__main__":
    test_tagged_hash_determinism()
    test_tagged_hash_domain_separation()
    test_tagged_hash_to_scalar()
    test_hash_keyagg()
    test_hash_nonce_includes_message()
    test_hash_nonce_nested_excludes_message()
    test_hash_sig_bip340_order()
    print("\nAll hashing tests passed!\n")
