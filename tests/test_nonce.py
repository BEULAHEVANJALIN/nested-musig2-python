from secp256k1lab.secp256k1 import GE, Scalar, G
from musig2.nonce import generate_nonce, aggregate_nonces, NU, SignerNonce

def test_nonce_generation_basic():
    nonce = generate_nonce()
    assert len(nonce.pub_nonces) == NU
    for R in nonce.pub_nonces:
        assert not R.infinity, "Nonce commitment should not be infinity"
    print("Nonce generation produces valid points")

def test_nonce_commitment_matches_secret():
    nonce = generate_nonce()
    # Access secrets (this consumes the nonce - one-time use)
    secrets = nonce.get_sec_nonces()
    for j in range(NU):
        expected_R = int(secrets[j]) * G
        assert expected_R == nonce.pub_nonces[j], (
            f"Nonce commitment mismatch at index {j}: R ≠ r·G"
        )
    print("Every pub_nonce R_j equals sec_nonce_j · G")

def test_nonce_reuse_prevented():
    """Attempting to use a nonce twice must raise an error."""
    nonce = generate_nonce()
    # First use: OK
    nonce.get_sec_nonces()
    # Second use: MUST fail
    try:
        nonce.get_sec_nonces()
        assert False, "Should have raised RuntimeError on nonce reuse"
    except RuntimeError as e:
        assert "reuse" in str(e).lower()
    print("Nonce reuse correctly detected and prevented")

def test_nonce_secrets_zeroed_after_use():
    """After get_sec_nonces(), the stored secrets should be zeroed."""
    nonce = generate_nonce()
    nonce.get_sec_nonces()
    # The internal secrets should now be zero
    for s in nonce._sec_nonces:
        assert int(s) == 0, "Secret nonce not zeroed after use"
    print("Secret nonces zeroed after consumption")

def test_nonces_are_fresh():
    """Two calls to generate_nonce() must produce different nonces."""
    n1 = generate_nonce()
    n2 = generate_nonce()
    # Overwhelmingly likely that random nonces differ
    assert n1.pub_nonces[0] != n2.pub_nonces[0], (
        "Two independently generated nonces should differ"
    )
    print("Each generate_nonce() call produces fresh randomness")

def test_aggregation_basic():
    """Aggregate nonces from 3 signers and verify coordinate-wise sum."""
    n1 = generate_nonce()
    n2 = generate_nonce()
    n3 = generate_nonce()
    all_nonces = [n1.pub_nonces, n2.pub_nonces, n3.pub_nonces]
    agg = aggregate_nonces(all_nonces)
    assert len(agg) == NU
    # Verify: agg[j] = n1[j] + n2[j] + n3[j]
    for j in range(NU):
        expected = n1.pub_nonces[j] + n2.pub_nonces[j] + n3.pub_nonces[j]
        assert agg[j] == expected, f"Aggregation mismatch at index {j}"
    print("Nonce aggregation: R_j = Σ R_{i,j} verified for 3 signers")

def test_aggregation_two_signers():
    n1 = generate_nonce()
    n2 = generate_nonce()
    agg = aggregate_nonces([n1.pub_nonces, n2.pub_nonces])
    for j in range(NU):
        expected = n1.pub_nonces[j] + n2.pub_nonces[j]
        assert agg[j] == expected
    print("Two-signer nonce aggregation works")

def test_aggregation_order_independent():
    """
    Nonce aggregation should give the same result regardless of
    the order signers are listed (because point addition is commutative).
    """
    n1 = generate_nonce()
    n2 = generate_nonce()
    n3 = generate_nonce()
    agg_123 = aggregate_nonces([n1.pub_nonces, n2.pub_nonces, n3.pub_nonces])
    agg_321 = aggregate_nonces([n3.pub_nonces, n2.pub_nonces, n1.pub_nonces])
    for j in range(NU):
        assert agg_123[j] == agg_321[j]
    print("Nonce aggregation is order-independent (commutativity)")

if __name__ == "__main__":
    test_nonce_generation_basic()
    test_nonce_commitment_matches_secret()
    test_nonce_reuse_prevented()
    test_nonce_secrets_zeroed_after_use()
    test_nonces_are_fresh()
    test_aggregation_basic()
    test_aggregation_two_signers()
    test_aggregation_order_independent()
    print("\nAll nonce tests passed!\n")