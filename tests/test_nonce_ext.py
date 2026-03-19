from secp256k1lab.secp256k1 import GE, Scalar, G
from musig2.keyagg import key_agg
from musig2.nonce import generate_nonce, aggregate_nonces, NU
from nested_musig2.nonce_ext import sign_agg_ext
from common.hashing import hash_nonce_nested

def _make_group(secrets: list[int]) -> tuple[list[Scalar], list[GE], GE]:
    """Create a group of signers and return (privkeys, pubkeys, agg_pk)."""
    privkeys = [Scalar(s) for s in secrets]
    pubkeys = [int(sk) * G for sk in privkeys]
    cache = key_agg(pubkeys)
    return privkeys, pubkeys, cache.agg_pk

def test_basic_sign_agg_ext():
    """SignAggExt produces valid non-infinity external nonces."""
    _, pubkeys, group_pk = _make_group([123, 456])
    nonces = [generate_nonce() for _ in range(2)]
    all_pub_nonces = [n.pub_nonces for n in nonces]
    internal_agg = aggregate_nonces(all_pub_nonces)
    external, b_nested = sign_agg_ext(internal_agg, group_pk)
    assert len(external) == NU
    for R in external:
        assert not R.infinity
    assert int(b_nested) != 0
    print("SignAggExt produces valid external nonces")

def test_first_nonce_unchanged():
    """
    R_1 = (R'_1)^{b̄^0} = R'_1 · 1 = R'_1.
    The first slot is multiplied by b̄^0 = 1, so it passes through unchanged.
    """
    _, pubkeys, group_pk = _make_group([300, 400])
    nonces = [generate_nonce() for _ in range(2)]
    internal_agg = aggregate_nonces([n.pub_nonces for n in nonces])
    external, _ = sign_agg_ext(internal_agg, group_pk)
    assert external[0] == internal_agg[0], "First external nonce should equal first internal nonce"
    print("First nonce unchanged: R_1 = R'_1 (b̄^0 = 1)")

def test_second_nonce_transformed():
    """
    R_2 = (R'_2)^{b̄} where b̄ = H̄_non(X̃, R'_1 || R'_2).
    The second slot is scaled by b̄, so it should differ from R'_2
    (unless b̄ = 1, which happens with negligible probability).
    """
    _, pubkeys, group_pk = _make_group([500, 600])
    nonces = [generate_nonce() for _ in range(2)]
    internal_agg = aggregate_nonces([n.pub_nonces for n in nonces])
    external, b_nested = sign_agg_ext(internal_agg, group_pk)
    # R_2 should differ from R'_2
    assert external[1] != internal_agg[1], "Second nonce should be transformed by b̄"
    # Verify manually: R_2 = b̄ · R'_2
    expected_R2 = int(b_nested) * internal_agg[1]
    assert external[1] == expected_R2, "R_2 should equal b̄ · R'_2"
    print("Second nonce transformed: R_2 = b̄ · R'_2")

def test_different_group_keys_different_output():
    """
    Different group aggregate keys produce different b̄ values and
    therefore different external nonces (even with same internal nonces).
    This prevents cross-group attacks where an attacker tries to
    reuse nonce relationships between different groups.
    """
    # Two different groups with different keys
    _, _, group_pk_a = _make_group([10, 20])
    _, _, group_pk_b = _make_group([30, 40])
    # Same internal nonces for both
    nonces = [generate_nonce() for _ in range(2)]
    internal_agg = aggregate_nonces([n.pub_nonces for n in nonces])
    external_a, b_a = sign_agg_ext(internal_agg, group_pk_a)
    external_b, b_b = sign_agg_ext(internal_agg, group_pk_b)
    assert int(b_a) != int(b_b), "Different group keys should produce different b̄"
    assert external_a[1] != external_b[1], "External nonces should differ for different groups"
    print("Different group keys produce different external nonces")

def test_deterministic():
    _, _, group_pk = _make_group([77, 88])
    # Fixed internal nonces (using known scalars for reproducibility)
    r1 = Scalar(11111)
    r2 = Scalar(22222)
    R1 = int(r1) * G
    R2 = int(r2) * G
    internal_agg = [R1, R2]
    external_1, b_1 = sign_agg_ext(internal_agg, group_pk)
    external_2, b_2 = sign_agg_ext(internal_agg, group_pk)
    assert int(b_1) == int(b_2)
    assert external_1[0] == external_2[0]
    assert external_1[1] == external_2[1]
    print("SignAggExt is deterministic")

def test_b_nested_matches_manual_hash():
    """Verify that b̄ is computed as H̄_non(X̃, R'_1 || R'_2)."""
    _, _, group_pk = _make_group([99, 100])
    r1 = Scalar(55555)
    r2 = Scalar(66666)
    internal_agg = [int(r1) * G, int(r2) * G]
    _, b_nested = sign_agg_ext(internal_agg, group_pk)
    # Manual computation
    pk_ser = group_pk.to_bytes_compressed()
    nonces_ser = internal_agg[0].to_bytes_compressed() + internal_agg[1].to_bytes_compressed()
    b_manual = hash_nonce_nested(pk_ser, nonces_ser)
    assert int(b_nested) == int(b_manual)
    print("b̄ matches manual H̄_non computation")

if __name__ == "__main__":
    test_basic_sign_agg_ext()
    test_first_nonce_unchanged()
    test_second_nonce_transformed()
    test_different_group_keys_different_output()
    test_deterministic()
    test_b_nested_matches_manual_hash()
    print("\nAll SignAggExt tests passed!\n")