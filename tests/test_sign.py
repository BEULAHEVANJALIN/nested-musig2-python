from secp256k1lab.secp256k1 import GE, Scalar, G
from musig2.keyagg import key_agg
from musig2.nonce import generate_nonce, aggregate_nonces
from musig2.sign import (
    create_session,
    sign,
    verify_partial_sig,
    aggregate_partial_sigs,
)
from common.schnorr import verify_schnorr

def _make_signer(secret: int) -> tuple[Scalar, GE]:
    sk = Scalar(secret)
    pk = int(sk) * G
    return sk, pk

def _run_musig2(
    privkeys: list[Scalar],
    pubkeys: list[GE],
    msg: bytes,
    verify_partials: bool = True,
) -> tuple[GE, Scalar, GE]:
    """
    Execute a complete MuSig2 session and return (R, s, agg_pk).
    Optionally verify partial signatures along the way.
    """
    n = len(privkeys)
    # Key aggregation
    cache = key_agg(pubkeys)
    # Round 1: generate and aggregate nonces
    nonces = [generate_nonce() for _ in range(n)]
    all_pub_nonces = [nonce.pub_nonces for nonce in nonces]
    agg_nonces = aggregate_nonces(all_pub_nonces)
    # Create session
    session = create_session(cache, agg_nonces, msg)
    # Round 2: partial signatures
    partial_sigs = []
    for i in range(n):
        s_i = sign(session, nonces[i], privkeys[i], pubkeys[i])
        partial_sigs.append(s_i)
        # Optional: verify each partial signature
        if verify_partials:
            valid = verify_partial_sig(
                session, pubkeys[i], all_pub_nonces[i], s_i
            )
            assert valid, f"Partial signature {i} failed verification"
    # Aggregate
    R, s = aggregate_partial_sigs(session, partial_sigs)
    return R, s, cache.agg_pk

def test_3of3_signing():
    sk1, pk1 = _make_signer(1001)
    sk2, pk2 = _make_signer(2002)
    sk3, pk3 = _make_signer(3003)
    msg = b"3-of-3 MuSig2 signing test"
    R, s, agg_pk = _run_musig2([sk1, sk2, sk3], [pk1, pk2, pk3], msg)
    # Verify the aggregate signature
    assert verify_schnorr(agg_pk, msg, R, s)
    print("3-of-3 MuSig2 produces valid Schnorr signature")

def test_2of2_signing():
    sk1, pk1 = _make_signer(42)
    sk2, pk2 = _make_signer(43)
    msg = b"2-of-2 test"
    R, s, agg_pk = _run_musig2([sk1, sk2], [pk1, pk2], msg)
    assert verify_schnorr(agg_pk, msg, R, s)
    print("2-of-2 MuSig2 produces valid Schnorr signature")

def test_wrong_message_rejected():
    sk1, pk1 = _make_signer(100)
    sk2, pk2 = _make_signer(200)
    R, s, agg_pk = _run_musig2(
        [sk1, sk2], [pk1, pk2], b"correct message", verify_partials=False
    )
    assert not verify_schnorr(agg_pk, b"wrong message", R, s)
    print("Wrong message correctly rejected")

def test_wrong_key_rejected():
    """Signature must not verify under a different aggregate key."""
    sk1, pk1 = _make_signer(500)
    sk2, pk2 = _make_signer(600)
    R, s, agg_pk = _run_musig2(
        [sk1, sk2], [pk1, pk2], b"test", verify_partials=False
    )
    # Create a different aggregate key
    _, pk3 = _make_signer(700)
    fake_cache = key_agg([pk1, pk3])
    assert not verify_schnorr(fake_cache.agg_pk, b"test", R, s)
    print("Wrong aggregate key correctly rejected")

def test_partial_sigs_verified():
    """Each partial signature should pass individual verification."""
    sk1, pk1 = _make_signer(11)
    sk2, pk2 = _make_signer(22)
    sk3, pk3 = _make_signer(33)
    pubkeys = [pk1, pk2, pk3]
    cache = key_agg(pubkeys)
    nonces = [generate_nonce() for _ in range(3)]
    all_pub_nonces = [n.pub_nonces for n in nonces]
    agg_nonces = aggregate_nonces(all_pub_nonces)
    msg = b"partial verification test"
    session = create_session(cache, agg_nonces, msg)
    # Sign and verify each partial
    privkeys = [sk1, sk2, sk3]
    for i in range(3):
        s_i = sign(session, nonces[i], privkeys[i], pubkeys[i])
        valid = verify_partial_sig(session, pubkeys[i], all_pub_nonces[i], s_i)
        assert valid, f"Partial sig {i} should be valid"
    print("All partial signatures pass individual verification")

def test_partial_sig_not_valid_for_other_signer():
    """Signer A's partial sig must not verify under signer B's key."""
    sk1, pk1 = _make_signer(77)
    sk2, pk2 = _make_signer(88)
    cache = key_agg([pk1, pk2])
    nonces = [generate_nonce() for _ in range(2)]
    all_pub_nonces = [n.pub_nonces for n in nonces]
    agg_nonces = aggregate_nonces(all_pub_nonces)
    session = create_session(cache, agg_nonces, b"cross-signer test")
    # Signer 1 signs
    s1 = sign(session, nonces[0], sk1, pk1)
    # Verify s1 under signer 2's key - should FAIL
    assert not verify_partial_sig(session, pk2, all_pub_nonces[0], s1)
    print("Partial sig from signer A rejected under signer B's key")

def test_multiple_sessions_different_messages():
    """Different messages produce different signatures (same signers)."""
    sk1, pk1 = _make_signer(1234)
    sk2, pk2 = _make_signer(5678)
    R_a, s_a, pk_a = _run_musig2(
        [sk1, sk2], [pk1, pk2], b"message A", verify_partials=False
    )
    R_b, s_b, pk_b = _run_musig2(
        [sk1, sk2], [pk1, pk2], b"message B", verify_partials=False
    )
    # Same aggregate key (same signers)
    assert pk_a == pk_b
    # Different nonces and signatures (fresh nonces each session)
    assert R_a != R_b
    assert int(s_a) != int(s_b)
    # Both verify for their respective messages
    assert verify_schnorr(pk_a, b"message A", R_a, s_a)
    assert verify_schnorr(pk_b, b"message B", R_b, s_b)
    print("Multiple sessions: same signers, different messages, both valid")

if __name__ == "__main__":
    test_3of3_signing()
    test_2of2_signing()
    test_wrong_message_rejected()
    test_wrong_key_rejected()
    test_partial_sigs_verified()
    test_partial_sig_not_valid_for_other_signer()
    test_multiple_sessions_different_messages()
    print("\nAll signing tests passed!\n")
