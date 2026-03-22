import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.bip340 import schnorr_verify as bip340_verify
from musig2.keyagg import key_agg
from common.schnorr import verify_schnorr
from nested_musig2.nested_sign import (
    LeafSigner,
    NestedGroup,
    run_nested_musig2,
)

def _check_bip340(agg_pk: GE, msg: bytes, R: GE, s: Scalar) -> bool:
    """Verify using the library's BIP 340 verifier."""
    sig_bytes = R.to_bytes_xonly() + int(s).to_bytes(32, 'big')
    return bip340_verify(msg, agg_pk.to_bytes_xonly(), sig_bytes)

def test_simple_nesting():
    """
    Two groups of two:
        Root
       ╱    ╲
    Group_AB  Group_CD
     ╱  ╲      ╱  ╲
    A    B    C    D
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    group_cd = NestedGroup("Group_CD", [carol, dave])
    msg = b"Simple nested MuSig2 test"
    R, s, agg_pk = run_nested_musig2([group_ab, group_cd], msg)
    assert verify_schnorr(agg_pk, msg, R, s), "Typed verification failed"
    assert _check_bip340(agg_pk, msg, R, s), "BIP 340 verification failed"
    print("Simple nesting (2 groups of 2) passes both verifiers")

def test_mixed_depth():
    """
    Some signers are nested, some are direct leaves at the top level:
          Root
        ╱   |   ╲
    Group_AB  Carol  Dave
     ╱  ╲
    A    B
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    msg = b"Mixed depth test"
    R, s, agg_pk = run_nested_musig2([group_ab, carol, dave], msg)
    assert verify_schnorr(agg_pk, msg, R, s), "Typed verification failed"
    assert _check_bip340(agg_pk, msg, R, s), "BIP 340 verification failed"
    print("Mixed depth (nested + direct leaves) passes both verifiers")

def test_deep_nesting():
    """
    Three levels deep:
            Root
           ╱    ╲
      Group_Top   Eve
       ╱    ╲
    Group_L  Carol
     ╱  ╲
    A    B
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    eve = LeafSigner.generate("Eve")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, carol])
    msg = b"Deep nesting test (3 levels)"
    R, s, agg_pk = run_nested_musig2([group_top, eve], msg)
    assert verify_schnorr(agg_pk, msg, R, s), "Typed verification failed"
    assert _check_bip340(agg_pk, msg, R, s), "BIP 340 verification failed"
    print("Deep nesting (3 levels) passes both verifiers")

def test_single_member_group():
    """
    A group with one member should work (degenerate case):
        Root
       ╱    ╲
    Group_A   Bob
      |
    Alice
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    group_a = NestedGroup("Group_A", [alice])
    msg = b"Single member group test"
    R, s, agg_pk = run_nested_musig2([group_a, bob], msg)
    assert verify_schnorr(agg_pk, msg, R, s), "Typed verification failed"
    assert _check_bip340(agg_pk, msg, R, s), "BIP 340 verification failed"
    print("Single-member nested group works")

def test_wrong_message_rejected():
    """Nested signature must not verify for wrong message."""
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    group_cd = NestedGroup("Group_CD", [carol, dave])
    R, s, agg_pk = run_nested_musig2([group_ab, group_cd], b"correct message")
    assert not verify_schnorr(agg_pk, b"wrong message", R, s)
    assert not _check_bip340(agg_pk, b"wrong message", R, s)
    print("Wrong message rejected for nested signature")

def test_privacy_property():
    """
    The aggregate key for a nested group equals the aggregate key
    for the same keys aggregated directly. 
    This is the privacy property: nesting is invisible to the outer level.
    KeyAgg(KeyAgg(A, B), KeyAgg(C, D)) produces the same ROOT aggregate
    key as running the nested protocol, and verifiers can't tell the difference.
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    # Method 1: Aggregate directly (standard MuSig2 key aggregation)
    direct_cache = key_agg([alice.pubkey, bob.pubkey])
    # Method 2: Create a nested group (NestedMuSig2)
    group = NestedGroup("Group", [alice, bob])
    # The group's internal aggregate key should match direct aggregation
    assert direct_cache.agg_pk == group.cache.agg_pk, (
        "Nested group key should equal direct key aggregation"
    )
    print("Privacy: nested group key equals direct aggregation key")

def test_many_sessions():
    """
    Run multiple nested signing sessions to exercise even-y handling.
    All must produce valid BIP 340 signatures.
    """
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    for i in range(20):
        # Must regenerate leaf signers each session because nonces are single-use
        a = LeafSigner.generate("Alice")
        b = LeafSigner.generate("Bob")
        c = LeafSigner.generate("Carol")
        g = NestedGroup("G", [a, b])
        msg = f"nested session {i}".encode()
        R, s, agg_pk = run_nested_musig2([g, c], msg)
        assert _check_bip340(agg_pk, msg, R, s), f"Session {i} failed BIP 340"
    print("20 nested sessions all pass BIP 340 verification")

if __name__ == "__main__":
    test_simple_nesting()
    test_mixed_depth()
    test_deep_nesting()
    test_single_member_group()
    test_wrong_message_rejected()
    test_privacy_property()
    test_many_sessions()
    print("\nAll nested MuSig2 tests passed!\n")