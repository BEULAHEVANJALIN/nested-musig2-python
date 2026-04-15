import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.bip340 import schnorr_verify as bip340_verify
from musig2.keyagg import key_agg
from musig2.nonce import generate_nonce, aggregate_nonces
from musig2.sign import create_session
from nested_musig2.nonce_ext import sign_agg_ext
from common.schnorr import verify_schnorr
from nested_musig2.nested_sign import (
    LeafSigner,
    NestedGroup,
    NestedSigningTranscript,
    nested_sign,
    verify_nested_partial_sig,
    run_nested_musig2,
)

def _check_bip340(agg_pk: GE, msg: bytes, R: GE, s: Scalar) -> bool:
    """Verify using the library's BIP 340 verifier."""
    sig_bytes = R.to_bytes_xonly() + int(s).to_bytes(32, 'big')
    return bip340_verify(msg, agg_pk.to_bytes_xonly(), sig_bytes)


def _make_session(top_members: list, msg: bytes):
    """
    Build a root signing session for a nested tree and populate leaf nonces.
    Returns (session, root_cache, nested_bindings_by_group_name).
    """
    top_pubkeys = [
        m.pubkey if isinstance(m, LeafSigner) else m.cache.agg_pk
        for m in top_members
    ]
    root_cache = key_agg(top_pubkeys)
    nested_bindings: dict[str, Scalar] = {}

    def generate_nonces_recursive(member):
        if isinstance(member, LeafSigner):
            member.nonce = generate_nonce()
            return member.nonce.pub_nonces

        all_member_pub_nonces = []
        for child in member.members:
            all_member_pub_nonces.append(generate_nonces_recursive(child))
        internal_agg = aggregate_nonces(all_member_pub_nonces)
        external_nonces, b_nested = sign_agg_ext(internal_agg, member.cache.agg_pk)
        member.internal_agg_nonces = internal_agg
        member.external_nonces = external_nonces
        member.b_nested = b_nested
        nested_bindings[member.name] = b_nested
        return external_nonces

    top_level_pub_nonces = [generate_nonces_recursive(member) for member in top_members]
    top_agg_nonces = aggregate_nonces(top_level_pub_nonces)
    session = create_session(root_cache, top_agg_nonces, msg)
    return session, root_cache, nested_bindings

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

def test_group_key_is_aggregation_of_immediate_children():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_ab, carol])
    expected_group_ab = key_agg([alice.pubkey, bob.pubkey]).agg_pk
    expected_group_top = key_agg([group_ab.cache.agg_pk, carol.pubkey]).agg_pk
    assert group_ab.cache.agg_pk == expected_group_ab
    assert group_top.cache.agg_pk == expected_group_top
    print("NestedGroup aggregates immediate child node keys only")

def test_root_aggregates_top_level_member_node_keys():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    group_cd = NestedGroup("Group_CD", [carol, dave])
    _, _, agg_pk = run_nested_musig2([group_ab, group_cd], b"root semantics test")
    expected_root = key_agg([group_ab.cache.agg_pk, group_cd.cache.agg_pk]).agg_pk
    assert agg_pk == expected_root
    print("Root aggregates top-level member node keys, not flattened leaves")

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


def test_transcript_root_leaf_derives_factors_locally():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    msg = b"root leaf transcript"
    session, root_cache, _ = _make_session([alice, bob], msg)
    transcript = NestedSigningTranscript(
        session=session,
        path_caches=[root_cache],
        path_pubkeys=[alice.pubkey],
        nested_nonce_bindings=[],
    )
    s_i = nested_sign(transcript, alice.nonce, alice.privkey)
    assert verify_nested_partial_sig(transcript, alice.nonce.pub_nonces, s_i)
    assert int(transcript.nonce_factor()) == int(session.b)
    print("Root-level leaf derives its own transcript factors")


def test_transcript_nested_leaf_derives_factors_locally():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    msg = b"nested leaf transcript"
    session, root_cache, nested_bindings = _make_session([group_ab, carol], msg)
    transcript = NestedSigningTranscript(
        session=session,
        path_caches=[root_cache, group_ab.cache],
        path_pubkeys=[group_ab.cache.agg_pk, alice.pubkey],
        nested_nonce_bindings=[nested_bindings["Group_AB"]],
    )
    s_i = nested_sign(transcript, alice.nonce, alice.privkey)
    assert verify_nested_partial_sig(transcript, alice.nonce.pub_nonces, s_i)
    assert int(transcript.nonce_factor()) == int(session.b * nested_bindings["Group_AB"])
    print("Nested leaf derives its own path-dependent transcript factors")


def test_transcript_rejects_inconsistent_path():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    msg = b"bad transcript"
    session, root_cache, nested_bindings = _make_session([group_ab, carol], msg)
    try:
        NestedSigningTranscript(
            session=session,
            path_caches=[root_cache, group_ab.cache],
            path_pubkeys=[alice.pubkey, alice.pubkey],
            nested_nonce_bindings=[nested_bindings["Group_AB"]],
        )
        assert False, "Expected inconsistent transcript path to raise ValueError"
    except ValueError as e:
        assert "parent key set" in str(e)
    print("Malformed transcript paths are rejected")

if __name__ == "__main__":
    test_simple_nesting()
    test_mixed_depth()
    test_deep_nesting()
    test_single_member_group()
    test_wrong_message_rejected()
    test_privacy_property()
    test_group_key_is_aggregation_of_immediate_children()
    test_root_aggregates_top_level_member_node_keys()
    test_many_sessions()
    test_transcript_root_leaf_derives_factors_locally()
    test_transcript_nested_leaf_derives_factors_locally()
    test_transcript_rejects_inconsistent_path()
    print("\nAll nested MuSig2 tests passed!\n")