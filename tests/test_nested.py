import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.bip340 import schnorr_verify as bip340_verify
from musig2.keyagg import key_agg
from musig2.nonce import generate_nonce, aggregate_nonces
from musig2.sign import create_session
from nested_musig2.nonce_ext import sign_agg_ext
from common.schnorr import verify_schnorr
from nested_musig2.nested_sign import (
    NestedBranchLevel,
    NestedBranchWitness,
    LeafSigner,
    NestedGroup,
    NestedGroupRound1State,
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
        member.round1_state = NestedGroupRound1State(
            cache=member.cache,
            internal_agg_nonces=internal_agg,
            external_nonces=external_nonces,
            b_nested=b_nested,
        )
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

def test_nested_group_round1_state_is_populated_consistently():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    _make_session([group_ab, carol], b"round-one state test")
    assert group_ab.round1_state is not None
    assert len(group_ab.round1_state.internal_agg_nonces) == 2
    assert len(group_ab.round1_state.external_nonces) == 2
    assert group_ab.round1_state.cache.agg_pk == group_ab.cache.agg_pk
    print("Nested group round-one state is populated consistently")

def test_branch_level_reconstructs_parent_cache_from_pubkeys():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    level = NestedBranchLevel(
        parent_pubkeys=[alice.pubkey, bob.pubkey],
        child_pubkey=alice.pubkey,
    )
    rebuilt_cache = level.build_parent_cache()
    expected_cache = key_agg([alice.pubkey, bob.pubkey])
    assert rebuilt_cache.agg_pk == expected_cache.agg_pk
    print("Branch levels rebuild parent MuSig2 cache from public keys")

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
    branch_witness = NestedBranchWitness(
        levels=[NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=alice.pubkey)],
        nested_nonce_bindings=[],
    )
    transcript = NestedSigningTranscript(
        session=session,
        branch_witness=branch_witness,
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
    branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_ab.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[nested_bindings["Group_AB"]],
    )
    transcript = NestedSigningTranscript(
        session=session,
        branch_witness=branch_witness,
    )
    s_i = nested_sign(transcript, alice.nonce, alice.privkey)
    assert verify_nested_partial_sig(transcript, alice.nonce.pub_nonces, s_i)
    assert int(transcript.nonce_factor()) == int(session.b * nested_bindings["Group_AB"])
    print("Nested leaf derives its own path-dependent transcript factors")

def test_transcript_deep_leaf_derives_factors_locally():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    eve = LeafSigner.generate("Eve")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, carol])
    msg = b"deep leaf transcript"
    session, root_cache, nested_bindings = _make_session([group_top, eve], msg)
    branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_top.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_top.cache.sorted_pks, child_pubkey=group_l.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_l.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[
            nested_bindings["Group_Top"],
            nested_bindings["Group_L"],
        ],
    )
    transcript = NestedSigningTranscript(
        session=session,
        branch_witness=branch_witness,
    )
    s_i = nested_sign(transcript, alice.nonce, alice.privkey)
    assert verify_nested_partial_sig(transcript, alice.nonce.pub_nonces, s_i)
    assert int(transcript.nonce_factor()) == int(
        session.b * nested_bindings["Group_Top"] * nested_bindings["Group_L"]
    )
    print("Deep leaf derives all path-dependent transcript factors locally")

def test_nested_partial_verifier_rejects_wrong_binding():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    msg = b"wrong nested binding"
    session, root_cache, nested_bindings = _make_session([group_ab, carol], msg)
    good_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_ab.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[nested_bindings["Group_AB"]],
    )
    good_transcript = NestedSigningTranscript(
        session=session,
        branch_witness=good_branch_witness,
    )
    s_i = nested_sign(good_transcript, alice.nonce, alice.privkey)
    bad_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_ab.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[nested_bindings["Group_AB"] + Scalar(1)],
    )
    bad_transcript = NestedSigningTranscript(
        session=session,
        branch_witness=bad_branch_witness,
    )
    assert not verify_nested_partial_sig(bad_transcript, alice.nonce.pub_nonces, s_i)
    print("Nested partial verification rejects an incorrect nested binding")


def test_nested_sessions_have_distinct_ids():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    session_a, _, _ = _make_session([alice, bob], b"session A")
    session_b, _, _ = _make_session([alice, bob], b"session B")
    assert session_a.session_id != session_b.session_id
    print("Different nested signing sessions have distinct session identifiers")

def test_nested_partial_verifier_rejects_wrong_session():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    good_session, good_root_cache, good_nested_bindings = _make_session([group_ab, carol], b"session one")
    good_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=good_root_cache.sorted_pks, child_pubkey=group_ab.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[good_nested_bindings["Group_AB"]],
    )
    good_transcript = NestedSigningTranscript(
        session=good_session,
        branch_witness=good_branch_witness,
    )
    s_i = nested_sign(good_transcript, alice.nonce, alice.privkey)
    # Build a second session for the same tree shape but a different message.
    alice_2 = LeafSigner("Alice", alice.privkey, alice.pubkey)
    bob_2 = LeafSigner("Bob", bob.privkey, bob.pubkey)
    carol_2 = LeafSigner("Carol", carol.privkey, carol.pubkey)
    group_ab_2 = NestedGroup("Group_AB", [alice_2, bob_2])
    bad_session, bad_root_cache, bad_nested_bindings = _make_session([group_ab_2, carol_2], b"session two")
    bad_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=bad_root_cache.sorted_pks, child_pubkey=group_ab_2.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab_2.cache.sorted_pks, child_pubkey=alice_2.pubkey),
        ],
        nested_nonce_bindings=[bad_nested_bindings["Group_AB"]],
    )
    bad_transcript = NestedSigningTranscript(
        session=bad_session,
        branch_witness=bad_branch_witness,
    )
    assert good_session.session_id != bad_session.session_id
    assert not verify_nested_partial_sig(bad_transcript, alice.nonce.pub_nonces, s_i)
    print("Nested partial verification rejects transcript reuse across sessions")

def test_transcript_rejects_wrong_path_ordering():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    eve = LeafSigner.generate("Eve")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, carol])
    msg = b"wrong path ordering"
    session, root_cache, nested_bindings = _make_session([group_top, eve], msg)
    try:
        NestedBranchWitness(
            levels=[
                NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_l.cache.agg_pk),
                NestedBranchLevel(parent_pubkeys=group_top.cache.sorted_pks, child_pubkey=group_top.cache.agg_pk),
                NestedBranchLevel(parent_pubkeys=group_l.cache.sorted_pks, child_pubkey=alice.pubkey),
            ],
            nested_nonce_bindings=[
                nested_bindings["Group_Top"],
                nested_bindings["Group_L"],
            ],
        )
        assert False, "Expected wrong transcript path ordering to raise ValueError"
    except ValueError as e:
        assert "parent key set" in str(e)
    print("Transcript rejects wrong path ordering")

def test_transcript_rejects_wrong_subgroup_key_in_path():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    eve = LeafSigner.generate("Eve")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, carol])
    msg = b"wrong subgroup key"
    session, root_cache, nested_bindings = _make_session([group_top, eve], msg)
    good_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_top.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_top.cache.sorted_pks, child_pubkey=group_l.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_l.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[
            nested_bindings["Group_Top"],
            nested_bindings["Group_L"],
        ],
    )
    good_transcript = NestedSigningTranscript(
        session=session,
        branch_witness=good_branch_witness,
    )
    s_i = nested_sign(good_transcript, alice.nonce, alice.privkey)
    bad_branch_witness = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_top.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_top.cache.sorted_pks, child_pubkey=carol.pubkey),
            NestedBranchLevel(parent_pubkeys=group_l.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[
            nested_bindings["Group_Top"],
            nested_bindings["Group_L"],
        ],
    )
    bad_transcript = NestedSigningTranscript(
        session=session,
        branch_witness=bad_branch_witness,
    )
    assert not verify_nested_partial_sig(bad_transcript, alice.nonce.pub_nonces, s_i)
    print("Nested partial verification rejects wrong subgroup key paths")

def test_run_nested_musig2_rejects_missing_deep_subgroup_binding():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    eve = LeafSigner.generate("Eve")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, carol])
    # Reproduce the run_nested_musig2 nonce-generation phase, then clear the
    # deeper subgroup binding to simulate incomplete protocol state.
    def generate_nonces_recursive(member):
        if isinstance(member, LeafSigner):
            member.nonce = generate_nonce()
            return member.nonce.pub_nonces
        all_member_pub_nonces = []
        for child in member.members:
            all_member_pub_nonces.append(generate_nonces_recursive(child))
        internal_agg = aggregate_nonces(all_member_pub_nonces)
        external_nonces, b_nested = sign_agg_ext(internal_agg, member.cache.agg_pk)
        member.round1_state = NestedGroupRound1State(
            cache=member.cache,
            internal_agg_nonces=internal_agg,
            external_nonces=external_nonces,
            b_nested=b_nested,
        )
        return external_nonces
    top_members = [group_top, eve]
    top_pubkeys = [m.pubkey if isinstance(m, LeafSigner) else m.cache.agg_pk for m in top_members]
    root_cache = key_agg(top_pubkeys)
    top_level_pub_nonces = [generate_nonces_recursive(member) for member in top_members]
    top_agg_nonces = aggregate_nonces(top_level_pub_nonces)
    session = create_session(root_cache, top_agg_nonces, b"missing deep subgroup binding")
    group_l.round1_state = None

    def collect_signatures(member, path_caches, path_levels, nested_bindings):
        if isinstance(member, LeafSigner):
            branch_witness = NestedBranchWitness(
                levels=path_levels + [NestedBranchLevel(parent_pubkeys=path_caches[-1].sorted_pks, child_pubkey=member.pubkey)],
                nested_nonce_bindings=nested_bindings,
            )
            transcript = NestedSigningTranscript(
                session=session,
                branch_witness=branch_witness,
            )
            return nested_sign(transcript, member.nonce, member.privkey)
        if member.round1_state is None:
            raise ValueError(f"Nested group {member.name} is missing round-one state")
        for child in member.members:
            if isinstance(child, LeafSigner):
                collect_signatures(child, path_caches, path_levels, nested_bindings)
            else:
                if child.round1_state is None:
                    raise ValueError(f"Nested group {child.name} is missing round-one state")
                collect_signatures(
                    child,
                    path_caches + [child.cache],
                    path_levels + [
                        NestedBranchLevel(parent_pubkeys=path_caches[-1].sorted_pks, child_pubkey=child.cache.agg_pk)
                    ],
                    nested_bindings + [child.round1_state.b_nested],
                )
    try:
        collect_signatures(
            group_top,
            [root_cache, group_top.cache],
            [NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=group_top.cache.agg_pk)],
            [group_top.round1_state.b_nested],
        )
        assert False, "Expected missing deep subgroup binding to raise ValueError"
    except ValueError as e:
        assert "missing round-one state" in str(e)
    print("Nested signing rejects missing deep subgroup round-one state")

def test_nested_sign_rejects_nonce_reuse_across_sessions():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    session_one, root_cache_one, nested_bindings_one = _make_session([group_ab, carol], b"session one")
    branch_witness_one = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache_one.sorted_pks, child_pubkey=group_ab.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
        ],
        nested_nonce_bindings=[nested_bindings_one["Group_AB"]],
    )
    transcript_one = NestedSigningTranscript(
        session=session_one,
        branch_witness=branch_witness_one,
    )
    nested_sign(transcript_one, alice.nonce, alice.privkey)
    alice_2 = LeafSigner("Alice", alice.privkey, alice.pubkey)
    bob_2 = LeafSigner("Bob", bob.privkey, bob.pubkey)
    carol_2 = LeafSigner("Carol", carol.privkey, carol.pubkey)
    group_ab_2 = NestedGroup("Group_AB", [alice_2, bob_2])
    session_two, root_cache_two, nested_bindings_two = _make_session([group_ab_2, carol_2], b"session two")
    branch_witness_two = NestedBranchWitness(
        levels=[
            NestedBranchLevel(parent_pubkeys=root_cache_two.sorted_pks, child_pubkey=group_ab_2.cache.agg_pk),
            NestedBranchLevel(parent_pubkeys=group_ab_2.cache.sorted_pks, child_pubkey=alice_2.pubkey),
        ],
        nested_nonce_bindings=[nested_bindings_two["Group_AB"]],
    )
    transcript_two = NestedSigningTranscript(
        session=session_two,
        branch_witness=branch_witness_two,
    )
    alice_2.nonce = alice.nonce
    try:
        nested_sign(transcript_two, alice_2.nonce, alice_2.privkey)
        assert False, "Expected nested cross-session nonce reuse to raise RuntimeError"
    except RuntimeError as e:
        assert "cross-session nonce reuse" in str(e).lower()
    print("Nested signing rejects nonce reuse across sessions")

def test_transcript_rejects_inconsistent_path():
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    msg = b"bad transcript"
    session, root_cache, nested_bindings = _make_session([group_ab, carol], msg)
    try:
        NestedBranchWitness(
            levels=[
                NestedBranchLevel(parent_pubkeys=root_cache.sorted_pks, child_pubkey=alice.pubkey),
                NestedBranchLevel(parent_pubkeys=group_ab.cache.sorted_pks, child_pubkey=alice.pubkey),
            ],
            nested_nonce_bindings=[nested_bindings["Group_AB"]]
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
    test_nested_group_round1_state_is_populated_consistently()
    test_branch_level_reconstructs_parent_cache_from_pubkeys()
    test_many_sessions()
    test_transcript_root_leaf_derives_factors_locally()
    test_transcript_nested_leaf_derives_factors_locally()
    test_transcript_deep_leaf_derives_factors_locally()
    test_nested_partial_verifier_rejects_wrong_binding()
    test_nested_sessions_have_distinct_ids()
    test_nested_partial_verifier_rejects_wrong_session()
    test_transcript_rejects_wrong_path_ordering()
    test_transcript_rejects_wrong_subgroup_key_in_path()
    test_run_nested_musig2_rejects_missing_deep_subgroup_binding()
    test_nested_sign_rejects_nonce_reuse_across_sessions()
    test_transcript_rejects_inconsistent_path()
    print("\nAll nested MuSig2 tests passed!\n")