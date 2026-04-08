import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.bip340      import schnorr_verify as bip340_verify
from musig2.keyagg             import key_agg, key_agg_coef
from musig2.nonce              import generate_nonce, aggregate_nonces, NU
from musig2.sign               import create_session, aggregate_partial_sigs
from nested_musig2.nested_sign import (
    LeafSigner,
    NestedGroup,
    NestedSigningTranscript,
    nested_sign,
    run_nested_musig2,
)
from nested_musig2.nonce_ext   import sign_agg_ext
from common.schnorr            import verify_schnorr

def pk_hex(point: GE) -> str:
    return point.to_bytes_compressed().hex()

def xonly_hex(point: GE) -> str:
    return point.to_bytes_xonly().hex()

def scalar_hex(s: Scalar) -> str:
    return f"{int(s):064x}"

def print_tree(node, prefix="", is_last=True):
    """Pretty-print the cosigner tree structure."""
    connector = "\t└── " if is_last else "\t├── "
    continuation = "\t" if is_last else "\t│"
    if isinstance(node, LeafSigner):
        print(f"{prefix}{connector} {node.name} pk = {pk_hex(node.pubkey)}")
    elif isinstance(node, NestedGroup):
        print(f"{prefix}{connector} {node.name} X̃ = {pk_hex(node.cache.agg_pk)}")
        for i, member in enumerate(node.members):
            is_member_last = (i == len(node.members) - 1)
            print_tree(member, prefix + continuation, is_member_last)

def check_both_verifiers(agg_pk: GE, msg: bytes, R: GE, s: Scalar) -> tuple[bool, bool]:
    typed_ok = verify_schnorr(agg_pk, msg, R, s)
    sig_bytes = R.to_bytes_xonly() + int(s).to_bytes(32, 'big')
    bip340_ok = bip340_verify(msg, agg_pk.to_bytes_xonly(), sig_bytes)
    return typed_ok, bip340_ok

def print_verification(agg_pk: GE, msg: bytes, R: GE, s: Scalar):
    """Print signature and verification results."""
    print(f"\n\t\tFinal signature σ = (R, s):")
    print(f"\t\tR = {xonly_hex(R)}")
    print(f"\t\ts = {scalar_hex(s)}")
    print(f"\t\tσ = {xonly_hex(R) + scalar_hex(s)}")
    print(f"\t\t({64 + 64} hex chars = 64 bytes)")

    print(f"\n\t\tVerification: s·G =? R + c·X̃")
    typed_ok, bip340_ok = check_both_verifiers(agg_pk, msg, R, s)
    print(f"\t\tTyped verifier:   {'VALID' if typed_ok else 'INVALID'}")
    print(f"\t\tBIP 340 verifier: {'VALID' if bip340_ok else 'INVALID'}")
    wrong_t, wrong_b = check_both_verifiers(agg_pk, b"wrong", R, s)
    print(f"\t\tWrong message:    {'rejected' if not (wrong_t or wrong_b) else 'BUG'}")
    assert typed_ok and bip340_ok and not wrong_t and not wrong_b
    return True

# Simple two-group nesting
def case_simple_nesting():
    print("Case 1: Simple Two-Group Nesting")
    width = 35
    print("\nTree structure:\n")
    print("Root".center(width))
    print("/    \\".center(width))
    print("Group_AB  Group_CD".center(width))
    print("/   \\     /    \\".center(width))
    print("Alice  Bob  Carol  Dave\n".center(width))

    # Phase 0: Key Generation
    print("\nPhase 0: Key Generation")
    print("\n\tAlgorithm: KeyGen()")
    print("\tx_i ←$ Z_n\t\t\t(random private key)")
    print("\tX_i = x_i · G\t\t\t(public key)\n")
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    for name, signer in [("Alice", alice), ("Bob", bob), ("Carol", carol), ("Dave", dave)]:
        print(f"\t\tx_{name:5s} = {scalar_hex(signer.privkey)}")
        print(f"\t\tX_{name:5s} = {pk_hex(signer.pubkey)}")

    # Phase 1: Key Aggregation
    print("\nPhase 1: Key Aggregation (non-interactive, recursive)")
    print("\n\tAlgorithm: KeyAgg(L)")
    print("\tL_sorted  = sort(L)")
    print("\tlist_hash = H('KeyAgg list', L_sorted)")
    print("\ta_i       = H('KeyAgg coefficient', list_hash || X_i)")
    print("\tX̃         = Σ a_i · X_i\n")
    # Group_AB
    group_ab = NestedGroup("Group_AB", [alice, bob])
    print(f"\t\tGroup_AB = KeyAgg(Alice, Bob)")
    print(f"\t\tlist_hash = {group_ab.cache.keyset_hash.hex()}")
    for pk in group_ab.cache.sorted_pks:
        a = key_agg_coef(group_ab.cache.keyset_hash, pk, group_ab.cache.second_key_bytes)
        name = "Alice" if pk == alice.pubkey else "Bob"
        coef = "1  (second-key optimization)" if int(a) == 1 else scalar_hex(a)
        print(f"\t\ta_{name:5s}   = {coef}")
    print(f"\t\t{'X̃_AB':10s} = {pk_hex(group_ab.cache.agg_pk)}")
    # Group_CD
    print()
    group_cd = NestedGroup("Group_CD", [carol, dave])
    print(f"\t\tGroup_CD = KeyAgg(Carol, Dave)")
    print(f"\t\tlist_hash = {group_cd.cache.keyset_hash.hex()}")
    for pk in group_cd.cache.sorted_pks:
        a = key_agg_coef(group_cd.cache.keyset_hash, pk, group_cd.cache.second_key_bytes)
        name = "Carol" if pk == carol.pubkey else "Dave"
        coef = "1  (second-key optimization)" if int(a) == 1 else scalar_hex(a)
        print(f"\t\ta_{name:5s}   = {coef}")
    print(f"\t\t{'X̃_CD':10s} = {pk_hex(group_cd.cache.agg_pk)}")
    # Root
    print()
    root_cache = key_agg([group_ab.cache.agg_pk, group_cd.cache.agg_pk])
    a_ab = key_agg_coef(root_cache.keyset_hash, group_ab.cache.agg_pk, root_cache.second_key_bytes)
    a_cd = key_agg_coef(root_cache.keyset_hash, group_cd.cache.agg_pk, root_cache.second_key_bytes)
    print(f"\t\tRoot = KeyAgg(Group_AB, Group_CD)")
    print(f"\t\tlist_hash  = {root_cache.keyset_hash.hex()}")
    coef_ab = "1  (second-key optimization)" if int(a_ab) == 1 else scalar_hex(a_ab)
    coef_cd = "1  (second-key optimization)" if int(a_cd) == 1 else scalar_hex(a_cd)
    print(f"\t\ta_GroupAB  = {coef_ab}")
    print(f"\t\ta_GroupCD  = {coef_cd}")
    print(f"\t\tX̃_Root     = {pk_hex(root_cache.agg_pk)}")

    print(f"\n\tCosigner tree:")
    print(f"\tRoot X̃ = {pk_hex(root_cache.agg_pk)}")
    print_tree(group_ab, "", is_last=False)
    print_tree(group_cd, "", is_last=True)

    # Phase 2: Round 1 - Nonces
    print("\nPhase 2: Round 1 - Nonce Generation")
    print("\n\tProtocol execution:")
    print("\tRound 1 (before message is known):")
    print("\t1. Alice, Bob, Carol, Dave each generate 2 random nonces")
    print("\t2. Group_AB aggregator runs SignAgg on Alice and Bob nonces")
    print("\t3. Group_AB aggregator runs SignAggExt to produce external nonces")
    print("\t   b_nested = H_non_bar(Group_AB_key, internal_nonces)  [no message]")
    print("\t4. Group_CD does the same for Carol and Dave")
    print("\t5. Root aggregator runs SignAgg on Group_AB and Group_CD external nonces\n")

    print("\n\tAlgorithm: Sign() - each leaf generates ν=2 random nonces")
    print("\tr_{i,j} ←$ Z_n")
    print("\tR_{i,j} = r_{i,j} · G\n")
    alice.nonce = generate_nonce()
    bob.nonce = generate_nonce()
    carol.nonce = generate_nonce()
    dave.nonce = generate_nonce()
    for name, signer in [("Alice", alice), ("Bob", bob), ("Carol", carol), ("Dave", dave)]:
        for j in range(NU):
            print(f"\t\tr_{name},{j+1} = {scalar_hex(signer.nonce._sec_nonces[j])}")
            print(f"\t\tR_{name},{j+1} = {pk_hex(signer.nonce.pub_nonces[j])}")

    # SignAgg (internal aggregation)
    print(f"\n\tAlgorithm: SignAgg - aggregate nonces coordinate-wise")
    print(f"\tR_j = Σ R_{{i,j}}\n")
    ab_internal = aggregate_nonces([alice.nonce.pub_nonces, bob.nonce.pub_nonces])
    print(f"\t\tGroup_AB internal (SignAgg):")
    for j in range(NU):
        print(f"\t\tR'_AB,{j+1} = R_Alice,{j+1} + R_Bob,{j+1} = {pk_hex(ab_internal[j])}")
    cd_internal = aggregate_nonces([carol.nonce.pub_nonces, dave.nonce.pub_nonces])
    print(f"\n\t\tGroup_CD internal (SignAgg):")
    for j in range(NU):
        print(f"\t\tR'_CD,{j+1} = R_Carol,{j+1} + R_Dave,{j+1} = {pk_hex(cd_internal[j])}")

    # SignAggExt
    print(f"\n\tAlgorithm: SignAggExt - extend internal aggregation with nonce hashing")
    print(f"\tb̄ = H̄_non(X̃_group, R'_1 || R'_2)")
    print(f"\tR_j = (R'_j)^{{b̄^{{j-1}}}}")
    print(f"\tFor ν=2: R_1 = R'_1,  R_2 = b̄ · R'_2\n")
    ab_external, ab_b_nested = sign_agg_ext(ab_internal, group_ab.cache.agg_pk)
    print(f"\t\tGroup_AB SignAggExt:")
    print(f"\t\tb̄_AB = H̄_non(X̃_AB, R'_AB,1 || R'_AB,2) = {scalar_hex(ab_b_nested)}")
    for j in range(NU):
        label = "\t\t(= R'_AB,1, unchanged)" if j == 0 else "\t\t(= b̄ · R'_AB,2)"
        print(f"\t\tR_AB,{j+1}   = {pk_hex(ab_external[j])}  {label}")
    cd_external, cd_b_nested = sign_agg_ext(cd_internal, group_cd.cache.agg_pk)
    print(f"\n\t\tGroup_CD SignAggExt:")
    print(f"\t\tb̄_CD = H̄_non(X̃_CD, R'_CD,1 || R'_CD,2) = {scalar_hex(cd_b_nested)}")
    for j in range(NU):
        label = "\t\t(= R'_CD,1, unchanged)" if j == 0 else "\t\t(= b̄ · R'_CD,2)"
        print(f"\t\tR_CD,{j+1}   = {pk_hex(cd_external[j])}  {label}")

    # Top-level SignAgg
    top_agg_nonces = aggregate_nonces([ab_external, cd_external])
    print(f"\n\t\tTop-level SignAgg:")
    for j in range(NU):
        print(f"\t\tR_{j+1} = R_AB,{j+1} + R_CD,{j+1} = {pk_hex(top_agg_nonces[j])}")

    # Phase 3: Round 2 - Signing
    print("\nPhase 3: Round 2 - Signing")
    print("\n\tProtocol execution:")
    print("\tRound 2 (after message is known):")
    print("\t6. Root aggregator computes session: b0, R, c")
    print("\t   b0 = H_non(root_key, agg_nonces, message)\t[includes message]")
    print("\t   R  = R_1 + b0 · R_2")
    print("\t   c  = H_sig(root_key, R, message)")
    print("\t7. Each leaf signer computes partial signature:")
    print("\t   b̌ = b0 · b_nested\t\t\t[product of all nonce hashes]")
    print("\t   č = c · a_outer · a_inner\t\t[challenge × all coefficients]")
    print("\t   s_i = č · x_i + r_1 + r_2 · b̌")
    print("\t8. Root aggregator sums: s = s_Alice + s_Bob + s_Carol + s_Dave")
    print("\t9. Final signature: (R, s)\t\t\t[standard BIP 340 Schnorr]\n")

    msg = b"Transfer 1 BTC from joint account to merchant"

    print(f"\n\t\tMessage: \"{msg.decode()}\"")
    print(f"\n\tAlgorithm: create_session")
    print(f"\tb_0 = H_non(X̃, R_1 || R_2, m)")
    print(f"\tR   = R_1 + b_0 · R_2")
    print(f"\tc   = H_sig(X̃, R, m)\n")
    session = create_session(root_cache, top_agg_nonces, msg)
    print(f"\t\tb_0 = {scalar_hex(session.b)}")
    print(f"\t\tR   = {xonly_hex(session.R)}")
    print(f"\t\tc   = {scalar_hex(session.c)}")
    print(f"\t\tnonce_negated = {session.nonce_negated}  (R had {'odd' if session.nonce_negated else 'even'} y)")
    print(f"\t\tkey_negated   = {session.key_negated}  (X̃ had {'odd' if session.key_negated else 'even'} y)")

    print(f"\n\tAlgorithm: nested_sign (each leaf)")
    print(f"\tb̌ = b_0 · b̄_group\t\t\t\t\t(product of ALL nonce hashes)")
    print(f"\tč = c · a_outer · a_inner\t\t\t\t(challenge × ALL coefficients)")
    print(f"\ts_i = č·x_i + r_{{i,1}} + r_{{i,2}}·b̌\t\t\t(with even-y adjustment)\n")

    partial_sigs = []
    # Group_AB leaves
    b_ab = session.b * ab_b_nested
    for name, signer in [("Alice", alice), ("Bob", bob)]:
        a_inner = key_agg_coef(group_ab.cache.keyset_hash, signer.pubkey, group_ab.cache.second_key_bytes)
        c_check = session.c * a_ab * a_inner
        a_inner_str = "1 (second-key opt)\t\t\t\t\t\t" if int(a_inner) == 1 else scalar_hex(a_inner)
        a_ab_str = "1 (second-key opt)\t\t\t\t\t\t" if int(a_ab) == 1 else scalar_hex(a_ab)
        print(f"\t\t{name}:")
        print(f"\t\ta_outer  = {a_ab_str}\t\t(Group_AB in Root)")
        print(f"\t\ta_inner  = {a_inner_str}\t\t({name} in Group_AB)")
        print(f"\t\tb̌ = b_0 · b̄_AB = {scalar_hex(b_ab)}")
        print(f"\t\tč = c · a_outer · a_inner = {scalar_hex(c_check)}")
        transcript = NestedSigningTranscript(
            session=session,
            path_caches=[root_cache, group_ab.cache],
            path_pubkeys=[group_ab.cache.agg_pk, signer.pubkey],
            nested_nonce_bindings=[ab_b_nested],
        )
        s_i = nested_sign(transcript, signer.nonce, signer.privkey)
        partial_sigs.append(s_i)
        print(f"\t\ts_{name} = {scalar_hex(s_i)}")
        print()
    # Group_CD leaves
    b_cd = session.b * cd_b_nested
    for name, signer in [("Carol", carol), ("Dave", dave)]:
        a_inner = key_agg_coef(group_cd.cache.keyset_hash, signer.pubkey, group_cd.cache.second_key_bytes)
        c_check = session.c * a_cd * a_inner
        a_inner_str = "1 (second-key opt)\t\t\t\t\t\t" if int(a_inner) == 1 else scalar_hex(a_inner)
        a_cd_str = "1 (second-key opt)\t\t\t\t\t\t" if int(a_cd) == 1 else scalar_hex(a_cd)
        print(f"\t\t{name}:")
        print(f"\t\ta_outer  = {a_cd_str}\t\t(Group_CD in Root)")
        print(f"\t\ta_inner  = {a_inner_str}\t\t({name} in Group_CD)")
        print(f"\t\tb̌ = b_0 · b̄_CD = {scalar_hex(b_cd)}")
        print(f"\t\tč = c · a_outer · a_inner = {scalar_hex(c_check)}")
        transcript = NestedSigningTranscript(
            session=session,
            path_caches=[root_cache, group_cd.cache],
            path_pubkeys=[group_cd.cache.agg_pk, signer.pubkey],
            nested_nonce_bindings=[cd_b_nested],
        )
        s_i = nested_sign(transcript, signer.nonce, signer.privkey)
        partial_sigs.append(s_i)
        print(f"\t\ts_{name} = {scalar_hex(s_i)}")
        print()

    # Phase 4: Aggregation and Verification
    print("Phase 4: Signature Aggregation and Verification")
    print(f"\n\tAlgorithm: SignAgg'")
    print(f"\t s = s_Alice + s_Bob + s_Carol + s_Dave   (mod n)")
    R, s = aggregate_partial_sigs(session, partial_sigs)
    print_verification(root_cache.agg_pk, msg, R, s)
    print("\nPASSED\n") if print_verification(root_cache.agg_pk, msg, R, s) else print("\nFAILED\n")

# Mixed depth
def case_mixed_depth():
    print("\ncase 2: Mixed Depth - Nested Group + Individual Signers")
    width = 50
    print("\nTree structure:\n")
    print("Root (X̃)".center(width))
    print("╱    │     ╲".center(width))
    print("Group_AB   Carol   Dave".center(width))
    print("╱   ╲".center(width - 20))
    print("Alice   Bob".center(width - 20))
    print("""\n
    Carol and Dave are individual signers at the top level.
    Alice and Bob are nested inside Group_AB.\n
    Note: Carol and Dave cannot tell that Group_AB
    is a group. From their perspective, it's just another signer
    with a single public key.\n""")
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    carol = LeafSigner.generate("Carol")
    dave = LeafSigner.generate("Dave")
    group_ab = NestedGroup("Group_AB", [alice, bob])
    top_members = [group_ab, carol, dave]
    root_cache = key_agg([
        group_ab.cache.agg_pk, carol.pubkey, dave.pubkey
    ])
    print(f"\tRoot  X̃={root_cache.agg_pk.to_bytes_compressed().hex()}")
    print_tree(group_ab, "  ", is_last=False)
    print_tree(carol, "  ", is_last=False)
    print_tree(dave, "  ", is_last=True)
    msg = b"Mixed depth signing: group + individuals"
    R, s, agg_pk = run_nested_musig2(top_members, msg)
    print("\nPASSED\n") if print_verification(agg_pk, msg, R, s) else print("\nFAILED\n")

# Deep nesting (3 levels)
def case_deep_nesting():
    print("\ncase 3: Deep Nesting - 3 Levels")
    print("""
        Tree structure:
                    Root (X̃)
                   ╱        ╲
            Group_Top       Frank
           ╱         ╲
       Group_L       Eve
      ╱       ╲
   Alice      Bob
    \n\tAlice and Bob are at depth 3.\n\tEve is at depth 2.\n\tFrank is at depth 1.
    \n\tFor Alice:
        b̌ = b_0 · b̄_GroupTop · b̄_GroupL
        č = c · a_{GroupTop_in_Root} · a_{GroupL_in_Top} · a_{Alice_in_L}
    \n\tThree levels of SignAggExt happen during Round 1, all before the message is known.
    """)
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    eve = LeafSigner.generate("Eve")
    frank = LeafSigner.generate("Frank")
    group_l = NestedGroup("Group_L", [alice, bob])
    group_top = NestedGroup("Group_Top", [group_l, eve])
    top_members = [group_top, frank]
    root_cache = key_agg([group_top.cache.agg_pk, frank.pubkey])
    print(f"\n\tCosigner tree:")
    print(f"\tRoot  X̃={pk_hex(root_cache.agg_pk)}")
    print_tree(group_top, "", is_last=False)
    print_tree(frank, "", is_last=True)
    print(f"\n\tDepth map:")
    print(f"\tAlice, Bob\t- depth 3\tb̌ = b_0 · b̄_Top · b̄_L\tč = c · a_Top · a_L · a_leaf")
    print(f"\tEve\t\t- depth 2\tb̌ = b_0 · b̄_Top\t\tč = c · a_Top · a_Eve")
    print(f"\tFrank\t\t- depth 1\tb̌ = b_0\t\t\tč = c · a_Frank")
    msg = b"Deep nesting: 3 levels of MuSig2 recursion"
    R, s, agg_pk = run_nested_musig2(top_members, msg)
    print("\nPASSED\n") if print_verification(agg_pk, msg, R, s) else print("\nFAILED\n")

# Privacy property
def case_privacy():
    print("\ncase 4: Privacy - Nesting Is Invisible\n")
    alice = LeafSigner.generate("Alice")
    bob = LeafSigner.generate("Bob")
    # Direct aggregation (standard MuSig2 key aggregation)
    direct_cache = key_agg([alice.pubkey, bob.pubkey])
    # Nested group
    group = NestedGroup("Group_AB", [alice, bob])
    direct_hex = direct_cache.agg_pk.to_bytes_compressed().hex()
    nested_hex = group.cache.agg_pk.to_bytes_compressed().hex()
    print(f"\tDirect KeyAgg(Alice, Bob):\t{direct_hex}")
    print(f"\tNested Group_AB key:\t\t{nested_hex}")
    keys_match = direct_cache.agg_pk == group.cache.agg_pk
    print(f"\tKeys identical: {'YES' if keys_match else 'NO'}")
    print("""
    Both produce the same aggregate key because KeyAgg is used unchanged - it's the same algorithm at every level.

    A verifier who receives a signature for this key cannot determine:
    \t- Whether nesting was used
    \t- How many signers participated
    \t- The internal tree structure
    \t- Which participants hold which keys
    """)
    assert keys_match
    print("\nPASSED\n")

def main():
    print()
    case_simple_nesting()
    case_mixed_depth()
    case_deep_nesting()
    case_privacy()

if __name__ == "__main__":
    main()