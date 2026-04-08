import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.util import int_from_bytes
from musig2.keyagg import key_agg, key_agg_coef, KeyAggCache
from musig2.nonce import generate_nonce, aggregate_nonces, SignerNonce, NU
from musig2.sign import create_session, SigningSession, aggregate_partial_sigs
from nested_musig2.nonce_ext import sign_agg_ext


def nested_sign(
    session: SigningSession,
    signer_nonce: SignerNonce,
    signer_privkey: Scalar,
    b_check: Scalar,
    c_check: Scalar,
) -> Scalar:
    """
    Compute a partial signature for a leaf signer in a nested cosigner tree.

    s_i = č · x_i + Σ_j r_{i,j} · b̌^{j-1}   (mod n)

    For ν = 2:
        s_i = č · x_i + r_{i,1} + r_{i,2} · b̌

    Parameters:
        session:        provides nonce_negated and key_negated
        signer_nonce:   consumed - single use
        signer_privkey: the leaf signer's private key
        b_check:        b̌ = product of all nonce hashes along the path
        c_check:        č = c · product of all key agg coefficients

    Returns: s_i partial signature for a leaf signer

    Why b̌ and č are passed in (not computed here):
    Each leaf signer sits at a specific position in the cosigner tree.
    The path from the root to this leaf determines which key aggregation
    coefficients and nonce binding hashes are multiplied together.
    The orchestrator (run_nested_musig2) traverses the tree and
    accumulates these products, then passes the result to each leaf.
    """
    # Consume the nonce (single-use enforcement)
    sec_nonces = signer_nonce.get_sec_nonces()

    # Key part: č · x_i, negated if aggregate key had odd y
    key_part = c_check * signer_privkey
    if session.key_negated:
        key_part = -key_part

    # Nonce part: Σ r_{i,j} · b̌^{j-1}, negated if aggregate nonce had odd y
    nonce_part = Scalar(0)
    b_power = Scalar(1)  # b̌^0 = 1
    for j in range(NU):
        nonce_part = nonce_part + sec_nonces[j] * b_power
        b_power = b_power * b_check  # b̌^j for next iteration
    if session.nonce_negated:
        nonce_part = -nonce_part
    return key_part + nonce_part

# Tree data structures
class LeafSigner:
    """
    A leaf node in the cosigner tree represents a single signer.
    Holds the signer's key pair and nonce state for the signing session.
    """
    def __init__(self, name: str, privkey: Scalar, pubkey: GE):
        self.name = name
        self.privkey = privkey
        self.pubkey = pubkey
        self.nonce: SignerNonce | None = None

    @staticmethod
    def generate(name: str) -> 'LeafSigner':
        """Create a LeafSigner with a random key pair."""
        while True:
            sk_int = int.from_bytes(os.urandom(32), 'big')
            if 0 < sk_int < GE.ORDER:
                sk = Scalar(sk_int)
                pk = int(sk) * G
                return LeafSigner(name, sk, pk)

class NestedGroup:
    """
    An internal node in the cosigner tree represents a group of signers
    that collectively acts as a single signer at the level above.
    Members can be LeafSigners or further NestedGroups (recursive).
    """
    def __init__(self, name: str, members: list):
        self.name = name
        self.members = members
        if not members:
            raise ValueError("NestedGroup must contain at least one member")
        # Collect member public keys
        self.member_pubkeys = [
            m.pubkey if isinstance(m, LeafSigner) else m.cache.agg_pk
            for m in members
        ]
        self.cache: KeyAggCache = key_agg(self.member_pubkeys)
        # Nonce state (populated during Round 1)
        self.internal_agg_nonces: list[GE] | None = None
        self.external_nonces: list[GE] | None = None
        self.b_nested: Scalar | None = None


# Full protocol orchestration
def run_nested_musig2(
    top_level_members: list,
    msg: bytes,
) -> tuple[GE, Scalar, GE]:
    """
    Complete Nested MuSig2 signing session.

    Orchestrates the entire protocol for an arbitrary cosigner tree:
    1. Round 1: generate nonces at leaves, aggregate upward, apply SignAggExt
    2. Create top-level session (b_0, R, c)
    3. Round 2: traverse tree, accumulate b̌ and č, collect leaf signatures
    4. Aggregate all leaf signatures into final Schnorr signature

    Parameters:
        top_level_members: List of LeafSigner or NestedGroup at the root level
        msg:               The message to sign

    Returns: (R, s, agg_pk) - the Schnorr signature and root aggregate key

    Privacy note:
    The output is a standard BIP 340 Schnorr signature. No verifier can
    determine whether nesting was used, how many signers participated,
    or what the tree structure looks like.
    """

    # Step 1: top-level public keys and root key aggregation
    top_pubkeys = [
        m.pubkey if isinstance(m, LeafSigner) else m.cache.agg_pk
        for m in top_level_members
    ]
    root_cache = key_agg(top_pubkeys)

    # Step 2: Round 1 - generate nonces bottom-up 
    def generate_nonces_recursive(member):
        if isinstance(member, LeafSigner):
            member.nonce = generate_nonce()
            return member.nonce.pub_nonces
        elif isinstance(member, NestedGroup):
            # Recurse into members
            all_member_pub_nonces = []
            for m in member.members:
                pub_nonces = generate_nonces_recursive(m)
                all_member_pub_nonces.append(pub_nonces)
            # SignAgg: aggregate member nonces internally
            member.internal_agg_nonces = aggregate_nonces(all_member_pub_nonces)
            # SignAggExt: transform to external nonces
            member.external_nonces, member.b_nested = sign_agg_ext(
                member.internal_agg_nonces,
                member.cache.agg_pk,
            )
            return member.external_nonces
    top_level_pub_nonces = []
    for member in top_level_members:
        pub_nonces = generate_nonces_recursive(member)
        top_level_pub_nonces.append(pub_nonces)
    # Final top-level aggregation of all nonces
    # No SignAggExt needed at the top level because there's no level above it
    # This is the final nonce used in the session creation
    top_agg_nonces = aggregate_nonces(top_level_pub_nonces)

    #  Step 3: Create signing session 
    session = create_session(root_cache, top_agg_nonces, msg)

    #  Step 4: Round 2 - collect partial signatures from all leaves 
    partial_sigs: list[Scalar] = []
    def collect_signatures(
        member,
        parent_cache: KeyAggCache,
        b_accumulated: Scalar,
        c_accumulated: Scalar,
    ):
        """
        Traverse the tree, accumulating b̌ and č, and collect leaf signatures.
        At each level, we multiply:
        - b_accumulated by the nonce binding at this level
        - c_accumulated by the key aggregation coefficient at this level
        When we reach a leaf, b_accumulated = b̌ and c_accumulated = č.
        """
        if isinstance(member, LeafSigner):
            # Leaf: compute this signer's coefficient and sign
            a_i = key_agg_coef(
                parent_cache.keyset_hash,
                member.pubkey,
                parent_cache.second_key_bytes,
            )
            # č for this leaf = c_accumulated · a_i
            c_check = c_accumulated * a_i
            # b̌ for this leaf = b_accumulated (already complete)
            b_check = b_accumulated
            s_i = nested_sign(
                session, member.nonce, member.privkey, b_check, c_check,
            )
            partial_sigs.append(s_i)
        elif isinstance(member, NestedGroup):
            # Internal node: multiply in this group's coefficient and b̄
            # This group's key aggregation coefficient in its parent
            a_group = key_agg_coef(
                parent_cache.keyset_hash,
                member.cache.agg_pk,
                parent_cache.second_key_bytes,
            )
            # Update accumulated values
            new_c = c_accumulated * a_group
            if member.b_nested is None:
                raise ValueError(f"Nested group {member.name} is missing its nested nonce binding")
            new_b = b_accumulated * member.b_nested
            # Recurse into members with this group's cache
            for m in member.members:
                collect_signatures(m, member.cache, new_b, new_c)
    # Start traversal from root
    # b̌ starts with b_0 (top-level nonce binding from the session)
    # č starts with c (the signature challenge from the session)
    for member in top_level_members:
        collect_signatures(member, root_cache, session.b, session.c)

    #  Step 5: Aggregate 
    R, s = aggregate_partial_sigs(session, partial_sigs)
    return R, s, root_cache.agg_pk