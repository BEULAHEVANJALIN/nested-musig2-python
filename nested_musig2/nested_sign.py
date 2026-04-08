import os
from dataclasses import dataclass
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.util import int_from_bytes
from musig2.keyagg import key_agg, key_agg_coef, KeyAggCache
from musig2.nonce import generate_nonce, aggregate_nonces, SignerNonce, NU, validate_nonce_points
from musig2.sign import create_session, SigningSession, aggregate_partial_sigs
from nested_musig2.nonce_ext import sign_agg_ext


@dataclass(frozen=True)
class NestedSigningTranscript:
    """
    Explicit signer-visible transcript for one leaf in a nested cosigner tree.
    """
    session: SigningSession
    path_caches: list[KeyAggCache]
    path_pubkeys: list[GE]
    nested_nonce_bindings: list[Scalar]

    def __post_init__(self) -> None:
        if not self.path_caches:
            raise ValueError("Nested transcript must contain at least one key aggregation level")
        if len(self.path_caches) != len(self.path_pubkeys):
            raise ValueError("Each path level must have exactly one public key")
        if len(self.nested_nonce_bindings) != len(self.path_caches) - 1:
            raise ValueError("Nested nonce bindings must match the number of nested levels")
        for cache, pk in zip(self.path_caches, self.path_pubkeys):
            if pk.infinity:
                raise ValueError("Transcript path public keys cannot be infinity")
            if pk not in cache.sorted_pks:
                raise ValueError("Transcript path public key is not in its parent key set")

    def nonce_factor(self) -> Scalar:
        b_check = self.session.b
        for b_nested in self.nested_nonce_bindings:
            b_check = b_check * b_nested
        return b_check

    def challenge_factor(self) -> Scalar:
        c_check = self.session.c
        for cache, pk in zip(self.path_caches, self.path_pubkeys):
            a_i = key_agg_coef(cache.keyset_hash, pk, cache.second_key_bytes)
            c_check = c_check * a_i
        return c_check

    def leaf_pubkey(self) -> GE:
        return self.path_pubkeys[-1]

def nested_sign(
    transcript: NestedSigningTranscript,
    signer_nonce: SignerNonce,
    signer_privkey: Scalar,
) -> Scalar:
    """
    Compute a partial signature for a leaf signer in a nested cosigner tree.

    s_i = č · x_i + Σ_j r_{i,j} · b̌^{j-1}   (mod n)

    For ν = 2:
        s_i = č · x_i + r_{i,1} + r_{i,2} · b̌

    Parameters:
        transcript:     explicit path transcript for this signer
        signer_nonce:   consumed - single use
        signer_privkey: the leaf signer's private key

    Returns: s_i partial signature for a leaf signer
    """
    session = transcript.session
    b_check = transcript.nonce_factor()
    c_check = transcript.challenge_factor()
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

def verify_nested_partial_sig(
    transcript: NestedSigningTranscript,
    signer_pub_nonces: list[GE],
    partial_sig: Scalar,
) -> bool:
    """
    Verify a nested partial signature against the signer's explicit path transcript.
    """
    try:
        validate_nonce_points(signer_pub_nonces, label="nested signer public nonce")
    except ValueError:
        return False

    session = transcript.session
    signer_pubkey = transcript.leaf_pubkey()
    if signer_pubkey.infinity:
        return False

    b_check = transcript.nonce_factor()
    c_check = transcript.challenge_factor()

    R_hat_i = GE()
    b_power = Scalar(1)
    for j in range(NU):
        R_hat_i += int(b_power) * signer_pub_nonces[j]
        b_power = b_power * b_check
    if session.nonce_negated:
        R_hat_i = -R_hat_i

    key_point = int(c_check) * signer_pubkey
    if session.key_negated:
        key_point = -key_point

    lhs = int(partial_sig) * G
    rhs = R_hat_i + key_point
    return lhs == rhs

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
        path_caches: list[KeyAggCache],
        path_pubkeys: list[GE],
        nested_bindings: list[Scalar],
    ):
        """
        Traverse the tree, collecting the explicit path transcript seen by a leaf.
        """
        if isinstance(member, LeafSigner):
            transcript = NestedSigningTranscript(
                session=session,
                path_caches=path_caches,
                path_pubkeys=path_pubkeys + [member.pubkey],
                nested_nonce_bindings=nested_bindings,
            )
            s_i = nested_sign(transcript, member.nonce, member.privkey)
            if not verify_nested_partial_sig(transcript, member.nonce.pub_nonces, s_i):
                raise ValueError(f"Nested partial signature failed verification for leaf {member.name}")
            partial_sigs.append(s_i)
        elif isinstance(member, NestedGroup):
            # Recurse into members with this group's cache
            if member.b_nested is None:
                raise ValueError(f"Nested group {member.name} is missing its nested nonce binding")
            for m in member.members:
                if isinstance(m, LeafSigner):
                    collect_signatures(m, path_caches, path_pubkeys, nested_bindings)
                else:
                    if m.b_nested is None:
                        raise ValueError(f"Nested group {m.name} is missing its nested nonce binding")
                    collect_signatures(
                        m,
                        path_caches + [m.cache],
                        path_pubkeys + [m.cache.agg_pk],
                        nested_bindings + [m.b_nested],
                    )
    # Start traversal from root
    for member in top_level_members:
        if isinstance(member, LeafSigner):
            collect_signatures(member, [root_cache], [], [])
        else:
            collect_signatures(member, [root_cache, member.cache], [member.cache.agg_pk], [member.b_nested])

    #  Step 5: Aggregate 
    R, s = aggregate_partial_sigs(session, partial_sigs)
    return R, s, root_cache.agg_pk