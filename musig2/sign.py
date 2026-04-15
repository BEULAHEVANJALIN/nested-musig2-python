"""
MuSig2 Signing - Round 2 and Signature Aggregation.
Implements:
    create_session(): Compute b, R, c from aggregated Round 1 data
    sign(): Signer computes partial signature s_i
    verify_partial_sig(): Aggregator verifies individual partial sig
    aggregate_partial_sigs(): Combine partial sigs into final Schnorr sig
Protocol flow:
    Round 1:  generate_nonce() - aggregate_nonces() 
    ──────── message m becomes known ────────
    Round 2:  create_session() - sign() - aggregate()

The session object bridges Round 1 and Round 2. It takes the
aggregate nonces from Round 1 plus the message, and computes
the binding coefficient b, effective nonce R, and challenge c
that all signers need for their partial signatures.
"""

from secp256k1lab.secp256k1 import GE, Scalar, G
from dataclasses import dataclass

from common.hashing import hash_nonce, hash_sig, hash_session_id
from musig2.keyagg import KeyAggCache, key_agg_coef
from musig2.nonce import SignerNonce, NU, validate_nonce_points


@dataclass
class SigningSession:
    """
    Computed values for a MuSig2 signing session.
    Created after Round 1 completes and the message is known.
    Shared with all signers so they can compute partial signatures.
    Fields:
        cache:      KeyAggCache from key aggregation
        agg_nonces: [R_1, R_2] from nonce aggregation
        session_id: Deterministic identifier for this signing session
        b:          Nonce binding coefficient
        R:          Effective aggregate nonce
        c:          Signature challenge
        msg:        The message being signed
        nonce_negated: Whether R was negated for even-y
        key_negated:   Whether X̃ was negated for even-y
    """
    cache: KeyAggCache
    agg_nonces: list[GE]
    session_id: bytes
    b: Scalar
    R: GE
    c: Scalar
    msg: bytes
    nonce_negated: bool
    key_negated: bool


def create_session(
    cache: KeyAggCache,
    agg_nonces: list[GE],
    msg: bytes,
) -> SigningSession:
    """
    Create a signing session from aggregated Round 1 data and the message.
    Algorithm:
        1. b = H_non(X̃, R_1 || R_2, m)  - nonce binding
        2. R = R_1 + b·R_2              - effective aggregate nonce
        3. If R has odd y, negate R     - BIP 340 convention
        4. c = H_sig(X̃_even, R_even, m) - challenge with even-y points
    Parameters:
        cache:      KeyAggCache from key_agg()
        agg_nonces: [R_1, R_2] from aggregate_nonces()
        msg:        The message to sign
    Returns: SigningSession with all computed values
    """
    validate_nonce_points(agg_nonces, label="aggregate nonce")
    # Step 1: Nonce binding coefficient
    # b = H_non(X̃, R_1 || R_2, m)
    agg_pk_ser = cache.agg_pk.to_bytes_compressed()
    nonces_ser = b"".join(R.to_bytes_compressed() for R in agg_nonces)
    session_id = hash_session_id(agg_pk_ser, nonces_ser, msg)
    b = hash_nonce(agg_pk_ser, nonces_ser, msg)
    # Step 2: Effective aggregate nonce
    R = GE()  # infinity
    b_power = Scalar(1)  # b^0 = 1
    for j in range(NU):
        R += int(b_power) * agg_nonces[j]
        b_power = b_power * b  # b^{j} for next iteration
    if R.infinity:
        raise ValueError("Effective aggregate nonce is infinity")
    nonce_negated = not R.has_even_y()
    if nonce_negated:
        R = -R
    key_negated = not cache.agg_pk.has_even_y()
    # Step 4: Signature challenge
    c = hash_sig(
        cache.agg_pk.to_bytes_xonly(),
        R.to_bytes_xonly(),
        msg,
    )
    return SigningSession(
        cache=cache,
        agg_nonces=agg_nonces,
        session_id=session_id,
        b=b,
        R=R,
        c=c,
        msg=msg,
        nonce_negated=nonce_negated,
        key_negated=key_negated,
    )

def sign(
    session: SigningSession,
    signer_nonce: SignerNonce,
    signer_privkey: Scalar,
    signer_pubkey: GE,
) -> Scalar:
    """
    Compute a partial signature (Sign' algorithm).
        s_i = a_i · c · x_i + r_{i,1} + r_{i,2} · b   (mod n)
    With BIP 340 even-y adjustments:
        s_i = g_key · a_i · c · x_i  +  g_nonce · (r_{i,1} + r_{i,2} · b)
    where:
        g_key   = -1 if X̃ had odd y, else 1
        g_nonce = -1 if R had odd y, else 1
    """
    if signer_pubkey.infinity:
        raise ValueError("Signer public key cannot be infinity")
    if signer_pubkey not in session.cache.sorted_pks:
        raise ValueError("Signer public key is not present in the aggregate key set")
    # Get the secret nonces (one-time use!)
    sec_nonces = signer_nonce.get_sec_nonces()
    a_i = key_agg_coef(
        session.cache.keyset_hash,
        signer_pubkey,
        session.cache.second_key_bytes,
    )
    # Key part: a_i · c · x_i, negated if aggregate key had odd y
    key_part = a_i * session.c * signer_privkey
    if session.key_negated:
        key_part = -key_part
    # Nonce part: Σ r_{i,j} · b^{j-1}, negated if aggregate nonce had odd y
    nonce_part = Scalar(0)
    b_power = Scalar(1)
    for j in range(NU):
        nonce_part = nonce_part + sec_nonces[j] * b_power
        b_power = b_power * session.b
    if session.nonce_negated:
        nonce_part = -nonce_part
    return key_part + nonce_part


def verify_partial_sig(
    session: SigningSession,
    signer_pubkey: GE,
    signer_pub_nonces: list[GE],
    partial_sig: Scalar,
) -> bool:
    """
    Verify a partial signature from a specific signer.
    Checks: s_i · G  =?  g_nonce · R̂_i  +  g_key · a_i · c · X_i
    where R̂_i = R_{i,1} + b · R_{i,2} is the signer's effective nonce.
    The g_nonce and g_key factors account for BIP 340 even-y negation.
    """
    if signer_pubkey.infinity:
        return False
    if signer_pubkey not in session.cache.sorted_pks:
        return False
    try:
        validate_nonce_points(signer_pub_nonces, label="signer public nonce")
    except ValueError:
        return False
    # Signer's effective nonce: R̂_i = Σ R_{i,j} · b^{j-1}
    R_hat_i = GE()
    b_power = Scalar(1)
    for j in range(NU):
        R_hat_i += int(b_power) * signer_pub_nonces[j]
        b_power = b_power * session.b
    if session.nonce_negated:
        R_hat_i = -R_hat_i
    a_i = key_agg_coef(
        session.cache.keyset_hash,
        signer_pubkey,
        session.cache.second_key_bytes,
    )
    key_point = int(a_i * session.c) * signer_pubkey
    if session.key_negated:
        key_point = -key_point
    # Check: s_i · G  =?  R̂_i + key_point
    lhs = int(partial_sig) * G
    rhs = R_hat_i + key_point
    return lhs == rhs


def aggregate_partial_sigs(
    session: SigningSession,
    partial_sigs: list[Scalar],
) -> tuple[GE, Scalar]:
    """
    Aggregate partial signatures into a final Schnorr signature.
    SignAgg'(s_1, ..., s_n) : σ = (R, s)
    Algorithm:
        s = Σ s_i   (mod n)
        σ = (R, s)  where R is guaranteed to have even y
    Returns: (R, s) - the aggregate Schnorr signature
    The output is a valid BIP 340 Schnorr signature.
    """
    if not partial_sigs:
        raise ValueError("No partial signatures to aggregate")
    s = Scalar(0)
    for s_i in partial_sigs:
        s = s + s_i
    return session.R, s