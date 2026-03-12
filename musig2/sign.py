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

from common.hashing import hash_nonce, hash_sig
from musig2.keyagg import KeyAggCache, key_agg_coef
from musig2.nonce import SignerNonce, NU


@dataclass
class SigningSession:
    """
    Computed values for a MuSig2 signing session.
    Created after Round 1 completes and the message is known.
    Shared with all signers so they can compute partial signatures.
    Fields:
        cache:      KeyAggCache from key aggregation
        agg_nonces: [R_1, R_2] from nonce aggregation
        b:          Nonce binding coefficient
        R:          Effective aggregate nonce
        c:          Signature challenge
        msg:        The message being signed
    """
    cache: KeyAggCache
    agg_nonces: list[GE]
    b: Scalar
    R: GE
    c: Scalar
    msg: bytes

def create_session(
    cache: KeyAggCache,
    agg_nonces: list[GE],
    msg: bytes,
) -> SigningSession:
    """
    Create a signing session from aggregated Round 1 data and the message.
    Algorithm:
        1. b = H_non(X̃, R_1 || R_2, m)  - nonce binding
        2. R = R_1 · R_2^b              - effective aggregate nonce
        3. c = H_sig(X̃, R, m)           - signature challenge
    Parameters:
        cache:      KeyAggCache from key_agg()
        agg_nonces: [R_1, R_2] from aggregate_nonces()
        msg:        The message to sign
    Returns: SigningSession with all computed values
    """
    if len(agg_nonces) != NU:
        raise ValueError(f"Expected {NU} aggregate nonces, got {len(agg_nonces)}")
    # Step 1: Nonce binding coefficient
    # b = H_non(X̃, R_1 || R_2, m)
    agg_pk_ser = cache.agg_pk.to_bytes_compressed()
    nonces_ser = b"".join(R.to_bytes_compressed() for R in agg_nonces)
    b = hash_nonce(agg_pk_ser, nonces_ser, msg)
    # Step 2: Effective aggregate nonce
    # R = Σ R_j · b^{j-1} = R_1 · b^0 + R_2 · b^1 = R_1 + b·R_2
    R = GE()  # infinity
    b_power = Scalar(1)  # b^0 = 1
    for j in range(NU):
        R += int(b_power) * agg_nonces[j]
        b_power = b_power * b  # b^{j} for next iteration
    if R.infinity:
        raise ValueError("Effective aggregate nonce is infinity (degenerate session)")
    # Step 3: Signature challenge
    # c = H_sig(X̃, R, m) - BIP 340 order: R || X̃ || m
    c = hash_sig(
        cache.agg_pk.to_bytes_xonly(),
        R.to_bytes_xonly(),
        msg,
    )
    # Step 4: Return the session object with all computed values
    return SigningSession(
        cache=cache,
        agg_nonces=agg_nonces,
        b=b,
        R=R,
        c=c,
        msg=msg,
    )

def sign(
    session: SigningSession,
    signer_nonce: SignerNonce,
    signer_privkey: Scalar,
    signer_pubkey: GE,
) -> Scalar:
    """
    Compute a partial signature (Sign' algorithm).
    s_i = a_i · c · x_i + Σ_j r_{i,j} · b^{j-1}   (mod n)
    For ν = 2:
        s_i = a_i · c · x_i + r_{i,1} + r_{i,2} · b
    Parameters:
        session:        SigningSession from create_session()
        signer_nonce:   SignerNonce from generate_nonce()
        signer_privkey: The signer's private key x_i
        signer_pubkey:  The signer's public key X_i
    Returns: Scalar (the partial signature s_i)
    """
    # Get the secret nonces (one-time use!)
    sec_nonces = signer_nonce.get_sec_nonces()
    a_i = key_agg_coef(
        session.cache.keyset_hash,
        signer_pubkey,
        session.cache.second_key_bytes,
    )
    # Compute the "key part": a_i · c · x_i
    key_part = a_i * session.c * signer_privkey
    # Compute the "nonce part": Σ r_{i,j} · b^{j-1}
    nonce_part = Scalar(0)
    b_power = Scalar(1)  # b^0 = 1
    for j in range(NU):
        nonce_part = nonce_part + sec_nonces[j] * b_power
        b_power = b_power * session.b  # b^j for next iteration
    # Partial signature
    s_i = key_part + nonce_part
    return s_i


def verify_partial_sig(
    session: SigningSession,
    signer_pubkey: GE,
    signer_pub_nonces: list[GE],
    partial_sig: Scalar,
) -> bool:
    """
    Verify a partial signature from a specific signer.
    Checks: s_i · G  =?  R̂_i + a_i · c · X_i
    where R̂_i = Σ R_{i,j} · b^{j-1} = R_{i,1} + b · R_{i,2}
    Parameters:
        session:           SigningSession
        signer_pubkey:     X_i - the signer's public key
        signer_pub_nonces: [R_{i,1}, R_{i,2}] - signer's public nonces
        partial_sig:       s_i - the partial signature to verify
    """
    # Compute signer's effective nonce: R̂_i = Σ R_{i,j} · b^{j-1}
    R_hat_i = GE()
    b_power = Scalar(1)
    for j in range(NU):
        R_hat_i += int(b_power) * signer_pub_nonces[j]
        b_power = b_power * session.b
    a_i = key_agg_coef(
        session.cache.keyset_hash,
        signer_pubkey,
        session.cache.second_key_bytes,
    )
    # Check: s_i · G  =?  R̂_i + a_i · c · X_i
    lhs = int(partial_sig) * G
    rhs = R_hat_i + int(a_i * session.c) * signer_pubkey
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
        σ = (R, s)
    Parameters:
        session:      SigningSession
        partial_sigs: [s_1, s_2, ..., s_n]
    Returns: (R, s) - the aggregate Schnorr signature
    """
    if not partial_sigs:
        raise ValueError("No partial signatures to aggregate")
    s = Scalar(0)
    for s_i in partial_sigs:
        s = s + s_i
    return session.R, s