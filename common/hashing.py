"""
Tagged hash functions for MuSig2 and Nested MuSig2.
BIP 340 defines:
    tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)

The following are specific tagged hash functions from BIP 327:
    H_agg   - key aggregation coefficients
    H_non   - nonce binding (top-level, includes message)
    H_sig   - signature challenge (BIP 340 Schnorr challenge)
And from the Nested MuSig2:
    H_non_nested    - nonce binding at nested levels (excludes message)
"""

import hashlib
from typing import List
from secp256k1lab.util import tagged_hash
from secp256k1lab.secp256k1 import GE, Scalar

def tagged_hash_to_scalar(tag: str, msg: bytes) -> Scalar:
    h = tagged_hash(tag, msg)
    return Scalar.from_bytes_wrapping(h)

def hash_keyagg_list(pubkeys_ser: bytes) -> bytes:
    """
    Precompute the key list hash.
    L = tagged_hash("KeyAgg list", X_1 || X_2 || ... || X_n)
    Input: concatenated compressed public keys (33 bytes each).
    Output: 32-byte hash.
    """
    return tagged_hash("KeyAgg list", pubkeys_ser)

def hash_keyagg_coef(keyagg_list_hash: bytes, pubkey_ser: bytes) -> Scalar:
    """
    H_agg: compute a key aggregation coefficient.
    a_i = tagged_hash("KeyAgg coefficient", L || X_i) mod n
    where L = hash_keyagg_list(all keys).
    Inputs:
        keyagg_list_hash: the 32-byte L from hash_keyagg_list()
        pubkey_ser:       the 33-byte compressed serialization of X_i
    Returns: Scalar (the coefficient a_i)
    """
    return tagged_hash_to_scalar("KeyAgg coefficient", keyagg_list_hash + pubkey_ser)

def hash_nonce(agg_pk_ser: bytes, agg_nonces_ser: bytes, msg: bytes) -> Scalar:
    """
    H_non: top-level nonce binding coefficient.
    b = tagged_hash("MuSig/noncecoef", X̃ || R_1 || ... || R_ν || m) mod n
    This binds the aggregate nonce to:
    - X̃: the aggregate key (prevents cross-key attacks)
    - R₁...Rν: all aggregate nonces (prevents nonce manipulation)
    - m: the message (prevents Wagner's attack across sessions)
    Inputs:
        agg_pk_ser:       33-byte compressed aggregate public key
        agg_nonces_ser:   concatenated serialized aggregate nonces
        msg:              the message being signed
    Returns: Scalar (the binding coefficient b)
    """
    data = agg_pk_ser + agg_nonces_ser + msg
    return tagged_hash_to_scalar("MuSig/noncecoef", data)

def hash_nonce_nested(agg_pk_ser: bytes, agg_nonces_ser: bytes) -> Scalar:
    """
    H̄_non: inner-level nonce binding (Nested MuSig2 only).
    b = tagged_hash("MuSig/nested-noncecoef", X̃ || R'_1 || ... || R'_ν) mod n
    Inputs:
        agg_pk_ser:       33-byte compressed aggregate key of the inner group
        agg_nonces_ser:   concatenated serialized internal aggregate nonces
    Returns: Scalar (the inner binding coefficient)
    """
    data = agg_pk_ser + agg_nonces_ser
    return tagged_hash_to_scalar("MuSig/nested-noncecoef", data)


def hash_sig(agg_pk_xonly: bytes, nonce_xonly: bytes, msg: bytes) -> Scalar:
    """
    H_sig: signature challenge (BIP 340 Schnorr challenge).
    c = tagged_hash("BIP0340/challenge", R || X̃ || m) mod n
    Inputs:
        agg_pk_xonly:  32-byte x-only aggregate public key
        nonce_xonly:   32-byte x-only aggregate nonce R
        msg:           the message being signed
    Returns: Scalar (the challenge c)
    """
    # BIP 340 order: R || X̃ || m
    data = nonce_xonly + agg_pk_xonly + msg
    return tagged_hash_to_scalar("BIP0340/challenge", data)