"""
MuSig2 Key Aggregation (BIP 327).

This is the NON-INTERACTIVE part of MuSig2. Given a set of public keys,
anyone can compute the aggregate key without communication.

Algorithm:
    1. Sort keys lexicographically by compressed serialization
    2. Compute list hash: L = H("KeyAgg list", X_1||X_2||...||X_n)
    3. Find the second distinct key (for the "coef = 1" optimization)
    4. For each key X_i:
         a_i = 1                                if X_i is the second distinct key
         a_i = H("KeyAgg coefficient", L||X_i)  otherwise
    5. Aggregate: X̃ = Σ a_i · X_i
"""

from secp256k1lab.secp256k1 import GE, Scalar, G
from common.hashing import hash_keyagg_list, hash_keyagg_coef
from dataclasses import dataclass

@dataclass
class KeyAggCache:
    """
    Cached data from key aggregation, needed during signing.
    Stored after KeyAgg and passed into Sign' so each signer can
    look up their coefficient without recomputing everything.
    Fields:
        sorted_pks:       Keys in the canonical sorted order
        agg_pk:           The aggregate public key X̃
        keyset_hash:      The 32-byte list hash L
        second_key_bytes: Compressed serialization of the second distinct key
                          (empty bytes if all keys are identical)
    """
    sorted_pks: list[GE]
    agg_pk: GE
    keyset_hash: bytes
    second_key_bytes: bytes

def _sort_pubkeys(pubkeys: list[GE]) -> list[GE]:
    """
    Sort keys lexicographically by compressed serialization.
    """
    return sorted(pubkeys, key=lambda pk: pk.to_bytes_compressed())

def _get_second_unique_key(sorted_pks: list[GE]) -> bytes:
    """
    Find the compressed serialization of the second distinct key.
    Returns empty bytes if all keys are identical (no second distinct key).
    """
    first_bytes = sorted_pks[0].to_bytes_compressed()
    for pk in sorted_pks[1:]:
        pk_bytes = pk.to_bytes_compressed()
        if pk_bytes != first_bytes:
            return pk_bytes
    return b""

def key_agg_coef(keyset_hash: bytes, pk: GE, second_key_bytes: bytes) -> Scalar:
    """
    Compute the key aggregation coefficient for a specific public key.
    KeyAggCoef*(L, X_i):
        if X_i is the second distinct key then return 1
        else return tagged_hash("KeyAgg coefficient", L || X_i) mod n
    Parameters:
        keyset_hash:      The 32-byte list hash L
        pk:               The public key X_i
        second_key_bytes: Compressed bytes of the second distinct key
    Returns: Scalar (the coefficient a_i)
    """
    pk_bytes = pk.to_bytes_compressed()
    # Second distinct key optimization: coefficient is 1
    if second_key_bytes and pk_bytes == second_key_bytes:
        return Scalar(1)
    return hash_keyagg_coef(keyset_hash, pk_bytes)

def key_agg(pubkeys: list[GE]) -> KeyAggCache:
    """
    Aggregate a list of public keys into a single aggregate key.
    Parameters:
        pubkeys: List of public keys (GE objects, non-infinity, on curve)
    Returns: KeyAggCache with the aggregate key and cached computation
    Raises: ValueError if any key is invalid or the result is infinity
    """
    if not pubkeys:
        raise ValueError("Cannot aggregate empty key list")
    for pk in pubkeys:
        if pk.infinity:
            raise ValueError("Point at infinity is not a valid public key")
    # Step 1: Sort
    sorted_pks = _sort_pubkeys(pubkeys)
    # Step 2: List hash
    serialized = b"".join(pk.to_bytes_compressed() for pk in sorted_pks)
    keyset_hash = hash_keyagg_list(serialized)
    # Step 3: Find second distinct key
    second_key_bytes = _get_second_unique_key(sorted_pks)
    # Step 4: Compute aggregate key X̃ = Σ a_i · X_i
    agg_pk = GE()  # Point at infinity (additive identity)
    for pk in sorted_pks:
        a_i = key_agg_coef(keyset_hash, pk, second_key_bytes)
        agg_pk += int(a_i) * pk
    if agg_pk.infinity:
        raise ValueError("Aggregate key is the point at infinity")
    # Step 5: Return
    return KeyAggCache(
        sorted_pks=sorted_pks,
        agg_pk=agg_pk,
        keyset_hash=keyset_hash,
        second_key_bytes=second_key_bytes,
    )