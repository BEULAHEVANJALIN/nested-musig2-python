"""
SignAggExt transforms a group's internal aggregate nonces into
external nonces that the outer level sees. This is what makes
a group of signers indistinguishable from a single signer.

Algorithm:
    Input:  internal aggregate nonces (R'_1, ..., R'_ν) and group key X̃
    Output: external nonces (R_1, ..., R_ν)
    b̄ = H̄_non(X̃, (R'_1, ..., R'_ν))
    For j = 1, ..., ν:
        R_j = (R'_j)^{b̄^{j-1}}
    return (R_1, ..., R_ν)
"""

from secp256k1lab.secp256k1 import GE, Scalar
from common.hashing import hash_nonce_nested
from musig2.nonce import NU, validate_nonce_points

def sign_agg_ext(
    internal_agg_nonces: list[GE],
    group_agg_pk: GE,
) -> tuple[list[GE], Scalar]:
    """
    Transform internal aggregate nonces into external nonces.
    SignAggExt(out, X̃):
        (R'_1, ..., R'_ν) := out
        b̄ := H̄_non(X̃, (R'_1, ..., R'_ν))
        For j = 1, ..., ν:
            R_j := (R'_j)^{b̄^{j-1}}
        return (R_1, ..., R_ν)
    Parameters:
        internal_agg_nonces: [R'_1, R'_2] - output of SignAgg at the inner level
        group_agg_pk:        X̃ - the group's aggregate public key
    Returns:
        (external_nonces, b_nested):
            external_nonces: [R_1, R_2] - what the outer level sees
            b_nested:        Scalar - the inner binding coefficient b̄
    """
    validate_nonce_points(internal_agg_nonces, label="internal aggregate nonce")
    # b̄ = H̄_non(X̃, (R'_1, ..., R'_ν))
    pk_ser = group_agg_pk.to_bytes_compressed()
    nonces_ser = b"".join(R.to_bytes_compressed() for R in internal_agg_nonces)
    b_nested = hash_nonce_nested(pk_ser, nonces_ser)
    # external nonces: R_j = (R'_j)^{b̄^{j-1}}
    external_nonces: list[GE] = []
    b_power = Scalar(1)  # b̄^0 = 1
    for j in range(NU):
        R_ext = int(b_power) * internal_agg_nonces[j]
        if R_ext.infinity:
            raise ValueError(f"External nonce {j} is infinity")
        external_nonces.append(R_ext)
        b_power = b_power * b_nested  # b̄^j for next iteration
    return external_nonces, b_nested