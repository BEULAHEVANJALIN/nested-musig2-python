"""
MuSig2 Nonce Generation and Aggregation (Round 1).
Implements:
    Sign(): Generate ν random nonces (signer-local, no inputs needed)
    SignAgg(): Aggregate all signers' nonces coordinate-wise
BIP 327 uses ν = 2 nonces per signer per session.
Each signer produces (R_{i,1}, R_{i,2}) in Round 1.
The aggregator computes (R_1, R_2) = (Π R_{i,1}, Π R_{i,2}).
"""
import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.util import int_from_bytes
from dataclasses import dataclass, field

# Number of nonces per signer per session.
# BIP 327 specifies ν = 2.
NU = 2

def validate_nonce_points(pub_nonces: list[GE], *, label: str = "nonce") -> None:
    """
    Validate a list of public nonce points received from a signer or subgroup.
    """
    if len(pub_nonces) != NU:
        raise ValueError(f"Expected {NU} {label} points, got {len(pub_nonces)}")
    for j, point in enumerate(pub_nonces):
        if point.infinity:
            raise ValueError(f"{label} point {j} is infinity")
@dataclass
class SignerNonce:
    """
    A signer's nonce state for one signing session.
    Created by generate_nonce(), consumed by sign().
    Fields:
        pub_nonces:  [R_1, R_2] - public commitments, shared with aggregator
        _sec_nonces: [r_1, r_2] - secret scalars, NEVER leave this object
        _used:       safety flag to prevent reuse
    Lifecycle:
        1. generate_nonce() creates this with fresh random nonces
        2. pub_nonces are sent to the aggregator
        3. sign() reads _sec_nonces exactly ONCE and marks _used = True
        4. After use, secret nonces are zeroed out
    """
    pub_nonces: list[GE]
    _sec_nonces: list[Scalar] = field(repr=False)
    _used: bool = field(default=False, repr=False)

    def get_sec_nonces(self) -> list[Scalar]:
        """
        Access the secret nonce scalars. Only callable once.
        Raises RuntimeError on attempted reuse.
        If sign() is accidentally called twice with the same nonce state,
        the two partial signatures would use the same r values but
        (potentially) different challenge values, enabling private key
        extraction: x = (s - s') / (c - c').
        """
        if self._used:
            raise RuntimeError(
                "FATAL: Nonce reuse detected. "
                "This nonce has already been consumed by sign(). "
                "Using it again would compromise the signer's private key. "
                "Each SignerNonce MUST be used exactly once."
            )
        self._used = True
        sec = self._sec_nonces
        # Zero out the stored nonces so they can't be recovered
        # from this object even if it's inspected after use.
        self._sec_nonces = [Scalar(0)] * NU
        return sec

def generate_nonce() -> SignerNonce:
    """
    Generate a fresh nonce pair for a signing session.
    Algorithm:
        For j = 1, ..., ν:
            r_{1,j} ←$ Z_n         (random scalar)
            R_{1,j} = r_{1,j} · G  (nonce commitment)
    Returns: SignerNonce containing public and secret nonces.
    """
    sec_nonces: list[Scalar] = []
    pub_nonces: list[GE] = []
    for _ in range(NU):
        # Generate a random nonzero scalar
        while True:
            r_bytes = os.urandom(32)
            r_int = int_from_bytes(r_bytes)
            if 0 < r_int < GE.ORDER:
                break
        r = Scalar(r_int)
        R = int(r) * G
        sec_nonces.append(r)
        pub_nonces.append(R)
    return SignerNonce(pub_nonces=pub_nonces, _sec_nonces=sec_nonces)

def aggregate_nonces(all_pub_nonces: list[list[GE]]) -> list[GE]:
    """
    Aggregate all signers' public nonces coordinate-wise.

    SignAgg(out_1, ..., out_n):
        For each j ∈ {1, ..., ν}:
            R_j = Σ R_{i,j}   (sum of all signers' j-th nonces)
    Input:
        all_pub_nonces: [[R_{1,1}, R_{1,2}], [R_{2,1}, R_{2,2}], ...]
                         signer 1's nonces    signer 2's nonces
    Output:
        [R_1, R_2] - aggregate nonces
    Mathematically,
        R_1 = R_{1,1} + R_{2,1} + ... + R_{n,1}
        R_2 = R_{1,2} + R_{2,2} + ... + R_{n,2}
    """
    n_signers = len(all_pub_nonces)
    if n_signers == 0:
        raise ValueError("No nonces to aggregate")
    for i, nonces in enumerate(all_pub_nonces):
        validate_nonce_points(nonces, label=f"signer {i} nonce")
    agg_nonces: list[GE] = []
    for j in range(NU):
        # Sum all signers' j-th nonce: R_j = Σ R_{i,j}
        R_j = GE()  # Start with infinity (additive identity)
        for i in range(n_signers):
            R_j += all_pub_nonces[i][j]
        if R_j.infinity:
            raise ValueError(f"Aggregate nonce {j} is infinity")
        agg_nonces.append(R_j)
    return agg_nonces