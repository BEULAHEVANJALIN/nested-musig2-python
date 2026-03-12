from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import GE, Scalar, G

from .hashing import hash_sig

def verify_schnorr(agg_pk: GE, msg: bytes, R: GE, s: Scalar) -> bool:
    """
    Verify a Schnorr signature from typed components.
    Checks: s·G == R + c·X̃
    Parameters:
        agg_pk: The (aggregate) public key X̃
        msg:    The signed message
        R:      The (aggregate) nonce point
        s:      The response scalar
    Returns: True if valid, False otherwise.
    """
    if R.infinity or agg_pk.infinity:
        return False
    # Use even-y versions of both points (BIP 340 convention)
    R_even = R if R.has_even_y() else -R
    pk_even = agg_pk if agg_pk.has_even_y() else -agg_pk
    # Challenge uses x-only bytes (same for P and -P)
    c = hash_sig(agg_pk.to_bytes_xonly(), R.to_bytes_xonly(), msg)
    # Verification equation: s·G == R_even + c·pk_even
    lhs = int(s) * G
    rhs = R_even + int(c) * pk_even
    return lhs == rhs

def verify_schnorr_bip340(pubkey_xonly: bytes, msg: bytes, sig: bytes) -> bool:
    """
    Verify a BIP 340 signature from serialized bytes.
    Parameters:
        pubkey_xonly: 32-byte x-only public key
        msg:          The signed message
        sig:          64-byte signature (R_x || s)
    Returns: True if valid, False otherwise.
    """
    return schnorr_verify(msg, pubkey_xonly, sig)

def sign_schnorr(seckey: bytes, msg: bytes, aux_rand: bytes) -> bytes:
    """
    Create a BIP 340 Schnorr signature (single-signer).
    Parameters:
        seckey:    32-byte secret key
        msg:       Message to sign
        aux_rand:  32-byte auxiliary randomness
    Returns: 64-byte signature (R_x || s)
    """
    return schnorr_sign(msg, seckey, aux_rand)
