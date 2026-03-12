from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.util import int_from_bytes
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
    # Compute challenge: c = H_sig(X̃, R, m)
    c = hash_sig(agg_pk.to_bytes_xonly(), R.to_bytes_xonly(), msg)
    # Check: s·G == R + c·X̃
    lhs = int(s) * G
    rhs = R + int(c) * agg_pk
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
