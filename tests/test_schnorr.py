import os
from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.bip340 import pubkey_gen
from secp256k1lab.util import int_from_bytes
from common.schnorr import sign_schnorr, verify_schnorr_bip340, verify_schnorr
from common.hashing import hash_sig


def test_single_signer_roundtrip():
    seckey = os.urandom(32)
    while int_from_bytes(seckey) == 0 or int_from_bytes(seckey) >= GE.ORDER:
        seckey = os.urandom(32)
    msg = b"Hello, Schnorr!"
    aux_rand = os.urandom(32)
    sig = sign_schnorr(seckey, msg, aux_rand)
    pubkey = pubkey_gen(seckey)
    assert len(sig) == 64
    assert len(pubkey) == 32
    assert verify_schnorr_bip340(pubkey, msg, sig)
    print("Single-signer sign and verify roundtrip works")

def test_invalid_message_rejected():
    seckey = os.urandom(32)
    while int_from_bytes(seckey) == 0 or int_from_bytes(seckey) >= GE.ORDER:
        seckey = os.urandom(32)
    msg = b"Correct message"
    aux_rand = os.urandom(32)
    sig = sign_schnorr(seckey, msg, aux_rand)
    pubkey = pubkey_gen(seckey)
    assert not verify_schnorr_bip340(pubkey, b"Wrong message", sig)
    print("Wrong message correctly rejected")


def test_invalid_key_rejected():
    seckey_a = os.urandom(32)
    seckey_b = os.urandom(32)
    while int_from_bytes(seckey_a) == 0 or int_from_bytes(seckey_a) >= GE.ORDER:
        seckey_a = os.urandom(32)
    while int_from_bytes(seckey_b) == 0 or int_from_bytes(seckey_b) >= GE.ORDER:
        seckey_b = os.urandom(32)
    msg = b"Test message"
    sig = sign_schnorr(seckey_a, msg, os.urandom(32))
    pubkey_b = pubkey_gen(seckey_b)
    assert not verify_schnorr_bip340(pubkey_b, msg, sig)
    print("Wrong public key correctly rejected")


def test_verification_equation():
    # Choose a private key and compute the public key
    x = Scalar(123456789)
    X = int(x) * G
    # Choose a random nonce
    r = Scalar(987654321)
    R = int(r) * G
    # Message
    msg = b"Verification equation test"
    # Compute challenge: c = H_sig(X, R, m)
    c = hash_sig(X.to_bytes_xonly(), R.to_bytes_xonly(), msg)
    # Compute signature: s = r + c·x (mod n)
    s = r + c * x
    # Verify: s·G should equal R + c·X
    lhs = int(s) * G
    rhs = R + int(c) * X
    assert lhs == rhs, "Verification equation s·G = R + c·X failed!"
    # Also verify using our typed function
    assert verify_schnorr(X, msg, R, s)
    print("Verification equation s·G = R + c·X holds")

def test_signature_decomposition():
    # Two signers
    x1 = Scalar(111)
    x2 = Scalar(222)
    X1 = int(x1) * G
    X2 = int(x2) * G
    # Aggregate key (simplified: just add, no coefficients)
    X_agg = X1 + X2
    # Each signer picks a nonce
    r1 = Scalar(333)
    r2 = Scalar(444)
    R1 = int(r1) * G
    R2 = int(r2) * G
    # Aggregate nonce
    R_agg = R1 + R2
    msg = b"Split signature test"
    # Challenge (computed by everyone, same for all signers)
    c = hash_sig(X_agg.to_bytes_xonly(), R_agg.to_bytes_xonly(), msg)
    # Each signer computes their partial signature
    s1 = r1 + c * x1   # Signer 1's partial sig
    s2 = r2 + c * x2   # Signer 2's partial sig
    # Aggregate signature
    s_agg = s1 + s2
    # Verify: s_agg · G should equal R_agg + c · X_agg
    assert verify_schnorr(X_agg, msg, R_agg, s_agg)
    print("Signature splits across two signers and recombines correctly")

if __name__ == "__main__":
    test_single_signer_roundtrip()
    test_invalid_message_rejected()
    test_invalid_key_rejected()
    test_verification_equation()
    test_signature_decomposition()
    print("\nAll Schnorr tests passed!\n")
