"""
This is a simplified simulation of the MuSig2 protocol, where
the 3 signers are Alice, Bob, and Carol.
They collaboratively produce a single signature on a message,
which can be verified against their aggregate public key.

Overview of the protocol phases:
    Phase 0: Key Generation        (each signer, independently)
    Phase 1: Key Aggregation       (anyone, non-interactive)
    Phase 2: Round 1 - Nonces      (each signer -> aggregator)
    Phase 3: Round 2 - Signing     (aggregator -> each signer -> aggregator)
    Phase 4: Verification          (anyone)

Communication pattern:
    Round 1:  Alice -> Aggregator <- Bob
                        ↑
                       Carol

    Round 2:  Aggregator -> Alice -> Aggregator
              Aggregator -> Bob   -> Aggregator
              Aggregator -> Carol -> Aggregator
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secp256k1lab.secp256k1 import GE, Scalar, G
from secp256k1lab.util import int_from_bytes

from musig2.keyagg import key_agg, key_agg_coef
from musig2.nonce import generate_nonce, aggregate_nonces, NU
from musig2.sign import create_session, sign, verify_partial_sig, aggregate_partial_sigs
from common.schnorr import verify_schnorr, verify_schnorr_bip340


def generate_secret_key() -> Scalar:
    """Generate a random private key from the OS CSPRNG."""
    while True:
        sk_bytes = os.urandom(32)
        sk_int = int_from_bytes(sk_bytes)
        if 0 < sk_int < GE.ORDER:
            return Scalar(sk_int)


def main():
    # Phase 0: Key Generation
    # Each signer generates their key pair independently.
    print("\nPhase 0: Key Generation")
    alice_sk = generate_secret_key()
    alice_pk = int(alice_sk) * G
    bob_sk = generate_secret_key()
    bob_pk = int(bob_sk) * G
    carol_sk = generate_secret_key()
    carol_pk = int(carol_sk) * G
    signers = {
        "Alice": {"sk": alice_sk, "pk": alice_pk},
        "Bob": {"sk": bob_sk, "pk": bob_pk},
        "Carol": {"sk": carol_sk, "pk": carol_pk},
    }
    for name, keys in signers.items():
        pk_hex = keys["pk"].to_bytes_compressed().hex()
        print(f"\t{name}: pk = {pk_hex}")

    # Phase 1: Key Aggregation (non-interactive, anyone with all public keys can do this)
    print("\nPhase 1: Key Aggregation")
    pubkeys = [alice_pk, bob_pk, carol_pk]
    cache = key_agg(pubkeys)
    print(f"\tAggregate key X̃ = {cache.agg_pk.to_bytes_compressed().hex()}")
    print(f"\tKey list hash L = {cache.keyset_hash.hex()}")
    print(f"\tSorted key order:")
    for i, pk in enumerate(cache.sorted_pks):
        # Identify which signer this is
        name = "?"
        for n, keys in signers.items():
            if keys["pk"] == pk:
                name = n
        a_i = key_agg_coef(cache.keyset_hash, pk, cache.second_key_bytes)
        coef_str = "1 (second-key optimization)" if int(a_i) == 1 else f"{int(a_i):x}"
        print(f"\t\t[{i}] {name:5s}  a_i = {coef_str}")

    # Phase 2: Round 1 - Nonce Generation
    # Each signer generates nonces. Can happen before the message.
    # Only public nonces are sent to the aggregator.
    print("\nPhase 2: Round 1 - Nonce Generation")
    alice_nonce = generate_nonce()
    bob_nonce = generate_nonce()
    carol_nonce = generate_nonce()
    for name, nonce in [
        ("Alice", alice_nonce),
        ("Bob", bob_nonce),
        ("Carol", carol_nonce),
    ]:
        for j in range(NU):
            R_hex = nonce.pub_nonces[j].to_bytes_compressed().hex()
            print(f"\t{name} sends to Aggregator: R_{name[0]},{j+1} = {R_hex}")
    # Aggregator combines nonces
    all_pub_nonces = [
        alice_nonce.pub_nonces,
        bob_nonce.pub_nonces,
        carol_nonce.pub_nonces,
    ]
    agg_nonces = aggregate_nonces(all_pub_nonces)
    print(f"\n\tAggregator computes aggregate nonces:")
    for j in range(NU):
        print(f"\t\tR_{j+1} = {agg_nonces[j].to_bytes_compressed().hex()}")

    # Phase 3: Round 2 - Signing
    # The message becomes known. Aggregator broadcasts session data.
    # Each signer computes their partial signature.
    print("\nPhase 3: Round 2 - Signing")
    msg = b"Pay 0.5 BTC from Alice + Bob + Carol to Dave"
    print(f'\tMessage: "{msg.decode()}"\n')
    # Aggregator (or each signer independently) creates the session
    session = create_session(cache, agg_nonces, msg)
    print(f"\tSession values (broadcast to all signers):")
    print(f"\t\tb (nonce binding) = {int(session.b):x}")
    print(f"\t\tR (eff. nonce)    = {session.R.to_bytes_compressed().hex()}")
    print(f"\t\tc (challenge)     = {int(session.c):x}")
    # Each signer computes their partial signature
    print(f"\n\tPartial signatures:")
    nonce_map = [
        ("Alice", alice_nonce, alice_sk, alice_pk),
        ("Bob", bob_nonce, bob_sk, bob_pk),
        ("Carol", carol_nonce, carol_sk, carol_pk),
    ]
    partial_sigs = []
    for name, nonce, sk, pk in nonce_map:
        s_i = sign(session, nonce, sk, pk)
        partial_sigs.append(s_i)
        print(f"\t\t{name} sends to Aggregator: s_{name[0]} = {int(s_i):x}")
    # Aggregator verifies each partial signature (optional, for accountability)
    print(f"\n\tPartial signature verification (aggregator):")
    for i, (name, _, _, pk) in enumerate(nonce_map):
        valid = verify_partial_sig(session, pk, all_pub_nonces[i], partial_sigs[i])
        print(f"\t\t{name}'s partial sig: {'valid' if valid else 'Invalid'}")
        assert valid, f"{name}'s partial signature is invalid!"

    # Phase 4: Aggregation and Verification
    print("\nPhase 4: Aggregation and Verification")
    R, s = aggregate_partial_sigs(session, partial_sigs)
    R_hex = R.to_bytes_xonly().hex()
    s_hex = f"{int(s):064x}"
    sig_hex = R_hex + s_hex
    print(f"\n\tFinal signature σ = (R, s):")
    print(f"\t\tR = {R_hex}")
    print(f"\t\ts = {s_hex}")
    print(f"\t\tσ = {sig_hex}  (64 bytes)")
    # Verify
    valid = verify_schnorr(cache.agg_pk, msg, R, s)
    print(f"\n\tVerification (s·G = R + c·X̃):\t\t{'VALID' if valid else 'INVALID'}")
    # Verify using the library's BIP 340 verifier
    sig_bytes = R.to_bytes_xonly() + int(s).to_bytes(32, "big")
    pk_bytes = cache.agg_pk.to_bytes_xonly()
    valid_bip340 = verify_schnorr_bip340(pk_bytes, msg, sig_bytes)
    print(f"\n\tBIP 340 verification:\t\t{'VALID' if valid_bip340 else 'INVALID'}")
    # Negative tests
    valid_wrong_msg = verify_schnorr(cache.agg_pk, b"wrong", R, s)
    print(f"\n\tWrong message:\t\t{'rejected' if not valid_wrong_msg else 'BUG'}")

    assert valid, "Aggregate signature failed typed verification!"
    assert valid_bip340, "Aggregate signature failed BIP 340 verification!"
    assert not valid_wrong_msg, "Wrong message was accepted!"

if __name__ == "__main__":
    main()