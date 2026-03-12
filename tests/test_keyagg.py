from secp256k1lab.secp256k1 import GE, Scalar, G
from musig2.keyagg import key_agg, key_agg_coef, _sort_pubkeys

def test_basic_aggregation():
    x1, x2, x3 = Scalar(101), Scalar(202), Scalar(303)
    X1, X2, X3 = int(x1) * G, int(x2) * G, int(x3) * G
    cache = key_agg([X1, X2, X3])
    assert not cache.agg_pk.infinity
    assert len(cache.sorted_pks) == 3
    assert len(cache.keyset_hash) == 32
    print("Basic 3-key aggregation produces valid result")

def test_order_independence():
    x1, x2, x3 = Scalar(111), Scalar(222), Scalar(333)
    X1, X2, X3 = int(x1) * G, int(x2) * G, int(x3) * G
    cache_abc = key_agg([X1, X2, X3])
    cache_cab = key_agg([X3, X1, X2])
    cache_bca = key_agg([X2, X3, X1])
    assert cache_abc.agg_pk == cache_cab.agg_pk
    assert cache_abc.agg_pk == cache_bca.agg_pk
    print("Key aggregation is order-independent")

def test_aggregate_private_key():
    """
    Verify that x̃ = Σ a_i·x_i is the private key for X̃.
    """
    x1, x2, x3 = Scalar(444), Scalar(555), Scalar(666)
    X1, X2, X3 = int(x1) * G, int(x2) * G, int(x3) * G
    cache = key_agg([X1, X2, X3])
    # x̃ = Σ a_i · x_i
    privkeys = [x1, x2, x3]
    x_agg = Scalar(0)
    for i, pk in enumerate(cache.sorted_pks):
        a_i = key_agg_coef(cache.keyset_hash, pk, cache.second_key_bytes)
        # Find the matching private key
        for j, Xj in enumerate([X1, X2, X3]):
            if pk == Xj:
                x_agg = x_agg + a_i * privkeys[j]
                break
    # Verify: x̃ · G should equal X̃
    computed_pk = int(x_agg) * G
    assert computed_pk == cache.agg_pk
    print("Aggregate private key x̃ = Σ a_i·x_i matches aggregate public key")

def test_second_key_optimization():
    x1, x2, x3 = Scalar(10), Scalar(20), Scalar(30)
    X1, X2, X3 = int(x1) * G, int(x2) * G, int(x3) * G
    cache = key_agg([X1, X2, X3])
    # The second key in sorted order should have coefficient 1
    second_pk = cache.sorted_pks[1]
    a_second = key_agg_coef(cache.keyset_hash, second_pk, cache.second_key_bytes)
    assert int(a_second) == 1, f"Second key coefficient should be 1, got {int(a_second)}"
    # The first and third keys should NOT have coefficient 1
    a_first = key_agg_coef(cache.keyset_hash, cache.sorted_pks[0], cache.second_key_bytes)
    a_third = key_agg_coef(cache.keyset_hash, cache.sorted_pks[2], cache.second_key_bytes)
    assert int(a_first) != 1, "First key should not have coefficient 1"
    assert int(a_third) != 1, "Third key should not have coefficient 1"
    print("Second distinct key has coefficient 1 (BIP 327 optimization)")

def test_changing_one_key_changes_everything():
    x1, x2, x3 = Scalar(100), Scalar(200), Scalar(300)
    X1, X2, X3 = int(x1) * G, int(x2) * G, int(x3) * G
    cache_original = key_agg([X1, X2, X3])
    # Replace X3 with a different key
    x3_new = Scalar(301)
    X3_new = int(x3_new) * G
    cache_modified = key_agg([X1, X2, X3_new])
    # Aggregate keys must differ
    assert cache_original.agg_pk != cache_modified.agg_pk
    # List hashes must differ
    assert cache_original.keyset_hash != cache_modified.keyset_hash
    # Coefficient for X1 must differ (because L changed)
    a1_original = key_agg_coef(
        cache_original.keyset_hash, X1, cache_original.second_key_bytes
    )
    a1_modified = key_agg_coef(
        cache_modified.keyset_hash, X1, cache_modified.second_key_bytes
    )
    assert int(a1_original) != int(a1_modified)
    print("Changing one key changes all coefficients (rogue-key defense)")


def test_duplicate_keys():
    x1 = Scalar(777)
    X1 = int(x1) * G
    x2 = Scalar(888)
    X2 = int(x2) * G
    # [X1, X1, X2] -> X1 appears twice
    cache = key_agg([X1, X1, X2])
    assert not cache.agg_pk.infinity
    assert len(cache.sorted_pks) == 3
    print("Duplicate keys handled correctly")

def test_two_keys():
    x1, x2 = Scalar(42), Scalar(43)
    X1, X2 = int(x1) * G, int(x2) * G
    cache = key_agg([X1, X2])
    assert not cache.agg_pk.infinity
    assert len(cache.sorted_pks) == 2
    print("Two-key aggregation works")

if __name__ == "__main__":
    test_basic_aggregation()
    test_order_independence()
    test_aggregate_private_key()
    test_second_key_optimization()
    test_changing_one_key_changes_everything()
    test_duplicate_keys()
    test_two_keys()
    print("\nAll key aggregation tests passed!\n")
