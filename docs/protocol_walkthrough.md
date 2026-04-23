# Protocol Walkthrough

## References
- [BIP 327 - MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
- [Nested MuSig2 Paper (ePrint 2026/223)](https://eprint.iacr.org/2026/223.pdf)

---

## Notation

| Symbol | Meaning |
|--------|---------|
| $G$ | Generator point of secp256k1 |
| $n$ | Group order (number of points on the curve) |
| $x, X = xG$ | Private key and corresponding public key |
| $r, R = rG$ | Nonce scalar and nonce commitment |
| $\tilde{X}$ | Aggregate public key |
| $a_i$ | Key aggregation coefficient for signer $i$ |
| $b$ | Nonce binding coefficient (top level) |
| $\bar{b}$ | Nonce binding coefficient (nested level, no message) |
| $\check{b}$ | Product of all nonce bindings along a path: $\prod_{\ell} b_\ell$ |
| $c$ | Signature challenge: $H_{\text{sig}}(\tilde{X}, R, m)$ |
| $\check{c}$ | Effective challenge: $c \cdot \prod_{\ell} a_{1,\ell}$ |
| $s_i$ | Partial signature from signer $i$ |
| $\sigma = (R, s)$ | Final Schnorr signature |
| $\nu$ | Number of nonces per signer per session ($=2$ in BIP 327) |
| $\Lambda$ | Nesting depth ($\Lambda = 1$ for standard MuSig2) |
| $\mathcal{L}$ | Multiset of public keys at a given level |

---

## Hash Functions
Four tagged hash functions, each with a distinct domain separation tag:

| Function | Tag | Inputs | Output |
|----------|-----|--------|--------|
| $H_{\text{agg-list}}$ | `"KeyAgg list"` | $X_1 \| X_2 \| \cdots \| X_n$ | 32-byte hash $L$ |
| $H_{\text{agg-coef}}$ | `"KeyAgg coefficient"` | $L \| X_i$ | Scalar $a_i \bmod n$ |
| $H_{\text{non}}$ | `"MuSig/noncecoef"` | $\tilde{X} \| R_1 \| R_2 \| m$ | Scalar $b \bmod n$ |
| $H_{\overline{\text{non}}}$ | `"MuSig/nested-noncecoef"` | $X_{\text{group}} \| R'_1 \| R'_2$ | Scalar $\bar{b} \bmod n$ |
| $H_{\text{sig}}$ | `"BIP0340/challenge"` | $R \| \tilde{X} \| m$ | Scalar $c \bmod n$ |

**Code**: `common/hashing.py`

Key Points:
- $H_{\text{non}}$ includes the message $m$, while $H_{\overline{\text{non}}}$ does not.
- $H_{\text{sig}}$ follows BIP 340 input ordering: $R$ first, then $\tilde{X}$, then $m$.
- All hash functions use tagged hashing: $\mathrm{tagged\\_hash}(tag, m) = \mathrm{SHA256}(\mathrm{SHA256}(tag) \| \mathrm{SHA256}(tag) \| m)\,$
- Domain separation via distinct tags prevents collisions between different protocol uses of hashing.

---



## Algorithm 1: KeyGen

> **KeyGen():**
> - $x \stackrel{\\$}{\leftarrow} \mathbb{Z}_n$ (sampled uniformly at random from a CSPRNG; used as the private key)
> - Compute $X := x \cdot G$ (public key, a point on the elliptic curve)
> - return $(x, X)$

**Code:** `LeafSigner.generate()` in `nested_musig2/nested_sign.py`
```python
while True:
    sk_int = int.from_bytes(os.urandom(32), 'big')
    if 0 < sk_int < GE.ORDER:
        sk = Scalar(sk_int)
        pk = int(sk) * G
        return LeafSigner(name, sk, pk)
```
**Why it exists:** Every signer needs a key pair. The private key $x$ must be uniformly random over $\\{1, \ldots, n-1\\}$. The public key $X$ is published.

**Security notes**
- Private Key $x$ must remain secret and should never be logged, transmitted insecurely, or reused across protocols.
- Public keys should be encoded consistently (compressed or uncompressed) before being shared.
- Key generation should occur offline in a secure and trusted environment.
- Randomness must come from a cryptographically secure source to prevent bias or predictability.

---

## Algorithm 2: KeyAgg

MuSig2 combines a set of public keys into a single aggregate public key $\tilde{X}$.

This happens at every level of the tree:

- at a leaf-only level, the inputs are ordinary signer public keys
- at a nested level, a subgroup contributes its own aggregate key upward
- a parent always aggregates only its immediate child node keys

This recursive structure is what allows a nested subgroup to behave like a single signer at the level above.

> **KeyAgg($X_1, \dots, X_n$):**
> - Sort the public keys lexicographically by compressed serialization
> - Compute
>   $L := H_{\text{agg-list}}(X_1 \| X_2 \| \cdots \| X_n)$
> - Let $X_{\text{second}}$ be the second distinct key in the sorted list, if one exists
> - For each key $X_i$, compute
>   - $a_i := 1$ if $X_i = X_{\text{second}}$
>   - otherwise $a_i := H_{\text{agg-coef}}(L \| X_i)$
> - Compute the aggregate key
>   $\tilde{X} := \sum_i a_i X_i$
> - Return $\tilde{X}$ together with cached values needed later during signing

**Code:** `key_agg(...)` and `key_agg_coef(...)` in `musig2/keyagg.py`

```python
sorted_pks = _sort_pubkeys(pubkeys)
serialized = b"".join(pk.to_bytes_compressed() for pk in sorted_pks)
keyset_hash = hash_keyagg_list(serialized)
second_key_bytes = _get_second_unique_key(sorted_pks)

agg_pk = GE()
for pk in sorted_pks:
    a_i = key_agg_coef(keyset_hash, pk, second_key_bytes)
    agg_pk += int(a_i) * pk
```

**Returned state:** The implementation returns a `KeyAggCache` containing:

- `sorted_pks`
- `agg_pk`
- `keyset_hash`
- `second_key_bytes`

These values are reused later during signing to derive each signer's key aggregation coefficient from the same canonical keyset.

**Why the coefficients matter?** The aggregate key is not just a plain sum of public keys. The coefficients $a_i$ bind each signer’s contribution to the full keyset at that level. This prevents rogue-key attacks and ensures that the aggregate key depends on the entire participant set.

**Nested interpretation:** In the nested setting, each node contributes exactly one public key upward:
- a `LeafSigner` contributes its own public key
- a `NestedGroup` contributes its subgroup aggregate key

So, if $Group_{AB} = {A, B}$ and $Group_{CD} = {C, D}$, then the root aggregates $\tilde{X}\_{AB}$ and $\tilde{X}\_{CD}$, respectively, rather than the four leaf keys directly at that level.

This matches the implementation’s tree semantics:
- parents aggregate immediate child node keys only
- descendants are not flattened into the parent keyset

**Security notes**
- Public keys must be valid curve points and must not be the point at infinity.
- Every participant must use the same canonical ordering of keys.
- The aggregate key must not be the point at infinity.

---

## Algorithm 3: Round 1 Nonce Generation and Aggregation

Round 1 creates fresh nonce commitments for one signing session.

Each leaf signer generates $\nu$ secret nonce scalars and publishes the corresponding $\nu$ public nonce points. The formulas are written using $\nu$ for consistency with the paper. This implementation follows the practical BIP 327 setting and fixes $\nu = 2$, including at every nested level.

For signer $i$:

> **NonceGen():**
> - For each $j \in \{1, \ldots, \nu\}$:
>   - Sample $r_{i,j}$ uniformly from $\{1, \ldots, n-1\}$
>   - Compute $R_{i,j} := r_{i,j} \cdot G$
> - Keep $(r_{i,1}, \ldots, r_{i,\nu})$ secret
> - Publish $(R_{i,1}, \ldots, R_{i,\nu})$

**Code:** `generate_nonce()` in `musig2/nonce.py`

```python
for _ in range(NU):
    while True:
        r_bytes = os.urandom(32)
        r_int = int_from_bytes(r_bytes)
        if 0 < r_int < GE.ORDER:
            break
    r = Scalar(r_int)
    R = int(r) * G
    sec_nonces.append(r)
    pub_nonces.append(R)
```

**Nonce aggregation:** After public nonces are collected, they are aggregated coordinate-wise.

Given public nonce tuples from all signers, $(R_{1,1}, \ldots, R_{1,\nu}), \ldots, (R_{N,1}, \ldots, R_{N,\nu})$, the aggregate nonce tuple is:

$$
R_j := \sum_{i=1}^{N} R_{i,j}
\quad \text{for each } j \in \{1, \ldots, \nu\}
$$

For $\nu = 2$:

$$
R_1 := \sum_{i=1}^{N} R_{i,1}
$$

$$
R_2 := \sum_{i=1}^{N} R_{i,2}
$$

**Code:** `aggregate_nonces(...)` in `musig2/nonce.py`

```python
agg_nonces: list[GE] = []
for j in range(NU):
    R_j = GE()
    for i in range(n_signers):
        R_j += all_pub_nonces[i][j]
    agg_nonces.append(R_j)
```

**Nonce state in the implementation:** The implementation stores each signer’s nonce data in a `SignerNonce` object.

It contains:

- `pub_nonces`: public nonce points $(R_{i,1}, R_{i,2})$
- `_sec_nonces`: secret nonce scalars $(r_{i,1}, r_{i,2})$
- `_used`: a safety flag that prevents accidental reuse

The secret nonces are consumed once during signing. After use, the object marks them as used and zeroes the stored secret nonce list.

**Why nonce reuse is dangerous?** A signer must never reuse the same secret nonce scalars in two different signing equations.

If the same nonce is used with different challenges, an attacker may be able to solve for the signer’s private key. The implementation therefore makes `SignerNonce.get_sec_nonces()` callable only once.

**Nested interpretation:** 

In a nested tree, Round 1 happens bottom-up.

`LeafSigner`
- generate a fresh nonce tuple
- return the public nonce tuple upward

`NestedGroup`
- recursively collect public nonce tuples from immediate children
- aggregate those child nonce tuples internally
- apply the nested extension `SignAggExt`
- return the transformed external nonce tuple upward

`root`
- collect public nonce tuples from all top-level members
- aggregate them with ordinary nonce aggregation
- do not apply `SignAggExt` again, because the root has no parent level

**Code:** bottom-up nonce generation inside `run_nested_musig2(...)` in `nested_musig2/nested_sign.py`

```python
if isinstance(member, LeafSigner):
    member.nonce = generate_nonce()
    return member.nonce.pub_nonces

all_member_pub_nonces = []
for m in member.members:
    pub_nonces = generate_nonces_recursive(m)
    all_member_pub_nonces.append(pub_nonces)

internal_agg_nonces = aggregate_nonces(all_member_pub_nonces)
external_nonces, b_nested = sign_agg_ext(
    internal_agg_nonces,
    member.cache.agg_pk,
)
```

**Validation:** The implementation rejects malformed nonce inputs:
- each nonce tuple must contain exactly $\nu$ points
- no nonce point may be the point at infinity
- aggregate nonce points must not be the point at infinity

**Output of Round 1**

At the end of Round 1, the root has an aggregate nonce tuple $(R_1, \ldots, R_\nu)$. For this implementation: $(R_1, R_2)$

This tuple is then used in the next step to create the signing session.

---

## Algorithm 4: Nested Extension / SignAggExt

`SignAggExt` is the nested-specific step that lets a subgroup expose a nonce tuple upward as if the whole subgroup were one ordinary MuSig2 signer. Inside a subgroup, child nonces are first aggregated normally. This gives an internal aggregate nonce tuple $(R'\_1, \ldots, R'\_\nu)$. Then the subgroup computes a nested nonce binding coefficient $\bar{b} := H_{\overline{\text{non}}}(\tilde{X}_{\text{group}} \| R'\_1 \| \cdots \| R'\_\nu)$. Finally, each internal aggregate nonce is transformed into an external nonce:

$$
R\_j := \bar{b}^{j-1} \cdot R'\_j
\quad \text{for each } j \in \{1, \ldots, \nu\}
$$

For the current implementation, $\nu = 2$, this becomes: $R_1 := R'_1,$ $R_2 := \bar{b} \cdot R'_2$. And the subgroup exposes $(R_1, R_2)$ to its parent level.

> **SignAggExt($\tilde{X}_{\text{group}},$ ($R'\_1, \ldots, R'\_\nu$)):**
> - Compute
>   $\bar{b} := H_{\overline{\text{non}}}(\tilde{X}_{\text{group}} \| R'\_1 \| \cdots \| R'\_\nu)$
> - For each $j \in \{1, \ldots, \nu\}$, compute
>   $R\_j := \bar{b}^{j-1} \cdot R'\_j$
> - Return $(R\_1, \ldots, R\_\nu)$ and $\bar{b}$

**Code:** `sign_agg_ext(...)` in `nested_musig2/nonce_ext.py`

```python
pk_ser = group_agg_pk.to_bytes_compressed()
nonces_ser = b"".join(R.to_bytes_compressed() for R in internal_agg_nonces)
b_nested = hash_nonce_nested(pk_ser, nonces_ser)

external_nonces: list[GE] = []
b_power = Scalar(1)

for j in range(NU):
    R_ext = int(b_power) * internal_agg_nonces[j]
    external_nonces.append(R_ext)
    b_power = b_power * b_nested

return external_nonces, b_nested
```
**Why this exists?** Without `SignAggExt`, a nested subgroup would not expose the right nonce structure to the parent level. The parent expects every participant to provide a nonce tuple $(R_1, \ldots, R_\nu)$.

A nested subgroup must therefore transform its internal aggregate nonce tuple into an external tuple of the same shape.

This is what allows the parent level to treat:
- a single leaf signer
- a whole nested subgroup

in the same way during nonce aggregation.

**Code:** `NestedGroupRound1State` in `nested_musig2/nested_sign.py`

It contains:
- `cache`: the subgroup’s key aggregation cache
- `internal_agg_nonces`: $(R'_1, \ldots, R'_\nu)$
- `external_nonces`: $(R_1, \ldots, R_\nu)$
- `b_nested`: $\bar{b}$

This state is later needed during Round 2, because each leaf signer inside that subgroup must include $\bar{b}$ when computing its effective nonce binding $\check{b}$.

**Top-level distinction: ** `SignAggExt` is used only for nested groups. At the root level:
- there is no parent above the root
- the top-level aggregate nonce tuple goes directly into session creation
- no extra nested extension is applied

So the root computes the ordinary MuSig2 session using the top-level aggregate nonce tuple.

**Note**

The current implementation computes $\bar{b}$ using $H_{\overline{\text{non}}}(\tilde{X}_{\text{group}} \| R'_1 \| R'_2)$ with the code tag `"MuSig/nested-noncecoef"`. We are keeping this as the current implementation behavior while the exact paper domain-separation wording remains paused for later review.

---

## Algorithm 5: Top-Level Session Creation

After Round 1 finishes, the root has:
- the root aggregate public key $\tilde{X}$
- the top-level aggregate nonce tuple $(R_1, \ldots, R_\nu)$
- the message $m$

At this point, the ordinary MuSig2 signing session is created.

This step computes:
- the top-level nonce binding coefficient $b$
- the effective aggregate nonce $R$
- the Schnorr challenge $c$

> **CreateSession($\tilde{X}, (R_1, \ldots, R_\nu), m$):**
> - Compute the top-level nonce binding:
>   $b := H_{\text{non}}(\tilde{X} \| R_1 \| \cdots \| R_\nu \| m)$
> - Compute the effective aggregate nonce: $R := \sum_{j=1}^{\nu} b^{j-1} R_j$
> - If $R$ is the point at infinity, abort
> - If $R$ has odd $y$, negate $R$
> - Record whether $\tilde{X}$ has odd $y$
> - Compute the challenge: $c := H_{\text{sig}}(R \| \tilde{X} \| m)$
> - Return the session state

For the current implementation, $\nu = 2$, so $R := R_1 + bR_2$

Here:
- $R$ denotes the even-y adjusted aggregate nonce
- $\tilde{X}$ is encoded in x-only form when computing $c$, following BIP 340 conventions

**Code:** `create_session(...)` in `musig2/sign.py`

```python
agg_pk_ser = cache.agg_pk.to_bytes_compressed()
nonces_ser = b"".join(R.to_bytes_compressed() for R in agg_nonces)
b = hash_nonce(agg_pk_ser, nonces_ser, msg)

R = GE()
b_power = Scalar(1)
for j in range(NU):
    R += int(b_power) * agg_nonces[j]
    b_power = b_power * b

if R.infinity:
    raise ValueError("Effective aggregate nonce is infinity")

nonce_negated = not R.has_even_y()
if nonce_negated:
    R = -R

key_negated = not cache.agg_pk.has_even_y()

c = hash_sig(
    cache.agg_pk.to_bytes_xonly(),
    R.to_bytes_xonly(),
    msg,
)
```

The implementation stores the result in `SigningSession`.

It contains:
- `cache`: the root `KeyAggCache`
- `agg_nonces`: the top-level aggregate nonce tuple
- `b`: the top-level nonce binding coefficient
- `R`: the effective aggregate nonce after even-y adjustment
- `c`: the Schnorr challenge
- `msg`: the message being signed
- `nonce_negated`: whether $R$ was negated
- `key_negated`: whether $\tilde{X}$ has odd $y$

**Why even-y handling matters?** BIP 340 signatures use x-only public keys and require the final nonce point to be treated canonically.

So the implementation:
- negates $R$ if it has odd $y$
- remembers this using `nonce_negated`
- records whether $\tilde{X}$ has odd $y$ using `key_negated`

These flags are later used during partial signing and partial signature verification.

Note that the challenge hash uses:
- the even-y adjusted nonce $R$
- the x-only encoding of $\tilde{X}$

The aggregate key is not explicitly negated before hashing, because x-only encoding already identifies a point and its negation by the same x-coordinate.

**Nested interpretation:** Only the root creates the final Schnorr signing session. Nested groups do **not** create independent Schnorr sessions for the final message. Instead:
- each nested group computes its own nested nonce binding $\bar{b}$
- the root computes the top-level values $b$, $R$, and $c$
- each leaf signer combines the root session values with its path-dependent nested values during Round 2

So the final output is still a standard Schnorr signature $\sigma = (R, s)$ under the root aggregate public key $\tilde{X}$.

---

## Algorithm 6: Leaf Transcript Construction

In ordinary MuSig2, a signer only needs the top-level session and its own key coefficient.

In Nested MuSig2, a leaf signer also needs information about its path through the cosigner tree.

The implementation represents this path using `NestedSigningTranscript`.

This transcript tells a leaf signer:
- what the root MuSig2 session is
- which parent keyset it belongs to at each level
- which child key it contributes at each level
- which nested nonce bindings $\bar{b}$ appear on its path

For one leaf signer, the transcript contains:
- `session`: the root `SigningSession`
- `path_caches`: the parent keyset at each level, from root to leaf
- `path_pubkeys`: the signer’s immediate child-node key inside each parent keyset
- `nested_nonce_bindings`: the nested nonce bindings encountered below the root

**Code:** `NestedSigningTranscript` in `nested_musig2/nested_sign.py`
```python
@dataclass(frozen=True)
class NestedSigningTranscript:
    session: SigningSession
    path_caches: list[KeyAggCache]
    path_pubkeys: list[GE]
    nested_nonce_bindings: list[Scalar]
```

**Validation:** The transcript is validated when it is constructed. It checks:
- there is at least one key aggregation level
- `path_caches` and `path_pubkeys` have the same length
- the number of nested nonce bindings matches the number of nested levels
- no path public key is the point at infinity
- each path public key is actually present in its corresponding parent keyset

**Code:** `NestedSigningTranscript.__post_init__()` in `nested_musig2/nested_sign.py`

These checks ensure that the signer’s path is structurally consistent before any partial signature is computed.

**Derived path values:** From this transcript, the signer derives two path-dependent values.
1. Effective nonce binding

    The signer multiplies the top-level nonce binding with all nested nonce bindings along its path:

$$
\check{b} := b \cdot \prod_{\ell} \bar{b}_{\ell}
$$

**Code:** `NestedSigningTranscript.nonce_factor()`
```python
b_check = self.session.b
for b_nested in self.nested_nonce_bindings:
    b_check = b_check * b_nested
```

2. Effective challenge

    The signer multiplies the top-level challenge with the key aggregation coefficients for its path keys at every level:

$$
\check{c} := c \cdot \prod_{\ell} a_{i,\ell}
$$

where $a_{i,\ell}$ is the coefficient of the signer’s child-node key inside the parent keyset at level $\ell$.

**Code:** `NestedSigningTranscript.challenge_factor()`
```python
c_check = self.session.c
for cache, pk in zip(self.path_caches, self.path_pubkeys):
    a_i = key_agg_coef(cache.keyset_hash, pk, cache.second_key_bytes)
    c_check = c_check * a_i
```

**Why this matters?** This is the key idea that makes Nested MuSig2 work. A leaf signer does not sign using only the top-level MuSig2 challenge $c$. Instead, it signs using:
- the root session values
- the nested nonce bindings on its path
- the key aggregation coefficients on its path

That is what turns the ordinary MuSig2 signing equation into the nested signing equation for one leaf.

**Example:** Suppose the tree is:
- root contains `Group_AB` and `Carol`
- `Group_AB` contains `Alice` and `Bob`

Then Alice’s transcript contains:
- the root session
- the root keyset: $\tilde{X}_{AB}, X_C$
- Alice’s child key in that root keyset: $\tilde{X}_{AB}$
- the subgroup keyset: $[X_A, X_B]$
- Alice’s child key in that subgroup keyset: $X_A$
- the nested binding $\bar{b}_{AB}$

From this, Alice derives 

$$
\check{b} = b \cdot \bar{b}_{AB}
$$

and

$$
\check{c} = c \cdot a_{\text{root}} \cdot a_{\text{subgroup}}
$$

Those are the values Alice uses in Round 2.

**How the implementation builds transcripts?** During `run_nested_musig2(...)`, the code traverses the tree recursively. As it descends:
- it appends the current parent cache to `path_caches`
- it appends the child-node key for that level to `path_pubkeys`
- it appends the subgroup’s `b_nested` value to `nested_nonce_bindings`

When it reaches a leaf, it constructs a `NestedSigningTranscript` and signs immediately.

**Code:** recursive `collect_signatures(...)` in `nested_musig2/nested_sign.py`


**Output:** For each leaf signer, the result of transcript construction is:
- a validated path through the tree
- an effective nonce binding $\check{b}$
- an effective challenge $\check{c}$

These values are then used to compute the leaf’s partial signature.

---

## Algorithm 7: Nested Partial Signing

Once a leaf signer has its validated transcript, it computes a partial signature using the path-dependent values:
- the effective nonce binding $\check{b}$
- the effective challenge $\check{c}$

This is the nested analogue of the ordinary MuSig2 partial signing step.

Let:
- $(r_{i,1}, \ldots, r_{i,\nu})$ be the leaf signer’s secret nonce scalars
- $x_i$ be the leaf signer’s private key
- $\check{b}$ be the effective nonce binding from the transcript
- $\check{c}$ be the effective challenge from the transcript

Then the nested partial signature is:

$$
s_i := \check{c} \cdot x_i + \sum_{j=1}^{\nu} r_{i,j}\check{b}^{j-1}
\pmod n
$$

For the current implementation, $\nu = 2$, so this becomes:

$$
s_i := \check{c} \cdot x_i + r_{i,1} + r_{i,2}\check{b}
\pmod n
$$


The implementation also applies the same sign conventions used in ordinary MuSig2 / BIP 340:
- if the aggregate key $\tilde{X}$ was marked odd, negate the key contribution
- if the effective nonce $R$ was marked odd, negate the nonce contribution

So the implementation computes:

$$
s_i := g_{\text{key}} \cdot \check{c} \cdot x_i
\;+\;
g_{\text{nonce}} \cdot \sum_{j=1}^{\nu} r_{i,j}\check{b}^{j-1}
\pmod n
$$

where:
- $g_{\text{key}} = -1$ if `key_negated` is true, else $1$
- $g_{\text{nonce}} = -1$ if `nonce_negated` is true, else $1$

**Code:** `nested_sign(...)` in `nested_musig2/nested_sign.py`
```python
session = transcript.session
b_check = transcript.nonce_factor()
c_check = transcript.challenge_factor()
sec_nonces = signer_nonce.get_sec_nonces()

key_part = c_check * signer_privkey
if session.key_negated:
    key_part = -key_part

nonce_part = Scalar(0)
b_power = Scalar(1)
for j in range(NU):
    nonce_part = nonce_part + sec_nonces[j] * b_power
    b_power = b_power * b_check

if session.nonce_negated:
    nonce_part = -nonce_part

return key_part + nonce_part
```

**Why this is different from ordinary MuSig2?** In ordinary MuSig2, the signer uses:
- the top-level nonce binding $b$
- the top-level challenge $c$
- its coefficient $a_i$ inside one keyset

In Nested MuSig2, a leaf signer instead uses:
- $\check{b}$, which includes every nested binding on its path
- $\check{c}$, which includes every key aggregation coefficient on its path

So the leaf’s signature share is bound not only to the top-level session, but also to the exact subgroup structure it belongs to.

**Nonce consumption:** The leaf signer’s secret nonce object is single-use.

When `nested_sign(...)` calls:
```python
sec_nonces = signer_nonce.get_sec_nonces()
```

the secret nonce scalars are consumed and zeroed out inside the `SignerNonce` object.

This prevents accidental nonce reuse.

**Output:** The output is one scalar partial signature $s_i$ for one leaf signer. All such leaf partial signatures are later aggregated into the final Schnorr signature.

---

## Algorithm 8: Nested Partial Signature Verification

Before aggregating leaf partial signatures into the final signature, the implementation verifies each nested partial signature against the signer’s explicit transcript and public nonce commitments.

This is the nested analogue of ordinary MuSig2 partial signature verification.

**Inputs:** For one leaf signer, verification uses:
- the validated `NestedSigningTranscript`
- the signer’s public nonce tuple $(R_{i,1}, \ldots, R_{i,\nu})$
- the claimed partial signature $s_i$

From the transcript, the verifier derives:
- the leaf public key $X_i$
- the effective nonce binding $\check{b}$
- the effective challenge $\check{c}$

First compute the signer’s effective public nonce:

$$
\hat{R}_i := \sum_{j=1}^{\nu} \check{b}^{j-1} R_{i,j}
$$

For the current implementation, $\nu = 2$, this becomes:

$$
\hat{R}_i := R_{i,1} + \check{b}R_{i,2}
$$

If the session indicates that the aggregate nonce was negated, negate $\hat{R}_i$.

Then compute the signer’s effective key term:

$$
\check{c} \cdot X_i
$$

If the session indicates that the aggregate key was negated, negate this key term.

Finally, verify:

$$
s_i G \stackrel{?}{=} \hat{R}_i + \check{c}X_i
$$

with the appropriate BIP 340 sign adjustments already applied.

**Code:** `verify_nested_partial_sig(...)` in `nested_musig2/nested_sign.py`

```python
b_check = transcript.nonce_factor()
c_check = transcript.challenge_factor()

R_hat_i = GE()
b_power = Scalar(1)
for j in range(NU):
    R_hat_i += int(b_power) * signer_pub_nonces[j]
    b_power = b_power * b_check

if session.nonce_negated:
    R_hat_i = -R_hat_i

key_point = int(c_check) * signer_pubkey
if session.key_negated:
    key_point = -key_point

lhs = int(partial_sig) * G
rhs = R_hat_i + key_point
return lhs == rhs
```

Before checking the equation, the implementation validates:
- the signer’s public nonce tuple has length $\nu$
- no nonce point is the point at infinity
- the leaf public key is not infinity

If any of these checks fail, verification returns `False`.

**Why this matters?** This step prevents malformed or inconsistent leaf signature shares from being aggregated into the final signature.

In particular, verification is sensitive to:
- the signer’s public nonce tuple
- the signer’s exact path through the tree
- the nested nonce bindings on that path
- the key aggregation coefficients on that path

So if any of those are wrong, the partial signature check fails.

**Nested interpretation:** This verification step is what makes the transcript meaningful.

A leaf partial signature is not valid “in general.” It is valid only for:
- one root session
- one specific leaf public key
- one specific path through the nested tree
- one specific sequence of nested bindings

That is why malformed path data or wrong nested bindings cause verification to fail in the tests.

**Output:** For each leaf signer, the result is either:
- valid partial signature
- invalid partial signature

Only valid partial signatures are included in the final aggregation.

---

## Algorithm 9: Final Signature Aggregation

After all leaf partial signatures have been computed and verified, the final Schnorr signature is obtained by summing those partial signature scalars.

The final nonce point is the top-level session nonce $R$ computed during session creation.

So the final signature is:

$$
\sigma = (R, s)
$$

where

$$
s := \sum_i s_i \pmod n
$$

and the sum is taken over all leaf partial signatures.

> **PartialSigAgg($s_1, \ldots, s_N$):**
> - Compute
>   $s := \sum_{i=1}^{N} s_i \pmod n$
> - Return
>   $\sigma := (R, s)$
>   where $R$ is the effective aggregate nonce from the root session

**Code:** `aggregate_partial_sigs(...)` in `musig2/sign.py`
```python
s = Scalar(0)
for s_i in partial_sigs:
    s = s + s_i
return session.R, s
```

**Why this works?** Each leaf partial signature already includes:
- the signer’s private-key contribution
- the nonce contribution
- the path-dependent nested factors
- the BIP 340 sign adjustments

So once each partial signature has been verified individually, the final aggregation step is just scalar addition.

No extra nested processing happens here.

The result is an ordinary Schnorr signature under the root aggregate public key.

**Nested interpretation:** Even though the signing process was recursive internally, the final output is indistinguishable from a standard MuSig2-style Schnorr signature.

A verifier only sees:
- the root aggregate public key $\tilde{X}$
- the final nonce point $R$
- the final scalar $s$

The verifier does not learn:
- how many nested subgroups existed
- how deep the tree was
- which leaves belonged to which subgroup

This is the privacy property of the nested construction.

The final signature is verified as an ordinary BIP 340 Schnorr signature:

$$
sG \stackrel{?}{=} R + c\tilde{X}
$$

with the standard BIP 340 x-only/even-y conventions.

In the implementation, the nested signing flow is tested against:
- the project’s Schnorr verifier
- the library BIP 340 verifier

This confirms that the final output is a standard Schnorr signature, not a special nested-only format.

**Output:** The complete nested signing flow returns:
- $R$: the effective top-level aggregate nonce
- $s$: the aggregate signature scalar
- $\tilde{X}$: the root aggregate public key

**Code:** `run_nested_musig2(...)` in `nested_musig2/nested_sign.py`

```python
R, s = aggregate_partial_sigs(session, partial_sigs)
return R, s, root_cache.agg_pk
```

---