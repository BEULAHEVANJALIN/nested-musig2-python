# Nested MuSig in Bark

This note explains how the nested MuSig model in this repository can be used to describe a Bark-style signing round.

### What "Bark" means in this note
For the purposes of this note, the only Bark-specific idea we need is the following:
- a Bark round can require multiple node-level signatures
- each such node produces a standard BIP340 Schnorr signature
- the set of participants contributing to a node-level signature can vary from
  node to node

The important distinction is:
- the Bark tree describes which transaction nodes need signatures
- nested MuSig describes how the participant keyset inside one such node can be structured recursively

So this note is not introducing a new transaction tree. It is showing how the MuSig participant set inside a Bark node can be reorganized using nested MuSig.

### The setting
Assume one Bark round has:
- users `A, B, C, D, E, F`
- a fixed server cosigner `S`
- two external cosigners `K, L`

In this example:
- `S` is a server key that appears in multiple node-level signing sets
- `K, L` are external cosigners that also appear across nodes
- different user subsets may appear together at different nodes depending on the transaction structure being signed

If every node-level MuSig is treated as flat, then a root-facing participant set can look like:
- `A + B + C + D + E + F + S + K + L`

and an intermediate participant set on `F`'s side can look like:
- `E + F + S + K + L`

### What nesting changes
Nested MuSig does not reduce the number of Bark signatures.

Instead, it changes the composition of the MuSig participant sets inside those signatures. The goal is to replace large flat signer lists with subgroup aggregate keys wherever the transaction structure allows that.

One useful decomposition is:
- `Group_ABCD = (A + B + C + D)`
- `Group_EF   = (E + F)`
- `Group_KL   = (K + L)`

Then the root-facing MuSig becomes:
- `Group_ABCD + Group_EF + S + Group_KL`

instead of:
- `A + B + C + D + E + F + S + K + L`

So the Bark node still produces one BIP340 signature, but its top-level MuSig participants drop from a large flat list to four top-level keys:
- `Group_ABCD`
- `Group_EF`
- `S`
- `Group_KL`

This is the main cryptographic effect of introducing nesting in this setting.

### What this means for user F
Consider user `F`.

In the flat version, `F` conceptually participates in a root-facing signing set that expands all the way to:
- `A + B + C + D + E + F + S + K + L`

In the nested version, `F` instead participates through the branch:
- `Group_EF` inside the root keyset
- `F` inside `Group_EF`

So the root-facing signing set is described using subgroup aggregate keys rather than by flattening all users into one level.

That is the structural reason nested MuSig can be attractive in Bark: it lets a large node-level MuSig be expressed recursively, while still producing a normal BIP340 signature at the end.

### What the current repository models
In the current implementation, a leaf signer's nested transcript stores:
- the root signing session
- the parent keyset at each level
- the signer's child-node key at each level
- the nested nonce bindings on the path

For user `F` in the Bark-style example above, the path is:
- `Group_EF` inside the root keyset
- `F` inside `Group_EF`

So the transcript can be written as:
- path_caches = [KeyAgg(Group_ABCD, Group_EF, S, Group_KL), KeyAgg(E, F)]
- path_pubkeys = [Group_EF, F]
- nested_nonce_bindings = [\bar{b}_{Group_EF}]

This already captures the main nested-MuSig benefit at the root level:
- the root path uses subgroup aggregate keys `Group_ABCD` and `Group_KL`
- it does not flatten all nine leaf/global keys into the root-facing signer path

### A possible Bark-specific witness optimization
If Bark wants to minimize what an individual participant stores or receives, a more specialized branch witness format could be introduced later.

For user `F`, that optimized witness could conceptually store:
- the fixed server key `S`
- the global cosigner aggregate key `Group_KL`
- the local neighbour key `E`
- the sibling subgroup aggregate key `Group_ABCD`

instead of full parent cache objects.

That is not the exact transcript format implemented in this repository today, but it is consistent with the same nested MuSig structure.

### Test coverage in this repository
The Bark-style nested root composition is exercised by:
- `tests/test_nested.py::test_bark_style_root_uses_nested_subgroup_keys`

That test checks that:
- the root aggregate key is built from subgroup aggregate keys plus the fixed
  cosigners
- user `F` signs successfully through the nested branch `Group_EF -> F`
- the path-dependent nested nonce factor is derived correctly for that branch