"""
The compressed sparse Merkle tree (qrdx/crypto/smt.py): its root is a function of its entries
alone, whatever the order and batching of the updates that made them; proofs of membership and
non-membership verify, and nothing else does.
"""
import asyncio
import random

import pytest

from qrdx.crypto import smt


class Store:
    def __init__(self):
        self.nodes = {}
        self.version = 0
        self.root = None

    async def load(self, nkey):
        return self.nodes.get(nkey)

    def apply(self, changes):
        self.version += 1
        tree = smt.Tree(self.load, self.version)
        self.root = asyncio.run(tree.update(self.root, sorted(changes.items())))
        self.nodes.update(tree.writes)
        return tree

    def prove(self, key, root=None):
        tree = smt.Tree(self.load, self.version)
        siblings, terminal, _payload = asyncio.run(
            tree.prove(self.root if root is None else root, key))
        return siblings, terminal


def _key(i):
    return smt.key_of(i.to_bytes(4, "big"))


def _val(i, v):
    return f"{i}:{v}".encode()  # an entry's payload


def _scratch(entries):
    s = Store()
    s.apply(dict(entries))
    return smt.root_hash(s.root)


@pytest.mark.parametrize("seed", range(6))
def test_the_root_is_a_function_of_the_entries_alone(seed):
    rng = random.Random(seed)
    s, live = Store(), {}
    for _ in range(30):
        batch = {}
        for _ in range(rng.randint(1, 12)):
            k = _key(rng.randrange(60))
            if rng.random() < 0.3 and live:
                k = rng.choice(sorted(live))
                batch[k] = None
            else:
                batch[k] = _val(rng.randrange(60), rng.randrange(1000))
        s.apply(batch)
        for k, v in batch.items():
            if v is None:
                live.pop(k, None)
            else:
                live[k] = v
        assert smt.root_hash(s.root) == _scratch(live)


def test_proofs_verify_members_and_non_members_and_nothing_else():
    s = Store()
    entries = {_key(i): _val(i, 0) for i in range(40)}
    s.apply(entries)
    root = smt.root_hash(s.root)
    for k, v in entries.items():
        siblings, terminal = s.prove(k)
        assert smt.verify(root, k, smt.value_hash(v), siblings, terminal)
        assert not smt.verify(root, k, smt.value_hash(b"x"), siblings, terminal)  # wrong value
        assert not smt.verify(root, k, None, siblings, terminal)            # "absent": no
    for i in range(1000, 1040):
        k = _key(i)
        siblings, terminal = s.prove(k)
        assert smt.verify(root, k, None, siblings, terminal)
        assert not smt.verify(root, k, smt.value_hash(_val(i, 0)), siblings, terminal)
    k = _key(3)
    siblings, terminal = s.prove(k)
    v = smt.value_hash(entries[k])
    assert not smt.verify(root, k, v, siblings[:-1], terminal)               # truncated
    assert not smt.verify(smt.EMPTY, k, v, siblings, terminal)


def test_an_old_version_still_proves_what_it_held():
    s = Store()
    s.apply({_key(1): _val(1, 1), _key(2): _val(2, 1)})
    old_root = s.root
    s.apply({_key(1): _val(1, 2), _key(3): _val(3, 1)})
    siblings, terminal = s.prove(_key(1), root=old_root)
    assert smt.verify(old_root.hash, _key(1), smt.value_hash(_val(1, 1)), siblings, terminal)


def test_empty_and_single_entry_trees():
    s = Store()
    assert smt.root_hash(s.root) == smt.EMPTY
    s.apply({_key(1): _val(1, 1)})
    assert s.root.leaf and s.root.hash == smt.leaf_hash(_key(1), smt.value_hash(_val(1, 1)))
    siblings, terminal = s.prove(_key(2))
    assert siblings == [] and smt.verify(s.root.hash, _key(2), None, siblings, terminal)
    s.apply({_key(1): None})
    assert s.root is None


def test_a_removal_collapses_the_lone_leaf_upward():
    s = Store()
    s.apply({_key(i): _val(i, 0) for i in range(8)})
    s.apply({_key(i): None for i in range(1, 8)})
    assert s.root.leaf and smt.root_hash(s.root) == _scratch({_key(0): _val(0, 0)})


def test_replaced_nodes_are_reported_stale_and_new_ones_written():
    s = Store()
    s.apply({_key(i): _val(i, 0) for i in range(16)})
    tree = s.apply({_key(5): _val(5, 1)})
    assert tree.stale and all(not k.startswith(f"{tree.version}:") for k in tree.stale)
    assert tree.writes and all(k.startswith(f"{tree.version}:") for k in tree.writes)
