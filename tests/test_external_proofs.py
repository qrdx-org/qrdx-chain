"""
verifyExternalProof (0x0201, qrdx/contracts/external_proof_evm.py): an account — and a storage
slot of it — on a bridged EVM chain, proven inside a QRDX contract call against a finalized head
the validators attested (docs/BRIDGE.md "Chain heads"). Real Merkle-Patricia proofs, as
``eth_getProof`` returns them; forged or unattested ones prove nothing.
"""
import rlp
from eth_utils import keccak
from test_bridge import CHAIN, Key, _genesis
from test_evm_world import ALICE, Chain, chain  # noqa: F401  (fixture)
from trie import HexaryTrie

from qrdx.contracts.evm_world import EXTERNAL_PROOF_ADDRESS
from qrdx.contracts.external_proof_evm import EMPTY_CODE, EMPTY_TRIE, encode
from qrdx.exchange import ExchangeOpType, ExchangeStateManager

LOCKBOX = bytes.fromhex("10" * 20)
SLOT = (7).to_bytes(32, "big")


def _world():
    """A source chain's state: some accounts, and a lockbox contract with storage."""
    storage = HexaryTrie(db={})
    storage[keccak(SLOT)] = rlp.encode(123_456)
    accounts = HexaryTrie(db={})
    for i in range(1, 40):
        accounts[keccak(bytes([i]) * 20)] = rlp.encode([i, 10 ** 15 * i, EMPTY_TRIE, EMPTY_CODE])
    accounts[keccak(LOCKBOX)] = rlp.encode([1, 5 * 10 ** 18, storage.root_hash, b"\xc0" * 32])
    return accounts, storage


def _proof(trie, key):
    return [rlp.encode(n) for n in trie.get_proof(keccak(key))]


_COMMITTEE = []


async def _attest(state_root, height=1000):
    mgr = ExchangeStateManager.get_instance()
    if not _COMMITTEE or mgr.oracle_committee is None:
        _COMMITTEE[:] = [Key(), Key(), Key()]
        v1, v2, v3 = _COMMITTEE
        mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    v1, _v2, v3 = _COMMITTEE
    head = {"chain": CHAIN, "height": height, "hash": "0x" + "ab" * 32,
            "state_root": "0x" + state_root.hex(), "timestamp": 1_800_000_000}
    for who in (v1, v3):
        r = mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"heads": [head]}))
        assert r.success, r.error
    assert mgr.bridge.head(CHAIN).height == height


async def _call(chain, data):
    r = await chain.tx(ALICE, EXTERNAL_PROOF_ADDRESS, data)
    assert r.success
    return r.output


async def test_an_account_and_its_slot_are_proven_against_an_attested_head(chain):
    accounts, storage = _world()
    await _attest(accounts.root_hash)
    out = await _call(chain, encode(CHAIN, 1000, LOCKBOX, _proof(accounts, LOCKBOX),
                                    SLOT, _proof(storage, SLOT)))
    assert out[0] == 1
    assert int.from_bytes(out[1:33], "big") == 1                       # nonce
    assert int.from_bytes(out[33:65], "big") == 5 * 10 ** 18           # balance
    assert out[65:97] == storage.root_hash
    assert int.from_bytes(out[129:161], "big") == 123_456              # the slot


async def test_absence_is_proven_as_zeros(chain):
    accounts, _storage = _world()
    await _attest(accounts.root_hash)
    nobody = bytes.fromhex("ee" * 20)
    out = await _call(chain, encode(CHAIN, 1000, nobody, _proof(accounts, nobody)))
    assert out == b"\x01" + bytes(64) + EMPTY_TRIE + EMPTY_CODE


async def test_forged_or_unattested_proofs_prove_nothing(chain):
    accounts, storage = _world()
    await _attest(accounts.root_hash)
    good = _proof(accounts, LOCKBOX)
    forged = good[:-1] + [rlp.encode([b"\x20" + keccak(LOCKBOX)[1:],
                                      rlp.encode([1, 10 ** 30, EMPTY_TRIE, EMPTY_CODE])])]
    assert await _call(chain, encode(CHAIN, 1000, LOCKBOX, forged)) == b"\x00"
    assert await _call(chain, encode(CHAIN, 999, LOCKBOX, good)) == b"\x00"      # not attested
    assert await _call(chain, encode(CHAIN + 1, 1000, LOCKBOX, good)) == b"\x00"
    # Another slot with slot 7's path: in a one-entry trie that path proves slot 8 absent — a
    # true statement, so it holds, as zero. A tampered storage node proves nothing.
    out = await _call(chain, encode(CHAIN, 1000, LOCKBOX, good, (8).to_bytes(32, "big"),
                                    _proof(storage, SLOT)))
    assert out[0] == 1 and out[-32:] == bytes(32)
    tampered = [rlp.encode([b"\x20" + keccak(SLOT)[1:], rlp.encode(999)])]
    out = await _call(chain, encode(CHAIN, 1000, LOCKBOX, good, SLOT, tampered))
    assert out == b"\x00"
    assert await _call(chain, b"\x00\x01") == b"\x00"                  # malformed


async def test_a_recent_head_still_proves_after_a_newer_one(chain):
    old_accounts, _ = _world()
    await _attest(old_accounts.root_hash, height=1000)
    newer = HexaryTrie(db={})
    newer[keccak(LOCKBOX)] = rlp.encode([2, 1, EMPTY_TRIE, EMPTY_CODE])
    await _attest(newer.root_hash, height=1001)
    out = await _call(chain, encode(CHAIN, 1000, LOCKBOX, _proof(old_accounts, LOCKBOX)))
    assert out[0] == 1 and int.from_bytes(out[33:65], "big") == 5 * 10 ** 18
