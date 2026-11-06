"""
PQ smart accounts (contracts/accounts/PQSmartAccount.sol, docs/PQ_SMART_ACCOUNTS.md), run in the
QRDX EVM: a contract account owned by an ML-DSA-65 key, checked by the 0x…0500 precompile, with
session keys, ERC-1271 and guardian recovery; and the precompile table under
``evm_standard_precompiles`` (0x09 is Ethereum's BLAKE2F again).
"""

import json
from pathlib import Path

from eth_abi import decode, encode
from eth_utils import keccak
from test_evm_world import ALICE, chain  # noqa: F401  (fixture)

from qrdx.contracts.evm_world import (
    BLAKE2F_ADDRESS,
    BLAKE3_ADDRESS,
    PQ_VERIFY_ADDRESS,
    EvmWorld,
    run,
)
from qrdx.contracts.native_token_evm import EvmSection, TokenWorld
from qrdx.crypto.pq.dilithium import PQPrivateKey

ART = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts/accounts/PQSmartAccount.artifact.json").read_text()
)
BOB = bytes.fromhex("b0" * 20)
DAY = 86_400
CALLS = "(address,uint256,bytes)[]"


def _sel(sig):
    return keccak(text=sig)[:4]


async def _tx(chain, sender, to, data=b"", value=0, gas=3_000_000, timestamp=1_000):
    """A transaction at block time ``timestamp`` (the helper's own runs at time 1)."""
    chain.height += 1
    chain.sm.reset_cache()
    section = EvmSection()
    snap = await chain.sm.snapshot()
    world = EvmWorld(chain.sm, tokens=TokenWorld(chain.db, section))
    r = await run(world, lambda: chain.ex.execute(
        sender, to, value, data, gas, 0, world=world, block_number=chain.height,
        timestamp=timestamp), preload=[sender, to])
    if not r.success:
        await chain.sm.revert(snap)
    await chain.sm.commit(chain.height)
    await chain.db.connection.commit()
    return r


async def _call(chain, to, data):
    r = await chain.call(to, data)
    assert r.success, r.error
    return bytes(r.output)


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.pub = self.key.public_key.to_bytes()
        self.hash = keccak(self.pub)

    def sign(self, digest: bytes) -> bytes:
        return self.key.sign(digest).to_bytes()


async def _setup(chain):
    impl = ART["contracts"]["PQSmartAccount"]
    fac = ART["contracts"]["PQAccountFactory"]
    r = await _tx(chain, ALICE, None, bytes.fromhex(impl["bytecode"][2:]))
    assert r.success, r.error
    implementation = r.created_address
    r = await _tx(chain, ALICE, None, bytes.fromhex(fac["bytecode"][2:]) + encode(["address"], [implementation]))
    assert r.success, r.error
    return implementation, r.created_address


async def _account(chain, owner: Key, salt=b"\x00" * 32):
    _impl, factory = await _setup(chain)
    (predicted,) = decode(["address"], await _call(
        chain, factory, _sel("predict(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner.hash, salt])))
    r = await _tx(chain, ALICE, factory, _sel("create(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner.hash, salt]))
    assert r.success, r.error
    account = bytes.fromhex(predicted[2:])
    await chain.fund(account, 10**21)
    return factory, account


async def _execute(chain, account, key: Key, calls, nonce=None, valid_until=0, timestamp=1_000,
                   sign_with=None):
    if nonce is None:
        (nonce,) = decode(["uint256"], await _call(chain, account, _sel("nonce()")))
    (digest,) = decode(["bytes32"], await _call(
        chain, account, _sel(f"executeHash({CALLS},uint256,uint256)") + encode([CALLS, "uint256", "uint256"], [calls, nonce, valid_until])))
    sig = (sign_with or key).sign(digest)
    data = _sel(f"execute({CALLS},uint256,uint256,bytes,bytes)") + encode(
        [CALLS, "uint256", "uint256", "bytes", "bytes"], [calls, nonce, valid_until, key.pub, sig])
    return await _tx(chain, ALICE, account, data, timestamp=timestamp)


async def _balance(chain, who: bytes) -> int:
    return await chain.sm.get_balance("0x" + who.hex())


# ── the account ───────────────────────────────────────────────────────────────────────


async def test_the_factory_makes_an_initialized_account_where_it_said(chain):
    owner = Key()
    factory, account = await _account(chain, owner)
    (key,) = decode(["bytes32"], await _call(chain, account, _sel("ownerKey()")))
    assert key == owner.hash
    again = await _tx(chain, ALICE, account, _sel("initialize(bytes32)") + encode(["bytes32"], [Key().hash]))
    assert not again.success                                   # initialized once
    dup = await _tx(chain, ALICE, factory, _sel("create(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner.hash, b"\x00" * 32]))
    assert not dup.success                                     # one account per (key, salt)


async def test_the_owner_key_runs_calls_once_and_nothing_else_does(chain):
    owner = Key()
    _factory, account = await _account(chain, owner)
    send = [(("0x" + BOB.hex()), 10**18, b"")]
    r = await _execute(chain, account, owner, send)
    assert r.success, r.error
    assert await _balance(chain, BOB) == 10**18
    replay = await _execute(chain, account, owner, send, nonce=0)
    assert not replay.success                                  # the nonce moved on
    stranger = Key()
    assert not (await _execute(chain, account, stranger, send)).success
    forged = await _execute(chain, account, owner, send, sign_with=stranger)  # owner's key, other's sig
    assert not forged.success
    expired = await _execute(chain, account, owner, send, valid_until=500, timestamp=1_000)
    assert not expired.success
    assert await _balance(chain, BOB) == 10**18


async def test_applications_can_check_the_owners_signature(chain):
    owner = Key()
    _factory, account = await _account(chain, owner)
    message = keccak(text="sign in to app.example")
    (chain_id,) = decode(["uint256"], encode(["uint256"], [chain.ex.chain_id if hasattr(chain.ex, "chain_id") else 0]))
    probe = _sel("isValidSignature(bytes32,bytes)")

    async def check(key: Key, chain_id_guess):
        bound = keccak(encode(["bytes32", "uint256", "address", "bytes32"],
                              [keccak(text="QRDX PQSmartAccount v1"), chain_id_guess, "0x" + account.hex(), message]))
        sig = encode(["bytes", "bytes"], [key.pub, key.sign(bound)])
        return (await _call(chain, account, probe + encode(["bytes32", "bytes"], [message, sig])))[:4]

    from qrdx.constants import CHAIN_ID

    assert await check(owner, CHAIN_ID) == bytes.fromhex("1626ba7e")
    assert await check(Key(), CHAIN_ID) != bytes.fromhex("1626ba7e")
    assert await check(owner, CHAIN_ID + 1) != bytes.fromhex("1626ba7e")  # bound to this chain


async def test_a_session_key_spends_within_its_limit_and_never_administers(chain):
    owner, session = Key(), Key()
    _factory, account = await _account(chain, owner)
    setup = [("0x" + account.hex(), 0, _sel("setSessionKey(bytes32,uint64,uint128)")
              + encode(["bytes32", "uint64", "uint128"], [session.hash, 200_000, 3 * 10**17]))]
    assert (await _execute(chain, account, owner, setup)).success
    pay = [("0x" + BOB.hex(), 2 * 10**17, b"")]
    assert (await _execute(chain, account, session, pay)).success
    assert not (await _execute(chain, account, session, pay)).success          # 0.4 > 0.3 a day
    tomorrow = (await _execute(chain, account, session, pay, timestamp=1_000 + DAY))
    assert tomorrow.success                                                      # a new day
    takeover = [("0x" + account.hex(), 0, _sel("setOwnerKey(bytes32)") + encode(["bytes32"], [session.hash]))]
    assert not (await _execute(chain, account, session, takeover)).success
    late = await _execute(chain, account, session, [("0x" + BOB.hex(), 1, b"")], timestamp=300_000)
    assert not late.success                                                      # expired
    assert await _balance(chain, BOB) == 4 * 10**17


async def test_guardians_replace_a_lost_key_after_the_delay_unless_the_owner_cancels(chain):
    owner, new_owner = Key(), Key()
    _factory, account = await _account(chain, owner)
    g1, g2 = bytes.fromhex("91" * 20), bytes.fromhex("92" * 20)
    for g in (g1, g2):
        await chain.fund(g, 10**20)
    guard = [("0x" + account.hex(), 0, _sel("setGuardians(address[],uint256,uint256)")
              + encode(["address[]", "uint256", "uint256"], [["0x" + g1.hex(), "0x" + g2.hex()], 2, DAY]))]
    assert (await _execute(chain, account, owner, guard)).success
    approve = _sel("approveRecovery(bytes32)") + encode(["bytes32"], [new_owner.hash])
    assert (await _tx(chain, g1, account, approve, timestamp=2_000)).success
    assert not (await _tx(chain, ALICE, account, approve, timestamp=2_000)).success  # not a guardian
    assert (await _tx(chain, g2, account, approve, timestamp=2_000)).success
    complete = _sel("completeRecovery()")
    assert not (await _tx(chain, ALICE, account, complete, timestamp=2_000 + DAY - 1)).success
    # The owner, still holding its key, cancels in time…
    cancel = [("0x" + account.hex(), 0, _sel("cancelRecovery()"))]
    assert (await _execute(chain, account, owner, cancel, timestamp=2_500)).success
    assert not (await _tx(chain, ALICE, account, complete, timestamp=2_000 + DAY)).success
    # …and when it has lost it, the guardians' key takes over after the delay.
    assert (await _tx(chain, g1, account, approve, timestamp=3_000)).success
    assert (await _tx(chain, g2, account, approve, timestamp=3_000)).success
    assert (await _tx(chain, ALICE, account, complete, timestamp=3_000 + DAY)).success
    send = [("0x" + BOB.hex(), 1, b"")]
    assert not (await _execute(chain, account, owner, send, timestamp=4_000 + DAY)).success
    assert (await _execute(chain, account, new_owner, send, timestamp=4_000 + DAY)).success


# ── the precompile table ──────────────────────────────────────────────────────────────


async def test_the_precompiles_sit_where_ethereum_expects(chain):
    key = Key()
    digest = keccak(text="m")
    ok = await chain.call(PQ_VERIFY_ADDRESS, digest + key.pub + key.sign(digest))
    assert ok.success and bytes(ok.output) == b"\x01"
    bad = await chain.call(PQ_VERIFY_ADDRESS, digest + key.pub + Key().sign(digest))
    assert bytes(bad.output) == b"\x00"
    # 0x09 is BLAKE2F again (EIP-152): one compression of "abc" from BLAKE2b-512's initial
    # state gives BLAKE2b-512("abc").
    import hashlib
    import struct

    iv = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
          0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179]
    h = [iv[0] ^ 0x01010040] + iv[1:]
    vector = (struct.pack(">I", 12) + struct.pack("<8Q", *h) + b"abc".ljust(128, b"\x00")
              + struct.pack("<2Q", 3, 0) + b"\x01")
    blake = await chain.call(BLAKE2F_ADDRESS, vector)
    assert blake.success and bytes(blake.output) == hashlib.blake2b(b"abc").digest()
    b3 = await chain.call(BLAKE3_ADDRESS, b"abc")
    assert b3.success and len(bytes(b3.output)) == 32
