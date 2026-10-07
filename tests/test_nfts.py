"""
Native NFTs (qrdx/exchange/nfts.py, docs/NATIVE_TOKENS.md §8): collections with metadata,
royalties and update / mint authorities; supply-1 members owned, approved, transferred and
burned through the exchange's NFT_* operations and through the EVM, where every collection is
an ERC-721 (qrdx/contracts/nft_evm.py) — with the registry committed in the exchange root,
reverted with a block, and rebuilt identically from the chain.
"""
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.contracts.nft_evm import (
    APPROVAL_FOR_ALL_TOPIC, ON_RECEIVED, SIGNATURES, _selector)
from qrdx.crypto.account_id import to_account_id
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction, views
from qrdx.exchange import block_processor as BP

D = Decimal
ARTIST, ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abcd")
_nonces = {}


def _tx(sender, op, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=10_000_000, gas_price=10**9)


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def run(m, sender, op, **params):
    return m.process_transaction(_tx(sender, op, **params))


def ok(m, sender, op, **params):
    r = run(m, sender, op, **params)
    assert r.success, r.error
    return r


def collection(m, **extra):
    params = dict(name="Quantum Art", symbol="QART", uri="ipfs://collection", royalty_bps=500)
    params.update(extra)
    return ok(m, ARTIST, Op.NFT_CREATE_COLLECTION, **params).data["collection"]


def owner(m, c, i):
    return views.nft(m, c, i)["owner"]


# ── collections and minting ──────────────────────────────────────────────────

def test_a_collection_and_its_members(mgr):
    c = collection(mgr, max_supply=3)
    info = views.nft_collection(mgr, c)
    assert (info["update_authority"], info["mint_authority"], info["royalty_recipient"]) == \
        (ARTIST, ARTIST, ARTIST)
    r = run(mgr, ALICE, Op.NFT_MINT, collection=c, uri="ipfs://1")
    assert not r.success and "mint authority" in r.error
    assert ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE, uri="ipfs://1",
              name="First").data["token_id"] == "1"
    assert ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE, token_id="10").data["token_id"] == "10"
    assert ok(mgr, ARTIST, Op.NFT_MINT, collection=c).data["token_id"] == "11"   # after the max id
    r = run(mgr, ARTIST, Op.NFT_MINT, collection=c)
    assert not r.success and "capped at 3" in r.error
    r = run(mgr, ARTIST, Op.NFT_MINT, collection=collection(mgr, symbol="TWO"), token_id="0x0a")
    assert r.success and r.data["token_id"] == "10"
    n = views.nft(mgr, c, "1")
    assert (n["owner"], n["uri"], n["name"], n["royalty_bps"]) == (ALICE, "ipfs://1", "First", 500)
    assert views.nft_collection(mgr, c)["supply"] == 3
    # an owner's NFTs, under either form of its address
    mine = views.nfts_of(mgr, to_account_id(ALICE))
    assert [(x["collection"], x["token_id"]) for x in mine] == [(c, "1"), (c, "10")]
    assert views.nfts_of(mgr, ALICE, c) == mine


def test_transfers_by_the_owner_its_approved_account_and_its_operators(mgr):
    c = collection(mgr)
    ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE)
    ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE)
    r = run(mgr, BOB, Op.NFT_TRANSFER, collection=c, token_id=1, to=BOB, **{"from": ALICE})
    assert not r.success and "not approved" in r.error
    ok(mgr, ALICE, Op.NFT_APPROVE, collection=c, token_id=1, spender=BOB)
    assert views.nft(mgr, c, 1)["approved"] == BOB
    ok(mgr, BOB, Op.NFT_TRANSFER, collection=c, token_id=1, to=CAROL, **{"from": ALICE})
    assert owner(mgr, c, 1) == CAROL and views.nft(mgr, c, 1)["approved"] is None  # cleared
    ok(mgr, ALICE, Op.NFT_SET_APPROVAL_FOR_ALL, collection=c, operator=BOB)
    assert views.nft_operator(mgr, c, ALICE, BOB)
    r = ok(mgr, BOB, Op.NFT_TRANSFER, collection=c, token_id=2, to=BOB, memo="gift",
           **{"from": ALICE})
    assert r.data["memo"] == "gift" and owner(mgr, c, 2) == BOB
    r = run(mgr, ALICE, Op.NFT_TRANSFER, collection=c, token_id=2, to=ALICE)
    assert not r.success and "not owned" in r.error
    ok(mgr, ALICE, Op.NFT_SET_APPROVAL_FOR_ALL, collection=c, operator=BOB, approved=False)
    assert not views.nft_operator(mgr, c, ALICE, BOB)


def test_burning_and_a_soulbound_collection(mgr):
    c = collection(mgr, non_transferable=True)
    ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE)
    r = run(mgr, ALICE, Op.NFT_TRANSFER, collection=c, token_id=1, to=BOB)
    assert not r.success and "soulbound" in r.error
    assert not run(mgr, BOB, Op.NFT_BURN, collection=c, token_id=1).success
    ok(mgr, ALICE, Op.NFT_BURN, collection=c, token_id=1)
    assert views.nft(mgr, c, 1) is None and views.nfts_of(mgr, ALICE) == []
    info = views.nft_collection(mgr, c)
    assert (info["supply"], info["minted"], info["burned"]) == (0, 1, 1)


def test_metadata_updates_and_authorities(mgr):
    c = collection(mgr)
    ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE, uri="ipfs://old")
    assert not run(mgr, ALICE, Op.NFT_UPDATE, collection=c, uri="x").success
    ok(mgr, ARTIST, Op.NFT_UPDATE, collection=c, uri="ipfs://new", royalty_bps=250)
    ok(mgr, ARTIST, Op.NFT_UPDATE, collection=c, token_id=1, uri="ipfs://revealed", name="One")
    n = views.nft(mgr, c, 1)
    assert (n["uri"], n["name"], n["royalty_bps"]) == ("ipfs://revealed", "One", 250)
    ok(mgr, ARTIST, Op.NFT_SET_AUTHORITY, collection=c, authority="update", new_authority="")
    r = run(mgr, ARTIST, Op.NFT_UPDATE, collection=c, uri="y")
    assert not r.success and "immutable" in r.error
    ok(mgr, ARTIST, Op.NFT_SET_AUTHORITY, collection=c, authority="mint", new_authority=BOB)
    assert not run(mgr, ARTIST, Op.NFT_MINT, collection=c).success
    ok(mgr, BOB, Op.NFT_MINT, collection=c)


def test_the_registry_is_committed_only_once_used_and_reverts(mgr):
    root = mgr.compute_state_root()
    hasher_before = mgr.nfts.canonical()
    assert hasher_before == {"collections": {}, "items": [], "operators": []}
    snap = mgr.take_snapshot()
    c = collection(mgr)
    ok(mgr, ARTIST, Op.NFT_MINT, collection=c, to=ALICE)
    assert mgr.compute_state_root() != root
    mgr._restore_snapshot(snap)
    assert not mgr.nfts.collections and mgr.nfts.by_owner == {}


# ── forward ≡ rebuild ───────────────────────────────────────────────────────

async def test_forward_and_rebuild_agree_on_nfts():
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.exchange import encode_exchange_txs
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        a1, a2 = k1.public_key.to_address(), k2.public_key.to_address()
        nonces = {a1: 0, a2: 0}

        def tx(key, op, **params):
            addr = key.public_key.to_address()
            t = ExchangeTransaction(op_type=op, sender=addr, nonce=nonces[addr], params=params,
                                    gas_limit=1_000_000)
            nonces[addr] += 1
            t.public_key = key.public_key.to_bytes()
            t.signature = key.sign(t.signing_bytes()).to_bytes()
            return t

        c = ExchangeStateManager.derive_collection_address(a1, 0, "QART")

        async def add(h, txs=(), alloc=()):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content="",
                               validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + h)
            for i, (r, amount) in enumerate(alloc):
                await db.add_transaction(tx_hash=f"a{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": amount}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(list(txs)))

        await add(0, alloc=[(a1, "1000"), (a2, "1000")])
        await add(1, [tx(k1, Op.NFT_CREATE_COLLECTION, name="Art", symbol="QART", uri="u"),
                      tx(k1, Op.NFT_MINT, collection=c, to=a2, uri="u/1"),
                      tx(k1, Op.NFT_MINT, collection=c, uri="u/2")])
        await add(2, [tx(k2, Op.NFT_SET_APPROVAL_FOR_ALL, collection=c, operator=a1),
                      tx(k1, Op.NFT_TRANSFER, collection=c, token_id=1, to=a1, **{"from": a2}),
                      tx(k1, Op.NFT_BURN, collection=c, token_id=2)])
        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        m = ExchangeStateManager.get_instance()
        BP.apply_enforcement(m)
        for h in (1, 2):
            txs = BP.decode_exchange_txs(await db.get_block_exchange_txs(f"{h:064x}"))
            await BP.preload_sender_balances(db, txs, m)
            await BP.preload_token_balances(db, txs, m)
            okk, err, _ = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, m)
            assert okk, err
            assert all(r.success for r in m._block_results), [r.error for r in m._block_results]
            m.commit_block()
            await BP.flush_exchange_balance_deltas(db, m, enforce=True)
            await BP.flush_token_balance_deltas(db, m)
        await db.connection.commit()
        assert views.nft(m, c, 1)["owner"] == a1 and views.nft(m, c, 2) is None
        forward = m.compute_state_root()

        await db.clear_account_state()
        await db.seed_genesis_account_state()
        await db.connection.commit()
        await db.clear_token_balances()
        ExchangeStateManager.reset_instance()
        await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
        rebuilt = ExchangeStateManager.get_instance()
        assert rebuilt.compute_state_root() == forward
        assert rebuilt.nfts.canonical() == m.nfts.canonical()
    finally:
        ExchangeStateManager.reset_instance()
        await db.close()
        os.remove(path)


# ── ERC-721 inside the EVM ───────────────────────────────────────────────────

from test_evm_world import ALICE as E_ALICE, BOB as E_BOB, CAROL as E_CAROL  # noqa: E402
from test_evm_world import STORE, _hex, addr_word, chain, word  # noqa: E402,F401


def sel(name):
    return _selector(SIGNATURES[name])


def _evm_collection(n=2, owner=E_ALICE, **extra):
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    _nonces.clear()
    c = collection(m, **extra)
    for _ in range(n):
        ok(m, ARTIST, Op.NFT_MINT, collection=c, to=_hex(owner), uri="ipfs://x")
    m.commit_block()
    return bytes.fromhex(c[2:])


async def _owner(chain, c, i):
    return (await chain.call(c, sel("ownerOf") + word(i))).output[12:]


async def test_erc721_reads(chain):
    from eth_abi import decode
    c = _evm_collection()
    assert decode(["string"], (await chain.call(c, sel("name"))).output) == ("Quantum Art",)
    assert int.from_bytes((await chain.call(c, sel("totalSupply"))).output, "big") == 2
    assert await _owner(chain, c, 1) == E_ALICE
    bal = (await chain.call(c, sel("balanceOf") + addr_word(E_ALICE))).output
    assert int.from_bytes(bal, "big") == 2
    assert decode(["string"], (await chain.call(c, sel("tokenURI") + word(1))).output) == \
        ("ipfs://x",)
    assert not (await chain.call(c, sel("ownerOf") + word(9))).success          # no such NFT
    for iface, yes in (("80ac58cd", 1), ("5b5e139f", 1), ("2a55205a", 1), ("ffffffff", 0)):
        out = (await chain.call(c, sel("supportsInterface") + bytes.fromhex(iface) + bytes(28))).output
        assert int.from_bytes(out, "big") == yes
    receiver, amount = decode(["address", "uint256"], (await chain.call(
        c, sel("royaltyInfo") + word(1) + word(10_000))).output)
    assert receiver.lower() == to_account_id(ARTIST) and amount == 500


async def test_erc721_transfers_approvals_and_operators(chain):
    c = _evm_collection()
    nfts = ExchangeStateManager.get_instance().nfts
    coll = _hex(c)
    xfer = sel("transferFrom") + addr_word(E_ALICE) + addr_word(E_BOB) + word(1)
    assert not (await chain.tx(E_BOB, c, xfer)).success                  # Bob is nobody yet
    r = await chain.tx(E_ALICE, c, sel("approve") + addr_word(E_BOB) + word(1))
    assert r.success, r.error
    assert nfts.find(coll, 1).approved == _hex(E_BOB)                     # in the registry
    r = await chain.tx(E_BOB, c, xfer)
    assert r.success, r.error
    assert await _owner(chain, c, 1) == E_BOB and nfts.find(coll, 1).approved is None
    assert nfts.balance(coll, _hex(E_BOB)) == 1 and nfts.balance(coll, _hex(E_ALICE)) == 1
    [log] = r.logs
    assert log[1][1:] == [int.from_bytes(E_ALICE, "big"), int.from_bytes(E_BOB, "big"), 1]
    r = await chain.tx(E_ALICE, c, sel("setApprovalForAll") + addr_word(E_CAROL) + word(1))
    assert r.success and r.logs[0][1][0] == APPROVAL_FOR_ALL_TOPIC
    assert nfts.is_operator(coll, _hex(E_ALICE), _hex(E_CAROL))
    r = await chain.tx(E_CAROL, c, sel("transferFrom") + addr_word(E_ALICE) + addr_word(E_CAROL)
                       + word(2))
    assert r.success and await _owner(chain, c, 2) == E_CAROL
    # the exchange sees the same owners
    assert views.nft(ExchangeStateManager.get_instance(), coll, 2)["owner"] == _hex(E_CAROL)


async def test_safe_transfer_asks_a_contract_recipient(chain):
    c = _evm_collection(n=3)
    # returns onERC721Received's selector: PUSH4 sel PUSH1 0xe0 SHL PUSH1 0 MSTORE ... RETURN
    receiver = await chain.deploy(bytes.fromhex("63") + ON_RECEIVED
                                  + bytes.fromhex("60e01b60005260206000f3"))
    stranger = await chain.deploy(STORE)                        # answers with something else
    safe = sel("safeTransferFrom")
    r = await chain.tx(E_ALICE, c, safe + addr_word(E_ALICE) + addr_word(receiver) + word(1))
    assert r.success, r.error
    assert await _owner(chain, c, 1) == receiver
    r = await chain.tx(E_ALICE, c, safe + addr_word(E_ALICE) + addr_word(stranger) + word(2))
    assert not r.success and await _owner(chain, c, 2) == E_ALICE
    r = await chain.tx(E_ALICE, c, safe + addr_word(E_ALICE) + addr_word(E_BOB) + word(2))
    assert r.success                                             # an account always accepts
    with_data = sel("safeTransferFromData") + addr_word(E_ALICE) + addr_word(receiver) + word(3) \
        + word(128) + word(3) + b"abc".ljust(32, b"\0")
    assert (await chain.tx(E_ALICE, c, with_data)).success


async def test_a_soulbound_collection_refuses_evm_transfers(chain):
    c = _evm_collection(n=1, non_transferable=True)
    r = await chain.tx(E_ALICE, c, sel("transferFrom") + addr_word(E_ALICE) + addr_word(E_BOB)
                       + word(1))
    assert not r.success and await _owner(chain, c, 1) == E_ALICE


async def test_native_addresses_have_code_size_inside_the_evm(chain):
    """Solidity checks EXTCODESIZE before calling a function that returns nothing (ERC-721's
    transfers, ERC-777's send): a collection's address reports a stub, never written back."""
    c = _evm_collection(n=1)
    probe = await chain.deploy(bytes.fromhex("73") + c + bytes.fromhex("3b60005260206000f3"))
    out = (await chain.call(probe)).output
    assert int.from_bytes(out, "big") == 1
    assert (await chain.tx(E_ALICE, probe)).success
    code = await chain.sm.get_code(_hex(c))
    assert not code                                              # nothing persisted


# ── the CLI ─────────────────────────────────────────────────────────────────

def test_the_nft_cli(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from qrdx.cli import nft as N
    from qrdx.cli import perp as P
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange.submission import parse_exchange_tx
    from qrdx.wallet_v2 import PQWallet
    wallet = PQWallet(private_key=PQPrivateKey.generate())
    calls = []

    def fake_rpc(node, method, params=None, timeout=20.0):
        calls.append((method, params))
        if method == "exchange_getNonce":
            return 0
        if method == "exchange_gasPrice":
            return 10 ** 9
        if method == "exchange_sendTransaction":
            return parse_exchange_tx(params[0]).tx_hash()
        if method == "exchange_getNftsOf":
            return [{"symbol": "QART", "token_id": "7", "owner": ALICE, "uri": "u", "name": "",
                     "approved": None}]
        raise AssertionError(method)

    for module in (P, N):
        monkeypatch.setattr(module, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    wf = tmp_path / "w.json"
    wf.write_text("{}")

    def sent(args):
        r = CliRunner().invoke(N.nft, args + ["--yes"])
        assert r.exit_code == 0, r.output
        return parse_exchange_tx(calls[-1][1][0])

    tx = sent(["create", str(wf), "Quantum Art", "QART", "--royalty-bps", "500", "--max-supply",
               "100", "--soulbound"])
    assert tx.op_type == Op.NFT_CREATE_COLLECTION and tx.params["non_transferable"] is True
    assert sent(["mint", str(wf), "0xc", "--to", ALICE, "--uri", "u/7"]).params == \
        {"collection": "0xc", "uri": "u/7", "name": "", "to": ALICE}
    assert sent(["transfer", str(wf), "0xc", "7", BOB]).op_type == Op.NFT_TRANSFER
    assert sent(["approve-all", str(wf), "0xc", BOB, "--revoke"]).params["approved"] is False
    assert sent(["approve", str(wf), "0xc", "7", "none"]).params["spender"] == ""
    assert sent(["burn", str(wf), "0xc", "7"]).op_type == Op.NFT_BURN
    assert sent(["update", str(wf), "0xc", "--token-id", "7", "--uri", "u/7b"]).params == \
        {"collection": "0xc", "token_id": "7", "uri": "u/7b"}
    assert sent(["set-authority", str(wf), "0xc", "mint", "none"]).params["new_authority"] == ""
    r = CliRunner().invoke(N.nft, ["owned", ALICE])
    assert r.exit_code == 0 and "QART #7" in r.output
