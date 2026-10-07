"""
Native NFT collections inside the EVM: every collection (qrdx/exchange/nfts.py) is an ERC-721
at its own address, backed by the one NFT registry (docs/NATIVE_TOKENS.md §8).

``name``, ``symbol``, ``totalSupply``, ``balanceOf``, ``ownerOf``, ``tokenURI``,
``getApproved``, ``isApprovedForAll`` read the registry; ``approve``, ``setApprovalForAll``,
``transferFrom`` and both ``safeTransferFrom``s change the same owners, approvals and operators
the exchange's NFT_* operations do, with the ERC-721 ``Transfer`` / ``Approval`` /
``ApprovalForAll`` events. ``safeTransferFrom`` to a contract calls its
``onERC721Received`` and reverts unless it answers with the selector. ERC-165
``supportsInterface``, ERC-2981 ``royaltyInfo`` and ``contractURI`` (collection metadata) are
there for marketplaces. Minting, burning and metadata changes are the native operations'.

Consistency is the native tokens' (qrdx/contracts/native_token_evm.py): changes are journaled
on the transaction's state (a reverted frame undoes them), join the block's ``EvmSection``, and
reach the registry only when the section is accepted.
"""
from __future__ import annotations

from eth.exceptions import Revert
from eth_utils import keccak

from ..crypto.account_id import to_account_id
from .native_token_evm import (
    APPROVAL_TOPIC, TRANSFER_TOPIC, _address_word, _bytes_arg, _string, _uint, _uint_word,
    revert_data,
)


def _selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


SIGNATURES = {
    "name": "name()", "symbol": "symbol()", "totalSupply": "totalSupply()",
    "balanceOf": "balanceOf(address)", "ownerOf": "ownerOf(uint256)",
    "tokenURI": "tokenURI(uint256)", "getApproved": "getApproved(uint256)",
    "isApprovedForAll": "isApprovedForAll(address,address)",
    "approve": "approve(address,uint256)",
    "setApprovalForAll": "setApprovalForAll(address,bool)",
    "transferFrom": "transferFrom(address,address,uint256)",
    "safeTransferFrom": "safeTransferFrom(address,address,uint256)",
    "safeTransferFromData": "safeTransferFrom(address,address,uint256,bytes)",
    "supportsInterface": "supportsInterface(bytes4)",
    "royaltyInfo": "royaltyInfo(uint256,uint256)",
    "contractURI": "contractURI()",
}
SELECTORS = {_selector(sig).hex(): fn for fn, sig in SIGNATURES.items()}
WRITES = {"approve", "setApprovalForAll", "transferFrom", "safeTransferFrom",
          "safeTransferFromData"}
GAS = {"approve": 25_000, "setApprovalForAll": 25_000, "transferFrom": 35_000,
       "safeTransferFrom": 40_000, "safeTransferFromData": 40_000}
GAS_READ = 2_600
APPROVAL_FOR_ALL_TOPIC = int.from_bytes(keccak(text="ApprovalForAll(address,address,bool)"), "big")
ON_RECEIVED = _selector("onERC721Received(address,address,uint256,bytes)")
INTERFACES = {bytes.fromhex(x) for x in ("01ffc9a7",      # ERC-165
                                         "80ac58cd",      # ERC-721
                                         "5b5e139f",      # ERC-721 metadata
                                         "2a55205a")}     # ERC-2981 royalties


def nft_precompile(computation):
    """The ERC-721 interface of the NFT collection at the called address."""
    state = computation.state
    world = state.native_tokens
    msg = computation.msg
    collection = world.collection(msg.code_address)
    data = bytes(msg.data_as_bytes)
    fn = SELECTORS.get(data[:4].hex())

    def fail(reason: str):
        computation.output = revert_data(reason)
        raise Revert(reason)

    computation.consume_gas(GAS.get(fn, GAS_READ), reason=f"native NFT {fn or 'call'}")
    if fn is None:
        fail(f"{collection.symbol} is a native NFT collection: it implements ERC-721 only")
    if msg.storage_address != msg.code_address:
        fail("a native NFT collection cannot be called with DELEGATECALL or CALLCODE")
    if msg.value:
        fail("NFT collections do not accept QRDX")
    if fn in WRITES and msg.is_static:
        fail("an NFT transfer or approval cannot run in a static call")

    address = collection.address
    args = data[4:]
    caller_raw = bytes(msg.sender)
    caller = to_account_id(caller_raw)

    def owner_of(tid: int) -> str:
        owner = world.nft_owner(state, address, tid)
        if owner is None:
            fail(f"{collection.symbol} #{tid} does not exist")
        return owner

    def transfer(frm_raw: bytes, to_raw: bytes, tid: int, safe: bool, extra: bytes) -> None:
        if collection.non_transferable:
            fail(f"{collection.symbol} is soulbound: its NFTs cannot be transferred")
        if not any(to_raw):
            fail("transfer to the zero address")
        owner = owner_of(tid)
        frm, to = to_account_id(frm_raw), to_account_id(to_raw)
        if owner != frm:
            fail(f"{collection.symbol} #{tid} is not owned by the sender")
        if not (caller == owner or world.nft_approved(state, address, tid) == caller
                or world.nft_operator(state, address, owner, caller)):
            fail("caller is not the owner, approved or an operator")
        state.token_journal.append(("nft_own", address, tid, to))
        state.token_journal.append(("nft_appr", address, tid, None))
        state.token_journal.append(("nft_bal", address, frm, -1))
        state.token_journal.append(("nft_bal", address, to, 1))
        computation.add_log_entry(msg.code_address, [
            TRANSFER_TOPIC, int.from_bytes(frm_raw, "big"), int.from_bytes(to_raw, "big"), tid],
            b"")
        if safe:
            _check_receiver(computation, to_raw, caller_raw, frm_raw, tid, extra, fail)

    try:
        if fn == "name":
            computation.output = _string(collection.name)
        elif fn == "symbol":
            computation.output = _string(collection.symbol)
        elif fn == "totalSupply":
            computation.output = _uint(collection.supply)
        elif fn == "contractURI":
            computation.output = _string(collection.uri)
        elif fn == "balanceOf":
            owner_raw = _address_word(args, 0)
            if not any(owner_raw):
                fail("the zero address owns nothing")
            computation.output = _uint(world.nft_balance(state, address, to_account_id(owner_raw)))
        elif fn == "ownerOf":
            computation.output = bytes(12) + bytes.fromhex(owner_of(_uint_word(args, 0))[2:])
        elif fn == "tokenURI":
            tid = _uint_word(args, 0)
            owner_of(tid)
            computation.output = _string(world.nft_uri(address, tid))
        elif fn == "getApproved":
            tid = _uint_word(args, 0)
            owner_of(tid)
            approved = world.nft_approved(state, address, tid)
            computation.output = bytes(12) + (bytes.fromhex(approved[2:]) if approved else bytes(20))
        elif fn == "isApprovedForAll":
            owner = to_account_id(_address_word(args, 0))
            operator = to_account_id(_address_word(args, 1))
            computation.output = _uint(1 if world.nft_operator(state, address, owner, operator)
                                       else 0)
        elif fn == "supportsInterface":
            word = args[:32]
            computation.output = _uint(1 if len(word) == 32 and word[:4] in INTERFACES else 0)
        elif fn == "royaltyInfo":
            sale = _uint_word(args, 1)
            recipient = collection.royalty_recipient
            amount = sale * collection.royalty_bps // 10_000 if recipient else 0
            computation.output = (bytes(12) + (bytes.fromhex(to_account_id(recipient)[2:])
                                               if recipient else bytes(20)) + _uint(amount))
        elif fn == "approve":
            spender_raw, tid = _address_word(args, 0), _uint_word(args, 1)
            owner = owner_of(tid)
            if not (caller == owner or world.nft_operator(state, address, owner, caller)):
                fail("caller is not the owner or an operator")
            spender = to_account_id(spender_raw) if any(spender_raw) else None
            if spender == owner:
                fail("cannot approve the owner")
            state.token_journal.append(("nft_appr", address, tid, spender))
            computation.add_log_entry(msg.code_address, [
                APPROVAL_TOPIC, int(owner, 16), int.from_bytes(spender_raw, "big"), tid], b"")
            computation.output = b""
        elif fn == "setApprovalForAll":
            operator_raw = _address_word(args, 0)
            approved = _uint_word(args, 1)
            if approved > 1:
                fail("malformed bool argument")
            operator = to_account_id(operator_raw)
            if operator == caller:
                fail("cannot approve yourself as an operator")
            if approved and not world.nft_operator(state, address, caller, operator):
                from ..exchange.nfts import MAX_OPERATORS_PER_OWNER
                if world.nft_operator_slots_used(state, caller) >= MAX_OPERATORS_PER_OWNER:
                    fail(f"an account may approve at most {MAX_OPERATORS_PER_OWNER} NFT operators")
            state.token_journal.append(("nft_op", address, caller, operator, bool(approved)))
            computation.add_log_entry(msg.code_address, [
                APPROVAL_FOR_ALL_TOPIC, int.from_bytes(caller_raw, "big"),
                int.from_bytes(operator_raw, "big")], _uint(approved))
            computation.output = b""
        elif fn == "transferFrom":
            transfer(_address_word(args, 0), _address_word(args, 1), _uint_word(args, 2),
                     False, b"")
            computation.output = b""
        elif fn == "safeTransferFrom":
            transfer(_address_word(args, 0), _address_word(args, 1), _uint_word(args, 2),
                     True, b"")
            computation.output = b""
        elif fn == "safeTransferFromData":
            transfer(_address_word(args, 0), _address_word(args, 1), _uint_word(args, 2),
                     True, _bytes_arg(args, 3))
            computation.output = b""
    except ValueError as e:
        fail(str(e))
    return computation


def _check_receiver(computation, to_raw: bytes, operator_raw: bytes, frm_raw: bytes, tid: int,
                    extra: bytes, fail) -> None:
    """ERC-721's safe transfer: a contract recipient must answer ``onERC721Received`` with its
    selector (an account without code always accepts)."""
    code = computation.state.get_code(to_raw)
    if not code:
        return
    pad = extra + b"\0" * ((-len(extra)) % 32)
    call = (ON_RECEIVED + bytes(12) + operator_raw + bytes(12) + frm_raw + _uint(tid) + _uint(128)
            + _uint(len(extra)) + pad)
    remaining = computation.get_gas_remaining()
    gas = remaining - remaining // 64
    computation.consume_gas(gas, reason="onERC721Received")
    child = computation.apply_child_computation(computation.prepare_child_message(
        gas=gas, to=to_raw, value=0, data=call, code=code))
    computation.return_gas(child.get_gas_remaining())
    if child.is_error or bytes(child.output[:4]) != ON_RECEIVED:
        fail("the recipient contract does not accept ERC-721 tokens")

