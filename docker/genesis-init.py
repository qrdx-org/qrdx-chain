#!/usr/bin/env python3
"""
Write the genesis for a containerised QRDX node that STARTS its own chain.

Generates, once, $(dirname $(dirname QRDX_DATABASE_PATH))/genesis_config.json —
the exact path the node checks at startup (qrdx/node/main.py walks two
directories up from the database), so the two can never disagree. The genesis
holds:

  * every allocation in QRDX_GENESIS_ALLOCATIONS, funded in account_state at
    block 0 (and re-seeded from block 0 after a reorg);
  * this node's validator (the wallet validator-init prepared or validated) as
    the sole genesis validator. Without one nobody can propose, and the chain
    would sit at block 0 forever.

Idempotent: if the genesis file already exists it is left alone. Genesis is
fixed for the life of the chain — changing QRDX_GENESIS_ALLOCATIONS afterwards
only logs a warning; a different genesis needs a wiped data volume.

An existing genesis is first checked with the node's own loader. One written by an
older release whose chain spec this release cannot run (it lacks a parameter added
since) fails HERE, with the reason and the fix, instead of passing and leaving the
node to crash-loop on import. Such a chain cannot be upgraded in place; run once with
--reset to start a new one:

  docker compose -f docker/docker-compose.tunnel.yml run --rm genesis-init --reset

--reset moves the old genesis and the database directory to <data>/retired/<UTC time>/
and writes a fresh genesis. The validator wallet and the node identity key are kept
(unlike `down -v`). It only ever replaces a genesis this release cannot run; on a
working chain it refuses.

The file is written atomically. A half-written file would fail to parse, and the
node would refuse to start on it.

The genesis file carries the chain's spec (docs/PROTOCOL_UPGRADES.md): its chain id,
name and every network parameter, taken from this script's environment. Every node of
the chain reads them from the file; a node whose environment disagrees refuses to start.

Environment
  QRDX_DATABASE_PATH            Node database path      [/app/data/databases/qrdx.db]
  QRDX_GENESIS_ALLOCATIONS      address:amount[,address:amount...] in QRDX (required)
  QRDX_GENESIS_VALIDATOR_STAKE  Genesis stake of this node's validator   [100000]
  QRDX_CHAIN_ID                 required — 762 for qrdx-mainnet, 7620 for qrdx-testnet,
                                otherwise an id no other EVM network uses (every signed
                                transaction is bound to it)
  QRDX_NETWORK_NAME             [qrdx-mainnet for 762, qrdx-testnet for 7620, else qrdx-mainnet]
  QRDX_SLOT_DURATION_MS, ...    any network parameter (qrdx/chain_spec.py PARAMS)
  QRDX_VALIDATOR_ENABLED        must be true — a genesis node has to propose
  QRDX_VALIDATOR_WALLET         [/app/data/validator/validator.json]
"""
import json
import logging
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

# Own handler, not propagated: importing qrdx replaces the root logger's handlers
# with a Rich console handler, which would swallow this script's output format.
log = logging.getLogger("genesis-init")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[genesis-init] %(message)s"))
log.addHandler(_handler)
log.setLevel(logging.INFO)
log.propagate = False

TRUTHY = ("1", "true", "yes", "on")

DATABASE_PATH = Path(os.getenv("QRDX_DATABASE_PATH") or "/app/data/databases/qrdx.db")
# Same derivation as the node's startup (qrdx/node/main.py).
GENESIS_FILE = DATABASE_PATH.parent.parent / "genesis_config.json"

ALLOCATIONS_RAW = os.getenv("QRDX_GENESIS_ALLOCATIONS", "")
VALIDATOR_STAKE_RAW = os.getenv("QRDX_GENESIS_VALIDATOR_STAKE", "100000")
CHAIN_ID_RAW = os.getenv("QRDX_CHAIN_ID", "").strip()
NETWORK_NAME = os.getenv("QRDX_NETWORK_NAME", "").strip()
VALIDATOR_ENABLED = os.getenv("QRDX_VALIDATOR_ENABLED", "false").lower() in TRUTHY
WALLET_PATH = Path(os.getenv("QRDX_VALIDATOR_WALLET") or "/app/data/validator/validator.json")


def parse_amount(raw: str, what: str) -> Decimal:
    try:
        amount = Decimal(raw.replace("_", ""))
    except InvalidOperation:
        raise ValueError(f"{what}: {raw!r} is not a number")
    if not amount.is_finite() or amount <= 0:
        raise ValueError(f"{what}: {raw!r} must be a positive amount")
    return Decimal(format(amount, "f"))  # "1e9" -> 1000000000, as the genesis file records it


def parse_allocations(raw: str) -> dict:
    """'addr:amount,addr:amount' -> {addr: Decimal}. Rejects anything malformed."""
    from qrdx.crypto.account_id import to_account_id
    from qrdx.crypto.address import is_checksum_address, is_valid_address

    allocations = {}
    for entry in filter(None, (e.strip() for e in raw.split(","))):
        address, sep, amount = entry.rpartition(":")
        address = address.strip()
        if not sep or not address:
            raise ValueError(f"allocation {entry!r} is not in address:amount form")
        if not is_valid_address(address):
            raise ValueError(f"allocation address {address!r} is not a valid QRDX address")
        # A mistyped mixed-case address is still well-formed hex, and funds a key
        # nobody holds — the checksum is what catches it.
        if not is_checksum_address(address):
            raise ValueError(
                f"allocation address {address!r} fails its checksum — copy it exactly as "
                f"the wallet shows it (mixed case); a typo here funds a key nobody holds"
            )
        if address in allocations:
            raise ValueError(f"allocation address {address!r} is listed twice")
        to_account_id(address)  # the ledger key genesis will fund; must derive
        allocations[address] = parse_amount(amount.strip(), f"allocation for {address}")

    if not allocations:
        raise ValueError("QRDX_GENESIS_ALLOCATIONS is empty — nothing to fund at genesis")
    return allocations


def load_validator() -> dict:
    data = json.loads(WALLET_PATH.read_text())
    missing = [k for k in ("address", "public_key") if not data.get(k)]
    if missing:
        raise ValueError(f"validator wallet {WALLET_PATH} is missing {', '.join(missing)}")
    return data


def warn_if_drifted(allocations: dict) -> None:
    """The genesis exists already; say so loudly if the config no longer matches it."""
    try:
        recorded = json.loads(GENESIS_FILE.read_text()).get("state", {}).get("accounts", {})
        recorded = {a: Decimal(str(info.get("balance"))) for a, info in recorded.items()}
    except Exception as e:
        log.warning("could not read existing %s to compare: %s", GENESIS_FILE, e)
        return
    for address, amount in recorded.items():
        log.info("genesis allocation: %s = %s QRDX", address, amount)
    if recorded != allocations:
        log.warning(
            "QRDX_GENESIS_ALLOCATIONS no longer matches the genesis this chain was started "
            "with; the RECORDED genesis above stays in force. A different genesis needs a "
            "fresh chain: `down -v` wipes the data volume (and the validator key on it)."
        )


def unusable_reason():
    """Why this release cannot run the chain whose genesis is on the volume, or None if it can.
    The same load the node does when it imports qrdx.constants."""
    from qrdx import chain_spec as cs  # no qrdx imports of its own; safe before the check

    try:
        cs.load_genesis_file(str(GENESIS_FILE))
    except cs.ChainSpecError as e:
        return str(e)
    return None


def activate_spec(spec) -> None:
    """Make qrdx.constants load THIS chain's spec when it is imported. With no genesis file it
    would build a dev network's spec from the environment instead, which refuses a QRDX
    network's chain id (762, 7620), and the genesis would be built under rules other than the
    ones its nodes will run. A stub holding only the spec stands in for the genesis file."""
    if "qrdx.constants" in sys.modules:
        raise RuntimeError("qrdx.constants was imported before the chain spec was activated")
    stub = Path(tempfile.mkdtemp()) / "genesis_config.json"
    stub.write_text(json.dumps({"chain_spec": spec.to_dict()}))
    os.environ["QRDX_GENESIS_FILE"] = str(stub)


def retire_chain() -> Path:
    """Move the old genesis and database directory to <data>/retired/<UTC time>/. Moved, not
    deleted: the old chain stays on the volume until you remove it."""
    db_dir = DATABASE_PATH.parent
    dest = GENESIS_FILE.parent / "retired" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest.mkdir(parents=True)
    # The database directory goes first, while the old genesis is still in place: a node
    # restarting meanwhile reads the old genesis and exits at import, before it opens a database.
    if db_dir.exists():
        shutil.move(str(db_dir), str(dest / db_dir.name))
    shutil.copy2(GENESIS_FILE, dest / GENESIS_FILE.name)  # the new one replaces it atomically
    return dest


def main() -> int:
    reset = "--reset" in sys.argv[1:]
    unusable = unusable_reason() if GENESIS_FILE.exists() else None

    if unusable and not reset:
        log.error("%s cannot be run by this release:", GENESIS_FILE)
        log.error("  %s", unusable)
        log.error(
            "It was written by an older release, and a chain cannot be upgraded in place. The "
            "node would crash on startup, so it is not started. To start a NEW chain (keeping "
            "this node's validator key and identity), run once:"
        )
        log.error("  docker compose -f docker/docker-compose.tunnel.yml run --rm genesis-init --reset")
        log.error("(with the same -f files you start the stack with), then `up -d` again.")
        return 1
    if reset and GENESIS_FILE.exists() and not unusable:
        log.error(
            "--reset refused: this release can run the chain on this volume. --reset only "
            "replaces a genesis it cannot run; to discard a working chain use `down -v` (which "
            "also deletes the validator key — back it up first)."
        )
        return 1
    if unusable:
        if WALLET_PATH.resolve().is_relative_to(DATABASE_PATH.parent.resolve()):
            log.error("--reset refused: the validator wallet %s is inside the database directory "
                      "%s, which --reset moves away", WALLET_PATH, DATABASE_PATH.parent)
            return 1

    try:
        allocations = parse_allocations(ALLOCATIONS_RAW)
        validator_stake = parse_amount(VALIDATOR_STAKE_RAW, "QRDX_GENESIS_VALIDATOR_STAKE")
    except ValueError as e:
        log.error("%s", e)
        return 1

    if GENESIS_FILE.exists() and not unusable:
        log.info("%s already exists — leaving it untouched.", GENESIS_FILE)
        warn_if_drifted(allocations)
        return 0

    if not VALIDATOR_ENABLED:
        log.error(
            "QRDX_VALIDATOR_ENABLED is not true. This node starts the chain, so it must be "
            "its first validator — with no genesis validator nothing is ever proposed."
        )
        return 1

    try:
        validator = load_validator()
    except Exception as e:
        log.error("cannot read the validator wallet at %s: %s", WALLET_PATH, e)
        return 1

    from qrdx import chain_spec as cs

    if not CHAIN_ID_RAW.isdigit():
        log.error("QRDX_CHAIN_ID must be set to this chain's id (a positive integer no other EVM "
                  "network uses — every signed transaction is bound to it); got %r", CHAIN_ID_RAW)
        return 1
    chain_id = int(CHAIN_ID_RAW)
    # A QRDX network's own chain id implies its name; otherwise the historical default.
    network = NETWORK_NAME or cs.QRDX_NETWORKS.get(chain_id, "qrdx-mainnet")
    try:
        spec = cs.build_spec(network, chain_id, cs.params_from_environment())
    except cs.ChainSpecError as e:
        log.error("invalid chain spec: %s", e)
        return 1

    activate_spec(spec)
    from qrdx.constants import MIN_VALIDATOR_STAKE
    from qrdx.validator.genesis import GenesisConfig, GenesisCreator

    if validator_stake < MIN_VALIDATOR_STAKE:
        log.error("QRDX_GENESIS_VALIDATOR_STAKE %s is below the minimum %s", validator_stake, MIN_VALIDATOR_STAKE)
        return 1

    config = GenesisConfig(
        chain_spec=spec,
        min_genesis_validators=1,
        pre_allocations=dict(allocations),
        enable_system_wallets=False,
    )
    creator = GenesisCreator(config)
    if not creator.add_validator(validator["address"], validator["public_key"], validator_stake):
        log.error("genesis rejected validator %s", validator["address"])
        return 1

    state, block = creator.create_genesis()

    GENESIS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = GENESIS_FILE.with_name(GENESIS_FILE.name + ".tmp")
    creator.export_genesis(state, block, str(tmp))
    if unusable:
        retired = retire_chain()
        log.info("retired the old chain to %s", retired)
    os.replace(tmp, GENESIS_FILE)

    log.info("wrote %s", GENESIS_FILE)
    log.info("chain        : %s (chain_id=%d, spec %s)", spec.network, spec.chain_id,
             spec.genesis_hash()[:16])
    log.info("genesis hash : %s", block.block_hash)
    for address, amount in allocations.items():
        log.info("allocation   : %s = %s QRDX", address, amount)
    log.info("validator    : %s (stake %s QRDX)", validator["address"], validator_stake)
    log.info(
        "Every other node on this chain must start from this SAME file; a node that builds "
        "its own genesis has a different block 0 and rejects this chain's blocks."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
