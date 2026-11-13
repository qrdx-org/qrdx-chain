"""
Slot-clock genesis-timestamp parsing (regression).

The genesis block stores its timestamp as an ISO-8601 TEXT string while later
blocks use integer Unix timestamps. `_get_current_slot` previously called
`datetime.fromtimestamp()` on the text string, which raised and fell back to
"now" on every call — pinning the slot to 0 forever and degenerating the PoS
proposer rotation (every validator believed it was the slot-0 proposer →
competing blocks → reorg churn; slot-based eligibility could never be enforced).

These tests pin that `parse_block_timestamp` accepts BOTH forms and that an
ISO-text genesis timestamp in the past yields an advancing (non-zero) slot.
"""

from datetime import datetime, timezone, timedelta

from qrdx.validator.node_integration import parse_block_timestamp


def test_parses_iso_text_timestamp_with_tz():
    dt = parse_block_timestamp("2026-06-08 13:57:09+00:00")
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt == datetime(2026, 6, 8, 13, 57, 9, tzinfo=timezone.utc)


def test_parses_integer_unix_timestamp():
    dt = parse_block_timestamp(1780927033)
    assert dt is not None and dt.tzinfo is not None
    assert int(dt.timestamp()) == 1780927033


def test_naive_iso_text_assumed_utc():
    dt = parse_block_timestamp("2026-06-08 13:57:09")
    assert dt is not None and dt.tzinfo == timezone.utc


def test_none_and_garbage_return_none():
    assert parse_block_timestamp(None) is None
    assert parse_block_timestamp("not-a-date") is None


def test_iso_text_genesis_yields_advancing_slot():
    """The real failure mode: a text genesis ts ~140s ago must give slot > 0."""
    SLOT_DURATION = 2
    genesis = datetime.now(timezone.utc) - timedelta(seconds=140)
    parsed = parse_block_timestamp(genesis.isoformat(sep=" "))
    elapsed = (datetime.now(timezone.utc) - parsed).total_seconds()
    slot = max(0, int(elapsed // SLOT_DURATION))
    assert slot >= 68, f"slot clock did not advance: {slot}"
