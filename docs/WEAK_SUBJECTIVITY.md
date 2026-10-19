# Weak subjectivity: trusted checkpoints

A running node never reorganizes below finality. A node syncing from genesis has no finality of
its own yet.

Validators that left long ago no longer have stake to lose: their stake is withdrawn, and
nothing is left to slash. They can still sign. Together, keys that once held two thirds of the
stake can build another history from an old block onward, complete with votes and finality, and
a new node cannot tell it from the real one. Every proof-of-stake chain answers this the same
way. A new node trusts one recent block hash it got from outside the protocol, and follows only
chains that contain it.

| Part | Where |
|---|---|
| Checkpoints, their checks, the reorganization floor | `qrdx/checkpoints.py` |
| In the chain spec | `"checkpoints"` (`qrdx/chain_spec.py`) |
| Checked on import | `_verify_chain_rules` (`qrdx/node/main.py`) |
| A checkpoint to give a new node | RPC `qrdx_weakSubjectivityCheckpoint` |
| Tests | `tests/test_trusted_checkpoints.py` |

## Where checkpoints come from

- **The network's chain spec.** `"checkpoints": [{"height": …, "hash": …}]`, appended by each
  signed release (docs/RELEASES.md). Like `forks`, they are outside what genesis commits to, so
  adding one changes no genesis hash.
- **The operator.** Set `QRDX_TRUSTED_CHECKPOINT=height:hash` (comma-separate several) to a
  recent finalized block from a source you trust: another operator, or the release notes. A node
  you trust prints one: `qrdx_weakSubjectivityCheckpoint` returns its finalized block, written as
  the variable.

A checkpoint the operator gives that contradicts the spec's is a startup error.

## What they decide

- **Import.** A block at a checkpoint's height must be the checkpoint, on every path: live,
  sync, fork-choice adoption. A block's hash commits to its ancestry, so a chain containing the
  checkpoint is the trusted chain up to it.
- **Reorganization.** Nothing rolls back below the highest checkpoint the node holds, or below
  finality, whichever is higher. That applies to sync's reorganization and to fork choice.
- **Startup.** A node whose database holds another block at a checkpoint height is on another
  chain. It refuses to start.
- **Staleness.** The weak-subjectivity period is how long a validator's stake stays slashable
  after it leaves: the unbonding period plus the withdrawal delay, ~3.9 days at the standard
  parameters. A node whose newest block is older than that, and which trusts no newer
  checkpoint, logs a warning: whatever it syncs next could be a long-range fork.

## For releases

When cutting a release, add the latest finalized block of each network to its spec's
`checkpoints`. Take it from `qrdx_weakSubjectivityCheckpoint` on nodes the maintainers run, and
check it against several. New nodes then sync safely as long as they start within the
weak-subjectivity period of the release. Later, they need an operator-supplied checkpoint.

## Not done

**Checkpoint sync** would start a new node from a checkpoint's state rather than replay from
genesis. The unified state root in each header could verify such a snapshot. A node still
replays every block, about 345,600 a day at 250 ms slots.
