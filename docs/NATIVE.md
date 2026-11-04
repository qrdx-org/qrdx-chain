# The native module (Rust)

`native/qrdx-native` is a Rust extension (PyO3) for the work in a block that Python does
slowly: checking its signatures and committing to its body. The node and the validator call it
through `qrdx/native.py`, and each function there has a pure-Python path that gives the same
result. A node without the module, or with `QRDX_NATIVE=0`, runs those paths and agrees with
every other node byte for byte.

## What it does

| Function | Stands in for | Used by |
|---|---|---|
| `mldsa65_verify_batch(items)` | liboqs through `oqs-python`, one signature at a time | `block_processor.verify_exchange_txs`: a block's section on import; a gossip batch on admission (`ExchangeSubmitter`) |
| `canonical_json(obj, compact, default_str)` | `json.dumps(obj, sort_keys=True, ensure_ascii=True)` | `qrdx/native.py` |
| `body_root_sha256(prefix, body)` | `sha256(prefix + json.dumps(body, ...))` | `block_verification.body_root`, on every block |

On a block of 2,000 transfers (`scripts/bench/exchange_block.py`, 24 cores):

| | Python | Native |
|---|---:|---:|
| Its 2,000 signatures | 130 ms (threads did not help) | 7 ms |
| Its body root (a 22 MB body) | 50 ms | 26 ms (16 ms of it SHA-256) |

### Signatures

The module links the system liboqs, the same library `oqs-python` loads (`ldd` shows
`liboqs.so.9`), and calls `OQS_SIG_ml_dsa_65_verify` on a thread pool (rayon), without Python's
lock. A signature is therefore judged by the same code either way.

Only the signature verdicts come from the batch. `verify_exchange_tx` still runs every other
check in Python: structure, chain id, gas, the key's binding to the sender, and multisig. It
reads each verdict where it would have asked liboqs (`dilithium.precomputed`). A transaction
that passed is marked with the exact bytes it passed for, so it is not checked again
(`block_processor.is_verified`). Change its payload, signature or key and it is checked afresh.

Python reached a block's signatures one at a time even on eight threads: `oqs-python` holds the
lock for its own work around each call. The first native version was no faster either, and the
reason was in the module itself: PyO3 converted each `bytes` to a vector element by element.
It now reads the bytes in place.

### Canonical JSON

The encoder writes what Python's `json` writes:

* keys sorted by code point;
* `\uXXXX` escapes in lowercase, with surrogate pairs above U+FFFF;
* the short escapes, and DEL escaped;
* integers of any size, as `int.__repr__` writes them;
* floats as `float.__repr__` writes them, and `NaN`, `Infinity`, `-Infinity`;
* tuples as arrays, and subclasses of str, int, float, dict and list.

Anything it does not reproduce exactly raises `Unsupported`, and `qrdx/native.py` encodes the
object with Python's `json` instead: a key that is not a string, an unpaired surrogate, nesting
past 900. An object `json` cannot serialize raises `TypeError`, as in Python.

## How it is held to Python

`tests/test_native.py` checks it against Python itself, on random inputs:

* 4,000 random structures, in both separator styles;
* `default=str` with `Decimal`, the fallbacks, and the errors;
* body roots with the module and without it;
* 60 signatures, valid and tampered (another message, a flipped bit, another key, a short
  signature), against liboqs through Python;
* a section of transactions, some tampered and some bound to the wrong sender, with the
  module and without it.

The tests skip when the module is not installed. CI builds it, so they run there.

## Building it

```
curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.86.0
pip install maturin==1.7.4
cd native/qrdx-native
maturin build --release --auditwheel skip -o dist
pip install --no-deps dist/qrdx_native-0.1.0-cp310-abi3-linux_x86_64.whl
```

* **Toolchain:** pinned to Rust 1.86.0 by `rust-toolchain.toml`; `Cargo.lock` pins every crate.
* **liboqs:** the module links the liboqs in `/usr/local/lib` (`QRDX_OQS_LIB_DIR` to look
  elsewhere). That is why the wheel is not "repaired" to bundle it: the node must check
  signatures with one library, the one `oqs-python` uses.
* **Wheel:** abi3, so one wheel serves Python 3.10 and later.
* **Threads:** `RAYON_NUM_THREADS` caps the threads a batch uses. By default it uses every core.

## What is not native yet

The block's execution, the order book and the state root still run in Python. So does the rest
of the node and the validator client: networking, fork choice, sync. These are the next
candidates (docs/PERFORMANCE.md, "What limits it next"). The Python versions would stay as the
reference the native ones are tested against.
