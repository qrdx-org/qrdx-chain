# Validator keys and slashing protection

How a validator holds its signing key, and what stops it from getting its own stake slashed.
Written for people who run validators. The code is in qrdx/validator/keystore.py,
qrdx/validator/slashing_protection.py and qrdx/validator/doppelganger.py, and the tools are in
scripts/validator/.

A validator's ML-DSA-65 key signs its blocks and its FFG votes. The chain slashes 50 % of the
stake, and ejects the validator, for two different blocks at one slot or two conflicting votes
(docs/STAKING.md). So the key needs two kinds of protection: it must not leak, and the validator
must never sign twice, even by accident.

## The key: an encrypted keystore

Outside dev networks the node accepts only an encrypted keystore. It refuses to start as a
validator, and says why, when given:

* a plaintext key;
* a keystore in the old AES-128 format;
* a keystore whose address, public key and secret key do not belong together.

The keystore format:

* **Cipher:** AES-256-GCM, under a key derived from the password by scrypt. The cost is
  N = 2^18, r = 8, p = 1 (EIP-2335's), about 256 MiB and a second per attempt. AES-256 keeps
  128-bit security against Grover's algorithm.
* **Binding:** the ciphertext is bound to the address and public key the file names, so a file
  whose public key was swapped does not open.
* **Check on open:** opening it signs and verifies a test message.

```sh
# a new validator key
python scripts/validator/keystore.py new --out validator.keystore.json
# an existing plaintext wallet (then delete the plaintext: shred -u validator.json)
python scripts/validator/keystore.py encrypt --in validator.json --out validator.keystore.json
# an old (AES-128) keystore, same password
python scripts/validator/keystore.py upgrade --in old.keystore.json --out validator.keystore.json
# check one
python scripts/validator/keystore.py check validator.keystore.json
```

Files are written with mode 0600, never over an existing file, and reopened before the tool
reports success.

Run the node with:

| Variable | Value |
|---|---|
| `QRDX_VALIDATOR_WALLET` | the keystore |
| `QRDX_VALIDATOR_PASSWORD_FILE` | a file holding the password (a container secret, say); one trailing newline is ignored |
| `QRDX_VALIDATOR_PASSWORD` | the password itself, if no file is given. The node removes it from its environment once read. Prefer the file: a variable shows in `/proc/<pid>/environ`. |

`docker/validator-init.py` generates an encrypted keystore when a password is configured.

Keep an offline backup of the keystore and its password. The key exists nowhere else, and
nothing can recover a lost one.

## Slashing protection

Before the validator signs a block or a vote, it records it in its slashing-protection record. The
record is written in the same transaction that checks it, and that transaction is durable before
the signing starts. The validator never signs:

* a second, different block at a slot it signed;
* a second, different attestation for a target epoch it voted in;
* a vote that surrounds, or is surrounded by, one it signed.

A crash between recording and signing costs that slot, never protection.

The record compares the whole signed attestation, slot and head block included, not only its
checkpoints. Importers judge two different attestations for one target a double vote
(`slashing_block.attestation_equivocation`). The chain database's older record compared only
checkpoints, so a validator restarted mid-epoch could sign a second attestation with the same
checkpoints at a later slot. On startup the new record takes that older record in, as
watermarks.

**Where the record lives.** It is its own SQLite file: `QRDX_SLASHING_PROTECTION_DB`, by default
`<chain database>.slashing-protection.sqlite`. Resyncing or deleting the chain database leaves it
alone. Wiping the whole data directory does not, so back the record up with the keystore.

**One process at a time.** The node holds an exclusive lock on `<record>.lock`. A second process
pointed at the same record refuses to start.

**Per network.** Rows are kept per network (the network's signing domain). What a key signed on
another network is not slashable here.

**Pruning.** Rows far behind the newest are folded into watermarks: 2^20 slots and 2^14 epochs.
Nothing at or below a watermark is signed again.

### Moving a validator to another machine

```sh
# old machine — stop the validator first, and make sure it stays stopped
python scripts/validator/slashing_protection.py export --out record.json
# new machine — before its validator first starts
python scripts/validator/slashing_protection.py import record.json
python scripts/validator/slashing_protection.py show
```

The format is EIP-3076's interchange format, with QRDX addresses in the `pubkey` field. An import
refuses another network's file. It raises the record's watermarks to the highest slot and epochs
the file names, so the new machine never signs at or below what the old one signed.

## The doppelganger check

A record cannot see a second machine running the same key with a record of its own: a hot
standby, a restored backup left running, a migration where the old host never stopped. Together
those two machines double-sign. So once a validator starts:

* **It listens before signing.** For `QRDX_DOPPELGANGER_EPOCHS` epochs it signs nothing (default
  3; 0 on dev networks). A second instance already running shows itself in that time, through its
  blocks and its once-an-epoch votes.
* **It keeps watching.** Every epoch it compares the blocks and votes the chain carries from its
  key, since it started, against its record. Anything the record does not hold was signed
  elsewhere. The validator then stops signing for good and logs the block or vote at CRITICAL. An
  operator must stop one of the two, then restart this one.

Restarting therefore costs those epochs' rewards. It is the price Lighthouse and Teku also ask.

**Verified live (2026-10-27).** On a 4-node test network:

* A second instance of a running validator's key started with a 2-epoch window. It found the
  first validator's block about 7 seconds in, then never signed.
* A third process opening that instance's record was refused by the lock.
* The original validator, restarted on its own record, resumed proposing and voting.
* No slashing evidence was recorded on any node.

## Never

* Run two validators with one key, "just for redundancy". That is what gets stakes slashed.
* Copy a data directory to start a second validator.
* Delete the slashing-protection record of a validator that has signed. Export it instead.
