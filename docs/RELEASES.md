# Releases: signed, reproducible, verifiable

How a QRDX release is built, signed and published, and how an operator checks that a release
is genuine before running it. Who reads what:

- **Operators:** §1, §2, §6.
- **Maintainers:** all of it, especially §4, §5 and §7.

Nodes never consult GitHub, or anything else, about which code they run (see
[PROTOCOL_UPGRADES.md §8a](PROTOCOL_UPGRADES.md#8a-release-integrity-how-operators-know-a-release-is-genuine)).
The people installing a release verify it before they install it, and the chain verifies
behaviour: blocks under each node's rules, and forks only after validators approve them on
chain.

## 1. What makes a release genuine

A release is a git tag `vX.Y.Z` plus a **release manifest**: a JSON file naming every
artifact of the release by hash. It is genuine when all of the following hold:

1. **Maintainers signed it.** At least `maintainer_threshold` (in `release/policy.json`,
   currently 2) distinct maintainers listed in `release/allowed_signers` signed the manifest's
   exact bytes with their SSH keys.
2. **The release workflow made it.** The manifest also carries a Sigstore signature from
   `.github/workflows/release.yml` running on that tag. The workflow signs keylessly with its
   GitHub OIDC identity, and the signature is recorded in the public Rekor transparency log.
3. **Everything matches its hash.** The source tarball, the genesis files and the image in
   the registry match the hashes in the manifest.
4. **Anyone can rebuild it.** Building the image from the tagged source gives the same image,
   byte for byte. The maintainers who sign have each done that rebuild (§5), and any operator
   can repeat it (§6).

No single party can forge a release:

| Who | What they can do alone |
|---|---|
| A compromised CI | Can't get maintainer signatures for an image the source doesn't build |
| A compromised maintainer | Can't reach the threshold, and can't produce the CI signature |
| A compromised registry | Can't change an image addressed by digest |

**Trust root.** Always verify with a `release/policy.json` and `release/allowed_signers` you
already trust: those in your checkout of the default branch, compared against the values the
project publishes out of band. Never use the copies inside the release you are checking, or a
release could vouch for itself. `verify-release.sh` prints the sha256 of both files for that
comparison.

## 2. What a release contains

GitHub release assets:

| Asset | What it is |
|---|---|
| `release-manifest.json` | Version, commit, tree, submodule commits, all build inputs (base image digest, Debian snapshot, liboqs commit, lock hashes, BuildKit), the consensus features the code can execute, every network's genesis file with its chain id, spec hash and scheduled forks (with the definition hashes validators approve on chain), and the image: `ref` (repository@digest) and `config_digest` |
| `release-manifest.json.cosign.bundle` | The release workflow's Sigstore signature over the manifest |
| `maintainer-*.sig` | Maintainer SSH signatures over the manifest (namespace `qrdx-release`) |
| `qrdx-chain-vX.Y.Z-src.tar.gz` | The exact source: the committed tree plus submodules at their recorded commits, deterministic (sorted, fixed times and owners) |
| `<network>.genesis_config.json` | Each network's genesis file, from `networks/<network>/genesis_config.json` |
| `sbom.spdx.json` | The image's software bill of materials |
| `SHA256SUMS` | Convenience checksums. The manifest is what is signed |

Next to the image in GHCR (`ghcr.io/qrdx-org/qrdx-chain`), the workflow also publishes:

- a cosign signature;
- the SBOM as a signed attestation;
- SLSA build provenance (`actions/attest-build-provenance`).

## 3. Reproducible builds

`scripts/release/build-image.sh` builds the node image so that two builds of the same commit
are identical. Every input is pinned:

- **Base image:** pinned by digest.
- **Debian packages:** fixed by a `snapshot.debian.org` timestamp, which must be no older than
  the base image.
- **liboqs:** pinned by tag, and the commit is checked.
- **Python dependencies:** every package by version and sha256 (`release/requirements.lock`).
  The few that ship only as source are built from pinned backends
  (`release/build-requirements.lock`) at fixed paths.
- **py-evm:** comes from the submodule, at the commit the tag records.
- **Build engine:** a fresh BuildKit container of a pinned version, with no cache.
- **Time:** `SOURCE_DATE_EPOCH` is the commit time. It drives the times inside built wheels,
  every application file's time, and BuildKit's `rewrite-timestamp` for the layers.

Anything that would still differ between two builds is removed:

- bytecode;
- debug info and build paths in compiled C;
- apt/dpkg logs and caches;
- checkout file modes, times and ownership;
- the "password last changed" date `useradd` records.

```sh
scripts/release/build-image.sh --ref v2.0.1                        # build a tag, print digests
scripts/release/build-image.sh --ref v2.0.1 --print-config-digest  # just the comparable digest
scripts/release/build-image.sh --worktree --load qrdx-node:dev     # development build of your tree
```

Builds use `--ref` by default. That exports the commit (`release.py export`) and builds the
export, never your working directory: untracked files, local edits and stray keys can't reach a
release image. A `--worktree` build is marked `-dirty` in its version, and it can't be pushed.

**What to compare.** Compare the **image config digest**. It covers the layer contents (their
`diff_id`s) and the full image configuration. The manifest digest also depends on how the image
was exported (OCI or Docker media types, compression), so only builds exported the same way can
be compared by it.

**Verified so far** (2026-10-09, linux/amd64), each build in a fresh builder with no cache:

- **Perturbed checkout.** A build of a working tree, and a build of a copy with scrambled file
  times (1999, 2001, 2035), modes (0777, 0700) and stray files (`node_key.priv`,
  `__pycache__`, logs), were bit-identical.
- **Full release rehearsal** on a scratch clone tagged `v2.0.1`: three independent builds were
  bit-identical, with config `sha256:34acc0cb…` and manifest `sha256:2f7e9f1e…`:
  - the tag built by name (OCI archive);
  - `release.py verify --rebuild` building the manifest's commit by hash;
  - a `--load` build.

  A second clone regenerated the source tarball and manifest byte for byte. Two maintainer
  signatures verified, and an unlisted third signature was ignored. A tampered manifest was
  rejected.
- **Tests inside the image.** The tag's unit suite ran inside the tag's image
  (`test-image.sh`): 2925 passed, 0 failed.

**Limits.**

- Images are built for linux/amd64 only.
- A rebuild needs network access to the pinned sources: Docker Hub, snapshot.debian.org,
  GitHub (liboqs), PyPI.
- `DEBIAN_SNAPSHOT` must be bumped together with `BASE_IMAGE`.

## 4. Dependency locks

```sh
scripts/release/lock-deps.sh                          # re-lock after editing requirements-v3.txt
scripts/release/lock-deps.sh --upgrade-package NAME   # move one package
scripts/release/lock-deps.sh --upgrade                # re-resolve everything (review carefully)
scripts/release/lock-deps.sh --check                  # CI: fail if any lock is stale
```

The locks are resolved for Python 3.11 on every platform:

- `release/requirements.lock`: what the image installs;
- `release/build-requirements.lock`: build backends;
- `release/test-requirements.lock`: test tools, constrained to the image's versions.

`requirements-v3.txt` keeps the human-edited ranges. A lock change is a reviewed change: read
the diff, and run `scripts/release/test-image.sh` on an image built with it.

## 5. Cutting a release (maintainers)

### One-time setup

1. **Keys.** Each maintainer adds one line to `release/allowed_signers`:

   ```
   alice@qrdx.org namespaces="git,qrdx-release" sk-ssh-ed25519@openssh.com AAAA…
   ```

   Both namespaces are required:
   - `git` covers the release tag, which the workflow checks with `git verify-tag`;
   - `qrdx-release` covers the manifest.

   `release.py preflight` refuses a list where a key lacks either. Prefer hardware-backed
   keys (`ssh-keygen -t ed25519-sk`). Changes to this file are trust changes: land them through
   review by existing maintainers, signed, and announce the new fingerprints out of band.
   Until at least `maintainer_threshold` keys are listed, **nothing verifies**. The file ships
   empty on purpose.
2. **Git signing.** Configure tag signing:

   ```sh
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519_sk.pub
   ```
3. **GitHub settings.** These settings are part of the security model:
   - protect the default branch: required review, no force-push, signed commits;
   - restrict who can create `v*` tags (a tag ruleset);
   - make the GHCR package public;
   - keep `release.yml` changes under the same review as code.

### Each release

1. **Prepare.** Bump `NODE_VERSION` (`qrdx/constants.py`) and `version` (`pyproject.toml`) to
   the same `X.Y.Z`. Run `scripts/release/lock-deps.sh --check`. Make sure every submodule
   commit is pushed to its public repository: a fresh clone must be able to fetch it. If the
   release ships a new fork, append it to the network's `networks/<name>/genesis_config.json`
   (PROTOCOL_UPGRADES.md §4 and §8).
2. **Preflight.** Run `python3 scripts/release/release.py preflight --ref HEAD`. It refuses
   when:
   - the tree is dirty;
   - the versions disagree;
   - a lock is missing;
   - a submodule is undeclared or unavailable;
   - a maintainer key line is malformed.
3. **Tag and push.** Run `git tag -s vX.Y.Z -m "QRDX vX.Y.Z" && git push origin vX.Y.Z`.
4. **The workflow runs.** `.github/workflows/release.yml`:
   1. checks the tag's signature against the **default branch's** `allowed_signers`, not the
      tag's own copy, and runs preflight;
   2. builds the image **twice**, each time in a fresh builder; the config digests must match;
   3. runs the unit suite **inside** the image (`test-image.sh`);
   4. pushes the image and checks the pushed config digest is the reproduced one;
   5. cosign-signs the image, attaches the SBOM and SLSA provenance, writes the source tarball
      and manifest, and Sigstore-signs the manifest;
   6. creates a **draft** GitHub release.
5. **Maintainers sign** (each one, independently, from an up-to-date default-branch checkout):

   ```sh
   scripts/release/sign-release.sh vX.Y.Z [--key ~/.ssh/id_ed25519_sk] [--publish]
   ```

   It signs only what it has reproduced itself:
   1. the checkout's policy and maintainer list match the default branch;
   2. the tag is maintainer-signed and passes preflight;
   3. the draft's CI signature, artifact hashes and registry image check out;
   4. the source tarball and manifest regenerated locally from the tag are **byte-identical**
      to the draft's;
   5. the image rebuilt locally has the recorded config digest.

   It then uploads `maintainer-<name>.sig` to the draft. With `--publish`, once the threshold
   is met, it verifies the release in full and publishes it.

Expect the rebuild to take several minutes: liboqs is compiled from source.

## 6. Verifying a release (operators)

```sh
git clone https://github.com/qrdx-org/qrdx-chain && cd qrdx-chain   # the trust root (§1)
scripts/release/verify-release.sh vX.Y.Z --network qrdx-mainnet          # add --rebuild to rebuild it too
```

The script needs `python3`, `ssh-keygen`, `cosign` and `docker`. It downloads the release
(nothing downloaded is trusted) and checks everything in §1. Then it prints:

- the image to run, **by digest**;
- the network's genesis file;
- the network's scheduled forks, with their definition hashes.

Run the image by that digest, never by a tag:

```sh
QRDX_IMAGE=ghcr.io/qrdx-org/qrdx-chain@sha256:… \
  docker compose -f docker/docker-compose.prod.yml up -d --no-build
```

Optional extra checks on the image itself:

```sh
cosign verify ghcr.io/qrdx-org/qrdx-chain@sha256:… \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/qrdx-org/qrdx-chain/\.github/workflows/release\.yml@refs/tags/v'
gh attestation verify oci://ghcr.io/qrdx-org/qrdx-chain@sha256:… --repo qrdx-org/qrdx-chain
```

## 7. Releases and on-chain upgrades

A release that schedules a fork is only half of an upgrade. The fork activates only if
validators approve its **exact definition** on chain before its approval deadline
(GOVERNANCE.md §4, PROTOCOL_UPGRADES.md §4a). The manifest lists each scheduled fork's
`definition_hash`. Before voting on an `approve_fork` proposal, a validator should check:

1. the release verifies (§6);
2. the proposal's `definition_hash` equals the one in the verified manifest. The value is also
   available from `governance_getForkApprovalParams` on a node running the release.

The vote's timelock is the window in which anyone, holders included, can inspect the release
behind a fork and veto it.

## 8. Tooling reference

| Command | Purpose |
|---|---|
| `release.py preflight --ref R` | Refuse an unreleasable ref |
| `release.py export --ref R --dest D` | The committed tree + submodules, nothing else |
| `release.py source-tarball --ref R --out F` | The deterministic source tarball |
| `release.py manifest --ref R … --out F` | Write the release manifest |
| `release.py sign --manifest F --key K --out S` | A maintainer signature |
| `release.py verify --manifest F --signatures DIR …` | Check a release against a policy. Flags: `--candidate` for a draft, `--check-image`, `--rebuild` |
| `release.py download --tag T --dest D` | Fetch a release's assets. Drafts need `GH_TOKEN` |
| `build-image.sh` | Reproducible image build (§3) |
| `test-image.sh IMAGE` | Unit suite inside an image, against the shipped code |
| `lock-deps.sh` | Dependency locks (§4) |
| `sign-release.sh` / `verify-release.sh` | Maintainer and operator flows (§5, §6) |

`release.py` uses only the Python standard library, plus the `git`, `ssh-keygen`, `cosign`
and `docker` programs. The workflows run every script through `bash` or `python3`, so a
checkout that lost the executable bit still works. This repository's checkouts often have
`core.fileMode=false`, which records new files as non-executable, so commit the scripts with
`git add --chmod=+x scripts/release/*.sh scripts/release/release.py` to keep them runnable as
`scripts/release/…`. `tests/test_release_tooling.py` covers it hermetically, against a
throwaway git repository with a submodule.

## 9. Not done yet

- **arm64 images.** The locks already cover it. The build and the workflow would need a
  second platform and a per-platform manifest entry.
- **Mainnet genesis file.** No `networks/` directory exists yet. A network's genesis file is
  committed there once its genesis is final, and pinned in `chain_spec.PINNED_NETWORKS`
  (PROTOCOL_UPGRADES.md §8a).
- **Maintainer keys.** `release/allowed_signers` is empty until maintainers register (§5).
