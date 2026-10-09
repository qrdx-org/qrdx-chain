"""
Release tooling (scripts/release/release.py, docs/RELEASES.md).

What must hold for a release to be trustworthy:
  * the source a release names is exactly the committed tree and its submodules at their
    recorded commits — nothing untracked, nothing uncommitted, byte-identical every time;
  * a release is refused unless its tag, NODE_VERSION and the package version agree;
  * a manifest verifies only with ≥ threshold distinct listed maintainers' signatures over its
    exact bytes — tampering, unlisted keys and duplicate signers do not count;
  * an empty maintainer list verifies nothing (fail closed);
  * every artifact the manifest names must match its hash;
  * a maintainer regenerating the manifest from the tag in their own clone gets the same bytes
    CI published (what they sign is what the tag says);
  * a candidate (draft) check runs every check but the signature count;
  * downloading a release lets no asset name choose where it is written, and finds drafts only
    with a token.

Runs against a throwaway git repository (with a submodule, like py-evm) so it is hermetic.
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None or shutil.which("git") is None,
                                reason="needs git and ssh-keygen")


def _load_release():
    spec = importlib.util.spec_from_file_location("release_tool", REPO / "scripts/release/release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_release()


def _git(cwd, *args, env=None):
    base = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@e", "GIT_AUTHOR_DATE": "2026-10-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-10-01T00:00:00Z", **(env or {})}
    return subprocess.run(["git", "-c", "safe.directory=*", "-c", "protocol.file.allow=always",
                           "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, env=base, check=True, capture_output=True).stdout.decode().strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A miniature qrdx-chain: the files the tooling reads, a network genesis, a submodule."""
    sub = tmp_path / "evm"
    sub.mkdir()
    _git(sub, "init", "-q")
    (sub / "eth.py").write_text("FORK = 'qrdx'\n")
    _git(sub, "add", "-A")
    _git(sub, "commit", "-qm", "evm")

    root = tmp_path / "chain"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "qrdx").mkdir()
    (root / "qrdx/__init__.py").write_text("")
    shutil.copy(REPO / "qrdx/chain_spec.py", root / "qrdx/chain_spec.py")
    (root / "qrdx/constants.py").write_text("NODE_VERSION = '2.0.1'\n")
    (root / "pyproject.toml").write_text('[project]\nname = "qrdx-chain"\nversion = "2.0.1"\n')
    (root / "docker").mkdir()
    shutil.copy(REPO / "docker/Dockerfile", root / "docker/Dockerfile")
    (root / "release").mkdir()
    for f in ("requirements.lock", "build-requirements.lock", "test-requirements.lock",
              "allowed_signers"):
        shutil.copy(REPO / "release" / f, root / "release" / f)
    (root / "run.sh").write_text("#!/bin/sh\necho hi\n")
    (root / "run.sh").chmod(0o755)
    import sys
    sys.path.insert(0, str(REPO))
    from qrdx import chain_spec as cs
    spec = cs.build_spec("qrdx-testnet", 7620, {}, forks=[
        {"name": "randao", "height": 1000, "features": ["randao_selection"]}])
    (root / "networks/qrdx-testnet").mkdir(parents=True)
    (root / "networks/qrdx-testnet/genesis_config.json").write_text(
        json.dumps({"chain_spec": spec.to_dict(), "block": {"block_hash": "ab" * 32}}))
    _git(root, "submodule", "add", "-q", str(sub), "py-evm")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "release")
    _git(root, "tag", "v2.0.1")
    monkeypatch.setattr(R, "REPO", root)
    return root


# ── source ──────────────────────────────────────────────────────────────────────────────

def test_the_source_tarball_is_deterministic_and_exactly_the_commit(repo):
    # Things a working-tree build would pick up, and a release must not.
    (repo / "qrdx/node_key.priv").write_text("secret")
    (repo / "qrdx/constants.py").write_text("NODE_VERSION = 'edited'\n")
    (repo / "py-evm/eth.py").write_text("FORK = 'uncommitted'\n")

    first, second = R.canonical_tar("v2.0.1"), R.canonical_tar("v2.0.1")
    assert first == second
    with tarfile.open(fileobj=io.BytesIO(first)) as tf:
        names = tf.getnames()
        assert names == sorted(names)
        assert "qrdx/node_key.priv" not in names
        assert tf.extractfile("qrdx/constants.py").read() == b"NODE_VERSION = '2.0.1'\n"
        assert tf.extractfile("py-evm/eth.py").read() == b"FORK = 'qrdx'\n"   # the recorded commit
        commit_time = R.commit_time("v2.0.1")
        for m in tf.getmembers():
            assert m.mtime == commit_time and m.uid == 0 and m.gid == 0
        assert tf.getmember("run.sh").mode == 0o755
        assert tf.getmember("qrdx/chain_spec.py").mode == 0o644


def test_the_tarball_file_and_its_content_hash(repo, tmp_path):
    out_a, out_b = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    info_a = R.write_source_tarball("v2.0.1", out_a)
    info_b = R.write_source_tarball("v2.0.1", out_b)
    assert out_a.read_bytes() == out_b.read_bytes()
    assert info_a["tar_sha256"] == hashlib.sha256(gzip.decompress(out_a.read_bytes())).hexdigest()


# ── preflight ───────────────────────────────────────────────────────────────────────────

def test_preflight_accepts_a_consistent_tag(repo):
    assert R.preflight("v2.0.1") == []


def test_preflight_refuses_inconsistent_versions_and_untagged_commits(repo):
    (repo / "pyproject.toml").write_text('[project]\nname = "qrdx-chain"\nversion = "2.0.0"\n')
    _git(repo, "commit", "-qam", "drift")
    _git(repo, "tag", "v2.0.2")
    problems = "\n".join(R.preflight("v2.0.2"))
    assert "NODE_VERSION" in problems and "pyproject.toml" in problems
    (repo / "run.sh").write_text("#!/bin/sh\necho wip\n")
    _git(repo, "commit", "-qam", "work in progress")                # no tag
    assert "not a release tag" in "\n".join(R.preflight("HEAD"))


def test_preflight_refuses_a_submodule_a_fresh_clone_cannot_fetch(repo):
    """A gitlink with no .gitmodules url (a nested repo added by accident) works in the checkout
    that has it and breaks every fresh clone — including the release workflow's."""
    commit = _git(repo, "rev-parse", "HEAD:py-evm")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{commit},orphan")
    _git(repo, "commit", "-qm", "orphan gitlink")
    _git(repo, "tag", "-f", "v2.0.1")
    problems = R.preflight("v2.0.1")
    assert any("orphan is recorded as a submodule" in p and "no url in .gitmodules" in p
               for p in problems)
    assert not any("py-evm" in p for p in problems)          # the declared one is fine


def test_the_version_is_a_function_of_the_commit_not_of_how_it_is_named(repo):
    """The version is built into the image (labels, QRDX_BUILD_VERSION): CI builds the tag by
    name, a verifier rebuilds the manifest's commit by hash — both must say the same."""
    commit = R.resolve("v2.0.1")
    assert R.version_of("v2.0.1") == R.version_of(commit) == R.version_of("HEAD") == "v2.0.1"
    _git(repo, "commit", "-q", "--allow-empty", "-m", "next")
    assert R.version_of("HEAD") == f"dev-{R.resolve('HEAD')[:12]}"
    _git(repo, "tag", "v2.0.10", commit)                      # numeric, not lexical, order
    _git(repo, "tag", "v2.0.9", commit)
    assert R.version_of(commit) == "v2.0.10"
    assert any("one commit, one release" in p for p in R.preflight("v2.0.1"))


def test_preflight_refuses_a_dirty_release_checkout(repo):
    (repo / "qrdx/constants.py").write_text("NODE_VERSION = '2.0.1'  # edited\n")
    problems = "\n".join(R.preflight("v2.0.1"))
    assert "uncommitted changes" in problems


# ── manifest ────────────────────────────────────────────────────────────────────────────

def test_the_manifest_records_source_build_inputs_and_networks(repo, tmp_path):
    tarball = tmp_path / "src.tar.gz"
    info = R.write_source_tarball("v2.0.1", tarball)
    m = R.build_manifest("v2.0.1", "ghcr.io/x/y@sha256:" + "1" * 64, "sha256:" + "2" * 64,
                         "linux/amd64", info)
    assert m["version"] == "v2.0.1" and m["node_version"] == "2.0.1"
    assert m["source"]["commit"] == R.resolve("v2.0.1")
    assert set(m["source"]["submodules"]) == {"py-evm"}
    assert m["build"]["liboqs"] == {"version": "0.15.0",
                                    "commit": "97f6b86b1b6d109cfd43cf276ae39c2e776aed80"}
    assert m["build"]["base_image"].startswith("python:3.11.17-slim-bookworm@sha256:")
    assert "randao_selection" in m["features"]
    net = m["networks"]["qrdx-testnet"]
    assert net["chain_id"] == 7620 and net["asset"] == "qrdx-testnet.genesis_config.json"
    assert net["forks"][0]["definition_hash"] == R_fork_hash(net)
    assert m["images"]["linux/amd64"]["config_digest"] == "sha256:" + "2" * 64


def test_a_maintainer_regenerates_the_published_manifest_byte_for_byte(repo, tmp_path, monkeypatch):
    """What CI writes and what a maintainer regenerates from the tag in their own clone (another
    path, another checkout time) must be the same bytes — that is what makes the comparison in
    sign-release.sh meaningful."""
    image, config = "ghcr.io/x/y@sha256:" + "1" * 64, "sha256:" + "2" * 64
    (tmp_path / "ci").mkdir()
    (tmp_path / "mine").mkdir()
    name = "qrdx-chain-v2.0.1-src.tar.gz"                     # sign-release.sh keeps the draft's name
    ci_tar, ci_manifest = tmp_path / "ci" / name, tmp_path / "ci" / "release-manifest.json"
    R.write_manifest(R.build_manifest("v2.0.1", image, config, "linux/amd64",
                                      R.write_source_tarball("v2.0.1", ci_tar)), ci_manifest)

    clone = tmp_path / "maintainer-clone"
    _git(tmp_path, "clone", "-q", "--recurse-submodules", str(repo), str(clone))
    monkeypatch.setattr(R, "REPO", clone)
    m_tar, m_manifest = tmp_path / "mine" / name, tmp_path / "mine" / "release-manifest.json"
    R.write_manifest(R.build_manifest("v2.0.1", image, config, "linux/amd64",
                                      R.write_source_tarball("v2.0.1", m_tar)), m_manifest)
    assert m_tar.read_bytes() == ci_tar.read_bytes()
    assert m_manifest.read_bytes() == ci_manifest.read_bytes()


def R_fork_hash(net):
    from qrdx import chain_spec as cs
    fork = {k: net["forks"][0][k] for k in ("name", "height", "features")}
    return cs.ChainSpec.fork_definition_hash(fork)


# ── signatures and verification ─────────────────────────────────────────────────────────

def _key(tmp_path, name):
    key = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)],
                   check=True)
    return key


@pytest.fixture
def signed(repo, tmp_path):
    """A manifest, three maintainer keys (two listed), a policy requiring two."""
    manifest = tmp_path / "release-manifest.json"
    R.write_manifest(R.build_manifest("v2.0.1", None, None, "linux/amd64", None), manifest)
    keys = {n: _key(tmp_path, n) for n in ("alice", "bob", "mallory")}
    signers = tmp_path / "allowed_signers"
    signers.write_text("".join(
        f'{n}@qrdx.org namespaces="qrdx-release" {(keys[n].with_suffix(".pub")).read_text()}'
        for n in ("alice", "bob")))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"format": 1, "maintainer_threshold": 2,
                                  "signing_namespace": "qrdx-release"}))
    sigs = tmp_path / "sigs"
    sigs.mkdir()
    return manifest, keys, signers, policy, sigs


def _verify(manifest, sigs, policy, signers, **kw):
    return R.verify(manifest, sigs, policy, signers, kw.get("bundle"), kw.get("artifacts"),
                    False, False, skip_ci=True)


def test_two_listed_maintainers_verify_a_release(signed):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    failures = _verify(manifest, sigs, policy, signers)
    assert failures and "requires 2" in failures[0]
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "qrdx-release")
    assert _verify(manifest, sigs, policy, signers) == []


def test_unlisted_keys_and_duplicate_signers_do_not_count(signed):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["alice"], sigs / "alice-again.sig", "qrdx-release")
    R.sign(manifest, keys["mallory"], sigs / "mallory.sig", "qrdx-release")
    failures = _verify(manifest, sigs, policy, signers)
    assert failures and "signed by 1 listed maintainer" in failures[0]


def test_a_signature_for_another_purpose_does_not_count(signed):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "git")           # wrong namespace
    assert _verify(manifest, sigs, policy, signers)


def test_any_change_to_the_manifest_breaks_every_signature(signed):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "qrdx-release")
    data = json.loads(manifest.read_text())
    data["source"]["commit"] = "0" * 40
    manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    failures = _verify(manifest, sigs, policy, signers)
    assert failures and "signed by 0" in failures[0]


def test_an_empty_maintainer_list_verifies_nothing(signed, tmp_path):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "qrdx-release")
    empty = tmp_path / "empty_signers"
    empty.write_text("# nobody yet\n")
    failures = _verify(manifest, sigs, policy, empty)
    assert failures and "no maintainers" in failures[0]


def test_the_ci_signature_is_required_unless_explicitly_skipped(signed):
    manifest, keys, signers, policy, sigs = signed
    data = json.loads(policy.read_text())
    data["ci_identity"] = {"issuer": "https://token.actions.githubusercontent.com",
                           "identity_regexp": "^https://github.com/x/y/.*$"}
    policy.write_text(json.dumps(data))
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "qrdx-release")
    failures = R.verify(manifest, sigs, policy, signers, None, None, False, False, skip_ci=False)
    assert failures and "CI signature" in failures[0]


def test_artifacts_must_match_their_recorded_hashes(signed, tmp_path):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    R.sign(manifest, keys["bob"], sigs / "bob.sig", "qrdx-release")
    assets = tmp_path / "assets"
    assets.mkdir()
    genesis = json.loads(manifest.read_text())["networks"]["qrdx-testnet"]
    src = R.REPO / genesis["file"]
    shutil.copy(src, assets / genesis["asset"])
    assert _verify(manifest, sigs, policy, signers, artifacts=assets) == []
    (assets / genesis["asset"]).write_text("{}")                    # a swapped genesis file
    failures = _verify(manifest, sigs, policy, signers, artifacts=assets)
    assert failures and "does NOT match" in failures[0]


def test_a_candidate_check_tolerates_missing_signatures_but_nothing_else(signed, tmp_path):
    manifest, keys, signers, policy, sigs = signed
    R.sign(manifest, keys["alice"], sigs / "alice.sig", "qrdx-release")
    assert R.verify(manifest, sigs, policy, signers, None, None, False, False,
                    skip_ci=True, candidate=True) == []
    assert R.verify(manifest, None, policy, signers, None, None, False, False,
                    skip_ci=True, candidate=True) == []
    assert _verify(manifest, sigs, policy, signers)          # not a release yet
    assets = tmp_path / "assets"
    assets.mkdir()
    genesis = json.loads(manifest.read_text())["networks"]["qrdx-testnet"]
    (assets / genesis["asset"]).write_text("{}")
    failures = R.verify(manifest, sigs, policy, signers, None, assets, False, False,
                        skip_ci=True, candidate=True)
    assert failures and "does NOT match" in failures[0]


# ── download ────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_github():
    """A minimal GitHub releases API: one published release, one draft (visible only with a
    token, as on GitHub)."""
    state = {"assets": {"release-manifest.json": b'{"version": "v2.0.1"}',
                        "maintainer-alice.sig": b"sig"},
             "draft_assets": {"release-manifest.json": b'{"version": "v2.0.2"}'},
             "auth": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _release(self, tag, assets):
            base = f"http://127.0.0.1:{self.server.server_port}"
            return {"tag_name": tag, "assets": [{"name": n, "url": f"{base}/asset/{tag}/{n}"}
                                                for n in assets]}

        def do_GET(self):
            state["auth"].append(self.headers.get("Authorization"))
            if self.path == "/repos/o/r/releases/tags/v2.0.1":
                return self._send(200, json.dumps(self._release("v2.0.1", state["assets"])).encode())
            if self.path.startswith("/repos/o/r/releases?") and self.headers.get("Authorization"):
                return self._send(200, json.dumps([self._release("v2.0.2", state["draft_assets"]),
                                                   self._release("v2.0.1", state["assets"])]).encode())
            if self.path.startswith("/asset/"):
                _, _, tag, name = self.path.split("/", 3)
                pool = state["assets"] if tag == "v2.0.1" else state["draft_assets"]
                return self._send(200, pool[name], "application/octet-stream")
            self._send(404, b'{"message": "Not Found"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()


def test_download_fetches_every_asset_of_a_published_release(fake_github, tmp_path):
    api, state = fake_github
    names = R.download("o/r", "v2.0.1", tmp_path / "dl", api=api)
    assert names == ["maintainer-alice.sig", "release-manifest.json"]
    assert (tmp_path / "dl/release-manifest.json").read_bytes() == b'{"version": "v2.0.1"}'
    assert set(state["auth"]) == {None}                       # no token sent when none given


def test_a_draft_is_visible_only_with_a_token(fake_github, tmp_path):
    api, state = fake_github
    with pytest.raises(R.ReleaseError, match="needs GH_TOKEN"):
        R.download("o/r", "v2.0.2", tmp_path / "dl", api=api)
    assert R.download("o/r", "v2.0.2", tmp_path / "dl", token="t0k", api=api) == ["release-manifest.json"]
    assert "Bearer t0k" in state["auth"]


@pytest.mark.parametrize("bad", ["../escape.json", ".hidden", "a/b.json", "x..y"])
def test_no_asset_name_chooses_where_it_is_written(fake_github, tmp_path, bad):
    api, state = fake_github
    state["assets"] = {bad: b"payload"}
    with pytest.raises(R.ReleaseError, match="unsafe name"):
        R.download("o/r", "v2.0.1", tmp_path / "dl", api=api)
    assert not (tmp_path / "escape.json").exists()


def test_download_refuses_a_malformed_repository(tmp_path):
    with pytest.raises(R.ReleaseError, match="owner/repo"):
        R.download("o/r/../../x", "v2.0.1", tmp_path / "dl", api="http://127.0.0.1:9")


# ── maintainer keys ─────────────────────────────────────────────────────────────────────

def test_a_maintainer_signed_tag_verifies_as_the_release_workflow_checks_it(tmp_path):
    """The workflow runs `git verify-tag` against release/allowed_signers. Git signs tags in the
    "git" namespace, so a maintainer line restricted to the manifest namespace alone would
    reject every genuine tag — the documented format allows both, and preflight lints for it."""
    key = _key(tmp_path, "alice")
    pub = key.with_suffix(".pub").read_text().strip()
    work = tmp_path / "r"
    work.mkdir()
    _git(work, "init", "-q")
    (work / "f").write_text("x")
    _git(work, "add", "f")
    _git(work, "commit", "-qm", "c")
    _git(work, "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}", "tag", "-s", "v1.0.0", "-m", "v1.0.0")

    def verify_tag(line):
        signers = tmp_path / "allowed_signers"
        signers.write_text(line + "\n")
        return subprocess.run(["git", "-c", "safe.directory=*", "-c", "gpg.format=ssh", "-c",
                               f"gpg.ssh.allowedSignersFile={signers}", "verify-tag", "v1.0.0"],
                              cwd=work, capture_output=True).returncode

    documented = f'alice@qrdx.org namespaces="git,qrdx-release" {pub}'
    manifest_only = f'alice@qrdx.org namespaces="qrdx-release" {pub}'
    assert verify_tag(documented) == 0
    assert verify_tag(manifest_only) != 0
    assert R.lint_allowed_signers(documented) == []
    assert "cannot sign in git" in R.lint_allowed_signers(manifest_only)[0]
    assert "no namespaces" in R.lint_allowed_signers(f"alice@qrdx.org {pub}")[0]
    assert R.lint_allowed_signers((REPO / "release/allowed_signers").read_text()) == []
