#!/usr/bin/env python3
"""
QRDX release tooling — reproducible artifacts, signed manifests, verification (docs/RELEASES.md).

Standard library only, so an operator can run it from any checkout. External programs:
``git`` (always), ``ssh-keygen`` (signatures; OpenSSH ≥ 8.2), ``cosign`` (the CI signature,
when verifying it) and ``docker`` (image checks and rebuilds).

    release.py preflight --ref v2.0.1          refuse a release that is not clean and consistent
    release.py export --ref v2.0.1 --dest DIR  the committed tree (+ submodules), nothing else
    release.py source-tarball --ref v2.0.1 --out qrdx-chain-v2.0.1-src.tar.gz
    release.py manifest --ref v2.0.1 --image-ref ghcr.io/…@sha256:… --image-config sha256:… \
                        --source-tarball F --out release-manifest.json
    release.py sign --manifest release-manifest.json --key ~/.ssh/id_ed25519 --out sigs/alice.sig
    release.py verify --manifest release-manifest.json --signatures sigs/ \
                      [--cosign-bundle release-manifest.json.cosign.bundle] [--artifacts DIR] \
                      [--check-image] [--rebuild]
    release.py download --tag v2.0.1 --dest DIR   a release's files from GitHub (no gh needed)

Trust model. A release is genuine when (1) at least ``maintainer_threshold`` of the maintainers
in release/allowed_signers signed its manifest, (2) the manifest was signed by the release
workflow's CI identity (Sigstore, keyless), and (3) everything it names — the source tarball,
the image, the networks' genesis files — has the hashes it records. Anyone can additionally
rebuild the image from the source and compare the image config digest, because the build is
reproducible. Verify with a policy and maintainer list you already trust (your own checkout's
release/ directory) — never with the copies shipped inside the release you are checking.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
MANIFEST_FORMAT = 1
DEFAULT_POLICY = REPO / "release" / "policy.json"
DEFAULT_SIGNERS = REPO / "release" / "allowed_signers"
# The BuildKit that release images are built with (scripts/release/build-image.sh). Pinned so a
# rebuild runs the same build engine.
BUILDKIT_IMAGE = ("moby/buildkit:v0.34.0@sha256:"
                  "b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c")


class ReleaseError(Exception):
    pass


# ── helpers ──────────────────────────────────────────────────────────────────────────────

def run(cmd: List[str], cwd: Optional[Path] = None, input: Optional[bytes] = None,
        check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, cwd=cwd, input=input, capture_output=True)
    except OSError as e:          # the program is missing, or cwd (e.g. a submodule) is absent
        raise ReleaseError(f"{' '.join(cmd)}: {e}") from e
    if check and proc.returncode != 0:
        raise ReleaseError(f"{' '.join(cmd)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc


def git(*args: str, cwd: Optional[Path] = None) -> str:
    return run(["git", "-c", "safe.directory=*", *args], cwd=cwd or REPO).stdout.decode().strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve(ref: str) -> str:
    return git("rev-parse", f"{ref}^{{commit}}")


def commit_time(ref: str) -> int:
    return int(git("show", "-s", "--format=%ct", resolve(ref)))


def submodules(commit: str) -> List[Tuple[str, str]]:
    """(path, commit) of every submodule recorded in ``commit``."""
    out = []
    for line in git("ls-tree", "-r", commit).splitlines():
        meta, path = line.split("\t", 1)
        mode, kind, obj = meta.split()
        if kind == "commit":
            out.append((path, obj))
    return sorted(out)


def gitmodules_paths(commit: str) -> Dict[str, str]:
    """{path: url} of the submodules ``commit``'s .gitmodules declares."""
    try:
        text = git("show", f"{commit}:.gitmodules")
    except ReleaseError:
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".gitmodules", delete=False) as fh:
        fh.write(text + "\n")
    try:
        found = run(["git", "config", "-f", fh.name, "--get-regexp", r"^submodule\..*\.(path|url)$"],
                    check=False).stdout.decode()
    finally:
        os.unlink(fh.name)
    paths, urls = {}, {}
    for line in found.splitlines():
        key, _, value = line.partition(" ")
        name, field = key[len("submodule."):].rsplit(".", 1)
        (paths if field == "path" else urls)[name] = value
    return {p: urls[n] for n, p in paths.items() if urls.get(n)}


def _release_tags(commit: str) -> List[str]:
    return sorted((t for t in git("tag", "--points-at", commit).splitlines()
                   if re.fullmatch(r"v\d+\.\d+\.\d+", t)),
                  key=lambda t: tuple(int(x) for x in t[1:].split(".")))


def version_of(ref: str) -> str:
    """``vX.Y.Z`` when ``ref`` is a release tag or a commit carrying one; otherwise
    ``dev-<short commit>``. Spelling the same commit as its tag or its hash gives the same
    answer — the version is built into the image, so it must be a function of the commit."""
    if re.fullmatch(r"v\d+\.\d+\.\d+", ref):
        return ref
    tags = _release_tags(resolve(ref))
    return tags[-1] if tags else f"dev-{resolve(ref)[:12]}"


# ── preflight ────────────────────────────────────────────────────────────────────────────

def preflight(ref: str) -> List[str]:
    """Why ``ref`` cannot be released (empty when it can)."""
    problems: List[str] = []
    commit = resolve(ref)
    version = version_of(ref)
    if not version.startswith("v"):
        problems.append(f"{ref} is not a release tag (vX.Y.Z)")
    others = [t for t in _release_tags(commit) if t != version]
    if version.startswith("v") and others:
        problems.append(f"commit {commit[:12]} also carries release tag(s) {', '.join(others)}: "
                        f"one commit, one release")
    # Every submodule the release records must be declared in .gitmodules (a fresh clone — the
    # release workflow's, an operator's — can fetch nothing else), and its commit available here.
    declared = gitmodules_paths(commit)
    for path, sub in submodules(commit):
        if path not in declared:
            problems.append(f"{path} is recorded as a submodule (commit {sub[:12]}) but has no "
                            f"url in .gitmodules: a fresh clone cannot fetch it. Declare it, or "
                            f"remove it (git rm --cached {path})")
            continue
        if not (REPO / path).is_dir():
            problems.append(f"submodule {path} is not checked out (git submodule update --init)")
            continue
        try:
            git("cat-file", "-e", f"{sub}^{{commit}}", cwd=REPO / path)
        except ReleaseError:
            problems.append(f"submodule {path} commit {sub[:12]} is not available locally "
                            f"(git submodule update --init)")
    status = git("status", "--porcelain", "--ignore-submodules=none")
    if status and resolve("HEAD") == commit:
        problems.append("the working tree has uncommitted changes (they would not be in the "
                        "release):\n" + "\n".join("    " + l for l in status.splitlines()[:20]))
    # One version everywhere.
    constants = git("show", f"{commit}:qrdx/constants.py")
    m = re.search(r"^NODE_VERSION\s*=\s*['\"]([^'\"]+)['\"]", constants, re.M)
    node_version = m.group(1) if m else None
    pyproject = git("show", f"{commit}:pyproject.toml")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    project_version = m.group(1) if m else None
    if version.startswith("v"):
        if node_version != version[1:]:
            problems.append(f"qrdx/constants.py NODE_VERSION is {node_version!r}, the tag {version}")
        if project_version != version[1:]:
            problems.append(f"pyproject.toml version is {project_version!r}, the tag {version}")
    # Every maintainer key must be usable for both signatures a release needs.
    try:
        signers_text = git("show", f"{commit}:release/allowed_signers")
    except ReleaseError:
        problems.append("release/allowed_signers is missing")
    else:
        problems += lint_allowed_signers(signers_text)
    # The image installs exactly the lock; the release workflow tests it with the test lock.
    for f in ("release/requirements.lock", "release/build-requirements.lock",
              "release/test-requirements.lock"):
        try:
            git("cat-file", "-e", f"{commit}:{f}")
        except ReleaseError:
            problems.append(f"{f} is missing")
    return problems


TAG_NAMESPACE = "git"   # what `git tag -s` signs under with an SSH key


def lint_allowed_signers(text: str, namespace: str = "qrdx-release") -> List[str]:
    """Maintainer lines that could not sign both a release tag (namespace "git") and a release
    manifest (``namespace``): a key restricted to one would silently fail the other check."""
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.search(r'(?:^|\s|,)namespaces="([^"]*)"', line)
        if m is None:
            problems.append(f"release/allowed_signers line {n}: no namespaces=\"{TAG_NAMESPACE},"
                            f"{namespace}\" restriction (an unrestricted key is valid for any purpose)")
            continue
        allowed = {x.strip() for x in m.group(1).split(",")}
        missing = sorted({TAG_NAMESPACE, namespace} - allowed)
        if missing:
            problems.append(f"release/allowed_signers line {n}: its key cannot sign in "
                            f"{', '.join(missing)} (needs namespaces=\"{TAG_NAMESPACE},{namespace}\")")
    return problems


# ── export & source tarball ──────────────────────────────────────────────────────────────

def _archive_members(ref_commit: str) -> List[Tuple[tarfile.TarInfo, Optional[bytes]]]:
    """Every file of the commit and of its submodules at their recorded commits, as git stores
    them (paths, content, executable bit) — nothing from the working tree."""
    members: Dict[str, Tuple[tarfile.TarInfo, Optional[bytes]]] = {}

    def add(tar_bytes: bytes) -> None:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            for info in tf.getmembers():
                if info.name == "pax_global_header":
                    continue
                data = tf.extractfile(info).read() if info.isfile() else None
                members[info.name.rstrip("/")] = (info, data)

    add(run(["git", "-c", "safe.directory=*", "archive", "--format=tar", ref_commit],
            cwd=REPO).stdout)
    for path, sub in submodules(ref_commit):
        add(run(["git", "-c", "safe.directory=*", "archive", "--format=tar",
                 f"--prefix={path}/", sub], cwd=REPO / path).stdout)
    return [members[k] for k in sorted(members)]


def canonical_tar(ref: str) -> bytes:
    """A deterministic tar of the release source: sorted, every timestamp the commit's,
    owner root, mode 0644/0755 by the executable bit git records."""
    commit = resolve(ref)
    mtime = commit_time(commit)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as out:
        for info, data in _archive_members(commit):
            ti = tarfile.TarInfo(info.name.rstrip("/"))
            ti.mtime = mtime
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.pax_headers = {}
            if info.isdir():
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                out.addfile(ti)
            elif info.issym():
                ti.type, ti.linkname, ti.mode = tarfile.SYMTYPE, info.linkname, 0o777
                out.addfile(ti)
            else:
                ti.mode = 0o755 if info.mode & 0o111 else 0o644
                ti.size = len(data or b"")
                out.addfile(ti, io.BytesIO(data or b""))
    return buf.getvalue()


def write_source_tarball(ref: str, out: Path) -> Dict[str, str]:
    tar_bytes = canonical_tar(ref)
    gz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz, mtime=0, compresslevel=9) as fh:
        fh.write(tar_bytes)
    out.write_bytes(gz.getvalue())
    # The uncompressed hash identifies the content whatever gzip implementation produced the
    # file; the file hash identifies the published artifact.
    return {"file": out.name, "sha256": sha256_file(out),
            "tar_sha256": hashlib.sha256(tar_bytes).hexdigest()}


def export(ref: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(canonical_tar(ref))) as tf:
        tf.extractall(dest, filter="tar") if sys.version_info >= (3, 12) else tf.extractall(dest)


# ── manifest ─────────────────────────────────────────────────────────────────────────────

def _dockerfile_args(dockerfile: str) -> Dict[str, str]:
    return dict(re.findall(r"^ARG\s+([A-Z_]+)=(\S+)", dockerfile, re.M))


def network_asset_name(network: str) -> str:
    """The release asset a network's genesis file is published as."""
    return f"{network}.genesis_config.json"


def _probe_source(source_dir: Path) -> Dict[str, Any]:
    """Facts only the release's own code can state: the consensus features it can execute, and
    every network genesis file it ships (networks/<name>/genesis_config.json) with its chain
    id, chain-spec hash and the forks it schedules — with the definition hashes validators
    approve on chain (docs/GOVERNANCE.md §4). Runs the release's chain_spec module, not ours."""
    files = sorted(source_dir.glob("networks/*/genesis_config.json"))
    probe = (
        "import json, sys\n"
        "from qrdx import chain_spec as cs\n"
        "nets = {}\n"
        "for path in sys.argv[1:]:\n"
        "    data, spec = cs.load_genesis_file(path)\n"
        "    nets[path] = {'network': spec.network, 'chain_id': spec.chain_id, 'dev': spec.dev,\n"
        "                  'spec_hash': spec.genesis_hash(),\n"
        "                  'genesis_block_hash': (data.get('block') or {}).get('block_hash'),\n"
        "                  'forks': [{'name': f['name'], 'height': f['height'],\n"
        "                             'features': f['features'],\n"
        "                             'definition_hash': cs.ChainSpec.fork_definition_hash(f)}\n"
        "                            for f in spec.forks]}\n"
        "print(json.dumps({'features': sorted(cs.FEATURES), 'networks': nets}))\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("QRDX_")}
    env["PYTHONPATH"] = str(source_dir)
    proc = subprocess.run([sys.executable, "-c", probe, *map(str, files)], cwd=source_dir,
                          env=env, capture_output=True)
    if proc.returncode != 0:
        raise ReleaseError(f"cannot read the release's chain specs: {proc.stderr.decode()[-800:]}")
    result = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    networks = {}
    for path in files:
        info = result["networks"][str(path)]
        info["file"] = str(path.relative_to(source_dir))
        info["asset"] = network_asset_name(info["network"])
        info["sha256"] = sha256_file(path)
        networks[info["network"]] = info
    return {"features": result["features"], "networks": networks}


def build_manifest(ref: str, image_ref: Optional[str], image_config: Optional[str],
                   platform: str, source: Optional[Dict[str, str]]) -> Dict[str, Any]:
    commit = resolve(ref)
    version = version_of(ref)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        export(commit, src)
        dockerfile = (src / "docker/Dockerfile").read_text()
        args = _dockerfile_args(dockerfile)
        node_version = re.search(r"^NODE_VERSION\s*=\s*['\"]([^'\"]+)['\"]",
                                 (src / "qrdx/constants.py").read_text(), re.M).group(1)
        probed = _probe_source(src)
        manifest: Dict[str, Any] = {
            "format": MANIFEST_FORMAT,
            "project": "qrdx-chain",
            "version": version,
            "node_version": node_version,
            "source": {
                "repository": "https://github.com/qrdx-org/qrdx-chain",
                "commit": commit,
                "tree": git("rev-parse", f"{commit}^{{tree}}"),
                "commit_time": commit_time(commit),
                "submodules": {p: c for p, c in submodules(commit)},
                **({"tarball": source} if source else {}),
            },
            "build": {
                "source_date_epoch": commit_time(commit),
                "dockerfile_sha256": hashlib.sha256(dockerfile.encode()).hexdigest(),
                "requirements_lock_sha256": sha256_file(src / "release/requirements.lock"),
                "build_requirements_lock_sha256": sha256_file(src / "release/build-requirements.lock"),
                "base_image": args.get("BASE_IMAGE"),
                "debian_snapshot": args.get("DEBIAN_SNAPSHOT"),
                "liboqs": {"version": args.get("LIBOQS_VERSION"), "commit": args.get("LIBOQS_COMMIT")},
                "buildkit": BUILDKIT_IMAGE,
            },
            "features": probed["features"],
            "networks": probed["networks"],
        }
    if image_ref or image_config:
        manifest["images"] = {platform: {"ref": image_ref, "config_digest": image_config}}
    return manifest


def write_manifest(manifest: Dict[str, Any], out: Path) -> None:
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


# ── signatures ───────────────────────────────────────────────────────────────────────────

def load_policy(path: Path) -> Dict[str, Any]:
    policy = json.loads(path.read_text())
    for key in ("maintainer_threshold", "signing_namespace"):
        if key not in policy:
            raise ReleaseError(f"{path}: missing {key}")
    if int(policy["maintainer_threshold"]) < 1:
        raise ReleaseError(f"{path}: maintainer_threshold must be at least 1")
    return policy


def sign(manifest: Path, key: Path, out: Path, namespace: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "manifest"
        shutil.copyfile(manifest, copy)
        run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(copy)])
        shutil.copyfile(str(copy) + ".sig", out)


def signer_of(manifest: Path, sig: Path, allowed_signers: Path, namespace: str) -> Optional[str]:
    """The maintainer (principal in allowed_signers) whose valid signature ``sig`` is, or None."""
    found = run(["ssh-keygen", "-Y", "find-principals", "-s", str(sig), "-f", str(allowed_signers)],
                check=False)
    for principal in found.stdout.decode().split():
        ok = run(["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", principal,
                  "-n", namespace, "-s", str(sig)], input=manifest.read_bytes(), check=False)
        if ok.returncode == 0:
            return principal
    return None


def maintainer_signers(manifest: Path, signatures: Path, allowed_signers: Path,
                       namespace: str) -> Tuple[List[str], List[str]]:
    """(distinct maintainers with a valid signature, signature files that did not verify)."""
    sigs = sorted(signatures.glob("*.sig")) if signatures.is_dir() else [signatures]
    good, bad = set(), []
    for sig in sigs:
        who = signer_of(manifest, sig, allowed_signers, namespace)
        if who:
            good.add(who)
        else:
            bad.append(sig.name)
    return sorted(good), bad


# ── verification ─────────────────────────────────────────────────────────────────────────

def image_config_digest(image_ref: str) -> str:
    """The config digest of a pushed image (what a reproducible rebuild must match)."""
    if shutil.which("docker") is None:
        raise ReleaseError("docker is not installed; cannot inspect the published image")
    out = run(["docker", "buildx", "imagetools", "inspect", image_ref, "--raw"]).stdout
    doc = json.loads(out)
    if "manifests" in doc:
        raise ReleaseError(f"{image_ref} is an index; name the platform manifest by digest")
    return doc["config"]["digest"]


def verify(manifest_path: Path, signatures: Optional[Path], policy_path: Path,
           signers_path: Path, cosign_bundle: Optional[Path], artifacts: Optional[Path],
           check_image: bool, rebuild: bool, skip_ci: bool, candidate: bool = False) -> List[str]:
    """Every reason the release is not genuine (empty when it is), printing what holds.

    ``candidate``: a draft a maintainer is about to sign — every check runs, but too few
    maintainer signatures is reported rather than failed (the signatures are what is missing)."""
    failures: List[str] = []

    def ok(msg: str) -> None:
        print(f"  ✓ {msg}")

    def fail(msg: str) -> None:
        print(f"  ✗ {msg}")
        failures.append(msg)

    policy = load_policy(policy_path)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("format") != MANIFEST_FORMAT:
        fail(f"manifest format {manifest.get('format')!r} is not {MANIFEST_FORMAT}")
        return failures
    print(f"Release {manifest['version']} — commit {manifest['source']['commit']}")

    # 1. Maintainers (k of n).
    threshold = int(policy["maintainer_threshold"])
    if not signers_path.exists() or not signers_path.read_text().strip() or \
            all(l.strip().startswith("#") or not l.strip() for l in signers_path.read_text().splitlines()):
        fail(f"no maintainers are listed in {signers_path}; nothing can be verified against it")
    elif signatures is None and not candidate:
        fail("no maintainer signatures given (--signatures)")
    else:
        good, bad = ([], []) if signatures is None else maintainer_signers(
            manifest_path, signatures, signers_path, policy["signing_namespace"])
        for name in bad:
            print(f"  · ignored {name}: not a valid signature by a listed maintainer")
        if len(good) >= threshold:
            ok(f"signed by {len(good)} maintainer(s) — {', '.join(good)} (threshold {threshold})")
        elif candidate:
            print(f"  · candidate: {len(good)} of {threshold} maintainer signature(s) so far"
                  + (f" — {', '.join(good)}" if good else ""))
        else:
            fail(f"signed by {len(good)} listed maintainer(s) {good}; the policy requires {threshold}")

    # 2. The release workflow's own signature (Sigstore keyless).
    ci = policy.get("ci_identity")
    if ci and not skip_ci:
        if cosign_bundle is None:
            fail("no CI signature bundle given (--cosign-bundle); pass --skip-ci-signature to "
                 "rely on maintainer signatures alone")
        elif shutil.which("cosign") is None:
            fail("cosign is not installed (https://docs.sigstore.dev); cannot check the CI signature")
        else:
            res = run(["cosign", "verify-blob", "--bundle", str(cosign_bundle),
                       "--certificate-identity-regexp", ci["identity_regexp"],
                       "--certificate-oidc-issuer", ci["issuer"], str(manifest_path)], check=False)
            if res.returncode == 0:
                ok(f"signed by the release workflow ({ci['issuer']})")
            else:
                fail(f"CI signature does not verify: {res.stderr.decode().strip()[-300:]}")

    # 3. Artifacts it names.
    if artifacts is not None:
        named = []
        tarball = manifest["source"].get("tarball")
        if tarball:
            named.append((tarball["file"], tarball["sha256"]))
        for net in manifest.get("networks", {}).values():
            named.append((net["asset"], net["sha256"]))
        for name, digest in named:
            path = artifacts / name
            if not path.exists():
                print(f"  · {name} not present in {artifacts}; not checked")
            elif sha256_file(path) == digest:
                ok(f"{name} matches the manifest")
            else:
                fail(f"{name} does NOT match the manifest (sha256 {sha256_file(path)}, "
                     f"manifest {digest})")

    # 4. The published image is the one recorded, and (optionally) rebuilds identically.
    for platform, image in (manifest.get("images") or {}).items():
        if check_image and image.get("ref"):
            actual = image_config_digest(image["ref"])
            if actual == image["config_digest"]:
                ok(f"{platform} image {image['ref']} has config {actual}")
            else:
                fail(f"{platform} image config is {actual}, the manifest records "
                     f"{image['config_digest']}")
        if rebuild:
            built = rebuild_image(manifest["source"]["commit"], platform, manifest["version"])
            if built == image["config_digest"]:
                ok(f"{platform} rebuild from source reproduces config {built}")
            else:
                fail(f"{platform} rebuild produced config {built}, the manifest records "
                     f"{image['config_digest']} — the release image is NOT what its source builds")
    return failures


def rebuild_image(ref: str, platform: str, version: str) -> str:
    """Rebuild the image for ``platform`` from the committed source, reporting ``version``
    (the manifest's); return its config digest."""
    script = REPO / "scripts" / "release" / "build-image.sh"
    out = run(["bash", str(script), "--ref", ref, "--platform", platform, "--version", version,
               "--print-config-digest"], cwd=REPO).stdout.decode().strip().splitlines()
    return out[-1].strip()


# ── download ─────────────────────────────────────────────────────────────────────────────

_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,200}")


def _github(url: str, token: Optional[str], accept: str = "application/vnd.github+json") -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "qrdx-release",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def download(repository: str, tag: str, dest: Path, token: Optional[str] = None,
             api: str = "https://api.github.com") -> List[str]:
    """Fetch every asset of ``tag``'s GitHub release into ``dest``. Nothing fetched is trusted:
    it is only input to ``verify``. With a token, a draft release is found too (maintainers
    checking a candidate); without one, only published releases are visible."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ReleaseError(f"not a GitHub owner/repo: {repository!r}")
    base = f"{api}/repos/{repository}/releases"
    release = None
    if token:
        for page in range(1, 11):
            batch = json.loads(_github(f"{base}?per_page=100&page={page}", token))
            release = next((r for r in batch if r.get("tag_name") == tag), None)
            if release or len(batch) < 100:
                break
    else:
        try:
            release = json.loads(_github(f"{base}/tags/{urllib.parse.quote(tag, safe='')}", None))
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    if not release:
        raise ReleaseError(f"{repository} has no release {tag}"
                           + ("" if token else " (a draft needs GH_TOKEN/GITHUB_TOKEN)"))
    dest.mkdir(parents=True, exist_ok=True)
    names = []
    for asset in release.get("assets", []):
        name = asset["name"]
        # Asset names come from the network: never let one choose where it is written.
        if not _ASSET_NAME.fullmatch(name) or ".." in name:
            raise ReleaseError(f"refusing release asset with an unsafe name: {name!r}")
        data = _github(asset["url"], token, accept="application/octet-stream")
        (dest / name).write_bytes(data)
        names.append(name)
    return sorted(names)


# ── CLI ──────────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("preflight", help="refuse a release that is not clean and consistent")
    p.add_argument("--ref", required=True)

    p = sub.add_parser("version", help="the version a ref builds as (vX.Y.Z or dev-<commit>)")
    p.add_argument("--ref", default="HEAD")

    p = sub.add_parser("export", help="the committed tree and its submodules, nothing else")
    p.add_argument("--ref", default="HEAD")
    p.add_argument("--dest", required=True, type=Path)

    p = sub.add_parser("source-tarball", help="deterministic source tarball")
    p.add_argument("--ref", default="HEAD")
    p.add_argument("--out", required=True, type=Path)

    p = sub.add_parser("manifest", help="write the release manifest")
    p.add_argument("--ref", required=True)
    p.add_argument("--image-ref")
    p.add_argument("--image-config")
    p.add_argument("--platform", default="linux/amd64")
    p.add_argument("--source-tarball", type=Path)
    p.add_argument("--out", required=True, type=Path)

    p = sub.add_parser("sign", help="sign a manifest with a maintainer's SSH key")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)

    p = sub.add_parser("verify", help="check a release against a trusted policy")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--signatures", type=Path, help="a .sig file or a directory of them")
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--allowed-signers", type=Path, default=DEFAULT_SIGNERS)
    p.add_argument("--cosign-bundle", type=Path)
    p.add_argument("--skip-ci-signature", action="store_true")
    p.add_argument("--artifacts", type=Path, help="directory holding the downloaded release files")
    p.add_argument("--check-image", action="store_true", help="pull the image's manifest and compare")
    p.add_argument("--rebuild", action="store_true", help="rebuild the image from source and compare")
    p.add_argument("--candidate", action="store_true",
                   help="a draft awaiting signatures: too few maintainer signatures is not a failure")

    p = sub.add_parser("download", help="a release's files from GitHub (untrusted until verified)")
    p.add_argument("--tag", required=True)
    p.add_argument("--dest", required=True, type=Path)
    p.add_argument("--repository", help="owner/repo (default: github_repository in the policy)")
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)

    a = ap.parse_args(argv)
    try:
        if a.cmd == "preflight":
            problems = preflight(a.ref)
            for prob in problems:
                print(f"✗ {prob}")
            if not problems:
                print(f"✓ {a.ref} ({resolve(a.ref)[:12]}) can be released as {version_of(a.ref)}")
            return 1 if problems else 0
        if a.cmd == "version":
            print(version_of(a.ref))
            return 0
        if a.cmd == "export":
            export(a.ref, a.dest)
            print(a.dest)
            return 0
        if a.cmd == "source-tarball":
            info = write_source_tarball(a.ref, a.out)
            print(json.dumps(info, indent=2))
            return 0
        if a.cmd == "manifest":
            source = None
            if a.source_tarball:
                source = {"file": a.source_tarball.name, "sha256": sha256_file(a.source_tarball),
                          "tar_sha256": hashlib.sha256(gzip.decompress(a.source_tarball.read_bytes())).hexdigest()}
            write_manifest(build_manifest(a.ref, a.image_ref, a.image_config, a.platform, source), a.out)
            print(a.out)
            return 0
        if a.cmd == "sign":
            sign(a.manifest, a.key, a.out, load_policy(a.policy)["signing_namespace"])
            print(a.out)
            return 0
        if a.cmd == "verify":
            failures = verify(a.manifest, a.signatures, a.policy, a.allowed_signers, a.cosign_bundle,
                              a.artifacts, a.check_image, a.rebuild, a.skip_ci_signature,
                              candidate=a.candidate)
            what = "CANDIDATE" if a.candidate else "RELEASE"
            print(f"\n{what} VERIFIED" if not failures else f"\n{what} NOT VERIFIED ({len(failures)} problem(s))")
            return 0 if not failures else 1
        if a.cmd == "download":
            repository = a.repository or load_policy(a.policy).get("github_repository")
            if not repository:
                raise ReleaseError("no --repository and no github_repository in the policy")
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            for name in download(repository, a.tag, a.dest, token):
                print(a.dest / name)
            return 0
    except ReleaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
