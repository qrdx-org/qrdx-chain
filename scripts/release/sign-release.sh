#!/usr/bin/env bash
# A maintainer's review-and-sign of a DRAFT release (docs/RELEASES.md §4).
#
#   scripts/release/sign-release.sh vX.Y.Z [--key ~/.ssh/id_ed25519] [--publish]
#
# Run it from an up-to-date checkout of the default branch: its release/policy.json and
# release/allowed_signers are the trust root, and they are checked against origin's before
# anything else. It signs nothing it has not independently reproduced:
#
#   1. the tag is signed by a listed maintainer, and the tagged tree is releasable (preflight);
#   2. the draft was produced by the release workflow (its Sigstore signature), the image it
#      names is the one in the registry, and every file it names has the recorded hash;
#   3. the source tarball and the manifest REGENERATED HERE from the tag are byte-identical to
#      the draft's — so every field in the manifest is what the tag says, not what CI says;
#   4. the image REBUILT HERE from the tag has the config digest the manifest records;
#
# then signs the manifest with the maintainer's SSH key (namespace from the policy) and
# uploads the signature to the draft. With --publish, once the policy's threshold of distinct
# maintainers has signed, the release is verified once more in full and published.
#
# Needs: git, python3, ssh-keygen, docker (with buildx), cosign, gh (authenticated).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RELEASE_PY="$REPO/scripts/release/release.py"
POLICY="$REPO/release/policy.json"
SIGNERS="$REPO/release/allowed_signers"

TAG=""; KEY="${QRDX_RELEASE_SIGNING_KEY:-$HOME/.ssh/id_ed25519}"; PUBLISH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --publish) PUBLISH=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    v*) TAG="$1"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: sign-release.sh vX.Y.Z [--key KEY] [--publish]" >&2; exit 2; }
for tool in git python3 ssh-keygen docker cosign gh; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
[[ -r "$KEY" ]] || { echo "signing key $KEY is not readable (--key, or QRDX_RELEASE_SIGNING_KEY)" >&2; exit 2; }

step() { printf '\n== %s\n' "$*"; }
die() { echo "REFUSING TO SIGN: $*" >&2; exit 1; }
git_() { git -c safe.directory='*' -C "$REPO" "$@"; }
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {'d': d}))" "$@"; }

GH_REPO="$(json "$POLICY" 'd["github_repository"]')"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
DRAFT="$WORK/draft"; REGEN="$WORK/regen"; mkdir -p "$REGEN"

step "Trust root: this checkout's release policy is the default branch's"
git_ fetch --quiet origin --tags
DEFAULT_BRANCH="$(git_ symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)"
for f in release/policy.json release/allowed_signers; do
  git_ diff --quiet "$DEFAULT_BRANCH" -- "$f" \
    || die "$f differs from $DEFAULT_BRANCH — sign from an unmodified, up-to-date checkout"
done
echo "policy and maintainer list match $DEFAULT_BRANCH"

step "1. The tag is signed by a maintainer and is releasable"
git_ -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$SIGNERS" verify-tag "$TAG" \
  || die "$TAG is not signed by a maintainer listed in release/allowed_signers"
python3 "$RELEASE_PY" preflight --ref "$TAG" || die "$TAG fails preflight"

step "2. The draft: CI signature, recorded hashes, the published image"
GH_TOKEN="${GH_TOKEN:-$(gh auth token)}" python3 "$RELEASE_PY" download --tag "$TAG" --dest "$DRAFT" >/dev/null
MANIFEST="$DRAFT/release-manifest.json"
[[ -f "$MANIFEST" ]] || die "the draft has no release-manifest.json"
[[ "$(json "$MANIFEST" 'd["version"]')" == "$TAG" ]] || die "the draft's manifest is not for $TAG"
python3 "$RELEASE_PY" verify --candidate --manifest "$MANIFEST" --signatures "$DRAFT" \
    --cosign-bundle "$DRAFT/release-manifest.json.cosign.bundle" --artifacts "$DRAFT" \
    --check-image \
  || die "the draft does not verify"

step "3. Regenerate the source tarball and manifest from the tag; they must be identical"
[[ "$(json "$MANIFEST" 'len(d.get("images") or {})')" == 1 ]] \
  || die "expected exactly one platform image in the manifest"
PLATFORM="$(json "$MANIFEST" 'next(iter(d["images"]))')"
IMAGE_REF="$(json "$MANIFEST" 'next(iter(d["images"].values()))["ref"]')"
IMAGE_CONFIG="$(json "$MANIFEST" 'next(iter(d["images"].values()))["config_digest"]')"
TARBALL="$(json "$MANIFEST" 'd["source"]["tarball"]["file"]')"
python3 "$RELEASE_PY" source-tarball --ref "$TAG" --out "$REGEN/$TARBALL" >/dev/null
cmp -s "$REGEN/$TARBALL" "$DRAFT/$TARBALL" || die "$TARBALL is not what $TAG produces"
python3 "$RELEASE_PY" manifest --ref "$TAG" --platform "$PLATFORM" --image-ref "$IMAGE_REF" \
    --image-config "$IMAGE_CONFIG" --source-tarball "$REGEN/$TARBALL" \
    --out "$REGEN/release-manifest.json" >/dev/null
if ! cmp -s "$REGEN/release-manifest.json" "$MANIFEST"; then
  diff -u "$REGEN/release-manifest.json" "$MANIFEST" >&2 || true
  die "the draft's manifest is not what $TAG produces (diff above: regenerated → draft)"
fi
echo "source tarball and manifest reproduced byte for byte"

step "4. Rebuild the image from the tag ($PLATFORM); the config digest must match"
BUILT="$(bash "$REPO/scripts/release/build-image.sh" --ref "$TAG" --platform "$PLATFORM" --print-config-digest)"
[[ "$BUILT" == "$IMAGE_CONFIG" ]] \
  || die "the rebuild produced $BUILT; the release records $IMAGE_CONFIG"
echo "rebuilt $BUILT — identical to the release image"

step "Sign"
python3 "$RELEASE_PY" sign --manifest "$MANIFEST" --key "$KEY" --out "$WORK/candidate.sig" >/dev/null
PRINCIPAL="$(ssh-keygen -Y find-principals -s "$WORK/candidate.sig" -f "$SIGNERS" | head -1)"
[[ -n "$PRINCIPAL" ]] || die "$KEY is not a maintainer key listed in release/allowed_signers"
NAMESPACE="$(json "$POLICY" 'd["signing_namespace"]')"
ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$WORK/candidate.sig" \
    < "$MANIFEST" >/dev/null || die "the new signature does not verify"
SIG_NAME="maintainer-$(printf '%s' "$PRINCIPAL" | tr -c 'A-Za-z0-9._-' '_').sig"
mv "$WORK/candidate.sig" "$WORK/$SIG_NAME"
gh release upload "$TAG" "$WORK/$SIG_NAME" --repo "$GH_REPO" --clobber
echo "signed as $PRINCIPAL → $SIG_NAME uploaded to the draft"

if [[ "$PUBLISH" == 1 ]]; then
  step "Publish (only when the full policy holds)"
  rm -rf "$DRAFT"
  GH_TOKEN="${GH_TOKEN:-$(gh auth token)}" python3 "$RELEASE_PY" download --tag "$TAG" --dest "$DRAFT" >/dev/null
  if python3 "$RELEASE_PY" verify --manifest "$DRAFT/release-manifest.json" --signatures "$DRAFT" \
       --cosign-bundle "$DRAFT/release-manifest.json.cosign.bundle" --artifacts "$DRAFT" --check-image; then
    gh release edit "$TAG" --repo "$GH_REPO" --draft=false --latest
    echo "published $TAG"
  else
    echo "not published yet: the release does not meet the policy (above)"
  fi
fi
