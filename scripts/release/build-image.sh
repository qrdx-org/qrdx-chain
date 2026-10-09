#!/usr/bin/env bash
# Reproducible build of the QRDX node image (docs/RELEASES.md).
#
#   scripts/release/build-image.sh [--ref REF | --worktree] [--platform linux/amd64]
#                                  [--version vX.Y.Z] [--push REPO] [--load TAG] [--oci FILE]
#                                  [--metadata FILE] [--print-config-digest]
#
# --ref REF     build the COMMITTED tree at REF (default HEAD), submodules at their recorded
#               commits — never the working directory. This is how releases are built.
# --worktree    build the working directory instead (development only; not reproducible
#               against any commit, and refused for --push).
# --version V   the version the image reports (labels, QRDX_BUILD_VERSION). Default: the
#               release tag on the commit, else dev-<commit>. It is part of the image, so a
#               rebuild of a release passes the version its manifest records.
#
# Every build runs in a fresh BuildKit container of a pinned version, with no cache, with
# SOURCE_DATE_EPOCH set to the commit's time and layer timestamps rewritten to it — so two
# builds of the same commit produce the same image config digest. It is printed last.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILDKIT_IMAGE="moby/buildkit:v0.34.0@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c"

REF="HEAD"; WORKTREE=0; PLATFORM="linux/amd64"; VERSION=""; PUSH=""; LOAD=""; OCI=""; META=""; PRINT_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --worktree) WORKTREE=1; shift ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --push) PUSH="$2"; shift 2 ;;
    --load) LOAD="$2"; shift 2 ;;
    --oci) OCI="$2"; shift 2 ;;
    --metadata) META="$2"; shift 2 ;;
    --print-config-digest) PRINT_ONLY=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "$PUSH" && "$WORKTREE" == 1 ]]; then
  echo "refusing to push a working-tree build: release images are built from a commit (--ref)" >&2
  exit 2
fi

log() { if [[ "$PRINT_ONLY" == 1 ]]; then echo "$*" >&2; else echo "$*"; fi; }
git_() { git -c safe.directory='*' -C "$REPO" "$@"; }

COMMIT="$(git_ rev-parse "${REF}^{commit}")"
SOURCE_DATE_EPOCH="$(git_ show -s --format=%ct "$COMMIT")"
# A function of the commit (never of how REF was spelled — a tag name and its commit hash must
# build the same image).
[[ -n "$VERSION" ]] || VERSION="$(python3 "$REPO/scripts/release/release.py" version --ref "$COMMIT")"

WORK="$(mktemp -d)"
BUILDER="qrdx-repro-$$-$RANDOM"
cleanup() {
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "$WORKTREE" == 1 ]]; then
  CONTEXT="$REPO"
  if [[ -n "$(git_ status --porcelain --ignore-submodules=none)" ]]; then
    VERSION="${VERSION}-dirty"; COMMIT_LABEL="${COMMIT}-dirty"
  else
    COMMIT_LABEL="$COMMIT"
  fi
  log "Building the WORKING TREE (development; ${VERSION})"
else
  CONTEXT="$WORK/src"
  python3 "$REPO/scripts/release/release.py" export --ref "$COMMIT" --dest "$CONTEXT" >/dev/null
  cp "$REPO/.dockerignore" "$CONTEXT/.dockerignore" 2>/dev/null || true
  COMMIT_LABEL="$COMMIT"
  log "Building commit ${COMMIT} (${VERSION}) from a clean export"
fi
log "  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}  platform=${PLATFORM}  buildkit=${BUILDKIT_IMAGE%%@*}"

docker buildx create --name "$BUILDER" --driver docker-container \
  --driver-opt "image=${BUILDKIT_IMAGE}" >/dev/null
docker buildx inspect "$BUILDER" --bootstrap >/dev/null

# Everything but a push is exported as an OCI archive — the exporter that always reports the
# config digest — and --load then loads that archive. (BuildKit's docker exporter omits the
# config digest from its metadata.) The name is an index annotation: it is not part of the
# image, so it changes no digest.
OCI_DEST="${OCI:-$WORK/image.oci.tar}"
if [[ -n "$PUSH" ]]; then
  OUTPUT="type=image,name=${PUSH}:${VERSION},push=true,oci-mediatypes=true,rewrite-timestamp=true"
else
  OUTPUT="type=oci,dest=${OCI_DEST},rewrite-timestamp=true${LOAD:+,name=${LOAD}}"
fi
METADATA="${META:-$WORK/metadata.json}"

# No provenance/SBOM attestations here: they carry build-time metadata into the image index.
# The release workflow attaches signed provenance and an SBOM separately (docs/RELEASES.md).
docker buildx build \
  --builder "$BUILDER" \
  --platform "$PLATFORM" \
  --no-cache \
  --provenance=false --sbom=false \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --build-arg "QRDX_VERSION=${VERSION}" \
  --build-arg "QRDX_GIT_COMMIT=${COMMIT_LABEL}" \
  --file "$CONTEXT/docker/Dockerfile" \
  --metadata-file "$METADATA" \
  --output "$OUTPUT" \
  "$CONTEXT" 1>&2

meta() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$METADATA" "$1"; }
CONFIG="$(meta containerimage.config.digest)"
DIGEST="$(meta containerimage.digest)"
if [[ -n "$PUSH" ]]; then
  # What the registry serves under the pushed digest, not what the builder says it sent.
  CONFIG="$(docker buildx imagetools inspect "${PUSH}@${DIGEST}" --raw \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["config"]["digest"])')"
fi
[[ "$CONFIG" == sha256:* ]] || { echo "the build reported no image config digest" >&2; exit 1; }
if [[ -n "$LOAD" ]]; then
  docker load -i "$OCI_DEST" >&2
  LOADED="$(docker image inspect "$LOAD" --format '{{.Id}}')"
  [[ "$LOADED" == "$DIGEST" || "$LOADED" == "$CONFIG" ]] \
    || { echo "loaded $LOAD is $LOADED, not the image just built ($DIGEST)" >&2; exit 1; }
fi
if [[ "$PRINT_ONLY" == 1 ]]; then
  echo "$CONFIG"
else
  echo "version:        ${VERSION}"
  echo "commit:         ${COMMIT_LABEL}"
  echo "platform:       ${PLATFORM}"
  echo "manifest:       ${DIGEST}"
  echo "config digest:  ${CONFIG}"
fi
