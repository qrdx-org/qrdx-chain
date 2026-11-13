#!/usr/bin/env bash
# An operator's check of a published release before running it (docs/RELEASES.md §5).
#
#   scripts/release/verify-release.sh vX.Y.Z [--rebuild] [--network NAME] [--dest DIR]
#                                            [--policy FILE] [--allowed-signers FILE]
#
# Downloads the release from GitHub (nothing downloaded is trusted) and verifies it against the
# policy and maintainer list in THIS checkout — or the ones given — never against copies inside
# the release itself:
#
#   * at least `maintainer_threshold` listed maintainers signed the manifest;
#   * the release workflow signed it (Sigstore keyless; needs cosign);
#   * the source tarball and genesis files have the hashes the manifest records;
#   * the image in the registry has the config digest the manifest records (needs docker);
#   * with --rebuild: the image rebuilt here from the release's commit is identical.
#
# On success it prints the image to run (by digest) and, for --network, that network's genesis
# file and scheduled upgrades with the definition hashes validators approve on chain.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RELEASE_PY="$REPO/scripts/release/release.py"
POLICY="$REPO/release/policy.json"; SIGNERS="$REPO/release/allowed_signers"
TAG=""; REBUILD=(); NETWORK=""; DEST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild) REBUILD=(--rebuild); shift ;;
    --network) NETWORK="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --allowed-signers) SIGNERS="$2"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    v*) TAG="$1"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: verify-release.sh vX.Y.Z [options]" >&2; exit 2; }
[[ -n "$DEST" ]] || DEST="$(pwd)/qrdx-release-$TAG"
if [[ -e "$DEST" ]] && [[ -n "$(ls -A "$DEST" 2>/dev/null)" ]]; then
  echo "$DEST exists and is not empty; choose another --dest" >&2; exit 2
fi

echo "Trust root (compare these out of band with the project's published values):"
echo "  policy           $POLICY  sha256 $(sha256sum "$POLICY" | cut -d' ' -f1)"
echo "  allowed_signers  $SIGNERS  sha256 $(sha256sum "$SIGNERS" | cut -d' ' -f1)"
echo

python3 "$RELEASE_PY" download --tag "$TAG" --dest "$DEST" --policy "$POLICY" >/dev/null
MANIFEST="$DEST/release-manifest.json"
[[ -f "$MANIFEST" ]] || { echo "the release has no release-manifest.json" >&2; exit 1; }

python3 "$RELEASE_PY" verify --manifest "$MANIFEST" --signatures "$DEST" \
    --policy "$POLICY" --allowed-signers "$SIGNERS" \
    --cosign-bundle "$DEST/release-manifest.json.cosign.bundle" --artifacts "$DEST" \
    --check-image ${REBUILD[@]+"${REBUILD[@]}"}

python3 - "$MANIFEST" "$TAG" "$NETWORK" "$DEST" <<'EOF'
import json, sys
manifest, tag, network, dest = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4]
if manifest["version"] != tag:
    sys.exit(f"the manifest is for {manifest['version']}, not {tag}")
print("\nRun this release by digest:")
for platform, image in sorted(manifest.get("images", {}).items()):
    print(f"  {platform}: {image['ref']}")
nets = manifest.get("networks", {})
if network:
    net = nets.get(network)
    if net is None:
        sys.exit(f"\nthis release ships no genesis file for network {network!r} (has: {', '.join(sorted(nets)) or 'none'})")
    print(f"\n{network} (chain id {net['chain_id']}): genesis file {dest}/{net['asset']}")
    print(f"  chain spec hash {net['spec_hash']}")
    for fork in net.get("forks", []):
        print(f"  fork {fork['name']} at height {fork['height']}: {', '.join(fork['features'])}")
        print(f"    definition hash {fork['definition_hash']} — activates only if validators "
              f"approved exactly this on chain (governance_getForkApprovalParams)")
elif nets:
    print(f"\nNetworks in this release: {', '.join(sorted(nets))} (--network NAME for details)")
EOF
