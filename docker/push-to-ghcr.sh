#!/bin/bash
set -e

# Push Docker image to GitHub Container Registry (ghcr.io)
# Usage: ./push-to-ghcr.sh [TAG] [REPOSITORY]
#   TAG: Docker tag (default: latest)
#   REPOSITORY: GitHub repository in format owner/repo (default: qrdx-org/qrdx-chain)

TAG="${1:-latest}"
REPOSITORY="${2:-qrdx-org/qrdx-chain}"
IMAGE_NAME="qrdx-node"
REGISTRY="ghcr.io"

echo "=================================================="
echo "Pushing to GitHub Container Registry"
echo "=================================================="
echo "Registry:   $REGISTRY"
echo "Repository: $REPOSITORY"
echo "Image:      $IMAGE_NAME"
echo "Tag:        $TAG"
echo "=================================================="
echo ""

# Check if local image exists
if ! docker image inspect "${IMAGE_NAME}:${TAG}" >/dev/null 2>&1; then
    echo "❌ Error: Local image ${IMAGE_NAME}:${TAG} not found"
    echo "Please build the image first:"
    echo "  docker build -f docker/Dockerfile -t ${IMAGE_NAME}:${TAG} ."
    exit 1
fi

# Check if GitHub token is set
if [ -z "$GITHUB_TOKEN" ]; then
    echo "⚠️  GITHUB_TOKEN environment variable not set"
    echo "Please set it with a Personal Access Token that has 'write:packages' scope:"
    echo "  export GITHUB_TOKEN=ghp_your_token_here"
    echo ""
    read -p "Continue anyway and enter credentials manually? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    MANUAL_LOGIN=true
else
    MANUAL_LOGIN=false
fi

# Login to GitHub Container Registry
echo "🔐 Logging in to $REGISTRY..."
if [ "$MANUAL_LOGIN" = true ]; then
    docker login "$REGISTRY"
else
    echo "$GITHUB_TOKEN" | docker login "$REGISTRY" -u "$GITHUB_USER" --password-stdin
fi

if [ $? -ne 0 ]; then
    echo "❌ Login failed"
    exit 1
fi
echo "✅ Login successful"
echo ""

# Tag the image for ghcr
GHCR_IMAGE="$REGISTRY/$REPOSITORY"
echo "🏷️  Tagging image..."
docker tag "${IMAGE_NAME}:${TAG}" "${GHCR_IMAGE}:${TAG}"
echo "✅ Tagged as ${GHCR_IMAGE}:${TAG}"
echo ""

# Push to registry
echo "📤 Pushing to registry..."
docker push "${GHCR_IMAGE}:${TAG}"

if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================="
    echo "✅ Successfully pushed to GitHub Container Registry!"
    echo "=================================================="
    echo ""
    echo "Pull the image with:"
    echo "  docker pull ${GHCR_IMAGE}:${TAG}"
    echo ""
    echo "Run the image with:"
    echo "  docker run --rm ${GHCR_IMAGE}:${TAG} --help"
    echo ""
else
    echo "❌ Push failed"
    exit 1
fi
