#!/bin/bash
set -e

# Push Docker images to GitHub Container Registry (ghcr.io)
# Usage: ./push-both-to-ghcr.sh [TAG] [REPOSITORY] [TARGET]
#   TAG: Docker tag (default: latest)
#   REPOSITORY: GitHub repository in format owner/repo (default: qrdx-org/qrdx-chain)
#   TARGET: Which images to push - node/validator/both (default: both)

TAG="${1:-latest}"
REPOSITORY="${2:-qrdx-org/qrdx-chain}"
TARGET="${3:-both}"
REGISTRY="ghcr.io"

echo "=================================================="
echo "Pushing to GitHub Container Registry"
echo "=================================================="
echo "Registry:   $REGISTRY"
echo "Repository: $REPOSITORY"
echo "Tag:        $TAG"
echo "Target:     $TARGET"
echo "=================================================="
echo ""

# Validate target
if [[ ! "$TARGET" =~ ^(node|validator|both)$ ]]; then
    echo "❌ Error: Invalid target '$TARGET'"
    echo "Valid options: node, validator, both"
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

# Function to push an image
push_image() {
    local IMAGE_TYPE=$1
    local LOCAL_NAME=$2
    local GHCR_NAME="$REGISTRY/$REPOSITORY/$IMAGE_TYPE"
    
    echo "=================================================="
    echo "Processing: $IMAGE_TYPE"
    echo "=================================================="
    
    # Check if local image exists
    if ! docker image inspect "${LOCAL_NAME}:${TAG}" >/dev/null 2>&1; then
        echo "❌ Error: Local image ${LOCAL_NAME}:${TAG} not found"
        echo "Please build the image first:"
        echo "  docker build -f docker/Dockerfile.${IMAGE_TYPE##*-} -t ${LOCAL_NAME}:${TAG} ."
        return 1
    fi
    
    # Tag the image for ghcr
    echo "🏷️  Tagging image..."
    docker tag "${LOCAL_NAME}:${TAG}" "${GHCR_NAME}:${TAG}"
    echo "✅ Tagged as ${GHCR_NAME}:${TAG}"
    echo ""
    
    # Push to registry
    echo "📤 Pushing to registry..."
    docker push "${GHCR_NAME}:${TAG}"
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully pushed ${IMAGE_TYPE}!"
        echo ""
        return 0
    else
        echo "❌ Push failed for ${IMAGE_TYPE}"
        return 1
    fi
}

# Push based on target
FAILED=0

if [ "$TARGET" == "node" ] || [ "$TARGET" == "both" ]; then
    push_image "qrdx-node" "qrdx-node" || FAILED=1
fi

if [ "$TARGET" == "validator" ] || [ "$TARGET" == "both" ]; then
    push_image "qrdx-validator" "qrdx-validator" || FAILED=1
fi

# Final summary
echo "=================================================="
if [ $FAILED -eq 0 ]; then
    echo "✅ All images pushed successfully!"
else
    echo "⚠️  Some images failed to push"
fi
echo "=================================================="
echo ""

if [ $FAILED -eq 0 ]; then
    echo "Pull and run the images:"
    echo ""
    
    if [ "$TARGET" == "node" ] || [ "$TARGET" == "both" ]; then
        echo "# Full Node (no validator)"
        echo "docker pull $REGISTRY/$REPOSITORY/qrdx-node:$TAG"
        echo "docker run -d -p 30303:30303 -p 8545:8545 \\"
        echo "  -v qrdx-node-data:/root/.local/share/trinity \\"
        echo "  $REGISTRY/$REPOSITORY/qrdx-node:$TAG"
        echo ""
    fi
    
    if [ "$TARGET" == "validator" ] || [ "$TARGET" == "both" ]; then
        echo "# Validator Node (requires 100k QRDX stake)"
        echo "docker pull $REGISTRY/$REPOSITORY/qrdx-validator:$TAG"
        echo "docker run -d -p 30303:30303 -p 8545:8545 \\"
        echo "  -v /path/to/validator_keys:/root/.local/share/trinity/validator_keys:ro \\"
        echo "  -v qrdx-validator-data:/root/.local/share/trinity \\"
        echo "  $REGISTRY/$REPOSITORY/qrdx-validator:$TAG"
        echo ""
    fi
    
    exit 0
else
    exit 1
fi
