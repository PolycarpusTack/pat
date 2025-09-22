#!/bin/bash
# Pat Fortress - Cross-Platform Build Script
# Builds binaries for all major platforms

set -e

VERSION=${VERSION:-"2.0.0"}
BUILD_DIR="build"
BINARY_NAME="pat-fortress"

echo "🏰 Building Pat Fortress v${VERSION}"

# Clean previous builds
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Build information
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS="-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT} -s -w"

# Platform targets
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "freebsd/amd64"
    "openbsd/amd64"
)

echo "📦 Building for ${#PLATFORMS[@]} platforms..."

for platform in "${PLATFORMS[@]}"; do
    GOOS=${platform%/*}
    GOARCH=${platform#*/}

    output_name="${BINARY_NAME}_${VERSION}_${GOOS}_${GOARCH}"
    if [[ "$GOOS" == "windows" ]]; then
        output_name="${output_name}.exe"
    fi

    echo "   Building ${GOOS}/${GOARCH}..."

    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="${LDFLAGS}" \
        -o "${BUILD_DIR}/${output_name}" \
        .

    if [[ $? -eq 0 ]]; then
        echo "   ✅ ${output_name}"
    else
        echo "   ❌ Failed to build ${output_name}"
        exit 1
    fi
done

echo ""
echo "🎉 Build complete! Binaries in ${BUILD_DIR}/"
ls -la ${BUILD_DIR}/

# Create checksums
echo ""
echo "🔐 Generating checksums..."
cd ${BUILD_DIR}
sha256sum * > checksums.txt
cd ..

echo "✅ Checksums generated"
echo ""
echo "📋 Build Summary:"
echo "   Version: ${VERSION}"
echo "   Build Time: ${BUILD_TIME}"
echo "   Git Commit: ${GIT_COMMIT}"
echo "   Binaries: $(ls ${BUILD_DIR}/${BINARY_NAME}_* | wc -l)"
echo ""
echo "🚀 Ready for distribution!"