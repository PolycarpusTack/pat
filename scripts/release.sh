#!/bin/bash
# Pat Fortress - Release Management Script
# Automates the complete release process

set -e

# Configuration
REPO_URL="https://github.com/pat-fortress/pat-fortress"
CURRENT_BRANCH=$(git branch --show-current)
BUILD_DIR="build"
PACKAGE_DIR="packages"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "🏰 Pat Fortress Release Manager"
    echo "=============================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    echo "Pat Fortress Release Manager"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  prepare <version>    Prepare release (update version, create changelog)"
    echo "  build <version>      Build all binaries and packages"
    echo "  test <version>       Test the release locally"
    echo "  publish <version>    Create GitHub release and publish"
    echo "  complete <version>   Run complete release process"
    echo ""
    echo "Options:"
    echo "  --dry-run           Show what would be done without executing"
    echo "  --skip-tests        Skip release testing"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 prepare 2.1.0    # Prepare version 2.1.0"
    echo "  $0 complete 2.1.0   # Complete release process"
    echo ""
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if we're on main branch
    if [[ "$CURRENT_BRANCH" != "main" ]]; then
        log_warn "Not on main branch (current: $CURRENT_BRANCH)"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Release cancelled"
            exit 1
        fi
    fi

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        log_error "Uncommitted changes found. Please commit or stash them."
        exit 1
    fi

    # Check required tools
    local missing_tools=()

    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi

    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi

    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    log_info "✅ Prerequisites satisfied"
}

validate_version() {
    local version="$1"

    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid version format: $version (expected: X.Y.Z)"
        exit 1
    fi

    # Check if version already exists
    if git tag -l | grep -q "^v$version$"; then
        log_error "Version v$version already exists"
        exit 1
    fi

    log_info "✅ Version $version is valid"
}

update_version_files() {
    local version="$1"

    log_info "Updating version files..."

    # Update go.mod if it has version info
    if grep -q "version" go.mod 2>/dev/null; then
        sed -i "s/version [0-9]\+\.[0-9]\+\.[0-9]\+/version $version/g" go.mod
    fi

    # Update main.go version
    if grep -q "version.*=" main.go; then
        sed -i "s/version = \"[^\"]*\"/version = \"$version\"/g" main.go
    fi

    # Update README.md
    sed -i "s/Version:\*\* [0-9]\+\.[0-9]\+\.[0-9]\+/Version:** $version/g" README.md
    sed -i "s/v[0-9]\+\.[0-9]\+\.[0-9]\+/v$version/g" README.md

    # Update PROJECT_STATUS.md
    sed -i "s/\*\*Version:\*\* [0-9]\+\.[0-9]\+\.[0-9]\+/**Version:** $version/g" PROJECT_STATUS.md

    log_info "✅ Version files updated"
}

generate_changelog() {
    local version="$1"
    local changelog_file="CHANGELOG.md"

    log_info "Generating changelog..."

    # Get last version tag
    local last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    local date=$(date '+%Y-%m-%d')

    # Create changelog header
    local changelog_entry="## [${version}] - ${date}\n\n"

    if [[ -n "$last_tag" ]]; then
        # Get commits since last tag
        local commits=$(git log ${last_tag}..HEAD --oneline --no-merges)

        if [[ -n "$commits" ]]; then
            changelog_entry+="### Changes\n"
            while IFS= read -r commit; do
                local commit_msg=$(echo "$commit" | cut -d' ' -f2-)
                changelog_entry+="- ${commit_msg}\n"
            done <<< "$commits"
        fi
    else
        changelog_entry+="### Changes\n"
        changelog_entry+="- Initial release\n"
    fi

    changelog_entry+="\n"

    # Prepend to changelog file
    if [[ -f "$changelog_file" ]]; then
        local temp_file=$(mktemp)
        echo -e "$changelog_entry" > "$temp_file"
        cat "$changelog_file" >> "$temp_file"
        mv "$temp_file" "$changelog_file"
    else
        echo "# Changelog" > "$changelog_file"
        echo "" >> "$changelog_file"
        echo -e "$changelog_entry" >> "$changelog_file"
    fi

    log_info "✅ Changelog generated"
}

prepare_release() {
    local version="$1"

    log_info "Preparing release v$version..."

    validate_version "$version"
    update_version_files "$version"
    generate_changelog "$version"

    # Commit changes
    git add .
    git commit -m "chore: prepare release v$version

- Update version to $version
- Generate changelog
- Update documentation"

    log_info "✅ Release v$version prepared"
    log_info "Next steps:"
    echo "  1. Review changes: git show"
    echo "  2. Build release: $0 build $version"
    echo "  3. Test release: $0 test $version"
    echo "  4. Publish release: $0 publish $version"
}

build_release() {
    local version="$1"

    log_info "Building release v$version..."

    # Set version for build
    export VERSION="$version"

    # Build binaries
    log_info "Building binaries..."
    chmod +x scripts/build.sh
    scripts/build.sh

    # Create packages
    log_info "Creating packages..."
    chmod +x scripts/package.sh
    scripts/package.sh

    log_info "✅ Release v$version built successfully"
    log_info "Artifacts created:"
    echo "  - Binaries: $BUILD_DIR/"
    echo "  - Packages: $PACKAGE_DIR/"
}

test_release() {
    local version="$1"

    log_info "Testing release v$version..."

    # Test binary execution
    local test_binary=""
    case "$(uname -s)" in
        Linux*)   test_binary="$BUILD_DIR/pat-fortress_${version}_linux_amd64" ;;
        Darwin*)  test_binary="$BUILD_DIR/pat-fortress_${version}_darwin_amd64" ;;
        *)        log_warn "Unsupported OS for testing: $(uname -s)" ;;
    esac

    if [[ -n "$test_binary" && -f "$test_binary" ]]; then
        log_info "Testing binary: $test_binary"

        # Test version output
        if "$test_binary" --version 2>&1 | grep -q "$version"; then
            log_info "✅ Version check passed"
        else
            log_error "Version check failed"
            return 1
        fi

        # Test help output
        if "$test_binary" --help 2>&1 | grep -q "Pat Fortress"; then
            log_info "✅ Help check passed"
        else
            log_error "Help check failed"
            return 1
        fi

        log_info "✅ Binary tests passed"
    else
        log_warn "No binary found for testing on this platform"
    fi

    # Test package structure
    if [[ -d "$PACKAGE_DIR" ]]; then
        local package_count=$(find "$PACKAGE_DIR" -name "*.deb" -o -name "*.rpm" -o -name "*.pkg" | wc -l)
        log_info "✅ Created $package_count packages"
    fi

    log_info "✅ Release testing completed"
}

publish_release() {
    local version="$1"

    log_info "Publishing release v$version..."

    # Create and push tag
    log_info "Creating git tag..."
    git tag -a "v$version" -m "Release v$version

Release notes:
- See CHANGELOG.md for detailed changes
- Binaries available for Linux, macOS, Windows, FreeBSD, OpenBSD
- Docker images: patfortress/pat-fortress:$version

Installation:
curl -sSL https://raw.githubusercontent.com/pat-fortress/pat-fortress/main/scripts/install.sh | bash"

    git push origin "v$version"
    git push origin main

    log_info "✅ Git tag created and pushed"
    log_info "GitHub Actions will automatically:"
    echo "  - Build all binaries and packages"
    echo "  - Create GitHub release"
    echo "  - Push Docker images"
    echo "  - Update Homebrew formula"
    echo ""
    log_info "Monitor the release at: $REPO_URL/actions"
}

complete_release() {
    local version="$1"

    log_info "Starting complete release process for v$version..."

    prepare_release "$version"

    if [[ "$SKIP_TESTS" != "true" ]]; then
        build_release "$version"
        test_release "$version"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "🧪 DRY RUN - Would publish release v$version"
        return
    fi

    # Confirm publication
    echo ""
    log_warn "Ready to publish release v$version"
    echo "This will:"
    echo "  ✓ Create git tag v$version"
    echo "  ✓ Push to GitHub"
    echo "  ✓ Trigger automated release process"
    echo ""
    read -p "Proceed with publication? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        publish_release "$version"
        log_info "🎉 Release v$version published successfully!"
    else
        log_info "Release publication cancelled"
    fi
}

# Parse arguments
DRY_RUN=false
SKIP_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        prepare|build|test|publish|complete)
            COMMAND="$1"
            VERSION="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_banner

    if [[ -z "$COMMAND" ]]; then
        show_help
        exit 1
    fi

    if [[ -z "$VERSION" ]]; then
        log_error "Version is required"
        show_help
        exit 1
    fi

    check_prerequisites

    case "$COMMAND" in
        prepare)
            prepare_release "$VERSION"
            ;;
        build)
            build_release "$VERSION"
            ;;
        test)
            test_release "$VERSION"
            ;;
        publish)
            publish_release "$VERSION"
            ;;
        complete)
            complete_release "$VERSION"
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

main