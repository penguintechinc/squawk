#!/usr/bin/env bash
#
# Version Management Script
# Updates version in vMajor.Minor.Patch.Build format
# Build number is epoch64 timestamp
#
# Usage:
#   ./update-version.sh          # Update build timestamp only (default)
#   ./update-version.sh patch    # Increment patch version
#   ./update-version.sh minor    # Increment minor version
#   ./update-version.sh major    # Increment major version
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Version files to update
VERSION_FILES=(
    "${PROJECT_ROOT}/.version"
    "${PROJECT_ROOT}/squawk-client/.version"
    "${PROJECT_ROOT}/dns-server/.version"
    "${PROJECT_ROOT}/squawk-client-go/.version"
)

# Read current version from root .version file
CURRENT_VERSION=$(cat "${PROJECT_ROOT}/.version" | tr -d '\n' | sed 's/^v//')

# Parse version components
if [[ $CURRENT_VERSION =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    BUILD="${BASH_REMATCH[5]:-0}"
else
    echo -e "${RED}Error: Invalid version format in .version file: ${CURRENT_VERSION}${NC}"
    echo "Expected format: vMajor.Minor.Patch or vMajor.Minor.Patch.Build"
    exit 1
fi

# Get current epoch64 timestamp
NEW_BUILD=$(date +%s)

# Determine what to update based on argument
UPDATE_TYPE="${1:-build}"

case "$UPDATE_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        BUILD=$NEW_BUILD
        echo -e "${YELLOW}Incrementing MAJOR version${NC}"
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        BUILD=$NEW_BUILD
        echo -e "${YELLOW}Incrementing MINOR version${NC}"
        ;;
    patch)
        PATCH=$((PATCH + 1))
        BUILD=$NEW_BUILD
        echo -e "${YELLOW}Incrementing PATCH version${NC}"
        ;;
    build|"")
        BUILD=$NEW_BUILD
        echo -e "${YELLOW}Updating BUILD timestamp${NC}"
        ;;
    *)
        echo -e "${RED}Error: Invalid argument '${UPDATE_TYPE}'${NC}"
        echo "Usage: $0 [major|minor|patch|build]"
        exit 1
        ;;
esac

# Construct new version
NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}.${BUILD}"

echo ""
echo "Current version: v${CURRENT_VERSION}"
echo "New version:     ${NEW_VERSION}"
echo ""

# Update all version files
echo "Updating version files..."
for VERSION_FILE in "${VERSION_FILES[@]}"; do
    if [[ -f "$VERSION_FILE" ]]; then
        echo "$NEW_VERSION" > "$VERSION_FILE"
        echo -e "${GREEN}✓${NC} Updated: $VERSION_FILE"
    else
        echo -e "${YELLOW}⚠${NC}  Skipped (not found): $VERSION_FILE"
    fi
done

echo ""
echo -e "${GREEN}Version update complete!${NC}"
echo ""
echo "To commit this change:"
echo "  git add .version */.version"
echo "  git commit -m 'Bump version to ${NEW_VERSION}'"
echo ""
