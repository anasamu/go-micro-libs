#!/bin/bash

# Script untuk versioning otomatis
# Usage: ./scripts/version.sh [major|minor|patch] [--prerelease]

set -e

# Colors untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function untuk print dengan warna
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function untuk help
show_help() {
    echo "Usage: $0 [major|minor|patch] [--prerelease]"
    echo ""
    echo "Arguments:"
    echo "  major       Increment major version (1.0.0 -> 2.0.0)"
    echo "  minor       Increment minor version (1.0.0 -> 1.1.0)"
    echo "  patch       Increment patch version (1.0.0 -> 1.0.1)"
    echo "  --prerelease Create prerelease version (1.0.0 -> 1.0.1-rc.1)"
    echo ""
    echo "Examples:"
    echo "  $0 patch                    # 1.0.0 -> 1.0.1"
    echo "  $0 minor --prerelease       # 1.0.0 -> 1.1.0-rc.1"
    echo "  $0 major                    # 1.0.0 -> 2.0.0"
}

# Function untuk mendapatkan versi saat ini
get_current_version() {
    local latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    echo "${latest_tag#v}"  # Remove 'v' prefix
}

# Function untuk menghitung versi baru
calculate_new_version() {
    local current_version="$1"
    local version_type="$2"
    local is_prerelease="$3"
    
    # Split version
    IFS='.' read -r major minor patch <<< "$current_version"
    
    # Increment version berdasarkan type
    case $version_type in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            print_error "Invalid version type: $version_type"
            exit 1
            ;;
    esac
    
    local new_version="v${major}.${minor}.${patch}"
    
    # Tambahkan prerelease suffix jika diperlukan
    if [ "$is_prerelease" = "true" ]; then
        new_version="${new_version}-rc.1"
    fi
    
    echo "$new_version"
}

# Function untuk generate changelog
generate_changelog() {
    local current_version="$1"
    local new_version="$2"
    
    print_info "Generating changelog..."
    
    local changelog_file="CHANGELOG.md"
    local temp_file=$(mktemp)
    
    # Header
    echo "# Changelog" > "$temp_file"
    echo "" >> "$temp_file"
    echo "All notable changes to this project will be documented in this file." >> "$temp_file"
    echo "" >> "$temp_file"
    echo "## [$new_version] - $(date +%Y-%m-%d)" >> "$temp_file"
    echo "" >> "$temp_file"
    
    # Get commits since last tag
    local commits
    if [ "$current_version" = "0.0.0" ]; then
        commits=$(git log --pretty=format:"- %s (%h)" --no-merges)
    else
        commits=$(git log "v${current_version}..HEAD" --pretty=format:"- %s (%h)" --no-merges)
    fi
    
    if [ -n "$commits" ]; then
        echo "### Changes" >> "$temp_file"
        echo "" >> "$temp_file"
        echo "$commits" >> "$temp_file"
        echo "" >> "$temp_file"
    else
        echo "### Changes" >> "$temp_file"
        echo "" >> "$temp_file"
        echo "- No changes" >> "$temp_file"
        echo "" >> "$temp_file"
    fi
    
    # Append existing changelog if exists
    if [ -f "$changelog_file" ]; then
        echo "" >> "$temp_file"
        tail -n +2 "$changelog_file" >> "$temp_file"
    fi
    
    # Replace changelog
    mv "$temp_file" "$changelog_file"
    
    print_success "Changelog generated: $changelog_file"
}

# Function untuk update version di file
update_version_files() {
    local new_version="$1"
    
    print_info "Updating version in files..."
    
    # Update version di go.mod jika ada
    if [ -f "go.mod" ] && grep -q "version" go.mod; then
        sed -i "s/version v[0-9]\+\.[0-9]\+\.[0-9]\+/version $new_version/" go.mod
        print_success "Updated version in go.mod"
    fi
    
    # Update version di README.md jika ada
    if [ -f "README.md" ] && grep -q "Version:" README.md; then
        sed -i "s/Version: v[0-9]\+\.[0-9]\+\.[0-9]\+/Version: $new_version/" README.md
        print_success "Updated version in README.md"
    fi
    
    # Update version di microservices.go jika ada
    if [ -f "microservices.go" ] && grep -q "Version:" microservices.go; then
        sed -i "s/Version: v[0-9]\+\.[0-9]\+\.[0-9]\+/Version: $new_version/" microservices.go
        print_success "Updated version in microservices.go"
    fi
}

# Function untuk commit dan tag
commit_and_tag() {
    local new_version="$1"
    local is_prerelease="$2"
    
    print_info "Committing changes and creating tag..."
    
    # Add all changes
    git add .
    
    # Commit message
    local commit_msg="chore: release $new_version"
    if [ "$is_prerelease" = "true" ]; then
        commit_msg="chore: prerelease $new_version"
    fi
    
    # Commit
    git commit -m "$commit_msg" || {
        print_warning "No changes to commit"
        return 0
    }
    
    # Create tag
    git tag -a "$new_version" -m "Release $new_version"
    
    print_success "Created tag: $new_version"
}

# Function untuk push ke remote
push_to_remote() {
    local new_version="$1"
    
    print_info "Pushing to remote..."
    
    # Push commits
    git push origin HEAD
    
    # Push tags
    git push origin "$new_version"
    
    print_success "Pushed to remote"
}

# Main function
main() {
    # Check arguments
    if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit 0
    fi
    
    local version_type="$1"
    local is_prerelease="false"
    
    # Check for prerelease flag
    if [ "$2" = "--prerelease" ]; then
        is_prerelease="true"
    fi
    
    # Validate version type
    if [[ ! "$version_type" =~ ^(major|minor|patch)$ ]]; then
        print_error "Invalid version type: $version_type"
        show_help
        exit 1
    fi
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
    
    # Check if working directory is clean
    if ! git diff-index --quiet HEAD --; then
        print_warning "Working directory is not clean. Uncommitted changes will be included."
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Aborted"
            exit 0
        fi
    fi
    
    # Get current version
    local current_version=$(get_current_version)
    print_info "Current version: v$current_version"
    
    # Calculate new version
    local new_version=$(calculate_new_version "$current_version" "$version_type" "$is_prerelease")
    print_info "New version: $new_version"
    
    # Confirm
    read -p "Create release $new_version? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted"
        exit 0
    fi
    
    # Generate changelog
    generate_changelog "$current_version" "$new_version"
    
    # Update version files
    update_version_files "$new_version"
    
    # Commit and tag
    commit_and_tag "$new_version" "$is_prerelease"
    
    # Push to remote
    push_to_remote "$new_version"
    
    print_success "Release $new_version created successfully!"
    print_info "You can now create a GitHub release manually or use GitHub Actions"
}

# Run main function
main "$@"
