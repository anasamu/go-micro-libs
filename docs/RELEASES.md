# Release Management

Dokumentasi ini menjelaskan cara menggunakan sistem rilis otomatis untuk microservices library Go.

## 🚀 Cara Membuat Rilis

### 1. Rilis Otomatis dengan GitHub Actions

#### Manual Release (Recommended)
1. Pergi ke tab **Actions** di GitHub repository
2. Pilih workflow **Release**
3. Klik **Run workflow**
4. Pilih:
   - **Version type**: `major`, `minor`, atau `patch`
   - **Prerelease**: `true` atau `false`
5. Klik **Run workflow**

#### Rilis dengan Tag
```bash
# Buat tag baru
git tag v1.1.0
git push origin v1.1.0
```

### 2. Rilis Manual dengan Script

```bash
# Patch version (1.0.0 -> 1.0.1)
./scripts/version.sh patch

# Minor version (1.0.0 -> 1.1.0)
./scripts/version.sh minor

# Major version (1.0.0 -> 2.0.0)
./scripts/version.sh major

# Prerelease (1.0.0 -> 1.0.1-rc.1)
./scripts/version.sh patch --prerelease
```

## 📋 Workflow yang Tersedia

### 1. Release Workflow (`.github/workflows/release.yml`)
- **Trigger**: Manual dispatch, push tag
- **Fungsi**: 
  - Menghitung versi baru
  - Generate changelog
  - Build untuk multiple platforms
  - Membuat GitHub release
  - Upload binary assets

### 2. CI Workflow (`.github/workflows/ci.yml`)
- **Trigger**: Push ke main/master/develop, PR
- **Fungsi**:
  - Test dengan multiple Go versions
  - Linting dengan golangci-lint
  - Security scanning dengan Gosec
  - Build untuk multiple OS

### 3. Dependabot (`.github/dependabot.yml`)
- **Trigger**: Weekly schedule
- **Fungsi**:
  - Update Go modules
  - Update GitHub Actions

## 🔧 Konfigurasi

### Environment Variables
```yaml
GO_VERSION: '1.21'
GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Required Secrets
- `GITHUB_TOKEN`: Otomatis tersedia di GitHub Actions

## 📦 Output Release

Setiap rilis akan menghasilkan:

### 1. GitHub Release
- Tag dengan format `vX.Y.Z`
- Changelog otomatis
- Release notes dengan installation guide
- Download links untuk binary

### 2. Binary Assets
- `microservices-linux-amd64`
- `microservices-darwin-amd64`
- `microservices-darwin-arm64`
- `microservices-windows-amd64.exe`

### 3. Updated Files
- `CHANGELOG.md`
- `go.mod` (jika ada version field)
- `README.md` (jika ada version field)
- `microservices.go` (jika ada version field)

## 🏷️ Versioning Strategy

Menggunakan [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (X.Y.0): New features, backward compatible
- **PATCH** (X.Y.Z): Bug fixes, backward compatible

### Prerelease
- Format: `vX.Y.Z-rc.N`
- Contoh: `v1.1.0-rc.1`

## 📝 Changelog Format

Changelog di-generate otomatis dengan format:

```markdown
## [v1.1.0] - 2024-01-15

### Changes
- feat: add new AI provider support
- fix: resolve connection timeout issue
- docs: update installation guide

**Full Changelog**: https://github.com/anasamu/go-micro-libs/compare/v1.0.0...v1.1.0
```

## 🔍 Monitoring Release

### GitHub Actions Dashboard
- Monitor progress di tab **Actions**
- View logs untuk debugging
- Check artifacts dan releases

### Release Page
- Lihat semua rilis di **Releases** tab
- Download binary files
- View changelog dan release notes

## 🚨 Troubleshooting

### Common Issues

1. **Workflow fails on version calculation**
   - Pastikan ada tag sebelumnya
   - Check git history

2. **Build fails**
   - Check Go version compatibility
   - Verify dependencies

3. **Release creation fails**
   - Check GitHub token permissions
   - Verify repository settings

### Debug Commands
```bash
# Check current tags
git tag -l

# Check git status
git status

# Check workflow logs
# Go to Actions tab in GitHub
```

## 📚 Best Practices

1. **Always test locally** sebelum membuat rilis
2. **Use semantic versioning** dengan benar
3. **Write clear commit messages** untuk changelog yang baik
4. **Review changelog** sebelum release
5. **Test binary files** setelah release

## 🔗 Links

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go Modules](https://golang.org/ref/mod)
