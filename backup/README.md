# Backup Library

The Backup library provides a unified interface for backup and restore operations across multiple storage providers. It supports various backup destinations including local storage, cloud storage (S3, GCS), and other backup services with features like compression, encryption, and metadata management.

## Features

- **Multi-Provider Support**: Local storage, S3, Google Cloud Storage, and more
- **Compression**: Built-in compression support for efficient storage
- **Encryption**: Optional encryption for secure backups
- **Metadata Management**: Rich metadata support with tags and descriptions
- **Health Monitoring**: Provider health checks and status monitoring
- **Flexible Storage**: Support for various backup destinations
- **Restore Operations**: Complete restore functionality with options
- **Backup Listing**: List and manage existing backups

## Supported Providers

- **Local**: Local file system backup
- **S3**: Amazon S3 backup storage
- **GCS**: Google Cloud Storage backup
- **Azure**: Azure Blob Storage backup
- **Custom**: Custom backup providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/backup
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"

    "github.com/anasamu/go-micro-libs/backup"
    "github.com/anasamu/go-micro-libs/backup/types"
)

func main() {
    // Create backup manager
    manager := backup.NewBackupManager()

    // Set provider (example with local provider)
    // localProvider := local.NewLocalProvider("/backup/path")
    // manager.SetProvider(localProvider)

    // Create backup
    ctx := context.Background()
    data := strings.NewReader("Hello, World! This is backup data.")
    
    opts := &types.BackupOptions{
        Compression: true,
        Encryption:  false,
        Tags: map[string]string{
            "environment": "production",
            "service":     "web-app",
        },
        Description: "Daily backup of application data",
    }

    metadata, err := manager.CreateBackup(ctx, "daily-backup-2024-01-15", data, opts)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Backup created: %s\n", metadata.ID)
    fmt.Printf("Size: %d bytes\n", metadata.Size)
}
```

## API Reference

### BackupManager

The main manager for handling backup and restore operations.

#### Methods

##### `NewBackupManager() *BackupManager`
Creates a new backup manager instance.

##### `SetProvider(provider types.Provider)`
Sets the backup provider to use for operations.

**Parameters:**
- `provider`: The backup provider implementation

##### `GetProvider() types.Provider`
Returns the current backup provider.

##### `CreateBackup(ctx context.Context, name string, data io.Reader, opts *types.BackupOptions) (*types.BackupMetadata, error)`
Creates a backup using the current provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `name`: Name for the backup
- `data`: Data to backup (io.Reader)
- `opts`: Backup options including compression and encryption

**Returns:**
- `*types.BackupMetadata`: Metadata about the created backup
- `error`: Any error that occurred

##### `RestoreBackup(ctx context.Context, backupID string, writer io.Writer, opts *types.RestoreOptions) error`
Restores a backup using the current provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `backupID`: ID of the backup to restore
- `writer`: Writer to write the restored data
- `opts`: Restore options

**Returns:**
- `error`: Any error that occurred

##### `ListBackups(ctx context.Context) ([]*types.BackupMetadata, error)`
Lists all available backups.

**Returns:**
- `[]*types.BackupMetadata`: List of backup metadata
- `error`: Any error that occurred

##### `GetBackup(ctx context.Context, backupID string) (*types.BackupMetadata, error)`
Retrieves backup metadata by ID.

##### `DeleteBackup(ctx context.Context, backupID string) error`
Removes a backup by ID.

##### `HealthCheck(ctx context.Context) error`
Checks if the current provider is healthy.

### Types

#### BackupMetadata
Metadata about a backup.

```go
type BackupMetadata struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Size        int64             `json:"size"`
    CreatedAt   time.Time         `json:"created_at"`
    Tags        map[string]string `json:"tags,omitempty"`
    Description string            `json:"description,omitempty"`
}
```

#### BackupOptions
Options for backup operations.

```go
type BackupOptions struct {
    Compression bool              `json:"compression"`
    Encryption  bool              `json:"encryption"`
    Tags        map[string]string `json:"tags,omitempty"`
    Description string            `json:"description,omitempty"`
}
```

#### RestoreOptions
Options for restore operations.

```go
type RestoreOptions struct {
    Overwrite bool `json:"overwrite"`
}
```

#### Provider Interface
Interface that backup providers must implement.

```go
type Provider interface {
    // CreateBackup creates a backup from the given data
    CreateBackup(ctx context.Context, name string, data io.Reader, opts *BackupOptions) (*BackupMetadata, error)

    // RestoreBackup restores a backup to the given writer
    RestoreBackup(ctx context.Context, backupID string, writer io.Writer, opts *RestoreOptions) error

    // ListBackups lists all available backups
    ListBackups(ctx context.Context) ([]*BackupMetadata, error)

    // GetBackup retrieves backup metadata
    GetBackup(ctx context.Context, backupID string) (*BackupMetadata, error)

    // DeleteBackup removes a backup
    DeleteBackup(ctx context.Context, backupID string) error

    // HealthCheck checks if the provider is healthy
    HealthCheck(ctx context.Context) error
}
```

## Advanced Usage

### Creating Backups with Compression

```go
// Create backup with compression
opts := &types.BackupOptions{
    Compression: true,
    Encryption:  false,
    Tags: map[string]string{
        "environment": "production",
        "service":     "database",
        "backup_type": "full",
    },
    Description: "Full database backup with compression",
}

data := strings.NewReader("Large amount of data to compress...")
metadata, err := manager.CreateBackup(ctx, "db-backup-2024-01-15", data, opts)
```

### Creating Encrypted Backups

```go
// Create encrypted backup
opts := &types.BackupOptions{
    Compression: true,
    Encryption:  true,
    Tags: map[string]string{
        "sensitive": "true",
        "compliance": "required",
    },
    Description: "Encrypted backup of sensitive data",
}

metadata, err := manager.CreateBackup(ctx, "sensitive-backup", data, opts)
```

### Restoring Backups

```go
// Restore backup to a file
file, err := os.Create("restored-data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()

restoreOpts := &types.RestoreOptions{
    Overwrite: true,
}

err = manager.RestoreBackup(ctx, "backup-id-123", file, restoreOpts)
if err != nil {
    log.Fatal(err)
}

fmt.Println("Backup restored successfully")
```

### Restoring to Memory

```go
// Restore backup to memory
var buf bytes.Buffer
err := manager.RestoreBackup(ctx, "backup-id-123", &buf, &types.RestoreOptions{})
if err != nil {
    log.Fatal(err)
}

restoredData := buf.String()
fmt.Printf("Restored data: %s\n", restoredData)
```

### Listing and Managing Backups

```go
// List all backups
backups, err := manager.ListBackups(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Found %d backups:\n", len(backups))
for _, backup := range backups {
    fmt.Printf("- ID: %s, Name: %s, Size: %d bytes, Created: %s\n",
        backup.ID, backup.Name, backup.Size, backup.CreatedAt)
    
    if len(backup.Tags) > 0 {
        fmt.Printf("  Tags: %v\n", backup.Tags)
    }
}

// Get specific backup metadata
metadata, err := manager.GetBackup(ctx, "backup-id-123")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Backup details: %+v\n", metadata)
```

### Filtering Backups by Tags

```go
// List backups and filter by tags
backups, err := manager.ListBackups(ctx)
if err != nil {
    log.Fatal(err)
}

// Filter backups by environment
var productionBackups []*types.BackupMetadata
for _, backup := range backups {
    if env, exists := backup.Tags["environment"]; exists && env == "production" {
        productionBackups = append(productionBackups, backup)
    }
}

fmt.Printf("Found %d production backups\n", len(productionBackups))
```

### Deleting Backups

```go
// Delete a specific backup
err := manager.DeleteBackup(ctx, "backup-id-123")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Backup deleted successfully")
```

### Health Monitoring

```go
// Check provider health
err := manager.HealthCheck(ctx)
if err != nil {
    fmt.Printf("Backup provider is unhealthy: %v\n", err)
} else {
    fmt.Println("Backup provider is healthy")
}
```

### Backup with Custom Metadata

```go
// Create backup with rich metadata
opts := &types.BackupOptions{
    Compression: true,
    Tags: map[string]string{
        "environment":   "production",
        "service":       "web-app",
        "backup_type":   "incremental",
        "retention":     "30d",
        "owner":         "devops-team",
        "compliance":    "sox",
    },
    Description: "Incremental backup of web application data for SOX compliance",
}

metadata, err := manager.CreateBackup(ctx, "webapp-incr-2024-01-15", data, opts)
```

### Batch Backup Operations

```go
// Create multiple backups
backupNames := []string{"config-backup", "data-backup", "logs-backup"}
backupData := []string{"config data", "application data", "log data"}

for i, name := range backupNames {
    opts := &types.BackupOptions{
        Compression: true,
        Tags: map[string]string{
            "batch_id": "batch-001",
            "sequence": fmt.Sprintf("%d", i+1),
        },
        Description: fmt.Sprintf("Batch backup item %d", i+1),
    }
    
    data := strings.NewReader(backupData[i])
    metadata, err := manager.CreateBackup(ctx, name, data, opts)
    if err != nil {
        log.Printf("Failed to create backup %s: %v", name, err)
        continue
    }
    
    fmt.Printf("Created backup: %s (ID: %s)\n", name, metadata.ID)
}
```

## Error Handling

The library provides comprehensive error handling:

```go
metadata, err := manager.CreateBackup(ctx, "backup-name", data, opts)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not set"):
        log.Fatal("No backup provider configured")
    case strings.Contains(err.Error(), "permission denied"):
        log.Fatal("Insufficient permissions for backup operation")
    case strings.Contains(err.Error(), "storage full"):
        log.Fatal("Backup storage is full")
    default:
        log.Printf("Backup failed: %v", err)
    }
    return
}

fmt.Printf("Backup created successfully: %s\n", metadata.ID)
```

## Best Practices

1. **Provider Selection**: Choose appropriate backup providers for your use case
2. **Compression**: Use compression for large backups to save storage space
3. **Encryption**: Encrypt sensitive backups for security
4. **Metadata**: Use descriptive tags and descriptions for easy management
5. **Health Checks**: Regularly check provider health
6. **Error Handling**: Implement comprehensive error handling
7. **Retention Policies**: Implement backup retention and cleanup policies
8. **Testing**: Regularly test backup and restore procedures
9. **Monitoring**: Monitor backup operations and storage usage
10. **Documentation**: Document backup procedures and recovery processes

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
