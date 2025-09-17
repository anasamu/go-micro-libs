# Storage Library

The Storage library provides a unified interface for object storage operations across multiple providers including S3, Google Cloud Storage, Azure Blob Storage, MinIO, and Cloudflare R2. It offers comprehensive storage capabilities with advanced features like presigned URLs, multipart uploads, versioning, and lifecycle management.

## Features

- **Multi-Provider Support**: S3, GCS, Azure, MinIO, R2, and more
- **Object Operations**: Put, get, delete, copy, and move objects
- **Batch Operations**: Efficient batch upload and delete operations
- **Presigned URLs**: Generate presigned URLs for secure access
- **Multipart Uploads**: Support for large file uploads
- **Versioning**: Object versioning and management
- **Encryption**: Built-in encryption support
- **Lifecycle Management**: Automated lifecycle policies
- **Bucket Management**: Create, delete, and manage buckets
- **Health Monitoring**: Provider health checks and statistics

## Supported Providers

- **S3**: Amazon S3 and S3-compatible storage
- **GCS**: Google Cloud Storage
- **Azure**: Azure Blob Storage
- **MinIO**: MinIO object storage
- **R2**: Cloudflare R2
- **Custom**: Custom storage providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/storage
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"
    "time"

    "github.com/anasamu/go-micro-libs/storage"
    "github.com/anasamu/go-micro-libs/storage/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create storage manager with default config
    config := storage.DefaultManagerConfig()
    manager := storage.NewStorageManager(config, logger)

    // Register S3 provider (example)
    // s3Provider := s3.NewS3Provider("us-east-1", "my-bucket")
    // manager.RegisterProvider(s3Provider)

    // Upload an object
    ctx := context.Background()
    data := strings.NewReader("Hello, World! This is a test file.")
    
    putReq := &types.PutObjectRequest{
        Bucket:      "my-bucket",
        Key:         "test/file.txt",
        Content:     data,
        Size:        35,
        ContentType: "text/plain",
        Metadata: map[string]string{
            "author": "john-doe",
            "project": "test-project",
        },
    }

    response, err := manager.PutObject(ctx, "s3", putReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Object uploaded: %s\n", response.Key)
    fmt.Printf("ETag: %s\n", response.ETag)
}
```

## API Reference

### StorageManager

The main manager for handling storage operations across multiple providers.

#### Methods

##### `NewStorageManager(config *ManagerConfig, logger *logrus.Logger) *StorageManager`
Creates a new storage manager with the given configuration and logger.

##### `RegisterProvider(provider StorageProvider) error`
Registers a new storage provider.

**Parameters:**
- `provider`: The storage provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (StorageProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (StorageProvider, error)`
Returns the default storage provider.

##### `PutObject(ctx context.Context, providerName string, request *types.PutObjectRequest) (*types.PutObjectResponse, error)`
Uploads an object using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Put object request with bucket, key, and content

**Returns:**
- `*types.PutObjectResponse`: Put response with object metadata
- `error`: Any error that occurred

##### `GetObject(ctx context.Context, providerName string, request *types.GetObjectRequest) (*types.GetObjectResponse, error)`
Downloads an object using the specified provider.

##### `DeleteObject(ctx context.Context, providerName string, request *types.DeleteObjectRequest) error`
Deletes an object using the specified provider.

##### `DeleteObjects(ctx context.Context, providerName string, request *types.DeleteObjectsRequest) (*types.DeleteObjectsResponse, error)`
Deletes multiple objects using the specified provider.

##### `ListObjects(ctx context.Context, providerName string, request *types.ListObjectsRequest) (*types.ListObjectsResponse, error)`
Lists objects in a bucket using the specified provider.

##### `ObjectExists(ctx context.Context, providerName string, request *types.ObjectExistsRequest) (bool, error)`
Checks if an object exists using the specified provider.

##### `CopyObject(ctx context.Context, providerName string, request *types.CopyObjectRequest) (*types.CopyObjectResponse, error)`
Copies an object using the specified provider.

##### `MoveObject(ctx context.Context, providerName string, request *types.MoveObjectRequest) (*types.MoveObjectResponse, error)`
Moves an object using the specified provider.

##### `GetObjectInfo(ctx context.Context, providerName string, request *types.GetObjectInfoRequest) (*types.ObjectInfo, error)`
Gets object information using the specified provider.

##### `GeneratePresignedURL(ctx context.Context, providerName string, request *types.PresignedURLRequest) (string, error)`
Generates a presigned URL using the specified provider.

##### `GeneratePublicURL(ctx context.Context, providerName string, request *types.PublicURLRequest) (string, error)`
Generates a public URL using the specified provider.

##### `CreateBucket(ctx context.Context, providerName string, request *types.CreateBucketRequest) error`
Creates a bucket using the specified provider.

##### `DeleteBucket(ctx context.Context, providerName string, request *types.DeleteBucketRequest) error`
Deletes a bucket using the specified provider.

##### `BucketExists(ctx context.Context, providerName string, request *types.BucketExistsRequest) (bool, error)`
Checks if a bucket exists using the specified provider.

##### `ListBuckets(ctx context.Context, providerName string) ([]types.BucketInfo, error)`
Lists buckets using the specified provider.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.StorageFeature, int64, []string, error)`
Returns capabilities of a specific provider.

##### `Close() error`
Closes all storage connections.

### Types

#### ManagerConfig
Configuration for the storage manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxFileSize     int64             `json:"max_file_size"`
    AllowedTypes    []string          `json:"allowed_types"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### PutObjectRequest
Represents a put object request.

```go
type PutObjectRequest struct {
    Bucket      string                 `json:"bucket"`
    Key         string                 `json:"key"`
    Content     io.Reader              `json:"-"`
    Size        int64                  `json:"size"`
    ContentType string                 `json:"content_type"`
    Metadata    map[string]string      `json:"metadata"`
    Tags        map[string]string      `json:"tags"`
    ACL         string                 `json:"acl,omitempty"`
    Encryption  *EncryptionConfig      `json:"encryption,omitempty"`
    Options     map[string]interface{} `json:"options,omitempty"`
}
```

#### PutObjectResponse
Represents a put object response.

```go
type PutObjectResponse struct {
    Key          string                 `json:"key"`
    ETag         string                 `json:"etag"`
    VersionID    string                 `json:"version_id,omitempty"`
    Size         int64                  `json:"size"`
    LastModified time.Time              `json:"last_modified"`
    Metadata     map[string]string      `json:"metadata"`
    ProviderData map[string]interface{} `json:"provider_data"`
}
```

#### GetObjectRequest
Represents a get object request.

```go
type GetObjectRequest struct {
    Bucket    string                 `json:"bucket"`
    Key       string                 `json:"key"`
    VersionID string                 `json:"version_id,omitempty"`
    Range     *RangeSpec             `json:"range,omitempty"`
    Options   map[string]interface{} `json:"options,omitempty"`
}
```

#### GetObjectResponse
Represents a get object response.

```go
type GetObjectResponse struct {
    Content      io.ReadCloser          `json:"-"`
    Size         int64                  `json:"size"`
    ContentType  string                 `json:"content_type"`
    ETag         string                 `json:"etag"`
    LastModified time.Time              `json:"last_modified"`
    Metadata     map[string]string      `json:"metadata"`
    ProviderData map[string]interface{} `json:"provider_data"`
}
```

#### ObjectInfo
Represents object information.

```go
type ObjectInfo struct {
    Key          string                 `json:"key"`
    Size         int64                  `json:"size"`
    LastModified time.Time              `json:"last_modified"`
    ETag         string                 `json:"etag"`
    ContentType  string                 `json:"content_type"`
    Metadata     map[string]string      `json:"metadata"`
    VersionID    string                 `json:"version_id,omitempty"`
    StorageClass string                 `json:"storage_class,omitempty"`
    ProviderData map[string]interface{} `json:"provider_data"`
}
```

#### PresignedURLRequest
Represents a presigned URL request.

```go
type PresignedURLRequest struct {
    Bucket  string                 `json:"bucket"`
    Key     string                 `json:"key"`
    Method  string                 `json:"method"` // GET, PUT, POST, DELETE
    Expires time.Duration          `json:"expires"`
    Headers map[string]string      `json:"headers,omitempty"`
    Options map[string]interface{} `json:"options,omitempty"`
}
```

## Advanced Usage

### Basic Object Operations

```go
// Upload an object
data := strings.NewReader("Hello, World!")
putReq := &types.PutObjectRequest{
    Bucket:      "my-bucket",
    Key:         "hello.txt",
    Content:     data,
    Size:        13,
    ContentType: "text/plain",
    Metadata: map[string]string{
        "author": "john-doe",
    },
}

response, err := manager.PutObject(ctx, "s3", putReq)
if err != nil {
    log.Fatal(err)
}

// Download an object
getReq := &types.GetObjectRequest{
    Bucket: "my-bucket",
    Key:    "hello.txt",
}

getResp, err := manager.GetObject(ctx, "s3", getReq)
if err != nil {
    log.Fatal(err)
}
defer getResp.Content.Close()

// Read content
content, err := io.ReadAll(getResp.Content)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Content: %s\n", string(content))

// Delete an object
deleteReq := &types.DeleteObjectRequest{
    Bucket: "my-bucket",
    Key:    "hello.txt",
}

err = manager.DeleteObject(ctx, "s3", deleteReq)
if err != nil {
    log.Fatal(err)
}
```

### Upload with Metadata and Tags

```go
// Upload with rich metadata
data := strings.NewReader("File content here...")
putReq := &types.PutObjectRequest{
    Bucket:      "my-bucket",
    Key:         "documents/report.pdf",
    Content:     data,
    Size:        1024,
    ContentType: "application/pdf",
    Metadata: map[string]string{
        "author":      "john-doe",
        "department":  "engineering",
        "project":     "q4-report",
        "created_at":  time.Now().Format(time.RFC3339),
    },
    Tags: map[string]string{
        "environment": "production",
        "classification": "internal",
        "retention": "7-years",
    },
    ACL: "private",
}

response, err := manager.PutObject(ctx, "s3", putReq)
```

### Batch Operations

```go
// Upload multiple files
files := map[string]string{
    "file1.txt": "Content of file 1",
    "file2.txt": "Content of file 2",
    "file3.txt": "Content of file 3",
}

for key, content := range files {
    data := strings.NewReader(content)
    putReq := &types.PutObjectRequest{
        Bucket:      "my-bucket",
        Key:         key,
        Content:     data,
        Size:        int64(len(content)),
        ContentType: "text/plain",
    }
    
    _, err := manager.PutObject(ctx, "s3", putReq)
    if err != nil {
        log.Printf("Failed to upload %s: %v", key, err)
    }
}

// Delete multiple objects
deleteReq := &types.DeleteObjectsRequest{
    Bucket: "my-bucket",
    Keys:   []string{"file1.txt", "file2.txt", "file3.txt"},
}

response, err := manager.DeleteObjects(ctx, "s3", deleteReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Deleted %d objects, %d errors\n", len(response.Deleted), len(response.Errors))
```

### List Objects with Pagination

```go
// List objects with pagination
listReq := &types.ListObjectsRequest{
    Bucket:            "my-bucket",
    Prefix:            "documents/",
    Delimiter:         "/",
    MaxKeys:           100,
    ContinuationToken: "",
}

response, err := manager.ListObjects(ctx, "s3", listReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Found %d objects:\n", len(response.Objects))
for _, obj := range response.Objects {
    fmt.Printf("- %s (%d bytes, modified: %s)\n", 
        obj.Key, obj.Size, obj.LastModified.Format(time.RFC3339))
}

// Handle pagination
if response.IsTruncated {
    fmt.Printf("More objects available. Next token: %s\n", response.NextContinuationToken)
}
```

### Copy and Move Operations

```go
// Copy object
copyReq := &types.CopyObjectRequest{
    SourceBucket: "source-bucket",
    SourceKey:    "original/file.txt",
    DestBucket:   "dest-bucket",
    DestKey:      "copied/file.txt",
    Metadata: map[string]string{
        "copied_at": time.Now().Format(time.RFC3339),
    },
}

copyResp, err := manager.CopyObject(ctx, "s3", copyReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Copied object: %s\n", copyResp.Key)

// Move object (copy + delete)
moveReq := &types.MoveObjectRequest{
    SourceBucket: "source-bucket",
    SourceKey:    "old/location/file.txt",
    DestBucket:   "dest-bucket",
    DestKey:      "new/location/file.txt",
}

moveResp, err := manager.MoveObject(ctx, "s3", moveReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Moved object: %s\n", moveResp.Key)
```

### Presigned URLs

```go
// Generate presigned URL for upload
uploadReq := &types.PresignedURLRequest{
    Bucket:  "my-bucket",
    Key:     "uploads/user-file.jpg",
    Method:  "PUT",
    Expires: 1 * time.Hour,
    Headers: map[string]string{
        "Content-Type": "image/jpeg",
    },
}

uploadURL, err := manager.GeneratePresignedURL(ctx, "s3", uploadReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Upload URL: %s\n", uploadURL)

// Generate presigned URL for download
downloadReq := &types.PresignedURLRequest{
    Bucket:  "my-bucket",
    Key:     "documents/report.pdf",
    Method:  "GET",
    Expires: 24 * time.Hour,
}

downloadURL, err := manager.GeneratePresignedURL(ctx, "s3", downloadReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Download URL: %s\n", downloadURL)
```

### Bucket Management

```go
// Create bucket
createReq := &types.CreateBucketRequest{
    Bucket: "new-bucket",
    Region: "us-east-1",
    ACL:    "private",
    Options: map[string]interface{}{
        "versioning": true,
        "encryption": map[string]string{
            "algorithm": "AES256",
        },
    },
}

err := manager.CreateBucket(ctx, "s3", createReq)
if err != nil {
    log.Fatal(err)
}

// Check if bucket exists
existsReq := &types.BucketExistsRequest{
    Bucket: "new-bucket",
}

exists, err := manager.BucketExists(ctx, "s3", existsReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Bucket exists: %v\n", exists)

// List all buckets
buckets, err := manager.ListBuckets(ctx, "s3")
if err != nil {
    log.Fatal(err)
}

for _, bucket := range buckets {
    fmt.Printf("Bucket: %s (created: %s)\n", 
        bucket.Name, bucket.CreationDate.Format(time.RFC3339))
}
```

### Object Information and Metadata

```go
// Get object information
infoReq := &types.GetObjectInfoRequest{
    Bucket: "my-bucket",
    Key:    "documents/report.pdf",
}

info, err := manager.GetObjectInfo(ctx, "s3", infoReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Object: %s\n", info.Key)
fmt.Printf("Size: %d bytes\n", info.Size)
fmt.Printf("Content Type: %s\n", info.ContentType)
fmt.Printf("Last Modified: %s\n", info.LastModified.Format(time.RFC3339))
fmt.Printf("ETag: %s\n", info.ETag)
fmt.Printf("Storage Class: %s\n", info.StorageClass)

if len(info.Metadata) > 0 {
    fmt.Println("Metadata:")
    for key, value := range info.Metadata {
        fmt.Printf("  %s: %s\n", key, value)
    }
}

// Check if object exists
existsReq := &types.ObjectExistsRequest{
    Bucket: "my-bucket",
    Key:    "documents/report.pdf",
}

exists, err := manager.ObjectExists(ctx, "s3", existsReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Object exists: %v\n", exists)
```

### Range Requests

```go
// Download specific range of bytes
rangeReq := &types.GetObjectRequest{
    Bucket: "my-bucket",
    Key:    "large-file.zip",
    Range: &types.RangeSpec{
        Start: 0,
        End:   1023, // First 1KB
    },
}

response, err := manager.GetObject(ctx, "s3", rangeReq)
if err != nil {
    log.Fatal(err)
}
defer response.Content.Close()

// Read only the requested range
data, err := io.ReadAll(response.Content)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Downloaded %d bytes\n", len(data))
```

### Encryption

```go
// Upload with encryption
data := strings.NewReader("Sensitive data")
putReq := &types.PutObjectRequest{
    Bucket:      "secure-bucket",
    Key:         "sensitive-data.txt",
    Content:     data,
    Size:        14,
    ContentType: "text/plain",
    Encryption: &types.EncryptionConfig{
        Algorithm: "AES256",
        KeyID:     "my-encryption-key",
        Context: map[string]string{
            "department": "finance",
            "classification": "confidential",
        },
    },
}

response, err := manager.PutObject(ctx, "s3", putReq)
```

### Health Monitoring

```go
// Check health of all providers
healthStatus := manager.HealthCheck(ctx)
for provider, err := range healthStatus {
    if err != nil {
        fmt.Printf("Provider %s is unhealthy: %v\n", provider, err)
    } else {
        fmt.Printf("Provider %s is healthy\n", provider)
    }
}

// Get provider capabilities
features, maxSize, allowedTypes, err := manager.GetProviderCapabilities("s3")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("S3 Features: %v\n", features)
fmt.Printf("Max file size: %d bytes\n", maxSize)
fmt.Printf("Allowed types: %v\n", allowedTypes)
```

### Error Handling

```go
response, err := manager.PutObject(ctx, "s3", putReq)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "bucket not found"):
        log.Printf("Bucket does not exist: %v", err)
    case strings.Contains(err.Error(), "access denied"):
        log.Printf("Access denied: %v", err)
    case strings.Contains(err.Error(), "file too large"):
        log.Printf("File exceeds maximum size: %v", err)
    case strings.Contains(err.Error(), "invalid content type"):
        log.Printf("Content type not allowed: %v", err)
    default:
        log.Printf("Storage operation failed: %v", err)
    }
    return
}

fmt.Printf("Object uploaded successfully: %s\n", response.Key)
```

## Best Practices

1. **Bucket Naming**: Use consistent, DNS-compliant bucket naming conventions
2. **Key Structure**: Organize objects with hierarchical key structures
3. **Metadata**: Use metadata for object categorization and search
4. **Error Handling**: Implement comprehensive error handling and retry logic
5. **Security**: Use appropriate ACLs and encryption for sensitive data
6. **Performance**: Use batch operations and presigned URLs for better performance
7. **Monitoring**: Monitor storage usage and access patterns
8. **Lifecycle**: Implement lifecycle policies for cost optimization
9. **Versioning**: Enable versioning for critical data
10. **Testing**: Test storage operations in different scenarios

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
