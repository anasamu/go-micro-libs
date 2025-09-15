# Microservices Library Go

Sebuah library Go yang komprehensif untuk pengembangan microservices dengan dukungan untuk berbagai layanan seperti AI, Authentication, Storage, Database, Cache, Messaging, dan banyak lagi.

## 🚀 Fitur Utama

Library ini menyediakan interface yang terpadu untuk semua komponen microservices, memungkinkan Anda untuk mengimpor semuanya dari satu modul:

```go
import "github.com/anasamu/go-micro-libs"
```

### 📦 Modul yang Tersedia

| Modul | Deskripsi | Provider |
|-------|-----------|----------|
| **AI** | Layanan AI dengan dukungan multiple provider | OpenAI, Anthropic, XAI, DeepSeek, Google |
| **API** | Integrasi API pihak ketiga dengan protokol multi | HTTP, GraphQL, gRPC, WebSocket |
| **Auth** | Autentikasi dan otorisasi | JWT, OAuth2, 2FA, RBAC, ABAC, ACL, Auth0, Keycloak, Okta |
| **Backup** | Backup dan restore data | GCS, Local, S3 |
| **Cache** | Sistem cache dengan fallback | Redis, Memcache, Memory |
| **Chaos** | Chaos engineering | HTTP, Kubernetes, Messaging |
| **Circuit Breaker** | Circuit breaker pattern | Custom, GoBreaker |
| **Communication** | Protokol komunikasi | HTTP, gRPC, GraphQL, WebSocket, SSE, QUIC |
| **Config** | Manajemen konfigurasi | Consul, Env, File, Vault |
| **Database** | Database abstraksi | PostgreSQL, MySQL, MongoDB, Redis, SQLite, Cassandra, CockroachDB, Elasticsearch, InfluxDB, MariaDB |
| **Discovery** | Service discovery | Consul, etcd, Kubernetes, Static |
| **Edge** | Edge computing dan deployment | Cloudflare Workers, Fastly, Akamai, WASM |
| **Email** | Layanan email | SMTP, IMAP, POP3 |
| **Event** | Event sourcing | Kafka, NATS, PostgreSQL |
| **FileGen** | Generasi file | CSV, DOCX, Excel, PDF, Custom |
| **Failover** | Failover management | Consul, Kubernetes |
| **Logging** | Sistem logging | Console, File, Elasticsearch |
| **Messaging** | Message queue | Kafka, NATS, RabbitMQ, SQS |
| **Middleware** | HTTP middleware | Auth, Cache, Circuit Breaker, dll |
| **Monitoring** | Monitoring dan observability | Prometheus, Jaeger, Elasticsearch |
| **Payment** | Payment processing | Stripe, PayPal, Midtrans, Xendit |
| **Rate Limit** | Rate limiting | In-memory, Redis |
| **Scheduling** | Job scheduling | Cron, Redis |
| **Storage** | Object storage | S3, GCS, Azure, MinIO, Cloudflare R2 |
| **ZeroTrust** | Zero Trust security | SPIFFE/SPIRE, Istio, mTLS |

## 🛠️ Instalasi

```bash
go get github.com/anasamu/go-micro-libs
```

## 📖 Penggunaan Dasar

### 1. AI Library

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/ai/types"
)

func main() {
    // Buat AI Manager
    aiManager := microservices.NewAIManager()
    
    // Tambahkan provider OpenAI
    config := &types.ProviderConfig{
        Name:    "openai",
        APIKey:  "your-api-key",
        BaseURL: "https://api.openai.com/v1",
    }
    
    err := aiManager.AddProvider(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Chat dengan AI
    ctx := context.Background()
    chatReq := &types.ChatRequest{
        Messages: []types.Message{
            {Role: "user", Content: "Hello, how are you?"},
        },
        Model: "gpt-4",
    }
    
    response, err := aiManager.Chat(ctx, "openai", chatReq)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("AI Response:", response.Choices[0].Message.Content)
}
```

### 2. Database Library

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/database"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat Database Manager
    logger := logrus.New()
    dbManager := microservices.NewDatabaseManager(nil, logger)
    
    // Buat PostgreSQL provider
    postgresProvider := postgresql.NewProvider(logger)
    
    // Konfigurasi provider
    config := map[string]interface{}{
        "host":     "localhost",
        "port":     5432,
        "user":     "postgres",
        "password": "password",
        "database": "mydb",
    }
    
    err := postgresProvider.Configure(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Daftarkan provider
    err = dbManager.RegisterProvider(postgresProvider)
    if err != nil {
        log.Fatal(err)
    }
    
    // Koneksi ke database
    ctx := context.Background()
    err = dbManager.Connect(ctx, "postgresql")
    if err != nil {
        log.Fatal(err)
    }
    
    // Eksekusi query
    result, err := dbManager.Query(ctx, "postgresql", "SELECT * FROM users LIMIT 10")
    if err != nil {
        log.Fatal(err)
    }
    
    // Proses hasil
    for result.Next() {
        // Proses setiap row
    }
}
```

### 3. Cache Library

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/cache/providers/redis"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat Cache Manager
    logger := logrus.New()
    cacheManager := microservices.NewCacheManager(nil, logger)
    
    // Buat Redis provider
    redisConfig := &redis.RedisConfig{
        Host: "localhost",
        Port: 6379,
    }
    
    redisProvider := redis.NewRedisProvider(redisConfig, logger)
    
    // Daftarkan provider
    err := cacheManager.RegisterProvider(redisProvider)
    if err != nil {
        log.Fatal(err)
    }
    
    // Koneksi ke Redis
    ctx := context.Background()
    err = redisProvider.Connect(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    // Set cache
    err = cacheManager.Set(ctx, "key", "value", 10*time.Minute)
    if err != nil {
        log.Fatal(err)
    }
    
    // Get cache
    var value string
    err = cacheManager.Get(ctx, "key", &value)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("Cached value:", value)
}
```

### 4. Storage Library

```go
package main

import (
    "context"
    "log"
    "strings"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/storage"
    "github.com/anasamu/go-micro-libs/storage/providers/s3"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat Storage Manager
    logger := logrus.New()
    storageManager := microservices.NewStorageManager(nil, logger)
    
    // Buat S3 provider
    s3Provider := s3.NewProvider(logger)
    
    // Konfigurasi S3
    config := map[string]interface{}{
        "region":            "us-east-1",
        "access_key_id":     "your-access-key",
        "secret_access_key": "your-secret-key",
        "bucket":            "my-bucket",
    }
    
    err := s3Provider.Configure(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Daftarkan provider
    err = storageManager.RegisterProvider(s3Provider)
    if err != nil {
        log.Fatal(err)
    }
    
    // Upload file
    ctx := context.Background()
    content := strings.NewReader("Hello, World!")
    
    putReq := &storage.PutObjectRequest{
        Bucket:      "my-bucket",
        Key:         "test.txt",
        Content:     content,
        Size:        13,
        ContentType: "text/plain",
    }
    
    response, err := storageManager.PutObject(ctx, "s3", putReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("File uploaded:", response.Key)
}
```

### 5. API Library

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/api"
    "github.com/anasamu/go-micro-libs/api/providers/http"
    "github.com/anasamu/go-micro-libs/api/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat API Manager
    logger := logrus.New()
    apiManager := microservices.NewAPIManager(nil, logger)
    
    // Buat HTTP provider
    httpProvider := http.NewProvider(logger)
    
    // Konfigurasi HTTP provider
    config := map[string]interface{}{
        "base_url": "https://api.example.com",
        "timeout":  30,
    }
    
    err := httpProvider.Configure(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Daftarkan provider
    err = apiManager.RegisterProvider(httpProvider)
    if err != nil {
        log.Fatal(err)
    }
    
    // Koneksi ke provider
    ctx := context.Background()
    err = apiManager.Connect(ctx, "http")
    if err != nil {
        log.Fatal(err)
    }
    
    // Buat request
    request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/users")
    request.AddHeader("Accept", "application/json")
    request.SetAuth(&types.Authentication{
        Type:  types.AuthTypeBearer,
        Token: "your-jwt-token",
    })
    
    // Kirim request
    response, err := apiManager.SendRequest(ctx, "http", request)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Response: %d - %v", response.StatusCode, response.Body)
}
```

### 6. Messaging Library

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/messaging"
    "github.com/anasamu/go-micro-libs/messaging/providers/kafka"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat Messaging Manager
    logger := logrus.New()
    msgManager := microservices.NewMessagingManager(nil, logger)
    
    // Buat Kafka provider
    kafkaProvider := kafka.NewProvider(logger)
    
    // Konfigurasi Kafka
    config := map[string]interface{}{
        "brokers": []string{"localhost:9092"},
    }
    
    err := kafkaProvider.Configure(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Daftarkan provider
    err = msgManager.RegisterProvider(kafkaProvider)
    if err != nil {
        log.Fatal(err)
    }
    
    // Koneksi ke Kafka
    ctx := context.Background()
    err = msgManager.Connect(ctx, "kafka")
    if err != nil {
        log.Fatal(err)
    }
    
    // Publish message
    message := messaging.CreateMessage("user.created", map[string]interface{}{
        "user_id": "123",
        "email":   "user@example.com",
    })
    
    publishReq := &messaging.PublishRequest{
        Topic:   "users",
        Message: message,
    }
    
    response, err := msgManager.PublishMessage(ctx, "kafka", publishReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("Message published:", response.MessageID)
}
```

### 7. Edge Computing Library

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat Edge Manager
    logger := logrus.New()
    edgeManager := microservices.NewEdgeManager()
    
    // Tambahkan Cloudflare provider
    cloudflareConfig := &types.ProviderConfig{
        Name:      "cloudflare",
        APIKey:    "your-cloudflare-api-key",
        AccountID: "your-account-id",
    }
    
    err := edgeManager.AddProvider(cloudflareConfig)
    if err != nil {
        log.Fatal("Failed to add Cloudflare provider:", err)
    }
    
    // Deploy worker
    deployReq := &types.DeployRequest{
        Name:    "my-worker",
        Runtime: "javascript",
        Code:    []byte("export default { async fetch(request) { return new Response('Hello from edge!'); } }"),
        Environment: map[string]string{
            "ENVIRONMENT": "production",
        },
        Memory:  128,
        Timeout: 30 * time.Second,
        Region:  "global",
    }
    
    ctx := context.Background()
    resp, err := edgeManager.Deploy(ctx, "cloudflare", deployReq)
    if err != nil {
        log.Fatal("Deployment failed:", err)
    }
    
    log.Printf("Deployed worker: %s at %s", resp.Name, resp.URL)
}
```

### 8. ZeroTrust Library

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/zerotrust"
    "github.com/anasamu/go-micro-libs/zerotrust/providers/spiffe"
    "github.com/anasamu/go-micro-libs/zerotrust/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Buat ZeroTrust Manager
    logger := logrus.New()
    ztManager := microservices.NewZeroTrustManager(nil, logger)
    
    // Daftarkan SPIFFE provider
    spiffeProvider := spiffe.NewSPIFFEProvider("spiffe", logger)
    spiffeConfig := map[string]interface{}{
        "server_url":   "spire-server:8081",
        "trust_domain": "example.org",
    }
    spiffeProvider.Configure(spiffeConfig)
    ztManager.RegisterProvider(spiffeProvider)
    
    // Autentikasi service
    authRequest := &types.ServiceAuthRequest{
        ServiceID:  "user-service",
        SPIFFEID:   "spiffe://example.org/service/user-service",
        TrustDomain: "example.org",
        Context: map[string]interface{}{
            "environment": "production",
        },
    }
    
    ctx := context.Background()
    response, err := ztManager.AuthenticateService(ctx, "spiffe", authRequest)
    if err != nil {
        log.Fatal(err)
    }
    
    if response.Success {
        log.Printf("Service authenticated: %s", response.IdentityID)
    }
}
```

## 🔧 Konfigurasi

### Environment Variables

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=mydb

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# S3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET=my-bucket

# OpenAI
OPENAI_API_KEY=your-api-key
```

### Configuration File

```yaml
# config.yaml
database:
  postgresql:
    host: localhost
    port: 5432
    user: postgres
    password: password
    database: mydb

cache:
  redis:
    host: localhost
    port: 6379
    password: ""

storage:
  s3:
    region: us-east-1
    access_key_id: your-access-key
    secret_access_key: your-secret-key
    bucket: my-bucket

ai:
  openai:
    api_key: your-api-key
    base_url: https://api.openai.com/v1
```

## 🏗️ Arsitektur

Library ini mengikuti pola arsitektur yang konsisten:

```
Manager (Interface)
    ↓
Provider (Implementation)
    ↓
External Service (Database, Cache, etc.)
```

### Pola Umum

1. **Manager**: Mengelola multiple provider dan menyediakan interface terpadu
2. **Provider**: Implementasi spesifik untuk setiap layanan eksternal
3. **Types**: Definisi tipe data dan interface yang digunakan
4. **Configuration**: Konfigurasi untuk setiap provider

## 🔒 Keamanan

- **Authentication**: Dukungan JWT, OAuth2, 2FA
- **Authorization**: RBAC, ABAC, ACL
- **Encryption**: Password hashing dengan bcrypt
- **Rate Limiting**: Built-in rate limiting
- **Circuit Breaker**: Pattern untuk resilience

## 📊 Monitoring

- **Metrics**: Prometheus integration
- **Tracing**: Jaeger support
- **Logging**: Structured logging dengan logrus
- **Health Checks**: Built-in health check endpoints

## 🧪 Testing

```bash
# Jalankan semua test
go test ./...

# Test dengan coverage
go test -cover ./...

# Test specific module
go test ./ai/...
```

## 📚 Contoh Lengkap

Lihat folder `examples/` untuk contoh implementasi lengkap dari setiap modul.

## 🤝 Kontribusi

1. Fork repository
2. Buat feature branch (`git checkout -b feature/amazing-feature`)
3. Commit perubahan (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Buat Pull Request

## 📄 Lisensi

Distributed under the MIT License. See `LICENSE` for more information.

## 🆘 Support

Jika Anda mengalami masalah atau memiliki pertanyaan:

1. Baca dokumentasi lengkap
2. Cek issues yang sudah ada
3. Buat issue baru jika diperlukan
4. Hubungi maintainer

## 🔄 Changelog

### v1.1.0
- **New Modules**: API, Email, Edge Computing, ZeroTrust
- **New Providers**: 
  - Storage: Cloudflare R2
  - Auth: Auth0, Keycloak, Okta
  - Database: Cassandra, CockroachDB, Elasticsearch, InfluxDB, MariaDB
- **Enhanced Features**: 
  - Improved API integration capabilities
  - Edge computing support with WASM compilation
  - Zero Trust security implementation
  - Email services integration
- **Documentation**: Updated examples and comprehensive guides
- **Performance**: Optimized provider implementations

### v1.0.0
- Initial release
- Support untuk 20+ modul microservices
- 50+ provider implementations
- Comprehensive documentation
- Full test coverage

---

**Dibuat dengan ❤️ untuk komunitas Go Indonesia**
