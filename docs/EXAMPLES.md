# Examples

## 1. AI Chat Application

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
    
    // Konfigurasi OpenAI
    openaiConfig := &types.ProviderConfig{
        Name:    "openai",
        APIKey:  "sk-your-openai-key",
        BaseURL: "https://api.openai.com/v1",
    }
    
    // Konfigurasi Anthropic
    anthropicConfig := &types.ProviderConfig{
        Name:    "anthropic",
        APIKey:  "sk-ant-your-anthropic-key",
        BaseURL: "https://api.anthropic.com",
    }
    
    // Tambahkan providers
    aiManager.AddProvider(openaiConfig)
    aiManager.AddProvider(anthropicConfig)
    
    // Chat dengan fallback
    ctx := context.Background()
    chatReq := &types.ChatRequest{
        Messages: []types.Message{
            {Role: "user", Content: "Explain quantum computing in simple terms"},
        },
        Model: "gpt-4",
    }
    
    response, err := aiManager.ChatWithFallback(ctx, "openai", chatReq)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("AI Response:", response.Choices[0].Message.Content)
}
```

## 2. Database CRUD Operations

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/database"
    "github.com/anasamu/go-micro-libs/database/providers/postgresql"
    "github.com/sirupsen/logrus"
)

type User struct {
    ID    int    `db:"id"`
    Name  string `db:"name"`
    Email string `db:"email"`
}

func main() {
    logger := logrus.New()
    dbManager := microservices.NewDatabaseManager(nil, logger)
    
    // Setup PostgreSQL
    postgresProvider := postgresql.NewProvider(logger)
    config := map[string]interface{}{
        "host":     "localhost",
        "port":     5432,
        "user":     "postgres",
        "password": "password",
        "database": "testdb",
    }
    
    postgresProvider.Configure(config)
    dbManager.RegisterProvider(postgresProvider)
    
    ctx := context.Background()
    dbManager.Connect(ctx, "postgresql")
    
    // Create table
    createTableSQL := `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL
        )
    `
    dbManager.Exec(ctx, "postgresql", createTableSQL)
    
    // Insert user
    insertSQL := "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id"
    result, err := dbManager.Query(ctx, "postgresql", insertSQL, "John Doe", "john@example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    var userID int
    if result.Next() {
        result.Scan(&userID)
    }
    
    // Select user
    selectSQL := "SELECT id, name, email FROM users WHERE id = $1"
    result, err = dbManager.Query(ctx, "postgresql", selectSQL, userID)
    if err != nil {
        log.Fatal(err)
    }
    
    var user User
    if result.Next() {
        result.Scan(&user.ID, &user.Name, &user.Email)
        log.Printf("User: %+v", user)
    }
}
```

## 3. Cache with Redis

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

type Product struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Price float64 `json:"price"`
}

func main() {
    logger := logrus.New()
    cacheManager := microservices.NewCacheManager(nil, logger)
    
    // Setup Redis
    redisConfig := &redis.RedisConfig{
        Host:     "localhost",
        Port:     6379,
        Password: "",
        DB:       0,
    }
    
    redisProvider := redis.NewRedisProvider(redisConfig, logger)
    cacheManager.RegisterProvider(redisProvider)
    
    ctx := context.Background()
    redisProvider.Connect(ctx)
    
    // Cache product
    product := Product{
        ID:    1,
        Name:  "Laptop",
        Price: 999.99,
    }
    
    err := cacheManager.Set(ctx, "product:1", product, 1*time.Hour)
    if err != nil {
        log.Fatal(err)
    }
    
    // Get from cache
    var cachedProduct Product
    err = cacheManager.Get(ctx, "product:1", &cachedProduct)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Cached product: %+v", cachedProduct)
    
    // Cache with tags
    err = cacheManager.SetWithTags(ctx, "product:2", Product{
        ID:    2,
        Name:  "Mouse",
        Price: 29.99,
    }, 1*time.Hour, []string{"electronics", "accessories"})
    if err != nil {
        log.Fatal(err)
    }
    
    // Invalidate by tag
    err = cacheManager.InvalidateByTag(ctx, "electronics")
    if err != nil {
        log.Fatal(err)
    }
}
```

## 4. File Upload to S3

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
    logger := logrus.New()
    storageManager := microservices.NewStorageManager(nil, logger)
    
    // Setup S3
    s3Provider := s3.NewProvider(logger)
    config := map[string]interface{}{
        "region":            "us-east-1",
        "access_key_id":     "your-access-key",
        "secret_access_key": "your-secret-key",
        "bucket":            "my-bucket",
    }
    
    s3Provider.Configure(config)
    storageManager.RegisterProvider(s3Provider)
    
    ctx := context.Background()
    
    // Upload file
    content := strings.NewReader("Hello, World! This is a test file.")
    
    putReq := &storage.PutObjectRequest{
        Bucket:      "my-bucket",
        Key:         "test/hello.txt",
        Content:     content,
        Size:        35,
        ContentType: "text/plain",
    }
    
    response, err := storageManager.PutObject(ctx, "s3", putReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("File uploaded: %s", response.Key)
    
    // Generate presigned URL
    urlReq := &storage.PresignedURLRequest{
        Bucket: "my-bucket",
        Key:    "test/hello.txt",
        Method: "GET",
        Expiry: 1 * time.Hour,
    }
    
    url, err := storageManager.GeneratePresignedURL(ctx, "s3", urlReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Presigned URL: %s", url)
}
```

## 5. Message Queue with Kafka

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
    logger := logrus.New()
    msgManager := microservices.NewMessagingManager(nil, logger)
    
    // Setup Kafka
    kafkaProvider := kafka.NewProvider(logger)
    config := map[string]interface{}{
        "brokers": []string{"localhost:9092"},
    }
    
    kafkaProvider.Configure(config)
    msgManager.RegisterProvider(kafkaProvider)
    
    ctx := context.Background()
    msgManager.Connect(ctx, "kafka")
    
    // Create topic
    createReq := &messaging.CreateTopicRequest{
        Topic: "user-events",
    }
    msgManager.CreateTopic(ctx, "kafka", createReq)
    
    // Publish message
    message := messaging.CreateMessage("user.created", map[string]interface{}{
        "user_id": "123",
        "email":   "user@example.com",
        "name":    "John Doe",
    })
    
    publishReq := &messaging.PublishRequest{
        Topic:   "user-events",
        Message: message,
    }
    
    response, err := msgManager.PublishMessage(ctx, "kafka", publishReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Message published: %s", response.MessageID)
    
    // Subscribe to topic
    subscribeReq := &messaging.SubscribeRequest{
        Topic: "user-events",
    }
    
    handler := func(ctx context.Context, message *messaging.Message) error {
        log.Printf("Received message: %s", message.Data)
        return nil
    }
    
    go func() {
        err := msgManager.SubscribeToTopic(ctx, "kafka", subscribeReq, handler)
        if err != nil {
            log.Fatal(err)
        }
    }()
    
    // Keep running
    select {}
}
```

## 6. Authentication with JWT

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/auth"
    "github.com/anasamu/go-micro-libs/auth/providers/authentication/jwt"
    "github.com/anasamu/go-micro-libs/auth/types"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    authManager := microservices.NewAuthManager(nil, logger)
    
    // Setup JWT provider
    jwtProvider := jwt.NewProvider(logger)
    config := map[string]interface{}{
        "secret_key": "your-secret-key",
        "expiry":     24 * 60 * 60, // 24 hours
    }
    
    jwtProvider.Configure(config)
    authManager.RegisterProvider(jwtProvider)
    
    ctx := context.Background()
    
    // Authenticate user
    authReq := &types.AuthRequest{
        Credentials: map[string]interface{}{
            "username": "john_doe",
            "password": "password123",
        },
    }
    
    authResp, err := authManager.Authenticate(ctx, "jwt", authReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Authentication successful: %s", authResp.Token)
    
    // Validate token
    validateReq := &types.TokenValidationRequest{
        Token: authResp.Token,
    }
    
    validateResp, err := authManager.ValidateToken(ctx, "jwt", validateReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Token valid: %v", validateResp.Valid)
    log.Printf("User ID: %s", validateResp.UserID)
}
```

## 7. Monitoring with Prometheus

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/monitoring"
    "github.com/anasamu/go-micro-libs/monitoring/providers/prometheus"
    "github.com/anasamu/go-micro-libs/monitoring/types"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    monitoringManager := microservices.NewMonitoringManager(nil, logger)
    
    // Setup Prometheus
    prometheusProvider := prometheus.NewProvider(logger)
    config := map[string]interface{}{
        "pushgateway_url": "http://localhost:9091",
    }
    
    prometheusProvider.Configure(config)
    monitoringManager.RegisterProvider(prometheusProvider)
    
    ctx := context.Background()
    
    // Submit metrics
    metricReq := &types.MetricRequest{
        Metrics: []types.Metric{
            {
                Name:   "http_requests_total",
                Value:  1,
                Labels: map[string]string{
                    "method": "GET",
                    "path":   "/api/users",
                    "status": "200",
                },
            },
            {
                Name:   "response_time_seconds",
                Value:  0.1,
                Labels: map[string]string{
                    "endpoint": "/api/users",
                },
            },
        },
    }
    
    err := monitoringManager.SubmitMetrics(ctx, "prometheus", metricReq)
    if err != nil {
        log.Fatal(err)
    }
    
    // Submit logs
    logReq := &types.LogRequest{
        Logs: []types.LogEntry{
            {
                Level:     "info",
                Message:   "User login successful",
                Timestamp: time.Now(),
                Fields: map[string]interface{}{
                    "user_id": "123",
                    "ip":      "192.168.1.1",
                },
            },
        },
    }
    
    err = monitoringManager.SubmitLogs(ctx, "prometheus", logReq)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("Metrics and logs submitted successfully")
}
```

## 8. HTTP Server with Middleware

```go
package main

import (
    "context"
    "log"
    "net/http"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/communication"
    "github.com/anasamu/go-micro-libs/communication/providers/http"
    "github.com/anasamu/go-micro-libs/middleware"
    "github.com/anasamu/go-micro-libs/middleware/providers/auth"
    "github.com/anasamu/go-micro-libs/middleware/providers/logging"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    
    // Setup HTTP communication
    commManager := microservices.NewCommunicationManager(nil, logger)
    httpProvider := http.NewProvider(logger)
    commManager.RegisterProvider(httpProvider)
    
    // Setup middleware
    middlewareManager := microservices.NewMiddlewareManager(nil, logger)
    
    // Auth middleware
    authProvider := auth.NewProvider(logger)
    middlewareManager.RegisterProvider(authProvider)
    
    // Logging middleware
    loggingProvider := logging.NewProvider(logger)
    middlewareManager.RegisterProvider(loggingProvider)
    
    ctx := context.Background()
    
    // Create middleware chain
    middlewareConfig := &middleware.MiddlewareConfig{
        Providers: []string{"logging", "auth"},
    }
    
    chain, err := middlewareManager.CreateChain(ctx, "http", middlewareConfig)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create HTTP handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Hello, World!"))
    })
    
    // Wrap with middleware
    wrappedHandler := middlewareManager.WrapHTTPHandler(handler, middlewareConfig)
    
    // Start server
    server := &http.Server{
        Addr:    ":8080",
        Handler: wrappedHandler,
    }
    
    log.Println("Server starting on :8080")
    log.Fatal(server.ListenAndServe())
}
```

## 9. Complete Microservice

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/auth/types"
    "github.com/anasamu/go-micro-libs/cache/providers/redis"
    "github.com/anasamu/go-micro-libs/database/providers/postgresql"
    "github.com/anasamu/go-micro-libs/messaging/providers/kafka"
    "github.com/anasamu/go-micro-libs/storage/providers/s3"
    "github.com/sirupsen/logrus"
)

type UserService struct {
    dbManager      *microservices.DatabaseManager
    cacheManager   *microservices.CacheManager
    authManager    *microservices.AuthManager
    msgManager     *microservices.MessagingManager
    storageManager *microservices.StorageManager
    logger         *logrus.Logger
}

func NewUserService() *UserService {
    logger := logrus.New()
    
    // Initialize managers
    dbManager := microservices.NewDatabaseManager(nil, logger)
    cacheManager := microservices.NewCacheManager(nil, logger)
    authManager := microservices.NewAuthManager(nil, logger)
    msgManager := microservices.NewMessagingManager(nil, logger)
    storageManager := microservices.NewStorageManager(nil, logger)
    
    // Setup providers
    setupDatabase(dbManager, logger)
    setupCache(cacheManager, logger)
    setupAuth(authManager, logger)
    setupMessaging(msgManager, logger)
    setupStorage(storageManager, logger)
    
    return &UserService{
        dbManager:      dbManager,
        cacheManager:   cacheManager,
        authManager:    authManager,
        msgManager:     msgManager,
        storageManager: storageManager,
        logger:         logger,
    }
}

func (s *UserService) CreateUser(ctx context.Context, name, email, password string) error {
    // Hash password
    hashedPassword, err := microservices.HashPassword(password)
    if err != nil {
        return err
    }
    
    // Insert to database
    query := "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id"
    result, err := s.dbManager.Query(ctx, "postgresql", query, name, email, hashedPassword)
    if err != nil {
        return err
    }
    
    var userID int
    if result.Next() {
        result.Scan(&userID)
    }
    
    // Cache user data
    user := map[string]interface{}{
        "id":    userID,
        "name":  name,
        "email": email,
    }
    
    s.cacheManager.Set(ctx, fmt.Sprintf("user:%d", userID), user, 1*time.Hour)
    
    // Publish event
    message := microservices.CreateMessage("user.created", user)
    publishReq := &microservices.PublishRequest{
        Topic:   "user-events",
        Message: message,
    }
    
    s.msgManager.PublishMessage(ctx, "kafka", publishReq)
    
    return nil
}

func (s *UserService) GetUser(ctx context.Context, userID int) (map[string]interface{}, error) {
    // Try cache first
    var user map[string]interface{}
    err := s.cacheManager.Get(ctx, fmt.Sprintf("user:%d", userID), &user)
    if err == nil {
        return user, nil
    }
    
    // Get from database
    query := "SELECT id, name, email FROM users WHERE id = $1"
    result, err := s.dbManager.Query(ctx, "postgresql", query, userID)
    if err != nil {
        return nil, err
    }
    
    if result.Next() {
        result.Scan(&user["id"], &user["name"], &user["email"])
        
        // Cache result
        s.cacheManager.Set(ctx, fmt.Sprintf("user:%d", userID), user, 1*time.Hour)
        
        return user, nil
    }
    
    return nil, microservices.ErrNotFound
}

func main() {
    service := NewUserService()
    
    // Create HTTP server
    http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
        ctx := context.Background()
        
        switch r.Method {
        case "POST":
            // Create user
            name := r.FormValue("name")
            email := r.FormValue("email")
            password := r.FormValue("password")
            
            err := service.CreateUser(ctx, name, email, password)
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }
            
            w.WriteHeader(http.StatusCreated)
            w.Write([]byte("User created successfully"))
            
        case "GET":
            // Get user
            userID := r.URL.Query().Get("id")
            if userID == "" {
                http.Error(w, "User ID required", http.StatusBadRequest)
                return
            }
            
            user, err := service.GetUser(ctx, userID)
            if err != nil {
                http.Error(w, err.Error(), http.StatusNotFound)
                return
            }
            
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusOK)
            // Return user as JSON
        }
    })
    
    log.Println("User service starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## 10. Configuration Management

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs"
    "github.com/anasamu/go-micro-libs/config"
    "github.com/anasamu/go-micro-libs/config/providers/env"
    "github.com/anasamu/go-micro-libs/config/providers/file"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    configManager := microservices.NewConfigManager(nil, logger)
    
    // Setup environment provider
    envProvider := env.NewProvider(logger)
    configManager.RegisterProvider(envProvider)
    
    // Setup file provider
    fileProvider := file.NewProvider(logger)
    fileConfig := map[string]interface{}{
        "path": "config.yaml",
    }
    fileProvider.Configure(fileConfig)
    configManager.RegisterProvider(fileProvider)
    
    ctx := context.Background()
    
    // Load configuration
    config, err := configManager.LoadConfig(ctx, "file")
    if err != nil {
        log.Fatal(err)
    }
    
    // Get specific values
    dbHost, err := configManager.GetString(ctx, "file", "database.host")
    if err != nil {
        log.Fatal(err)
    }
    
    dbPort, err := configManager.GetInt(ctx, "file", "database.port")
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Database: %s:%d", dbHost, dbPort)
    
    // Watch for changes
    configManager.WatchConfig(ctx, "file", func(newConfig map[string]interface{}) {
        log.Println("Configuration updated")
    })
}
```
