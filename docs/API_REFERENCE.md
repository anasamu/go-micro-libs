# API Reference

## AI Manager

### Constructor
```go
func NewAIManager() *AIManager
```

### Methods

#### AddProvider
```go
func (m *AIManager) AddProvider(config *types.ProviderConfig) error
```
Menambahkan provider AI baru.

#### Chat
```go
func (m *AIManager) Chat(ctx context.Context, providerName string, req *types.ChatRequest) (*types.ChatResponse, error)
```
Mengirim chat request ke provider AI.

#### ChatWithFallback
```go
func (m *AIManager) ChatWithFallback(ctx context.Context, primaryProvider string, req *types.ChatRequest) (*types.ChatResponse, error)
```
Chat dengan fallback otomatis ke provider lain jika gagal.

#### GenerateText
```go
func (m *AIManager) GenerateText(ctx context.Context, providerName string, req *types.TextGenerationRequest) (*types.TextGenerationResponse, error)
```
Generate text menggunakan AI.

#### EmbedText
```go
func (m *AIManager) EmbedText(ctx context.Context, providerName string, req *types.EmbeddingRequest) (*types.EmbeddingResponse, error)
```
Generate embedding untuk text.

## Database Manager

### Constructor
```go
func NewDatabaseManager(config *types.ManagerConfig, logger *logrus.Logger) *DatabaseManager
```

### Methods

#### RegisterProvider
```go
func (m *DatabaseManager) RegisterProvider(provider types.DatabaseProvider) error
```
Mendaftarkan database provider.

#### Connect
```go
func (m *DatabaseManager) Connect(ctx context.Context, providerName string) error
```
Koneksi ke database.

#### Query
```go
func (m *DatabaseManager) Query(ctx context.Context, providerName string, query string, args ...interface{}) (types.QueryResult, error)
```
Eksekusi query SELECT.

#### Exec
```go
func (m *DatabaseManager) Exec(ctx context.Context, providerName string, query string, args ...interface{}) (types.ExecResult, error)
```
Eksekusi query INSERT/UPDATE/DELETE.

#### BeginTransaction
```go
func (m *DatabaseManager) BeginTransaction(ctx context.Context, providerName string) (types.Transaction, error)
```
Mulai transaction.

## Cache Manager

### Constructor
```go
func NewCacheManager(config *types.ManagerConfig, logger *logrus.Logger) *CacheManager
```

### Methods

#### RegisterProvider
```go
func (m *CacheManager) RegisterProvider(provider types.CacheProvider) error
```
Mendaftarkan cache provider.

#### Set
```go
func (m *CacheManager) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
```
Set value ke cache.

#### Get
```go
func (m *CacheManager) Get(ctx context.Context, key string, dest interface{}) error
```
Get value dari cache.

#### Delete
```go
func (m *CacheManager) Delete(ctx context.Context, key string) error
```
Hapus key dari cache.

#### SetWithTags
```go
func (m *CacheManager) SetWithTags(ctx context.Context, key string, value interface{}, ttl time.Duration, tags []string) error
```
Set value dengan tags.

#### InvalidateByTag
```go
func (m *CacheManager) InvalidateByTag(ctx context.Context, tag string) error
```
Invalidate cache berdasarkan tag.

## Storage Manager

### Constructor
```go
func NewStorageManager(config *types.ManagerConfig, logger *logrus.Logger) *StorageManager
```

### Methods

#### RegisterProvider
```go
func (m *StorageManager) RegisterProvider(provider types.StorageProvider) error
```
Mendaftarkan storage provider.

#### PutObject
```go
func (m *StorageManager) PutObject(ctx context.Context, providerName string, request *types.PutObjectRequest) (*types.PutObjectResponse, error)
```
Upload object ke storage.

#### GetObject
```go
func (m *StorageManager) GetObject(ctx context.Context, providerName string, request *types.GetObjectRequest) (*types.GetObjectResponse, error)
```
Download object dari storage.

#### DeleteObject
```go
func (m *StorageManager) DeleteObject(ctx context.Context, providerName string, request *types.DeleteObjectRequest) error
```
Hapus object dari storage.

#### GeneratePresignedURL
```go
func (m *StorageManager) GeneratePresignedURL(ctx context.Context, providerName string, request *types.PresignedURLRequest) (string, error)
```
Generate presigned URL untuk object.

## Messaging Manager

### Constructor
```go
func NewMessagingManager(config *types.ManagerConfig, logger *logrus.Logger) *MessagingManager
```

### Methods

#### RegisterProvider
```go
func (m *MessagingManager) RegisterProvider(provider types.MessagingProvider) error
```
Mendaftarkan messaging provider.

#### Connect
```go
func (m *MessagingManager) Connect(ctx context.Context, providerName string) error
```
Koneksi ke messaging service.

#### PublishMessage
```go
func (m *MessagingManager) PublishMessage(ctx context.Context, providerName string, request *types.PublishRequest) (*types.PublishResponse, error)
```
Publish message ke topic.

#### SubscribeToTopic
```go
func (m *MessagingManager) SubscribeToTopic(ctx context.Context, providerName string, request *types.SubscribeRequest, handler types.MessageHandler) error
```
Subscribe ke topic.

## Auth Manager

### Constructor
```go
func NewAuthManager(config *types.ManagerConfig, logger *logrus.Logger) *AuthManager
```

### Methods

#### RegisterProvider
```go
func (m *AuthManager) RegisterProvider(provider types.AuthProvider) error
```
Mendaftarkan auth provider.

#### Authenticate
```go
func (m *AuthManager) Authenticate(ctx context.Context, providerName string, request *types.AuthRequest) (*types.AuthResponse, error)
```
Autentikasi user.

#### ValidateToken
```go
func (m *AuthManager) ValidateToken(ctx context.Context, providerName string, request *types.TokenValidationRequest) (*types.TokenValidationResponse, error)
```
Validasi token.

#### Authorize
```go
func (m *AuthManager) Authorize(ctx context.Context, providerName string, request *types.AuthorizationRequest) (*types.AuthorizationResponse, error)
```
Otorisasi akses.

## Monitoring Manager

### Constructor
```go
func NewMonitoringManager(config *types.ManagerConfig, logger *logrus.Logger) *MonitoringManager
```

### Methods

#### RegisterProvider
```go
func (m *MonitoringManager) RegisterProvider(provider types.MonitoringProvider) error
```
Mendaftarkan monitoring provider.

#### SubmitMetrics
```go
func (m *MonitoringManager) SubmitMetrics(ctx context.Context, providerName string, request *types.MetricRequest) error
```
Submit metrics.

#### SubmitLogs
```go
func (m *MonitoringManager) SubmitLogs(ctx context.Context, providerName string, request *types.LogRequest) error
```
Submit logs.

#### SubmitTraces
```go
func (m *MonitoringManager) SubmitTraces(ctx context.Context, providerName string, request *types.TraceRequest) error
```
Submit traces.

## Communication Manager

### Constructor
```go
func NewCommunicationManager(config *types.ManagerConfig, logger *logrus.Logger) *CommunicationManager
```

### Methods

#### RegisterProvider
```go
func (m *CommunicationManager) RegisterProvider(provider types.CommunicationProvider) error
```
Mendaftarkan communication provider.

#### Start
```go
func (m *CommunicationManager) Start(ctx context.Context, providerName string, config map[string]interface{}) error
```
Start communication server.

#### HandleRequest
```go
func (m *CommunicationManager) HandleRequest(ctx context.Context, providerName string, request *types.Request) (*types.Response, error)
```
Handle HTTP request.

#### SendMessage
```go
func (m *CommunicationManager) SendMessage(ctx context.Context, providerName string, request *types.SendMessageRequest) (*types.SendMessageResponse, error)
```
Send message.

## Middleware Manager

### Constructor
```go
func NewMiddlewareManager(config *types.ManagerConfig, logger *logrus.Logger) *MiddlewareManager
```

### Methods

#### RegisterProvider
```go
func (m *MiddlewareManager) RegisterProvider(provider types.MiddlewareProvider) error
```
Mendaftarkan middleware provider.

#### ProcessRequest
```go
func (m *MiddlewareManager) ProcessRequest(ctx context.Context, providerName string, request *types.MiddlewareRequest) (*types.MiddlewareResponse, error)
```
Process HTTP request.

#### ProcessResponse
```go
func (m *MiddlewareManager) ProcessResponse(ctx context.Context, providerName string, response *types.MiddlewareResponse) (*types.MiddlewareResponse, error)
```
Process HTTP response.

#### CreateChain
```go
func (m *MiddlewareManager) CreateChain(ctx context.Context, providerName string, config *types.MiddlewareConfig) (*types.MiddlewareChain, error)
```
Create middleware chain.

## Utils

### String Utils
```go
func IsEmpty(s string) bool
func IsNotEmpty(s string) bool
func Truncate(s string, length int) string
func Contains(s, substr string) bool
func StartsWith(s, prefix string) bool
func EndsWith(s, suffix string) bool
```

### Validation Utils
```go
func IsValidEmail(email string) bool
func IsValidURL(url string) bool
func IsValidPhone(phone string) bool
func IsValidUUID(uuid string) bool
```

### Crypto Utils
```go
func HashPassword(password string) (string, error)
func VerifyPassword(password, hash string) bool
func GenerateRandomString(length int) (string, error)
func Encrypt(plaintext, key string) (string, error)
func Decrypt(ciphertext, key string) (string, error)
```

### Time Utils
```go
func NowUTC() time.Time
func ParseTime(layout, value string) (time.Time, error)
func FormatTime(t time.Time, layout string) string
func AddDays(t time.Time, days int) time.Time
func AddHours(t time.Time, hours int) time.Time
```

### UUID Utils
```go
func GenerateUUID() uuid.UUID
func GenerateUUIDString() string
func ParseUUID(s string) (uuid.UUID, error)
```

### File Utils
```go
func GetFileExtension(filename string) string
func GetFileSize(filepath string) (int64, error)
func FileExists(filepath string) bool
func CreateDirectory(dirpath string) error
func DeleteFile(filepath string) error
```
