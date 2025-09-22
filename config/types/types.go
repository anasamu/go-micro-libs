package types

import (
	"fmt"
	"time"
)

// TLSConfig holds TLS configuration
type TLSConfig struct {
	CertFile           string   `mapstructure:"cert_file"`
	KeyFile            string   `mapstructure:"key_file"`
	CAFile             string   `mapstructure:"ca_file"`
	ServerName         string   `mapstructure:"server_name"`
	InsecureSkipVerify bool     `mapstructure:"insecure_skip_verify"`
	MinVersion         string   `mapstructure:"min_version"`
	MaxVersion         string   `mapstructure:"max_version"`
	CipherSuites       []string `mapstructure:"cipher_suites"`
}

// ConfigProvider represents a configuration provider interface
type ConfigProvider interface {
	Load() (*Config, error)
	Save(config *Config) error
	Watch(callback func(*Config)) error
	Close() error
}

// Config holds all configuration for the application
type Config struct {
	Server         ServerConfig            `mapstructure:"server"`
	Database       DatabaseConfig          `mapstructure:"database"`
	Configuration  ConfigurationConfig     `mapstructure:"config"`
	Logging        LoggingConfig           `mapstructure:"logging"`
	Monitoring     MonitoringConfig        `mapstructure:"monitoring"`
	Storage        StorageConfig           `mapstructure:"storage"`
	Auth           AuthConfig              `mapstructure:"auth"`
	API            APIConfig               `mapstructure:"api"`
	Communication  CommunicationConfig     `mapstructure:"communication"`
	Cache          CacheConfig             `mapstructure:"cache"`
	Messaging      MessagingConfig         `mapstructure:"messaging"`
	Email          EmailConfig             `mapstructure:"email"`
	Payment        PaymentConfig           `mapstructure:"payment"`
	Discovery      DiscoveryConfig         `mapstructure:"discovery"`
	Failover       FailoverConfig          `mapstructure:"failover"`
	Edge           EdgeConfig              `mapstructure:"edge"`
	CircuitBreaker CircuitBreakerLibConfig `mapstructure:"circuitbreaker"`
	Event          EventConfig             `mapstructure:"event"`
	RateLimit      RateLimitConfig         `mapstructure:"ratelimit"`
	Scheduling     SchedulingConfig        `mapstructure:"scheduling"`
	ZeroTrust      ZeroTrustConfig         `mapstructure:"zerotrust"`
	Backup         BackupConfig            `mapstructure:"backup"`
	Chaos          ChaosConfig             `mapstructure:"chaos"`
	AI             AIConfig                `mapstructure:"ai"`
	Middleware     MiddlewareConfig        `mapstructure:"middleware"`
	FileGen        FileGenConfig           `mapstructure:"filegen"`
	Services       ServicesConfig          `mapstructure:"services"`
	Custom         map[string]interface{}  `mapstructure:",remain"` // Dynamic custom configuration
}

// ServerConfig holds server configuration
type ServerConfig struct {
	ServiceName   string              `mapstructure:"service_name"`
	Version       string              `mapstructure:"version"`
	Environment   string              `mapstructure:"environment"`
	Configuration ConfigurationConfig `mapstructure:"config"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	PostgreSQL  PostgreSQLConfig `mapstructure:"postgresql"`
	MongoDB     MongoDBConfig    `mapstructure:"mongodb"`
	MySQL       MySQLConfig      `mapstructure:"mysql"`
	MariaDB     MariaDBConfig    `mapstructure:"mariadb"`
	SQLite      SQLiteConfig     `mapstructure:"sqlite"`
	Cassandra   CassandraConfig  `mapstructure:"cassandra"`
	CockroachDB CockroachConfig  `mapstructure:"cockroachdb"`
	Redis       RedisDBConfig    `mapstructure:"redis"`
	InfluxDB    InfluxDBConfig   `mapstructure:"influxdb"`
	Elastic     ElasticDBConfig  `mapstructure:"elasticsearch"`
}

// PostgreSQLConfig holds PostgreSQL configuration
type PostgreSQLConfig struct {
	// Basic connection settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`

	// SSL/TLS settings
	SSLMode   string    `mapstructure:"sslmode"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Connection pool settings
	MaxOpenConns    int `mapstructure:"max_open_conns"`
	MaxIdleConns    int `mapstructure:"max_idle_conns"`
	MinOpenConns    int `mapstructure:"min_open_conns"`
	ConnMaxLifetime int `mapstructure:"conn_max_lifetime"`  // seconds
	ConnMaxIdleTime int `mapstructure:"conn_max_idle_time"` // seconds

	// Timeout settings
	ConnectTimeout   int `mapstructure:"connect_timeout"`   // seconds
	QueryTimeout     int `mapstructure:"query_timeout"`     // seconds
	StatementTimeout int `mapstructure:"statement_timeout"` // milliseconds

	// Performance settings
	PreferSimpleProtocol bool `mapstructure:"prefer_simple_protocol"`
	BinaryParameters     bool `mapstructure:"binary_parameters"`
	FallbackToSimple     bool `mapstructure:"fallback_to_simple"`

	// Connection parameters
	ApplicationName             string `mapstructure:"application_name"`
	Timezone                    string `mapstructure:"timezone"`
	SearchPath                  string `mapstructure:"search_path"`
	DefaultTransactionIsolation string `mapstructure:"default_transaction_isolation"`

	// Replication settings
	ReplicationMode string `mapstructure:"replication_mode"`
	StandbyMode     string `mapstructure:"standby_mode"`

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// Backup and recovery
	EnableWALArchiving bool   `mapstructure:"enable_wal_archiving"`
	ArchiveCommand     string `mapstructure:"archive_command"`
	RestoreCommand     string `mapstructure:"restore_command"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// MongoDBConfig holds MongoDB configuration
type MongoDBConfig struct {
	// Connection settings
	URI      string   `mapstructure:"uri"`
	Database string   `mapstructure:"database"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	Hosts    []string `mapstructure:"hosts"`

	// Connection pool settings
	MaxPoolSize     int `mapstructure:"max_pool_size"`
	MinPoolSize     int `mapstructure:"min_pool_size"`
	MaxConnIdleTime int `mapstructure:"max_conn_idle_time"` // milliseconds
	MaxConnecting   int `mapstructure:"max_connecting"`
	MaxConnLifeTime int `mapstructure:"max_conn_life_time"` // milliseconds

	// Timeout settings
	ConnectTimeout    int `mapstructure:"connect_timeout"`    // milliseconds
	SocketTimeout     int `mapstructure:"socket_timeout"`     // milliseconds
	ServerTimeout     int `mapstructure:"server_timeout"`     // milliseconds
	HeartbeatInterval int `mapstructure:"heartbeat_interval"` // milliseconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Authentication settings
	AuthSource    string `mapstructure:"auth_source"`
	AuthMechanism string `mapstructure:"auth_mechanism"`

	// Replica set settings
	ReplicaSetName string             `mapstructure:"replica_set_name"`
	ReadPreference string             `mapstructure:"read_preference"` // primary, secondary, etc.
	WriteConcern   WriteConcernConfig `mapstructure:"write_concern"`
	ReadConcern    ReadConcernConfig  `mapstructure:"read_concern"`

	// Compression settings
	Compressors []string `mapstructure:"compressors"` // snappy, zlib, zstd

	// Performance settings
	DirectConnection bool `mapstructure:"direct_connection"`
	RetryWrites      bool `mapstructure:"retry_writes"`
	RetryReads       bool `mapstructure:"retry_reads"`

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// GridFS settings
	GridFSBucket string `mapstructure:"gridfs_bucket"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// WriteConcernConfig holds MongoDB write concern configuration
type WriteConcernConfig struct {
	W        interface{} `mapstructure:"w"` // int or string
	J        bool        `mapstructure:"j"`
	WTimeout int         `mapstructure:"wtimeout"` // milliseconds
}

// ReadConcernConfig holds MongoDB read concern configuration
type ReadConcernConfig struct {
	Level string `mapstructure:"level"` // local, majority, linearizable, etc.
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	// Basic connection settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	Username string `mapstructure:"username"`

	// Connection pool settings
	PoolSize        int `mapstructure:"pool_size"`
	MinIdleConns    int `mapstructure:"min_idle_conns"`
	MaxConnAge      int `mapstructure:"max_conn_age"`    // seconds
	PoolTimeout     int `mapstructure:"pool_timeout"`    // seconds
	IdleTimeout     int `mapstructure:"idle_timeout"`    // seconds
	IdleCheckFreq   int `mapstructure:"idle_check_freq"` // seconds
	MaxRetries      int `mapstructure:"max_retries"`
	MinRetryBackoff int `mapstructure:"min_retry_backoff"` // milliseconds
	MaxRetryBackoff int `mapstructure:"max_retry_backoff"` // milliseconds

	// Timeout settings
	DialTimeout  int `mapstructure:"dial_timeout"`  // seconds
	ReadTimeout  int `mapstructure:"read_timeout"`  // seconds
	WriteTimeout int `mapstructure:"write_timeout"` // seconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Cluster settings
	ClusterNodes []string `mapstructure:"cluster_nodes"`
	MaxRedirects int      `mapstructure:"max_redirects"`

	// Sentinel settings
	SentinelMasterName string   `mapstructure:"sentinel_master_name"`
	SentinelAddrs      []string `mapstructure:"sentinel_addrs"`
	SentinelPassword   string   `mapstructure:"sentinel_password"`

	// Redis Streams settings
	StreamBlockTimeout int `mapstructure:"stream_block_timeout"` // milliseconds
	StreamReadCount    int `mapstructure:"stream_read_count"`

	// Performance settings
	DisableIndentity bool   `mapstructure:"disable_indentity"`
	IdentitySuffix   string `mapstructure:"identity_suffix"`

	// Monitoring and health check
	HealthCheckInterval int  `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// VaultConfig holds Vault configuration
type VaultConfig struct {
	Address string `mapstructure:"address"`
	Token   string `mapstructure:"token"`
	Path    string `mapstructure:"path"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level   string              `mapstructure:"level"`
	Format  string              `mapstructure:"format"`
	Output  string              `mapstructure:"output"`
	Elastic ElasticsearchConfig `mapstructure:"elastic"`
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
	Jaeger     JaegerConfig     `mapstructure:"jaeger"`
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    string `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

// JaegerConfig holds Jaeger configuration
type JaegerConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
	Service  string `mapstructure:"service"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	MinIO MinIOConfig `mapstructure:"minio"`
	S3    S3Config    `mapstructure:"s3"`
	GCS   GCSConfig   `mapstructure:"gcs"`
	Azure AzureConfig `mapstructure:"azure"`
	R2    R2Config    `mapstructure:"r2"`
}

// MinIOConfig holds MinIO configuration
type MinIOConfig struct {
	// Basic settings
	Endpoint        string `mapstructure:"endpoint"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	BucketName      string `mapstructure:"bucket_name"`

	// SSL/TLS settings
	UseSSL    bool      `mapstructure:"use_ssl"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Connection settings
	Timeout      int `mapstructure:"timeout"` // seconds
	MaxRetries   int `mapstructure:"max_retries"`
	RetryBackoff int `mapstructure:"retry_backoff"` // milliseconds

	// Upload settings
	PartSize    int64 `mapstructure:"part_size"` // bytes
	Concurrency int   `mapstructure:"concurrency"`

	// Storage class
	StorageClass string `mapstructure:"storage_class"`

	// Server-side encryption
	SSEAlgorithm   string `mapstructure:"sse_algorithm"`
	SSEKMSKeyID    string `mapstructure:"sse_kms_key_id"`
	SSECustomerKey string `mapstructure:"sse_customer_key"`

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// S3Config holds S3 configuration
type S3Config struct {
	// Basic settings
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	BucketName      string `mapstructure:"bucket_name"`
	Endpoint        string `mapstructure:"endpoint"`

	// Authentication
	SessionToken string `mapstructure:"session_token"`
	Profile      string `mapstructure:"profile"`

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Connection settings
	MaxRetries   int `mapstructure:"max_retries"`
	Timeout      int `mapstructure:"timeout"`       // seconds
	RetryBackoff int `mapstructure:"retry_backoff"` // milliseconds

	// Upload settings
	PartSize       int64 `mapstructure:"part_size"` // bytes
	MaxUploadParts int   `mapstructure:"max_upload_parts"`
	Concurrency    int   `mapstructure:"concurrency"`
	UseAccelerate  bool  `mapstructure:"use_accelerate"`
	UseDualStack   bool  `mapstructure:"use_dual_stack"`

	// Storage class
	StorageClass string `mapstructure:"storage_class"` // STANDARD, REDUCED_REDUNDANCY, etc.

	// Server-side encryption
	SSEAlgorithm   string `mapstructure:"sse_algorithm"`
	SSEKMSKeyID    string `mapstructure:"sse_kms_key_id"`
	SSECustomerKey string `mapstructure:"sse_customer_key"`

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// SearchConfig holds search configuration
type SearchConfig struct {
	Elasticsearch ElasticsearchConfig `mapstructure:"elasticsearch"`
}

// ElasticsearchConfig holds Elasticsearch configuration
type ElasticsearchConfig struct {
	// Basic connection settings
	URLs     []string `mapstructure:"urls"`
	URL      string   `mapstructure:"url"` // legacy support
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	APIKey   string   `mapstructure:"api_key"`

	// Connection settings
	MaxRetries    int `mapstructure:"max_retries"`
	RetryInterval int `mapstructure:"retry_interval"` // milliseconds

	// Timeout settings
	DialTimeout    int `mapstructure:"dial_timeout"`    // seconds
	RequestTimeout int `mapstructure:"request_timeout"` // seconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Connection pool settings
	MaxIdleConns        int `mapstructure:"max_idle_conns"`
	MaxIdleConnsPerHost int `mapstructure:"max_idle_conns_per_host"`
	IdleConnTimeout     int `mapstructure:"idle_conn_timeout"` // seconds

	// Index settings
	Index       string   `mapstructure:"index"`
	Indices     []string `mapstructure:"indices"`
	IndexPrefix string   `mapstructure:"index_prefix"`
	IndexSuffix string   `mapstructure:"index_suffix"`

	// Elasticsearch specific settings
	CompressionLevel int  `mapstructure:"compression_level"`
	EnableSniffing   bool `mapstructure:"enable_sniffing"`
	SniffInterval    int  `mapstructure:"sniff_interval"` // seconds
	SniffTimeout     int  `mapstructure:"sniff_timeout"`  // seconds

	// Authentication methods
	CloudID      string `mapstructure:"cloud_id"`
	CloudAPIKey  string `mapstructure:"cloud_api_key"`
	ServiceToken string `mapstructure:"service_token"`

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// Bulk operation settings
	BulkFlushInterval  int `mapstructure:"bulk_flush_interval"`  // milliseconds
	BulkFlushThreshold int `mapstructure:"bulk_flush_threshold"` // number of documents
	BulkMaxRetries     int `mapstructure:"bulk_max_retries"`

	// Search settings
	DefaultSize    int  `mapstructure:"default_size"`
	MaxSize        int  `mapstructure:"max_size"`
	TrackTotalHits bool `mapstructure:"track_total_hits"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWT           JWTConfig           `mapstructure:"jwt"`
	OAuth         OAuthConfig         `mapstructure:"oauth"`
	Keycloak      KeycloakConfig      `mapstructure:"keycloak"`
	Auth0         Auth0Config         `mapstructure:"auth0"`
	Okta          OktaConfig          `mapstructure:"okta"`
	TwoFA         TwoFAConfig         `mapstructure:"twofa"`
	Authorization AuthorizationConfig `mapstructure:"authorization"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey  string `mapstructure:"secret_key"`
	Expiration int    `mapstructure:"expiration"`
	RefreshExp int    `mapstructure:"refresh_exp"`
	Issuer     string `mapstructure:"issuer"`
	Audience   string `mapstructure:"audience"`
}

// OAuthConfig holds OAuth2 configuration
type OAuthConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURIs []string `mapstructure:"redirect_uris"`
	Provider     string   `mapstructure:"provider"`
	AuthURL      string   `mapstructure:"auth_url"`
	TokenURL     string   `mapstructure:"token_url"`
	Scopes       []string `mapstructure:"scopes"`
}

// KeycloakConfig holds Keycloak configuration
type KeycloakConfig struct {
	BaseURL      string `mapstructure:"base_url"`
	Realm        string `mapstructure:"realm"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// Auth0Config holds Auth0 configuration
type Auth0Config struct {
	Domain       string `mapstructure:"domain"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// OktaConfig holds Okta configuration
type OktaConfig struct {
	Domain       string `mapstructure:"domain"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// TwoFAConfig holds two-factor authentication configuration
type TwoFAConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Issuer  string `mapstructure:"issuer"`
}

// AuthorizationConfig holds authorization configuration
type AuthorizationConfig struct {
	RBAC RBACConfig `mapstructure:"rbac"`
	ABAC ABACConfig `mapstructure:"abac"`
	ACL  ACLConfig  `mapstructure:"acl"`
}

type RBACConfig struct {
	Roles map[string][]string `mapstructure:"roles"`
}

type ABACConfig struct {
	Policies []string `mapstructure:"policies"`
}

type ACLConfig struct {
	Rules map[string][]string `mapstructure:"rules"`
}

// RabbitMQConfig holds RabbitMQ configuration
type RabbitMQConfig struct {
	// Basic connection settings
	URL      string `mapstructure:"url"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	VHost    string `mapstructure:"vhost"`

	// Exchange and queue settings
	Exchange   string `mapstructure:"exchange"`
	Queue      string `mapstructure:"queue"`
	RoutingKey string `mapstructure:"routing_key"`

	// Connection settings
	DialTimeout  int `mapstructure:"dial_timeout"`  // seconds
	ReadTimeout  int `mapstructure:"read_timeout"`  // seconds
	WriteTimeout int `mapstructure:"write_timeout"` // seconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Connection pool settings
	MaxOpenConns    int `mapstructure:"max_open_conns"`
	MaxIdleConns    int `mapstructure:"max_idle_conns"`
	ConnMaxLifetime int `mapstructure:"conn_max_lifetime"` // seconds

	// Publishing settings
	Mandatory   bool   `mapstructure:"mandatory"`
	Immediate   bool   `mapstructure:"immediate"`
	Persistent  bool   `mapstructure:"persistent"`
	ContentType string `mapstructure:"content_type"`

	// Consumer settings
	AutoAck       bool `mapstructure:"auto_ack"`
	Exclusive     bool `mapstructure:"exclusive"`
	NoLocal       bool `mapstructure:"no_local"`
	NoWait        bool `mapstructure:"no_wait"`
	PrefetchCount int  `mapstructure:"prefetch_count"`
	PrefetchSize  int  `mapstructure:"prefetch_size"`

	// Retry settings
	MaxRetries   int `mapstructure:"max_retries"`
	RetryBackoff int `mapstructure:"retry_backoff"` // milliseconds

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// KafkaConfig holds Kafka configuration
type KafkaConfig struct {
	// Basic connection settings
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
	GroupID string   `mapstructure:"group_id"`

	// Authentication
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	SASLMechanism string `mapstructure:"sasl_mechanism"` // plain, scram-sha-256, scram-sha-512

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Producer settings
	Producer ProducerConfig `mapstructure:"producer"`

	// Consumer settings
	Consumer ConsumerConfig `mapstructure:"consumer"`

	// Connection settings
	DialTimeout  int `mapstructure:"dial_timeout"`  // seconds
	ReadTimeout  int `mapstructure:"read_timeout"`  // seconds
	WriteTimeout int `mapstructure:"write_timeout"` // seconds

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// ProducerConfig holds Kafka producer configuration
type ProducerConfig struct {
	RequiredAcks    int    `mapstructure:"required_acks"` // 0, 1, -1
	RetryMax        int    `mapstructure:"retry_max"`
	RetryBackoff    int    `mapstructure:"retry_backoff"`   // milliseconds
	Compression     string `mapstructure:"compression"`     // none, gzip, snappy, lz4, zstd
	BatchSize       int    `mapstructure:"batch_size"`      // bytes
	BatchTimeout    int    `mapstructure:"batch_timeout"`   // milliseconds
	FlushFrequency  int    `mapstructure:"flush_frequency"` // milliseconds
	MaxMessageBytes int    `mapstructure:"max_message_bytes"`
}

// ConsumerConfig holds Kafka consumer configuration
type ConsumerConfig struct {
	AutoOffsetReset    string `mapstructure:"auto_offset_reset"`  // earliest, latest
	SessionTimeout     int    `mapstructure:"session_timeout"`    // milliseconds
	HeartbeatInterval  int    `mapstructure:"heartbeat_interval"` // milliseconds
	MaxPollRecords     int    `mapstructure:"max_poll_records"`
	FetchMinBytes      int    `mapstructure:"fetch_min_bytes"`
	FetchMaxBytes      int    `mapstructure:"fetch_max_bytes"`
	FetchMaxWait       int    `mapstructure:"fetch_max_wait"` // milliseconds
	EnableAutoCommit   bool   `mapstructure:"enable_auto_commit"`
	AutoCommitInterval int    `mapstructure:"auto_commit_interval"` // milliseconds
}

// APIConfig holds API-related configuration
type APIConfig struct {
	HTTP    HTTPServerConfig    `mapstructure:"http"`
	GraphQL GraphQLServerConfig `mapstructure:"graphql"`
	GRPC    GRPCConfig          `mapstructure:"grpc"`
}

type HTTPServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         string `mapstructure:"port"`
	BasePath     string `mapstructure:"base_path"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

type GraphQLServerConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

// GRPCConfig holds gRPC configuration
type GRPCConfig struct {
	Port    string `mapstructure:"port"`
	Host    string `mapstructure:"host"`
	Timeout int    `mapstructure:"timeout"`
}

// FailoverConfig holds failover-related configuration
type FailoverConfig struct {
	Consul     ConsulConfig     `mapstructure:"consul"`
	Kubernetes KubernetesConfig `mapstructure:"kubernetes"`
}

// ServicesConfig holds microservices configuration
type ServicesConfig struct {
	UserService         ServiceConfig            `mapstructure:"user_service"`
	AuthService         ServiceConfig            `mapstructure:"auth_service"`
	PaymentService      ServiceConfig            `mapstructure:"payment_service"`
	NotificationService ServiceConfig            `mapstructure:"notification_service"`
	FileService         ServiceConfig            `mapstructure:"file_service"`
	ReportService       ServiceConfig            `mapstructure:"report_service"`
	CustomServices      map[string]ServiceConfig `mapstructure:"custom_services"` // Dynamic services
}

// MiddlewareConfig holds middleware toggles
type MiddlewareConfig struct {
	Auth           bool `mapstructure:"auth"`
	CircuitBreaker bool `mapstructure:"circuitbreaker"`
	Communication  bool `mapstructure:"communication"`
	Logging        bool `mapstructure:"logging"`
	Messaging      bool `mapstructure:"messaging"`
	RateLimit      bool `mapstructure:"ratelimit"`
	Storage        bool `mapstructure:"storage"`
}

// ServiceConfig holds individual service configuration
type ServiceConfig struct {
	Name           string                 `mapstructure:"name"`
	Host           string                 `mapstructure:"host"`
	Port           string                 `mapstructure:"port"`
	Protocol       string                 `mapstructure:"protocol"` // http, grpc, tcp
	Version        string                 `mapstructure:"version"`
	Environment    string                 `mapstructure:"environment"`
	HealthCheck    HealthCheckConfig      `mapstructure:"health_check"`
	Retry          RetryConfig            `mapstructure:"retry"`
	Timeout        TimeoutConfig          `mapstructure:"timeout"`
	CircuitBreaker CircuitBreakerConfig   `mapstructure:"circuit_breaker"`
	LoadBalancer   LoadBalancerConfig     `mapstructure:"load_balancer"`
	Metadata       map[string]interface{} `mapstructure:"metadata"`
	Custom         map[string]interface{} `mapstructure:",remain"` // Dynamic service-specific config
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Path        string `mapstructure:"path"`
	Interval    int    `mapstructure:"interval"` // seconds
	Timeout     int    `mapstructure:"timeout"`  // seconds
	Retries     int    `mapstructure:"retries"`
	GracePeriod int    `mapstructure:"grace_period"` // seconds
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	MaxAttempts  int     `mapstructure:"max_attempts"`
	InitialDelay int     `mapstructure:"initial_delay"` // milliseconds
	MaxDelay     int     `mapstructure:"max_delay"`     // milliseconds
	Multiplier   float64 `mapstructure:"multiplier"`
	Jitter       bool    `mapstructure:"jitter"`
}

// TimeoutConfig holds timeout configuration
type TimeoutConfig struct {
	Connect int `mapstructure:"connect"` // milliseconds
	Read    int `mapstructure:"read"`    // milliseconds
	Write   int `mapstructure:"write"`   // milliseconds
	Total   int `mapstructure:"total"`   // milliseconds
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled               bool    `mapstructure:"enabled"`
	FailureThreshold      int     `mapstructure:"failure_threshold"`
	SuccessThreshold      int     `mapstructure:"success_threshold"`
	Timeout               int     `mapstructure:"timeout"` // seconds
	MaxRequests           int     `mapstructure:"max_requests"`
	Interval              int     `mapstructure:"interval"` // seconds
	ErrorPercentThreshold float64 `mapstructure:"error_percent_threshold"`
}

// LoadBalancerConfig holds load balancer configuration
type LoadBalancerConfig struct {
	Strategy    string   `mapstructure:"strategy"` // round_robin, least_conn, random, weighted
	Servers     []string `mapstructure:"servers"`
	Weights     []int    `mapstructure:"weights"`
	HealthCheck bool     `mapstructure:"health_check"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Provider string         `mapstructure:"provider"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Memory   MemoryCache    `mapstructure:"memory"`
	Memcache MemcacheConfig `mapstructure:"memcache"`

	// Global cache settings
	DefaultTTL int `mapstructure:"default_ttl"` // seconds
	MaxSize    int `mapstructure:"max_size"`    // bytes

	// Cache policies
	EvictionPolicy string `mapstructure:"eviction_policy"` // lru, lfu, fifo

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`
}

type MemoryCache struct {
	// Capacity settings
	MaxEntries int `mapstructure:"max_entries"`
	MaxMemory  int `mapstructure:"max_memory"` // bytes

	// Eviction settings
	EvictionPolicy string `mapstructure:"eviction_policy"` // lru, lfu, fifo

	// Cleanup settings
	CleanupInterval int `mapstructure:"cleanup_interval"` // seconds

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`
}

type MemcacheConfig struct {
	// Server settings
	Servers []string `mapstructure:"servers"`

	// Connection settings
	MaxIdleConns int `mapstructure:"max_idle_conns"`
	Timeout      int `mapstructure:"timeout"` // milliseconds

	// Failover settings
	MaxFailoverAttempts int `mapstructure:"max_failover_attempts"`

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`
}

// MessagingConfig holds messaging configuration
type MessagingConfig struct {
	Provider string         `mapstructure:"provider"`
	Kafka    KafkaConfig    `mapstructure:"kafka"`
	RabbitMQ RabbitMQConfig `mapstructure:"rabbitmq"`
	NATS     NATSConfig     `mapstructure:"nats"`
	SQS      SQSConfig      `mapstructure:"sqs"`
}

// EmailConfig holds email configuration
type EmailConfig struct {
	SMTP SMTPConfig `mapstructure:"smtp"`
	IMAP IMAPConfig `mapstructure:"imap"`
	POP3 POP3Config `mapstructure:"pop3"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	TLS      bool   `mapstructure:"tls"`
}

type IMAPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	TLS      bool   `mapstructure:"tls"`
}

type POP3Config struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	TLS      bool   `mapstructure:"tls"`
}

// PaymentConfig holds payment providers configuration
type PaymentConfig struct {
	Midtrans MidtransConfig `mapstructure:"midtrans"`
	Paypal   PaypalConfig   `mapstructure:"paypal"`
	Stripe   StripeConfig   `mapstructure:"stripe"`
	Xendit   XenditConfig   `mapstructure:"xendit"`
}

type MidtransConfig struct {
	ServerKey string `mapstructure:"server_key"`
	ClientKey string `mapstructure:"client_key"`
	BaseURL   string `mapstructure:"base_url"`
}

type PaypalConfig struct {
	ClientID string `mapstructure:"client_id"`
	Secret   string `mapstructure:"secret"`
	Env      string `mapstructure:"env"`
}

type StripeConfig struct {
	SecretKey      string `mapstructure:"secret_key"`
	PublishableKey string `mapstructure:"publishable_key"`
}

type XenditConfig struct {
	Mode   string `mapstructure:"mode"`
	APIKey string `mapstructure:"api_key"`
}

// DiscoveryConfig holds service discovery configuration
type DiscoveryConfig struct {
	Consul     ConsulConfig     `mapstructure:"consul"`
	Etcd       EtcdConfig       `mapstructure:"etcd"`
	Kubernetes KubernetesConfig `mapstructure:"kubernetes"`
	Static     StaticDiscovery  `mapstructure:"static"`
}

type ConsulConfig struct {
	Address string `mapstructure:"address"`
	Token   string `mapstructure:"token"`
	Path    string `mapstructure:"path"`
}

type EtcdConfig struct {
	Endpoints []string `mapstructure:"endpoints"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
}

type KubernetesConfig struct {
	Namespace string `mapstructure:"namespace"`
	Label     string `mapstructure:"label"`
	InCluster bool   `mapstructure:"in_cluster"`
}

type StaticDiscovery struct {
	Services map[string][]string `mapstructure:"services"`
}

// EdgeConfig holds edge providers configuration
type EdgeConfig struct {
	Cloudflare CloudflareConfig `mapstructure:"cloudflare"`
	Akamai     AkamaiConfig     `mapstructure:"akamai"`
	Fastly     FastlyConfig     `mapstructure:"fastly"`
	Wasm       WasmConfig       `mapstructure:"wasm"`
}

type CloudflareConfig struct {
	APIToken string `mapstructure:"api_token"`
	Account  string `mapstructure:"account"`
	ZoneID   string `mapstructure:"zone_id"`
}

type AkamaiConfig struct {
	ClientToken  string `mapstructure:"client_token"`
	ClientSecret string `mapstructure:"client_secret"`
	AccessToken  string `mapstructure:"access_token"`
}

type FastlyConfig struct {
	APIKey    string `mapstructure:"api_key"`
	ServiceID string `mapstructure:"service_id"`
}

type WasmConfig struct {
	ModulePath string `mapstructure:"module_path"`
}

// EventConfig holds event sourcing configuration
type EventConfig struct {
	Provider   string           `mapstructure:"provider"`
	Kafka      KafkaConfig      `mapstructure:"kafka"`
	NATS       NATSConfig       `mapstructure:"nats"`
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
}

// RateLimitConfig holds rate limit configuration
type RateLimitConfig struct {
	Provider string             `mapstructure:"provider"`
	InMemory InMemoryRateConfig `mapstructure:"inmemory"`
	Redis    RedisRateConfig    `mapstructure:"redis"`
}

type InMemoryRateConfig struct {
	Requests int `mapstructure:"requests"`
	WindowMs int `mapstructure:"window_ms"`
}

type RedisRateConfig struct {
	Prefix string `mapstructure:"prefix"`
}

// SchedulingConfig holds scheduling configuration
type SchedulingConfig struct {
	Cron  CronConfig          `mapstructure:"cron"`
	Redis RedisScheduleConfig `mapstructure:"redis"`
}

type CronConfig struct {
	Timezone string `mapstructure:"timezone"`
}

type RedisScheduleConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// ZeroTrustConfig holds zero trust configuration
type ZeroTrustConfig struct {
	Istio  IstioConfig  `mapstructure:"istio"`
	MTLS   MTLSConfig   `mapstructure:"mtls"`
	Spiffe SpiffeConfig `mapstructure:"spiffe"`
}

type IstioConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type MTLSConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type SpiffeConfig struct {
	TrustDomain string `mapstructure:"trust_domain"`
}

// BackupConfig holds backup providers configuration
type BackupConfig struct {
	Provider string      `mapstructure:"provider"`
	S3       S3Config    `mapstructure:"s3"`
	GCS      GCSConfig   `mapstructure:"gcs"`
	Local    LocalBackup `mapstructure:"local"`
}

type LocalBackup struct {
	Path string `mapstructure:"path"`
}

// ChaosConfig holds chaos engineering configuration
type ChaosConfig struct {
	HTTP       ChaosHTTPConfig       `mapstructure:"http"`
	Kubernetes ChaosKubernetesConfig `mapstructure:"kubernetes"`
	Messaging  ChaosMessagingConfig  `mapstructure:"messaging"`
}

type ChaosHTTPConfig struct {
	Enabled     bool    `mapstructure:"enabled"`
	FailureRate float64 `mapstructure:"failure_rate"`
	LatencyMs   int     `mapstructure:"latency_ms"`
	StatusCode  int     `mapstructure:"status_code"`
}

type ChaosKubernetesConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type ChaosMessagingConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// AIConfig holds AI provider configuration
type AIConfig struct {
	Provider  string          `mapstructure:"provider"`
	OpenAI    OpenAIConfig    `mapstructure:"openai"`
	Google    GoogleAIConfig  `mapstructure:"google"`
	Anthropic AnthropicConfig `mapstructure:"anthropic"`
	XAI       XAIConfig       `mapstructure:"xai"`
	DeepSeek  DeepSeekConfig  `mapstructure:"deepseek"`
}

type OpenAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	BaseURL string `mapstructure:"base_url"`
	Model   string `mapstructure:"model"`
}

type GoogleAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	Project string `mapstructure:"project"`
	Model   string `mapstructure:"model"`
}

type AnthropicConfig struct {
	APIKey string `mapstructure:"api_key"`
	Model  string `mapstructure:"model"`
}

type XAIConfig struct {
	APIKey string `mapstructure:"api_key"`
	Model  string `mapstructure:"model"`
}

type DeepSeekConfig struct {
	APIKey string `mapstructure:"api_key"`
	Model  string `mapstructure:"model"`
}

// CommunicationConfig holds services communication config
type CommunicationConfig struct {
	Provider  string              `mapstructure:"provider"`
	HTTP      HTTPClientConfig    `mapstructure:"http"`
	GRPC      GRPCConfig          `mapstructure:"grpc"`
	QUIC      QUICConfig          `mapstructure:"quic"`
	Websocket WebsocketConfig     `mapstructure:"websocket"`
	SSE       SSEConfig           `mapstructure:"sse"`
	GraphQL   GraphQLClientConfig `mapstructure:"graphql"`
}

type HTTPClientConfig struct {
	// Server addressing
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	BasePath string `mapstructure:"base_path"`

	// Backward compatibility (optional full URL)
	BaseURL string `mapstructure:"base_url"`

	// Timeouts (seconds)
	ReadTimeout  int `mapstructure:"read_timeout"`
	WriteTimeout int `mapstructure:"write_timeout"`
	IdleTimeout  int `mapstructure:"idle_timeout"`

	// Retries
	Retries int `mapstructure:"retries"`
}

type QUICConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	MaxStreams      int64  `mapstructure:"max_streams"`
	MaxIdleTimeout  int    `mapstructure:"max_idle_timeout"`  // seconds
	KeepAlivePeriod int    `mapstructure:"keep_alive_period"` // seconds
}

type WebsocketConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	Path           string `mapstructure:"path"`
	PingInterval   int    `mapstructure:"ping_interval"`    // seconds
	PongTimeout    int    `mapstructure:"pong_timeout"`     // seconds
	MaxMessageSize int    `mapstructure:"max_message_size"` // bytes
}

type SSEConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

type GraphQLClientConfig struct {
	// Server addressing
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Path string `mapstructure:"path"`

	// Backward compatibility (single endpoint)
	Endpoint string `mapstructure:"endpoint"`

	// Timeouts (seconds)
	ReadTimeout  int `mapstructure:"read_timeout"`
	WriteTimeout int `mapstructure:"write_timeout"`
	IdleTimeout  int `mapstructure:"idle_timeout"`
}

// FileGenConfig holds file generation providers configuration
type FileGenConfig struct {
	Provider string          `mapstructure:"provider"`
	PDF      PDFGenConfig    `mapstructure:"pdf"`
	DOCX     DOCXGenConfig   `mapstructure:"docx"`
	Excel    ExcelGenConfig  `mapstructure:"excel"`
	CSV      CSVGenConfig    `mapstructure:"csv"`
	Custom   CustomGenConfig `mapstructure:"custom"`
}

type PDFGenConfig struct {
	TemplatesPath string `mapstructure:"templates_path"`
}

type DOCXGenConfig struct {
	TemplatesPath string `mapstructure:"templates_path"`
}

type ExcelGenConfig struct {
	TemplatesPath string `mapstructure:"templates_path"`
}

type CSVGenConfig struct {
	Delimiter string `mapstructure:"delimiter"`
}

type CustomGenConfig struct {
	TemplatesPath string `mapstructure:"templates_path"`
}

// NATSConfig holds NATS configuration
type NATSConfig struct {
	// Basic connection settings
	URL     string   `mapstructure:"url"`
	URLs    []string `mapstructure:"urls"`
	Subject string   `mapstructure:"subject"`
	Queue   string   `mapstructure:"queue"`

	// Authentication
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Token    string `mapstructure:"token"`
	JWT      string `mapstructure:"jwt"`
	NKey     string `mapstructure:"nkey"`

	// Connection settings
	Timeout       int `mapstructure:"timeout"`        // seconds
	ReconnectWait int `mapstructure:"reconnect_wait"` // seconds
	MaxReconnects int `mapstructure:"max_reconnects"`
	PingInterval  int `mapstructure:"ping_interval"` // seconds
	MaxPingsOut   int `mapstructure:"max_pings_out"`

	// TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Cluster settings
	DiscoveredServers []string `mapstructure:"discovered_servers"`

	// JetStream settings (for NATS 2.0+)
	UseJetStream bool   `mapstructure:"use_jetstream"`
	StreamName   string `mapstructure:"stream_name"`
	ConsumerName string `mapstructure:"consumer_name"`

	// Monitoring
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// SQSConfig holds AWS SQS configuration
type SQSConfig struct {
	Region    string `mapstructure:"region"`
	QueueURL  string `mapstructure:"queue_url"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
}

// GCSConfig holds Google Cloud Storage configuration
type GCSConfig struct {
	BucketName  string `mapstructure:"bucket_name"`
	ProjectID   string `mapstructure:"project_id"`
	Credentials string `mapstructure:"credentials"`
}

// AzureConfig holds Azure Blob configuration
type AzureConfig struct {
	AccountName string `mapstructure:"account_name"`
	AccountKey  string `mapstructure:"account_key"`
	Container   string `mapstructure:"container"`
}

// R2Config holds Cloudflare R2 configuration
type R2Config struct {
	AccountID       string `mapstructure:"account_id"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	BucketName      string `mapstructure:"bucket_name"`
	Endpoint        string `mapstructure:"endpoint"`
}

// MySQLConfig holds MySQL configuration
type MySQLConfig struct {
	// Basic connection settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`

	// Connection parameters
	Params string `mapstructure:"params"`

	// Connection pool settings
	MaxOpenConns    int `mapstructure:"max_open_conns"`
	MaxIdleConns    int `mapstructure:"max_idle_conns"`
	MinOpenConns    int `mapstructure:"min_open_conns"`
	ConnMaxLifetime int `mapstructure:"conn_max_lifetime"`  // seconds
	ConnMaxIdleTime int `mapstructure:"conn_max_idle_time"` // seconds

	// Timeout settings
	ConnectTimeout int `mapstructure:"connect_timeout"` // seconds
	ReadTimeout    int `mapstructure:"read_timeout"`    // seconds
	WriteTimeout   int `mapstructure:"write_timeout"`   // seconds
	QueryTimeout   int `mapstructure:"query_timeout"`   // seconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// MySQL specific settings
	Charset           string `mapstructure:"charset"`
	Collation         string `mapstructure:"collation"`
	ParseTime         bool   `mapstructure:"parse_time"`
	Loc               string `mapstructure:"loc"`
	MultiStatements   bool   `mapstructure:"multi_statements"`
	InterpolateParams bool   `mapstructure:"interpolate_params"`

	// Replication settings
	ReadTimeoutSlave  int `mapstructure:"read_timeout_slave"`  // seconds
	WriteTimeoutSlave int `mapstructure:"write_timeout_slave"` // seconds

	// Performance settings
	MaxAllowedPacket int `mapstructure:"max_allowed_packet"` // bytes
	NetBufferLength  int `mapstructure:"net_buffer_length"`  // bytes

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// MariaDBConfig holds MariaDB configuration
type MariaDBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
}

// SQLiteConfig holds SQLite configuration
type SQLiteConfig struct {
	Path string `mapstructure:"path"`
}

// CassandraConfig holds Cassandra configuration
type CassandraConfig struct {
	// Basic connection settings
	Hosts    []string `mapstructure:"hosts"`
	Keyspace string   `mapstructure:"keyspace"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`

	// Connection settings
	Port            int `mapstructure:"port"`
	ConnectTimeout  int `mapstructure:"connect_timeout"` // milliseconds
	Timeout         int `mapstructure:"timeout"`         // milliseconds
	NumConns        int `mapstructure:"num_conns"`
	MaxConnAttempts int `mapstructure:"max_conn_attempts"`

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Consistency and replication
	Consistency       string `mapstructure:"consistency"`
	SerialConsistency string `mapstructure:"serial_consistency"`
	Replication       int    `mapstructure:"replication"`
	DataCenter        string `mapstructure:"data_center"`

	// Retry policy
	RetryPolicy string `mapstructure:"retry_policy"` // simple, exponential
	MaxRetries  int    `mapstructure:"max_retries"`

	// Load balancing
	LoadBalancingPolicy string `mapstructure:"load_balancing_policy"` // round_robin, token_aware

	// Reconnection policy
	ReconnectInterval    int `mapstructure:"reconnect_interval"` // milliseconds
	MaxReconnectAttempts int `mapstructure:"max_reconnect_attempts"`

	// Compression
	Compression string `mapstructure:"compression"` // snappy, lz4

	// Protocol version
	ProtoVersion int `mapstructure:"proto_version"`

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// Query settings
	DefaultPageSize int `mapstructure:"default_page_size"`
	MaxPageSize     int `mapstructure:"max_page_size"`

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// CockroachConfig holds CockroachDB configuration
type CockroachConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

// RedisDBConfig holds Redis database configuration (legacy, use RedisConfig instead)
type RedisDBConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	// Extended options
	PoolSize            int                    `mapstructure:"pool_size"`
	MinIdleConns        int                    `mapstructure:"min_idle_conns"`
	MaxConnAge          int                    `mapstructure:"max_conn_age"`
	PoolTimeout         int                    `mapstructure:"pool_timeout"`
	IdleTimeout         int                    `mapstructure:"idle_timeout"`
	DialTimeout         int                    `mapstructure:"dial_timeout"`
	ReadTimeout         int                    `mapstructure:"read_timeout"`
	WriteTimeout        int                    `mapstructure:"write_timeout"`
	MaxRetries          int                    `mapstructure:"max_retries"`
	UseTLS              bool                   `mapstructure:"use_tls"`
	TLSConfig           TLSConfig              `mapstructure:"tls_config"`
	HealthCheckInterval int                    `mapstructure:"health_check_interval"`
	EnableMetrics       bool                   `mapstructure:"enable_metrics"`
	Custom              map[string]interface{} `mapstructure:",remain"`
}

// InfluxDBConfig holds InfluxDB configuration
type InfluxDBConfig struct {
	// Basic connection settings
	URL      string `mapstructure:"url"`
	Token    string `mapstructure:"token"`
	Org      string `mapstructure:"org"`
	Bucket   string `mapstructure:"bucket"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// Connection settings
	Timeout        int `mapstructure:"timeout"`         // seconds
	ConnectTimeout int `mapstructure:"connect_timeout"` // seconds
	RequestTimeout int `mapstructure:"request_timeout"` // seconds

	// SSL/TLS settings
	UseTLS    bool      `mapstructure:"use_tls"`
	TLSConfig TLSConfig `mapstructure:"tls_config"`

	// Batch settings
	BatchSize     int `mapstructure:"batch_size"`
	FlushInterval int `mapstructure:"flush_interval"` // milliseconds
	MaxRetries    int `mapstructure:"max_retries"`
	RetryInterval int `mapstructure:"retry_interval"` // milliseconds

	// Precision settings
	Precision string `mapstructure:"precision"` // ns, us, ms, s

	// Retention policy
	RetentionPolicy string `mapstructure:"retention_policy"`

	// Monitoring and health check
	HealthCheckInterval int    `mapstructure:"health_check_interval"` // seconds
	EnableMetrics       bool   `mapstructure:"enable_metrics"`
	LogLevel            string `mapstructure:"log_level"`

	// Query settings
	QueryTimeout int `mapstructure:"query_timeout"` // seconds

	// Custom settings
	Custom map[string]interface{} `mapstructure:",remain"`
}

// ElasticDBConfig holds Elasticsearch DB configuration
type ElasticDBConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Index    string `mapstructure:"index"`
}

// ConfigOptions represents configuration options
type ConfigOptions struct {
	Provider     string            `json:"provider"`
	ConfigPath   string            `json:"config_path"`
	Environment  string            `json:"environment"`
	WatchChanges bool              `json:"watch_changes"`
	SecretsPath  string            `json:"secrets_path"`
	Metadata     map[string]string `json:"metadata"`
}

// ConfigChangeEvent represents a configuration change event
type ConfigChangeEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Changes   map[string]interface{} `json:"changes"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// IsDevelopment returns true if environment is development
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// IsProduction returns true if environment is production
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// GetDatabaseURL returns PostgreSQL connection string
func (c *Config) GetDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.PostgreSQL.User,
		c.Database.PostgreSQL.Password,
		c.Database.PostgreSQL.Host,
		c.Database.PostgreSQL.Port,
		c.Database.PostgreSQL.DBName,
		c.Database.PostgreSQL.SSLMode,
	)
}

// GetRedisURL returns Redis connection string
func (c *Config) GetRedisURL() string {
	if c.Cache.Redis.Password != "" {
		return fmt.Sprintf("redis://:%s@%s:%d/%d",
			c.Cache.Redis.Password,
			c.Cache.Redis.Host,
			c.Cache.Redis.Port,
			c.Cache.Redis.DB,
		)
	}
	return fmt.Sprintf("redis://%s:%d/%d",
		c.Cache.Redis.Host,
		c.Cache.Redis.Port,
		c.Cache.Redis.DB,
	)
}

// GetCustomValue returns a custom configuration value
func (c *Config) GetCustomValue(key string) (interface{}, bool) {
	if c.Custom == nil {
		return nil, false
	}
	value, exists := c.Custom[key]
	return value, exists
}

// SetCustomValue sets a custom configuration value
func (c *Config) SetCustomValue(key string, value interface{}) {
	if c.Custom == nil {
		c.Custom = make(map[string]interface{})
	}
	c.Custom[key] = value
}

// GetCustomString returns a custom configuration value as string
func (c *Config) GetCustomString(key string, defaultValue string) string {
	if value, exists := c.GetCustomValue(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetCustomInt returns a custom configuration value as int
func (c *Config) GetCustomInt(key string, defaultValue int) int {
	if value, exists := c.GetCustomValue(key); exists {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if intValue, err := fmt.Sscanf(v, "%d", &defaultValue); err == nil && intValue == 1 {
				return defaultValue
			}
		}
	}
	return defaultValue
}

// GetCustomBool returns a custom configuration value as bool
func (c *Config) GetCustomBool(key string, defaultValue bool) bool {
	if value, exists := c.GetCustomValue(key); exists {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}
	return defaultValue
}

// GetServiceConfig returns configuration for a specific service
func (c *Config) GetServiceConfig(serviceName string) (*ServiceConfig, bool) {
	if c.Services.CustomServices != nil {
		if service, exists := c.Services.CustomServices[serviceName]; exists {
			return &service, true
		}
	}
	return nil, false
}

// SetServiceConfig sets configuration for a specific service
func (c *Config) SetServiceConfig(serviceName string, serviceConfig ServiceConfig) {
	if c.Services.CustomServices == nil {
		c.Services.CustomServices = make(map[string]ServiceConfig)
	}
	c.Services.CustomServices[serviceName] = serviceConfig
}

// GetServiceURL returns the full URL for a service
func (c *Config) GetServiceURL(serviceName string) (string, error) {
	service, exists := c.GetServiceConfig(serviceName)
	if !exists {
		return "", fmt.Errorf("service %s not found", serviceName)
	}

	protocol := service.Protocol
	if protocol == "" {
		protocol = "http"
	}

	return fmt.Sprintf("%s://%s:%s", protocol, service.Host, service.Port), nil
}

// GetServiceHealthCheckURL returns the health check URL for a service
func (c *Config) GetServiceHealthCheckURL(serviceName string) (string, error) {
	service, exists := c.GetServiceConfig(serviceName)
	if !exists {
		return "", fmt.Errorf("service %s not found", serviceName)
	}

	baseURL, err := c.GetServiceURL(serviceName)
	if err != nil {
		return "", err
	}

	healthPath := service.HealthCheck.Path
	if healthPath == "" {
		healthPath = "/health"
	}

	return fmt.Sprintf("%s%s", baseURL, healthPath), nil
}

// GetAllServices returns all configured services
func (c *Config) GetAllServices() map[string]ServiceConfig {
	services := make(map[string]ServiceConfig)

	// Add predefined services
	services["user_service"] = c.Services.UserService
	services["auth_service"] = c.Services.AuthService
	services["payment_service"] = c.Services.PaymentService
	services["notification_service"] = c.Services.NotificationService
	services["file_service"] = c.Services.FileService
	services["report_service"] = c.Services.ReportService

	// Add custom services
	if c.Services.CustomServices != nil {
		for name, service := range c.Services.CustomServices {
			services[name] = service
		}
	}

	return services
}
