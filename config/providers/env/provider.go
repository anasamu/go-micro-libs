package env

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/anasamu/go-micro-libs/config/types"
)

// Provider implements configuration provider for environment variables
type Provider struct {
	prefix string
}

// NewProvider creates a new environment-based configuration provider
func NewProvider(prefix string) *Provider {
	return &Provider{
		prefix: prefix,
	}
}

// Load loads configuration from environment variables
func (p *Provider) Load() (*types.Config, error) {
	config := &types.Config{}

	// Load server configuration
	config.Server = types.ServerConfig{
		ServiceName: p.getString("SERVER_SERVICE_NAME", ""),
		Version:     p.getString("SERVER_VERSION", ""),
		Environment: p.getString("SERVER_ENVIRONMENT", "development"),
		Configuration: types.ConfigurationConfig{
			Provider: p.getString("CONFIG_PROVIDER", "file"),
			File: types.FileConfigProvider{
				Path: p.getString("CONFIG_FILE_PATH", ""),
				Type: p.getString("CONFIG_FILE_TYPE", "yaml"),
			},
			Env:    types.EnvConfigProvider{Prefix: p.getString("CONFIG_ENV_PREFIX", "")},
			Consul: types.ConsulConfig{Address: p.getString("CONFIG_CONSUL_ADDRESS", ""), Token: p.getString("CONFIG_CONSUL_TOKEN", "")},
			Vault:  types.VaultConfig{Address: p.getString("CONFIG_VAULT_ADDRESS", ""), Token: p.getString("CONFIG_VAULT_TOKEN", ""), Path: p.getString("CONFIG_VAULT_PATH", "")},
		},
	}

	// Load database configuration
	config.Database = types.DatabaseConfig{
		PostgreSQL: types.PostgreSQLConfig{
			Host:            p.getString("DB_POSTGRESQL_HOST", "localhost"),
			Port:            p.getInt("DB_POSTGRESQL_PORT", 5432),
			User:            p.getString("DB_POSTGRESQL_USER", ""),
			Password:        p.getString("DB_POSTGRESQL_PASSWORD", ""),
			DBName:          p.getString("DB_POSTGRESQL_DBNAME", ""),
			SSLMode:         p.getString("DB_POSTGRESQL_SSLMODE", "disable"),
			MaxOpenConns:    p.getInt("DB_POSTGRESQL_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    p.getInt("DB_POSTGRESQL_MAX_IDLE_CONNS", 5),
			MinOpenConns:    p.getInt("DB_POSTGRESQL_MIN_OPEN_CONNS", 5),
			ConnMaxLifetime: p.getInt("DB_POSTGRESQL_CONN_MAX_LIFETIME", 3600),
			ConnMaxIdleTime: p.getInt("DB_POSTGRESQL_CONN_MAX_IDLE_TIME", 1800),
		},
		MongoDB: types.MongoDBConfig{
			URI:               p.getString("DB_MONGODB_URI", "mongodb://localhost:27017"),
			Database:          p.getString("DB_MONGODB_DATABASE", ""),
			Username:          p.getString("DB_MONGODB_USERNAME", ""),
			Password:          p.getString("DB_MONGODB_PASSWORD", ""),
			Hosts:             p.getStringSlice("DB_MONGODB_HOSTS", []string{}),
			MaxPoolSize:       p.getInt("DB_MONGODB_MAX_POOL_SIZE", 100),
			MinPoolSize:       p.getInt("DB_MONGODB_MIN_POOL_SIZE", 10),
			MaxConnIdleTime:   p.getInt("DB_MONGODB_MAX_CONN_IDLE_TIME", 300000),
			MaxConnecting:     p.getInt("DB_MONGODB_MAX_CONNECTING", 10),
			MaxConnLifeTime:   p.getInt("DB_MONGODB_MAX_CONN_LIFE_TIME", 3600000),
			ConnectTimeout:    p.getInt("DB_MONGODB_CONNECT_TIMEOUT", 30000),
			SocketTimeout:     p.getInt("DB_MONGODB_SOCKET_TIMEOUT", 30000),
			ServerTimeout:     p.getInt("DB_MONGODB_SERVER_TIMEOUT", 30000),
			HeartbeatInterval: p.getInt("DB_MONGODB_HEARTBEAT_INTERVAL", 10000),
		},
	}

	// Load Cache Redis configuration
	config.Cache = types.CacheConfig{
		Provider: p.getString("CACHE_PROVIDER", "memory"),
		Redis: types.RedisConfig{
			Host:                p.getString("REDIS_HOST", "localhost"),
			Port:                p.getInt("REDIS_PORT", 6379),
			Username:            p.getString("REDIS_USERNAME", ""),
			Password:            p.getString("REDIS_PASSWORD", ""),
			DB:                  p.getInt("REDIS_DB", 0),
			PoolSize:            p.getInt("REDIS_POOL_SIZE", 10),
			MinIdleConns:        p.getInt("REDIS_MIN_IDLE_CONNS", 5),
			MaxConnAge:          p.getInt("REDIS_MAX_CONN_AGE", 3600),
			PoolTimeout:         p.getInt("REDIS_POOL_TIMEOUT", 30),
			IdleTimeout:         p.getInt("REDIS_IDLE_TIMEOUT", 300),
			DialTimeout:         p.getInt("REDIS_DIAL_TIMEOUT", 30),
			ReadTimeout:         p.getInt("REDIS_READ_TIMEOUT", 30),
			WriteTimeout:        p.getInt("REDIS_WRITE_TIMEOUT", 30),
			MaxRetries:          p.getInt("REDIS_MAX_RETRIES", 3),
			UseTLS:              p.getBool("REDIS_USE_TLS", false),
			HealthCheckInterval: p.getInt("REDIS_HEALTH_CHECK_INTERVAL", 30),
			EnableMetrics:       p.getBool("REDIS_ENABLE_METRICS", false),
		},
	}

	// Load Vault configuration into config.Configuration
	config.Configuration.Vault = types.VaultConfig{
		Address: p.getString("VAULT_ADDRESS", ""),
		Token:   p.getString("VAULT_TOKEN", ""),
		Path:    p.getString("VAULT_PATH", ""),
	}

	// Load logging configuration
	config.Logging = types.LoggingConfig{
		Level:  p.getString("LOGGING_LEVEL", "info"),
		Format: p.getString("LOGGING_FORMAT", "json"),
		Output: p.getString("LOGGING_OUTPUT", "stdout"),
		Elastic: types.ElasticsearchConfig{
			URL:      p.getString("LOGGING_ELASTIC_URL", ""),
			Index:    p.getString("LOGGING_INDEX", ""),
			Username: p.getString("LOGGING_ELASTIC_USERNAME", ""),
			Password: p.getString("LOGGING_ELASTIC_PASSWORD", ""),
		},
	}

	// Load monitoring configuration
	config.Monitoring = types.MonitoringConfig{
		Prometheus: types.PrometheusConfig{
			Enabled: p.getBool("MONITORING_PROMETHEUS_ENABLED", true),
			Port:    p.getString("MONITORING_PROMETHEUS_PORT", "9090"),
			Path:    p.getString("MONITORING_PROMETHEUS_PATH", "/metrics"),
		},
		Jaeger: types.JaegerConfig{
			Enabled:  p.getBool("MONITORING_JAEGER_ENABLED", false),
			Endpoint: p.getString("MONITORING_JAEGER_ENDPOINT", ""),
			Service:  p.getString("MONITORING_JAEGER_SERVICE", ""),
		},
	}

	// Load storage configuration
	config.Storage = types.StorageConfig{
		MinIO: types.MinIOConfig{
			Endpoint:        p.getString("STORAGE_MINIO_ENDPOINT", "localhost:9000"),
			AccessKeyID:     p.getString("STORAGE_MINIO_ACCESS_KEY_ID", ""),
			SecretAccessKey: p.getString("STORAGE_MINIO_SECRET_ACCESS_KEY", ""),
			UseSSL:          p.getBool("STORAGE_MINIO_USE_SSL", false),
			BucketName:      p.getString("STORAGE_MINIO_BUCKET_NAME", ""),
		},
		S3: types.S3Config{
			Region:          p.getString("STORAGE_S3_REGION", ""),
			AccessKeyID:     p.getString("STORAGE_S3_ACCESS_KEY_ID", ""),
			SecretAccessKey: p.getString("STORAGE_S3_SECRET_ACCESS_KEY", ""),
			BucketName:      p.getString("STORAGE_S3_BUCKET_NAME", ""),
		},
	}

	// No separate Search in new config; map to Logging.Elastic if needed

	// Load auth configuration
	config.Auth = types.AuthConfig{
		JWT: types.JWTConfig{
			SecretKey:  p.getString("AUTH_JWT_SECRET_KEY", ""),
			Expiration: p.getInt("AUTH_JWT_EXPIRATION", 3600),
			RefreshExp: p.getInt("AUTH_JWT_REFRESH_EXP", 86400),
			Issuer:     p.getString("AUTH_JWT_ISSUER", "siakad"),
			Audience:   p.getString("AUTH_JWT_AUDIENCE", ""),
		},
	}

	// Messaging
	config.Messaging = types.MessagingConfig{
		Provider: p.getString("MESSAGING_PROVIDER", "kafka"),
		Kafka: types.KafkaConfig{
			Brokers: p.getStringSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
			Topic:   p.getString("KAFKA_TOPIC", ""),
			GroupID: p.getString("KAFKA_GROUP_ID", ""),
		},
		RabbitMQ: types.RabbitMQConfig{
			URL:      p.getString("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"),
			Exchange: p.getString("RABBITMQ_EXCHANGE", ""),
			Queue:    p.getString("RABBITMQ_QUEUE", ""),
		},
	}

	// API (HTTP/GRPC)
	config.API = types.APIConfig{
		HTTP: types.HTTPServerConfig{
			Host:         p.getString("SERVER_HOST", "0.0.0.0"),
			Port:         p.getString("SERVER_PORT", "8080"),
			BasePath:     p.getString("SERVER_BASE_PATH", "/"),
			ReadTimeout:  p.getInt("SERVER_READ_TIMEOUT", 30),
			WriteTimeout: p.getInt("SERVER_WRITE_TIMEOUT", 30),
		},
		GRPC: types.GRPCConfig{
			Host:    p.getString("GRPC_HOST", "0.0.0.0"),
			Port:    p.getString("GRPC_PORT", "50051"),
			Timeout: p.getInt("GRPC_TIMEOUT", 30),
		},
	}

	// Load services configuration
	config.Services = types.ServicesConfig{
		UserService: types.ServiceConfig{
			Name:     p.getString("SERVICES_USER_SERVICE_NAME", "user-service"),
			Host:     p.getString("SERVICES_USER_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_USER_SERVICE_PORT", "8001"),
			Protocol: p.getString("SERVICES_USER_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled:  p.getBool("SERVICES_USER_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:     p.getString("SERVICES_USER_SERVICE_HEALTH_CHECK_PATH", "/health"),
				Interval: p.getInt("SERVICES_USER_SERVICE_HEALTH_CHECK_INTERVAL", 30),
			},
			Retry: types.RetryConfig{
				Enabled:      p.getBool("SERVICES_USER_SERVICE_RETRY_ENABLED", true),
				MaxAttempts:  p.getInt("SERVICES_USER_SERVICE_RETRY_MAX_ATTEMPTS", 3),
				InitialDelay: p.getInt("SERVICES_USER_SERVICE_RETRY_INITIAL_DELAY", 1000),
			},
			Timeout: types.TimeoutConfig{
				Connect: p.getInt("SERVICES_USER_SERVICE_TIMEOUT_CONNECT", 5000),
				Read:    p.getInt("SERVICES_USER_SERVICE_TIMEOUT_READ", 10000),
			},
			CircuitBreaker: types.CircuitBreakerConfig{
				Enabled:          p.getBool("SERVICES_USER_SERVICE_CIRCUIT_BREAKER_ENABLED", true),
				FailureThreshold: p.getInt("SERVICES_USER_SERVICE_CIRCUIT_BREAKER_FAILURE_THRESHOLD", 5),
			},
		},
		AuthService: types.ServiceConfig{
			Name:     p.getString("SERVICES_AUTH_SERVICE_NAME", "auth-service"),
			Host:     p.getString("SERVICES_AUTH_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_AUTH_SERVICE_PORT", "8002"),
			Protocol: p.getString("SERVICES_AUTH_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled: p.getBool("SERVICES_AUTH_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:    p.getString("SERVICES_AUTH_SERVICE_HEALTH_CHECK_PATH", "/health"),
			},
		},
		PaymentService: types.ServiceConfig{
			Name:     p.getString("SERVICES_PAYMENT_SERVICE_NAME", "payment-service"),
			Host:     p.getString("SERVICES_PAYMENT_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_PAYMENT_SERVICE_PORT", "8003"),
			Protocol: p.getString("SERVICES_PAYMENT_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled: p.getBool("SERVICES_PAYMENT_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:    p.getString("SERVICES_PAYMENT_SERVICE_HEALTH_CHECK_PATH", "/health"),
			},
		},
		NotificationService: types.ServiceConfig{
			Name:     p.getString("SERVICES_NOTIFICATION_SERVICE_NAME", "notification-service"),
			Host:     p.getString("SERVICES_NOTIFICATION_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_NOTIFICATION_SERVICE_PORT", "8004"),
			Protocol: p.getString("SERVICES_NOTIFICATION_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled: p.getBool("SERVICES_NOTIFICATION_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:    p.getString("SERVICES_NOTIFICATION_SERVICE_HEALTH_CHECK_PATH", "/health"),
			},
		},
		FileService: types.ServiceConfig{
			Name:     p.getString("SERVICES_FILE_SERVICE_NAME", "file-service"),
			Host:     p.getString("SERVICES_FILE_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_FILE_SERVICE_PORT", "8005"),
			Protocol: p.getString("SERVICES_FILE_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled: p.getBool("SERVICES_FILE_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:    p.getString("SERVICES_FILE_SERVICE_HEALTH_CHECK_PATH", "/health"),
			},
		},
		ReportService: types.ServiceConfig{
			Name:     p.getString("SERVICES_REPORT_SERVICE_NAME", "report-service"),
			Host:     p.getString("SERVICES_REPORT_SERVICE_HOST", "localhost"),
			Port:     p.getString("SERVICES_REPORT_SERVICE_PORT", "8006"),
			Protocol: p.getString("SERVICES_REPORT_SERVICE_PROTOCOL", "http"),
			HealthCheck: types.HealthCheckConfig{
				Enabled: p.getBool("SERVICES_REPORT_SERVICE_HEALTH_CHECK_ENABLED", true),
				Path:    p.getString("SERVICES_REPORT_SERVICE_HEALTH_CHECK_PATH", "/health"),
			},
		},
	}

	// Load custom configuration from environment variables
	config.Custom = p.loadCustomConfig()

	return config, nil
}

// Save is not supported for environment provider
func (p *Provider) Save(config *types.Config) error {
	return fmt.Errorf("save operation not supported for environment provider")
}

// Watch is not supported for environment provider
func (p *Provider) Watch(callback func(*types.Config)) error {
	return fmt.Errorf("watch operation not supported for environment provider")
}

// Close closes the provider
func (p *Provider) Close() error {
	return nil
}

// getString gets a string value from environment variable with fallback
func (p *Provider) getString(key, defaultValue string) string {
	fullKey := p.prefix + key
	if value := os.Getenv(fullKey); value != "" {
		return value
	}
	return defaultValue
}

// getInt gets an integer value from environment variable with fallback
func (p *Provider) getInt(key string, defaultValue int) int {
	fullKey := p.prefix + key
	if value := os.Getenv(fullKey); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getBool gets a boolean value from environment variable with fallback
func (p *Provider) getBool(key string, defaultValue bool) bool {
	fullKey := p.prefix + key
	if value := os.Getenv(fullKey); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// getStringSlice gets a string slice from environment variable with fallback
func (p *Provider) getStringSlice(key string, defaultValue []string) []string {
	fullKey := p.prefix + key
	if value := os.Getenv(fullKey); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// loadCustomConfig loads custom configuration from environment variables
func (p *Provider) loadCustomConfig() map[string]interface{} {
	custom := make(map[string]interface{})

	// Get all environment variables with CUSTOM_ prefix
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// Check if it's a custom configuration variable
		if strings.HasPrefix(key, p.prefix+"CUSTOM_") {
			customKey := strings.TrimPrefix(key, p.prefix+"CUSTOM_")
			customKey = strings.ToLower(customKey)
			customKey = strings.ReplaceAll(customKey, "_", ".")

			// Try to parse as different types
			if boolValue, err := strconv.ParseBool(value); err == nil {
				custom[customKey] = boolValue
			} else if intValue, err := strconv.Atoi(value); err == nil {
				custom[customKey] = intValue
			} else if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
				custom[customKey] = floatValue
			} else {
				custom[customKey] = value
			}
		}
	}

	return custom
}
