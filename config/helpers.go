package config

import (
	"fmt"
	"strings"
	"time"

	api "github.com/anasamu/go-micro-libs/api"
	cache "github.com/anasamu/go-micro-libs/cache"
	cbreaker "github.com/anasamu/go-micro-libs/circuitbreaker"
	cfgtypes "github.com/anasamu/go-micro-libs/config/types"
	db "github.com/anasamu/go-micro-libs/database"
	"github.com/anasamu/go-micro-libs/logx"
	messaging "github.com/anasamu/go-micro-libs/messaging"
	"github.com/sirupsen/logrus"
)

// BuildLogrusFromConfig builds a configured logrus.Logger from central config
func BuildLogrusFromConfig(c *cfgtypes.Config) *logrus.Logger {
	lg := logrus.New()

	// Level
	level := c.Logging.Level
	if level == "" {
		level = "info"
	}
	if lvl, err := logrus.ParseLevel(level); err == nil {
		lg.SetLevel(lvl)
	}

	// Format
	switch strings.ToLower(c.Logging.Format) {
	case "json":
		formatter := &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
			},
		}
		lg.SetFormatter(formatter)
	case "text":
		formatter := &logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339Nano,
			ForceColors:     c.Server.Environment != "production",
		}
		lg.SetFormatter(formatter)
	case "structured":
		formatter := &logrus.TextFormatter{
			DisableColors:   true,
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339Nano,
		}
		lg.SetFormatter(formatter)
	default:
		// Default to JSON for production, text for development
		if c.IsProduction() {
			formatter := &logrus.JSONFormatter{
				TimestampFormat: time.RFC3339Nano,
				FieldMap: logrus.FieldMap{
					logrus.FieldKeyTime:  "timestamp",
					logrus.FieldKeyLevel: "level",
					logrus.FieldKeyMsg:   "message",
					logrus.FieldKeyFunc:  "function",
				},
			}
			lg.SetFormatter(formatter)
		} else {
			formatter := &logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: time.RFC3339Nano,
				ForceColors:     true,
			}
			lg.SetFormatter(formatter)
		}
	}

	// Add service context to all log entries
	lg = lg.WithFields(logrus.Fields{
		"service": c.Server.ServiceName,
		"version": c.Server.Version,
		"env":     c.Server.Environment,
	}).Logger

	// Output is handled by caller (stdout/stderr/file) for simplicity
	return lg
}

// BuildLoggerFacade returns the logx facade bound to a configured logrus logger
func BuildLoggerFacade(c *cfgtypes.Config) logx.Logger {
	core := BuildLogrusFromConfig(c)
	return logx.NewLogrusAdapter(core)
}

// BuildAPIManagerConfig maps central config to API manager config
func BuildAPIManagerConfig(c *cfgtypes.Config) *api.ManagerConfig {
	// Determine default provider based on configuration
	defaultProvider := "http"
	if c.API.GRPC.Port != "" {
		defaultProvider = "grpc"
	} else if c.API.GraphQL.Endpoint != "" {
		defaultProvider = "graphql"
	}

	// Set timeouts with sensible defaults
	readTimeout := c.API.HTTP.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30
	}

	writeTimeout := c.API.HTTP.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 30
	}

	// Use the longer timeout for overall request timeout
	requestTimeout := readTimeout
	if writeTimeout > readTimeout {
		requestTimeout = writeTimeout
	}

	return &api.ManagerConfig{
		DefaultProvider: defaultProvider,
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         time.Duration(requestTimeout) * time.Second,
		MaxRequestSize:  10 * 1024 * 1024, // 10MB
		Metadata: map[string]string{
			"service":   c.Server.ServiceName,
			"env":       c.Server.Environment,
			"version":   c.Server.Version,
			"host":      c.API.HTTP.Host,
			"port":      c.API.HTTP.Port,
			"base_path": c.API.HTTP.BasePath,
		},
	}
}

// BuildDatabaseManagerConfig maps central config to Database manager config
func BuildDatabaseManagerConfig(c *cfgtypes.Config) *db.ManagerConfig {
	// Determine default provider based on configuration
	defaultProvider := "postgresql"
	if c.Database.MongoDB.URI != "" {
		defaultProvider = "mongodb"
	} else if c.Database.MySQL.Host != "" {
		defaultProvider = "mysql"
	} else if len(c.Database.Cassandra.Hosts) > 0 {
		defaultProvider = "cassandra"
	} else if c.Database.Redis.Addr != "" {
		defaultProvider = "redis"
	}

	// Set connection limits with sensible defaults
	maxConnections := c.Database.PostgreSQL.MaxOpenConns
	if maxConnections == 0 {
		maxConnections = 25
	}

	// Set timeout with sensible default
	timeout := c.Database.PostgreSQL.ConnectTimeout
	if timeout == 0 {
		timeout = 30
	}

	return &db.ManagerConfig{
		DefaultProvider: defaultProvider,
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         time.Duration(timeout) * time.Second,
		MaxConnections:  maxConnections,
		Metadata: map[string]string{
			"service":  c.Server.ServiceName,
			"env":      c.Server.Environment,
			"provider": defaultProvider,
		},
	}
}

// BuildMessagingManagerConfig maps central config to Messaging manager config
func BuildMessagingManagerConfig(c *cfgtypes.Config) *messaging.ManagerConfig {
	// Determine default provider based on configuration
	defaultProvider := c.Messaging.Provider
	if defaultProvider == "" {
		// Auto-detect based on available configurations
		if len(c.Messaging.Kafka.Brokers) > 0 {
			defaultProvider = "kafka"
		} else if c.Messaging.RabbitMQ.URL != "" || c.Messaging.RabbitMQ.Host != "" {
			defaultProvider = "rabbitmq"
		} else if c.Messaging.NATS.URL != "" || len(c.Messaging.NATS.URLs) > 0 {
			defaultProvider = "nats"
		} else if c.Messaging.SQS.QueueURL != "" {
			defaultProvider = "sqs"
		} else {
			defaultProvider = "kafka" // default fallback
		}
	}

	return &messaging.ManagerConfig{
		DefaultProvider: defaultProvider,
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         30 * time.Second,
		Metadata: map[string]string{
			"service":  c.Server.ServiceName,
			"env":      c.Server.Environment,
			"provider": defaultProvider,
		},
	}
}

// BuildCircuitBreakerManagerConfig maps central config to Circuit Breaker manager config
func BuildCircuitBreakerManagerConfig(c *cfgtypes.Config) *cbreaker.ManagerConfig {
	// Determine default provider
	defaultProvider := c.CircuitBreaker.Provider
	if defaultProvider == "" {
		defaultProvider = "gobreaker"
	}

	return &cbreaker.ManagerConfig{
		DefaultProvider: defaultProvider,
		RetryAttempts:   0, // Circuit breaker manages its own retry logic
		RetryDelay:      0,
		Timeout:         0,
		Metadata: map[string]string{
			"service":  c.Server.ServiceName,
			"env":      c.Server.Environment,
			"provider": defaultProvider,
		},
	}
}

// BuildCacheManagerConfig maps central config to Cache manager config
func BuildCacheManagerConfig(c *cfgtypes.Config) *cache.ManagerConfig {
	// Determine default provider based on configuration
	defaultProvider := c.Cache.Provider
	if defaultProvider == "" {
		// Auto-detect based on available configurations
		if c.Cache.Redis.Host != "" {
			defaultProvider = "redis"
		} else if len(c.Cache.Memcache.Servers) > 0 {
			defaultProvider = "memcache"
		} else {
			defaultProvider = "memory" // fallback to memory cache
		}
	}

	return &cache.ManagerConfig{
		DefaultProvider: defaultProvider,
		RetryAttempts:   3,
		RetryDelay:      2 * time.Second,
		Timeout:         5 * time.Second,
		Metadata: map[string]string{
			"service":  c.Server.ServiceName,
			"env":      c.Server.Environment,
			"provider": defaultProvider,
		},
	}
}

// GetRedisConnectionURL builds Redis connection URL from config
func GetRedisConnectionURL(c *cfgtypes.Config) string {
	redis := c.Cache.Redis
	if redis.Host == "" {
		return ""
	}

	port := redis.Port
	if port == 0 {
		port = 6379
	}

	scheme := "redis"
	if redis.UseTLS {
		scheme = "rediss"
	}

	if redis.Password != "" {
		if redis.Username != "" {
			return fmt.Sprintf("%s://%s:%s@%s:%d/%d", scheme, redis.Username, redis.Password, redis.Host, port, redis.DB)
		}
		return fmt.Sprintf("%s://:%s@%s:%d/%d", scheme, redis.Password, redis.Host, port, redis.DB)
	}

	return fmt.Sprintf("%s://%s:%d/%d", scheme, redis.Host, port, redis.DB)
}

// GetDatabaseConnectionURL builds database connection URL from config
func GetDatabaseConnectionURL(c *cfgtypes.Config, provider string) string {
	switch strings.ToLower(provider) {
	case "postgresql", "postgres":
		return c.GetDatabaseURL()
	case "mysql":
		mysql := c.Database.MySQL
		if mysql.Host == "" {
			return ""
		}
		port := mysql.Port
		if port == 0 {
			port = 3306
		}
		scheme := "mysql"
		if mysql.UseTLS {
			scheme = "mysql+tls"
		}
		return fmt.Sprintf("%s://%s:%s@%s:%d/%s", scheme, mysql.User, mysql.Password, mysql.Host, port, mysql.DBName)
	case "mongodb":
		return c.Database.MongoDB.URI
	case "redis":
		return GetRedisConnectionURL(c)
	default:
		return ""
	}
}

// GetServiceEndpoint builds service endpoint URL from config
func GetServiceEndpoint(c *cfgtypes.Config, serviceName string) (string, error) {
	return c.GetServiceURL(serviceName)
}

// BuildCommunicationStartConfigForService maps a service config to communication provider name and start config
// This aligns host/port and timeouts with the selected provider based on service.Protocol
func BuildCommunicationStartConfigForService(c *cfgtypes.Config, serviceName string) (string, map[string]interface{}, error) {
	service, ok := c.GetServiceConfig(serviceName)
	if !ok {
		return "", nil, fmt.Errorf("service %s not found", serviceName)
	}

	// Determine provider based on service protocol
	provider := service.Protocol
	if provider == "" {
		provider = "http"
	}

	// Derive timeouts with sensible defaults (in seconds for server APIs)
	connectMs := service.Timeout.Connect
	readMs := service.Timeout.Read
	writeMs := service.Timeout.Write
	idleSec := 120

	if connectMs == 0 {
		connectMs = 5000
	}
	if readMs == 0 {
		readMs = 10000
	}
	if writeMs == 0 {
		writeMs = 10000
	}

	// Build provider-specific config
	cfg := map[string]interface{}{
		"host":          service.Host,
		"port":          parsePortStringToInt(service.Port),
		"read_timeout":  time.Duration(readMs) * time.Millisecond,
		"write_timeout": time.Duration(writeMs) * time.Millisecond,
		"idle_timeout":  time.Duration(idleSec) * time.Second,
	}

	switch provider {
	case "grpc":
		// gRPC specific defaults
		if cfg["port"].(int) == 0 {
			cfg["port"] = 9090
		}
		if _, ok := cfg["max_recv_msg_size"]; !ok {
			cfg["max_recv_msg_size"] = 4 * 1024 * 1024
		}
		if _, ok := cfg["max_send_msg_size"]; !ok {
			cfg["max_send_msg_size"] = 4 * 1024 * 1024
		}
		if _, ok := cfg["enable_reflection"]; !ok {
			cfg["enable_reflection"] = true
		}
	default:
		// http or others -> ensure defaults
		if cfg["port"].(int) == 0 {
			cfg["port"] = 8080
		}
	}

	return provider, cfg, nil
}

// parsePortStringToInt converts a numeric string port to int, returns 0 if invalid
func parsePortStringToInt(port string) int {
	if port == "" {
		return 0
	}
	var value int
	if _, err := fmt.Sscanf(port, "%d", &value); err == nil {
		return value
	}
	return 0
}

// ValidateConfig performs basic validation on the configuration
func ValidateConfig(c *cfgtypes.Config) []error {
	var errors []error

	// Validate server configuration
	if c.Server.ServiceName == "" {
		errors = append(errors, fmt.Errorf("server.service_name is required"))
	}
	if c.Server.Environment == "" {
		errors = append(errors, fmt.Errorf("server.environment is required"))
	}

	// Validate database configuration
	if c.Database.PostgreSQL.Host != "" {
		if c.Database.PostgreSQL.User == "" {
			errors = append(errors, fmt.Errorf("database.postgresql.user is required when host is specified"))
		}
		if c.Database.PostgreSQL.DBName == "" {
			errors = append(errors, fmt.Errorf("database.postgresql.dbname is required when host is specified"))
		}
	}

	// Validate cache configuration
	if c.Cache.Redis.Host != "" {
		if c.Cache.Redis.Port == 0 {
			c.Cache.Redis.Port = 6379 // Set default port
		}
	}

	// Validate API configuration
	if c.API.HTTP.Host != "" {
		if c.API.HTTP.Port == "" {
			errors = append(errors, fmt.Errorf("api.http.port is required when host is specified"))
		}
	}

	return errors
}

// GetConfigSummary returns a summary of the current configuration
func GetConfigSummary(c *cfgtypes.Config) map[string]interface{} {
	summary := map[string]interface{}{
		"service": map[string]interface{}{
			"name":        c.Server.ServiceName,
			"version":     c.Server.Version,
			"environment": c.Server.Environment,
		},
		"providers": map[string]interface{}{},
	}

	// Add database provider info
	if c.Database.PostgreSQL.Host != "" {
		summary["providers"].(map[string]interface{})["database"] = "postgresql"
	} else if c.Database.MongoDB.URI != "" {
		summary["providers"].(map[string]interface{})["database"] = "mongodb"
	} else if c.Database.MySQL.Host != "" {
		summary["providers"].(map[string]interface{})["database"] = "mysql"
	}

	// Add cache provider info
	if c.Cache.Redis.Host != "" {
		summary["providers"].(map[string]interface{})["cache"] = "redis"
	} else if len(c.Cache.Memcache.Servers) > 0 {
		summary["providers"].(map[string]interface{})["cache"] = "memcache"
	} else {
		summary["providers"].(map[string]interface{})["cache"] = "memory"
	}

	// Add messaging provider info
	if len(c.Messaging.Kafka.Brokers) > 0 {
		summary["providers"].(map[string]interface{})["messaging"] = "kafka"
	} else if c.Messaging.RabbitMQ.URL != "" || c.Messaging.RabbitMQ.Host != "" {
		summary["providers"].(map[string]interface{})["messaging"] = "rabbitmq"
	} else if c.Messaging.NATS.URL != "" || len(c.Messaging.NATS.URLs) > 0 {
		summary["providers"].(map[string]interface{})["messaging"] = "nats"
	}

	return summary
}
