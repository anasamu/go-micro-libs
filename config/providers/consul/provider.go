package consul

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/config/types"
	"github.com/hashicorp/consul/api"
)

// Provider implements configuration provider for HashiCorp Consul
type Provider struct {
	client    *api.Client
	prefix    string
	watchers  []func(*types.Config)
	stopChan  chan struct{}
	options   *ConsulOptions
	lastIndex uint64
}

// ConsulOptions holds additional options for Consul provider
type ConsulOptions struct {
	Token         string
	Datacenter    string
	Namespace     string
	WaitTime      time.Duration
	RetryInterval time.Duration
	MaxRetries    int
	TLSConfig     *api.TLSConfig
}

// NewProvider creates a new Consul-based configuration provider
func NewProvider(address, prefix string, options *ConsulOptions) (*Provider, error) {
	config := api.DefaultConfig()
	config.Address = address

	// Apply options
	if options != nil {
		if options.Token != "" {
			config.Token = options.Token
		}
		if options.Datacenter != "" {
			config.Datacenter = options.Datacenter
		}
		if options.Namespace != "" {
			config.Namespace = options.Namespace
		}
		if options.TLSConfig != nil {
			config.TLSConfig = *options.TLSConfig
		}

		// Set defaults for options
		if options.WaitTime == 0 {
			options.WaitTime = 30 * time.Second
		}
		if options.RetryInterval == 0 {
			options.RetryInterval = 5 * time.Second
		}
		if options.MaxRetries == 0 {
			options.MaxRetries = 3
		}
	} else {
		options = &ConsulOptions{
			WaitTime:      30 * time.Second,
			RetryInterval: 5 * time.Second,
			MaxRetries:    3,
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating consul client: %w", err)
	}

	return &Provider{
		client:    client,
		prefix:    prefix,
		watchers:  make([]func(*types.Config), 0),
		stopChan:  make(chan struct{}),
		options:   options,
		lastIndex: 0,
	}, nil
}

// Load loads configuration from Consul KV store
func (p *Provider) Load() (*types.Config, error) {
	config := &types.Config{}

	// Load configuration from Consul KV store
	kv := p.client.KV()

	// Get all keys with the prefix using blocking query for better performance
	queryOptions := &api.QueryOptions{
		WaitIndex: p.lastIndex,
		WaitTime:  p.options.WaitTime,
	}

	pairs, meta, err := kv.List(p.prefix, queryOptions)
	if err != nil {
		return nil, fmt.Errorf("error listing consul keys: %w", err)
	}

	// Update last index for blocking queries
	if meta != nil {
		p.lastIndex = meta.LastIndex
	}

	// Convert KV pairs to map
	configMap := make(map[string]interface{})
	for _, pair := range pairs {
		key := pair.Key
		if len(p.prefix) > 0 {
			key = key[len(p.prefix)+1:] // Remove prefix and slash
		}

		// Try to parse JSON values, fallback to string
		var value interface{}
		if err := json.Unmarshal(pair.Value, &value); err != nil {
			value = string(pair.Value)
		}
		configMap[key] = value
	}

	// Parse configuration using enhanced structures
	config.Server = types.ServerConfig{
		ServiceName:   p.getString(configMap, "server/service_name", ""),
		Version:       p.getString(configMap, "server/version", ""),
		Environment:   p.getString(configMap, "server/environment", "development"),
		Configuration: p.getConfigurationConfig(configMap, "server/config"),
	}

	config.Database = types.DatabaseConfig{
		PostgreSQL:  p.getPostgreSQLConfig(configMap, "database/postgresql"),
		MongoDB:     p.getMongoDBConfig(configMap, "database/mongodb"),
		MySQL:       p.getMySQLConfig(configMap, "database/mysql"),
		MariaDB:     p.getMariaDBConfig(configMap, "database/mariadb"),
		SQLite:      p.getSQLiteConfig(configMap, "database/sqlite"),
		Cassandra:   p.getCassandraConfig(configMap, "database/cassandra"),
		CockroachDB: p.getCockroachConfig(configMap, "database/cockroachdb"),
		Redis:       p.getRedisDBConfig(configMap, "database/redis"),
		InfluxDB:    p.getInfluxDBConfig(configMap, "database/influxdb"),
		Elastic:     p.getElasticDBConfig(configMap, "database/elasticsearch"),
	}

	config.Configuration = p.getConfigurationConfig(configMap, "config")
	config.Logging = p.getLoggingConfig(configMap, "logging")
	config.Monitoring = p.getMonitoringConfig(configMap, "monitoring")
	config.Storage = p.getStorageConfig(configMap, "storage")
	config.Auth = p.getAuthConfig(configMap, "auth")
	config.API = p.getAPIConfig(configMap, "api")
	config.Communication = p.getCommunicationConfig(configMap, "communication")
	config.Cache = p.getCacheConfig(configMap, "cache")
	config.Messaging = p.getMessagingConfig(configMap, "messaging")
	config.Email = p.getEmailConfig(configMap, "email")
	config.Payment = p.getPaymentConfig(configMap, "payment")
	config.Discovery = p.getDiscoveryConfig(configMap, "discovery")
	config.Failover = p.getFailoverConfig(configMap, "failover")
	config.Edge = p.getEdgeConfig(configMap, "edge")
	config.CircuitBreaker = p.getCircuitBreakerConfig(configMap, "circuitbreaker")
	config.Event = p.getEventConfig(configMap, "event")
	config.RateLimit = p.getRateLimitConfig(configMap, "ratelimit")
	config.Scheduling = p.getSchedulingConfig(configMap, "scheduling")
	config.ZeroTrust = p.getZeroTrustConfig(configMap, "zerotrust")
	config.Backup = p.getBackupConfig(configMap, "backup")
	config.Chaos = p.getChaosConfig(configMap, "chaos")
	config.AI = p.getAIConfig(configMap, "ai")
	config.Middleware = p.getMiddlewareConfig(configMap, "middleware")
	config.FileGen = p.getFileGenConfig(configMap, "filegen")
	config.Services = p.getServicesConfig(configMap, "services")
	config.Custom = p.getCustomConfig(configMap)

	return config, nil
}

// Placeholder methods for configuration parsing - implement these based on your needs
func (p *Provider) getMongoDBConfig(configMap map[string]interface{}, prefix string) types.MongoDBConfig {
	return types.MongoDBConfig{
		URI:                 p.getString(configMap, prefix+"/uri", "mongodb://localhost:27017"),
		Database:            p.getString(configMap, prefix+"/database", ""),
		Username:            p.getString(configMap, prefix+"/username", ""),
		Password:            p.getString(configMap, prefix+"/password", ""),
		Hosts:               p.getStringSlice(configMap, prefix+"/hosts", []string{}),
		MaxPoolSize:         p.getInt(configMap, prefix+"/max_pool_size", 100),
		MinPoolSize:         p.getInt(configMap, prefix+"/min_pool_size", 10),
		MaxConnIdleTime:     p.getInt(configMap, prefix+"/max_conn_idle_time", 300000),
		MaxConnecting:       p.getInt(configMap, prefix+"/max_connecting", 10),
		MaxConnLifeTime:     p.getInt(configMap, prefix+"/max_conn_life_time", 3600000),
		ConnectTimeout:      p.getInt(configMap, prefix+"/connect_timeout", 30000),
		SocketTimeout:       p.getInt(configMap, prefix+"/socket_timeout", 30000),
		ServerTimeout:       p.getInt(configMap, prefix+"/server_timeout", 30000),
		HeartbeatInterval:   p.getInt(configMap, prefix+"/heartbeat_interval", 10000),
		UseTLS:              p.getBool(configMap, prefix+"/use_tls", false),
		AuthSource:          p.getString(configMap, prefix+"/auth_source", ""),
		AuthMechanism:       p.getString(configMap, prefix+"/auth_mechanism", ""),
		ReplicaSetName:      p.getString(configMap, prefix+"/replica_set_name", ""),
		ReadPreference:      p.getString(configMap, prefix+"/read_preference", "primary"),
		WriteConcern:        p.getWriteConcernConfig(configMap, prefix+"/write_concern"),
		ReadConcern:         p.getReadConcernConfig(configMap, prefix+"/read_concern"),
		Compressors:         p.getStringSlice(configMap, prefix+"/compressors", []string{}),
		DirectConnection:    p.getBool(configMap, prefix+"/direct_connection", false),
		RetryWrites:         p.getBool(configMap, prefix+"/retry_writes", true),
		RetryReads:          p.getBool(configMap, prefix+"/retry_reads", true),
		HealthCheckInterval: p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:       p.getBool(configMap, prefix+"/enable_metrics", false),
		LogLevel:            p.getString(configMap, prefix+"/log_level", "info"),
		GridFSBucket:        p.getString(configMap, prefix+"/gridfs_bucket", ""),
		Custom:              p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getMySQLConfig(configMap map[string]interface{}, prefix string) types.MySQLConfig {
	return types.MySQLConfig{
		Host:                p.getString(configMap, prefix+"/host", "localhost"),
		Port:                p.getInt(configMap, prefix+"/port", 3306),
		User:                p.getString(configMap, prefix+"/user", ""),
		Password:            p.getString(configMap, prefix+"/password", ""),
		DBName:              p.getString(configMap, prefix+"/dbname", ""),
		Params:              p.getString(configMap, prefix+"/params", ""),
		MaxOpenConns:        p.getInt(configMap, prefix+"/max_open_conns", 25),
		MaxIdleConns:        p.getInt(configMap, prefix+"/max_idle_conns", 5),
		MinOpenConns:        p.getInt(configMap, prefix+"/min_open_conns", 5),
		ConnMaxLifetime:     p.getInt(configMap, prefix+"/conn_max_lifetime", 3600),
		ConnMaxIdleTime:     p.getInt(configMap, prefix+"/conn_max_idle_time", 1800),
		ConnectTimeout:      p.getInt(configMap, prefix+"/connect_timeout", 30),
		ReadTimeout:         p.getInt(configMap, prefix+"/read_timeout", 30),
		WriteTimeout:        p.getInt(configMap, prefix+"/write_timeout", 30),
		QueryTimeout:        p.getInt(configMap, prefix+"/query_timeout", 30),
		UseTLS:              p.getBool(configMap, prefix+"/use_tls", false),
		Charset:             p.getString(configMap, prefix+"/charset", "utf8mb4"),
		Collation:           p.getString(configMap, prefix+"/collation", "utf8mb4_unicode_ci"),
		ParseTime:           p.getBool(configMap, prefix+"/parse_time", true),
		Loc:                 p.getString(configMap, prefix+"/loc", "UTC"),
		MultiStatements:     p.getBool(configMap, prefix+"/multi_statements", false),
		InterpolateParams:   p.getBool(configMap, prefix+"/interpolate_params", false),
		ReadTimeoutSlave:    p.getInt(configMap, prefix+"/read_timeout_slave", 30),
		WriteTimeoutSlave:   p.getInt(configMap, prefix+"/write_timeout_slave", 30),
		MaxAllowedPacket:    p.getInt(configMap, prefix+"/max_allowed_packet", 4194304),
		NetBufferLength:     p.getInt(configMap, prefix+"/net_buffer_length", 16384),
		HealthCheckInterval: p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:       p.getBool(configMap, prefix+"/enable_metrics", false),
		LogLevel:            p.getString(configMap, prefix+"/log_level", "info"),
		Custom:              p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getMariaDBConfig(configMap map[string]interface{}, prefix string) types.MariaDBConfig {
	return types.MariaDBConfig{
		Host:     p.getString(configMap, prefix+"/host", "localhost"),
		Port:     p.getInt(configMap, prefix+"/port", 3306),
		User:     p.getString(configMap, prefix+"/user", ""),
		Password: p.getString(configMap, prefix+"/password", ""),
		DBName:   p.getString(configMap, prefix+"/dbname", ""),
	}
}

func (p *Provider) getSQLiteConfig(configMap map[string]interface{}, prefix string) types.SQLiteConfig {
	return types.SQLiteConfig{
		Path: p.getString(configMap, prefix+"/path", ""),
	}
}

func (p *Provider) getCassandraConfig(configMap map[string]interface{}, prefix string) types.CassandraConfig {
	return types.CassandraConfig{
		Hosts:                p.getStringSlice(configMap, prefix+"/hosts", []string{}),
		Keyspace:             p.getString(configMap, prefix+"/keyspace", ""),
		Username:             p.getString(configMap, prefix+"/username", ""),
		Password:             p.getString(configMap, prefix+"/password", ""),
		Port:                 p.getInt(configMap, prefix+"/port", 9042),
		ConnectTimeout:       p.getInt(configMap, prefix+"/connect_timeout", 60000),
		Timeout:              p.getInt(configMap, prefix+"/timeout", 60000),
		NumConns:             p.getInt(configMap, prefix+"/num_conns", 2),
		MaxConnAttempts:      p.getInt(configMap, prefix+"/max_conn_attempts", 3),
		UseTLS:               p.getBool(configMap, prefix+"/use_tls", false),
		Consistency:          p.getString(configMap, prefix+"/consistency", "ONE"),
		SerialConsistency:    p.getString(configMap, prefix+"/serial_consistency", "SERIAL"),
		Replication:          p.getInt(configMap, prefix+"/replication", 1),
		DataCenter:           p.getString(configMap, prefix+"/data_center", ""),
		RetryPolicy:          p.getString(configMap, prefix+"/retry_policy", "simple"),
		MaxRetries:           p.getInt(configMap, prefix+"/max_retries", 3),
		LoadBalancingPolicy:  p.getString(configMap, prefix+"/load_balancing_policy", "round_robin"),
		ReconnectInterval:    p.getInt(configMap, prefix+"/reconnect_interval", 1000),
		MaxReconnectAttempts: p.getInt(configMap, prefix+"/max_reconnect_attempts", 5),
		Compression:          p.getString(configMap, prefix+"/compression", "snappy"),
		ProtoVersion:         p.getInt(configMap, prefix+"/proto_version", 4),
		HealthCheckInterval:  p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:        p.getBool(configMap, prefix+"/enable_metrics", false),
		LogLevel:             p.getString(configMap, prefix+"/log_level", "info"),
		DefaultPageSize:      p.getInt(configMap, prefix+"/default_page_size", 5000),
		MaxPageSize:          p.getInt(configMap, prefix+"/max_page_size", 10000),
		Custom:               p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getCockroachConfig(configMap map[string]interface{}, prefix string) types.CockroachConfig {
	return types.CockroachConfig{
		Host:     p.getString(configMap, prefix+"/host", "localhost"),
		Port:     p.getInt(configMap, prefix+"/port", 26257),
		User:     p.getString(configMap, prefix+"/user", ""),
		Password: p.getString(configMap, prefix+"/password", ""),
		DBName:   p.getString(configMap, prefix+"/dbname", ""),
		SSLMode:  p.getString(configMap, prefix+"/sslmode", "disable"),
	}
}

func (p *Provider) getRedisDBConfig(configMap map[string]interface{}, prefix string) types.RedisDBConfig {
	return types.RedisDBConfig{
		Addr:                p.getString(configMap, prefix+"/addr", "localhost:6379"),
		Password:            p.getString(configMap, prefix+"/password", ""),
		DB:                  p.getInt(configMap, prefix+"/db", 0),
		PoolSize:            p.getInt(configMap, prefix+"/pool_size", 10),
		MinIdleConns:        p.getInt(configMap, prefix+"/min_idle_conns", 5),
		MaxConnAge:          p.getInt(configMap, prefix+"/max_conn_age", 3600),
		PoolTimeout:         p.getInt(configMap, prefix+"/pool_timeout", 30),
		IdleTimeout:         p.getInt(configMap, prefix+"/idle_timeout", 300),
		DialTimeout:         p.getInt(configMap, prefix+"/dial_timeout", 30),
		ReadTimeout:         p.getInt(configMap, prefix+"/read_timeout", 30),
		WriteTimeout:        p.getInt(configMap, prefix+"/write_timeout", 30),
		MaxRetries:          p.getInt(configMap, prefix+"/max_retries", 3),
		UseTLS:              p.getBool(configMap, prefix+"/use_tls", false),
		HealthCheckInterval: p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:       p.getBool(configMap, prefix+"/enable_metrics", false),
		Custom:              p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getInfluxDBConfig(configMap map[string]interface{}, prefix string) types.InfluxDBConfig {
	return types.InfluxDBConfig{
		URL:                 p.getString(configMap, prefix+"/url", "http://localhost:8086"),
		Token:               p.getString(configMap, prefix+"/token", ""),
		Org:                 p.getString(configMap, prefix+"/org", ""),
		Bucket:              p.getString(configMap, prefix+"/bucket", ""),
		Username:            p.getString(configMap, prefix+"/username", ""),
		Password:            p.getString(configMap, prefix+"/password", ""),
		Timeout:             p.getInt(configMap, prefix+"/timeout", 30),
		ConnectTimeout:      p.getInt(configMap, prefix+"/connect_timeout", 30),
		RequestTimeout:      p.getInt(configMap, prefix+"/request_timeout", 30),
		UseTLS:              p.getBool(configMap, prefix+"/use_tls", false),
		BatchSize:           p.getInt(configMap, prefix+"/batch_size", 5000),
		FlushInterval:       p.getInt(configMap, prefix+"/flush_interval", 1000),
		MaxRetries:          p.getInt(configMap, prefix+"/max_retries", 3),
		RetryInterval:       p.getInt(configMap, prefix+"/retry_interval", 1000),
		Precision:           p.getString(configMap, prefix+"/precision", "ns"),
		RetentionPolicy:     p.getString(configMap, prefix+"/retention_policy", ""),
		HealthCheckInterval: p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:       p.getBool(configMap, prefix+"/enable_metrics", false),
		LogLevel:            p.getString(configMap, prefix+"/log_level", "info"),
		QueryTimeout:        p.getInt(configMap, prefix+"/query_timeout", 30),
		Custom:              p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getElasticDBConfig(configMap map[string]interface{}, prefix string) types.ElasticDBConfig {
	return types.ElasticDBConfig{
		URL:      p.getString(configMap, prefix+"/url", "http://localhost:9200"),
		Username: p.getString(configMap, prefix+"/username", ""),
		Password: p.getString(configMap, prefix+"/password", ""),
		Index:    p.getString(configMap, prefix+"/index", ""),
	}
}

// Helper methods for nested config structures
func (p *Provider) getWriteConcernConfig(configMap map[string]interface{}, prefix string) types.WriteConcernConfig {
	return types.WriteConcernConfig{
		W:        p.getInterface(configMap, prefix+"/w", 1),
		J:        p.getBool(configMap, prefix+"/j", false),
		WTimeout: p.getInt(configMap, prefix+"/wtimeout", 10000),
	}
}

func (p *Provider) getReadConcernConfig(configMap map[string]interface{}, prefix string) types.ReadConcernConfig {
	return types.ReadConcernConfig{
		Level: p.getString(configMap, prefix+"/level", "local"),
	}
}

func (p *Provider) getInterface(configMap map[string]interface{}, key string, defaultValue interface{}) interface{} {
	if value, ok := configMap[key]; ok {
		return value
	}
	return defaultValue
}

// Save saves configuration to Consul KV store
func (p *Provider) Save(config *types.Config) error {
	kv := p.client.KV()

	// Convert config to KV pairs
	pairs := []*api.KVPair{
		{Key: p.prefix + "/server/environment", Value: []byte(config.Server.Environment)},
		{Key: p.prefix + "/server/service_name", Value: []byte(config.Server.ServiceName)},
		{Key: p.prefix + "/server/version", Value: []byte(config.Server.Version)},

		// Database - PostgreSQL
		{Key: p.prefix + "/database/postgresql/host", Value: []byte(config.Database.PostgreSQL.Host)},
		{Key: p.prefix + "/database/postgresql/port", Value: []byte(fmt.Sprintf("%d", config.Database.PostgreSQL.Port))},
		{Key: p.prefix + "/database/postgresql/user", Value: []byte(config.Database.PostgreSQL.User)},
		{Key: p.prefix + "/database/postgresql/password", Value: []byte(config.Database.PostgreSQL.Password)},
		{Key: p.prefix + "/database/postgresql/dbname", Value: []byte(config.Database.PostgreSQL.DBName)},
		{Key: p.prefix + "/database/postgresql/sslmode", Value: []byte(config.Database.PostgreSQL.SSLMode)},
		{Key: p.prefix + "/database/postgresql/max_open_conns", Value: []byte(fmt.Sprintf("%d", config.Database.PostgreSQL.MaxOpenConns))},
		{Key: p.prefix + "/database/postgresql/max_idle_conns", Value: []byte(fmt.Sprintf("%d", config.Database.PostgreSQL.MaxIdleConns))},
		{Key: p.prefix + "/database/postgresql/min_open_conns", Value: []byte(fmt.Sprintf("%d", config.Database.PostgreSQL.MinOpenConns))},

		// Database - MongoDB
		{Key: p.prefix + "/database/mongodb/uri", Value: []byte(config.Database.MongoDB.URI)},
		{Key: p.prefix + "/database/mongodb/database", Value: []byte(config.Database.MongoDB.Database)},
		{Key: p.prefix + "/database/mongodb/max_pool_size", Value: []byte(fmt.Sprintf("%d", config.Database.MongoDB.MaxPoolSize))},
		{Key: p.prefix + "/database/mongodb/min_pool_size", Value: []byte(fmt.Sprintf("%d", config.Database.MongoDB.MinPoolSize))},

		// Auth
		{Key: p.prefix + "/auth/jwt/secret_key", Value: []byte(config.Auth.JWT.SecretKey)},
		{Key: p.prefix + "/auth/jwt/expiration", Value: []byte(fmt.Sprintf("%d", config.Auth.JWT.Expiration))},
		{Key: p.prefix + "/auth/jwt/refresh_exp", Value: []byte(fmt.Sprintf("%d", config.Auth.JWT.RefreshExp))},
		{Key: p.prefix + "/auth/jwt/issuer", Value: []byte(config.Auth.JWT.Issuer)},
		{Key: p.prefix + "/auth/jwt/audience", Value: []byte(config.Auth.JWT.Audience)},
	}

	// Write all pairs
	for _, pair := range pairs {
		_, err := kv.Put(pair, nil)
		if err != nil {
			return fmt.Errorf("error writing to consul: %w", err)
		}
	}

	return nil
}

// Watch watches for configuration changes in Consul
func (p *Provider) Watch(callback func(*types.Config)) error {
	p.watchers = append(p.watchers, callback)

	if len(p.watchers) == 1 {
		go p.watchConsul()
	}

	return nil
}

// watchConsul watches for changes in Consul
func (p *Provider) watchConsul() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			config, err := p.Load()
			if err != nil {
				continue
			}

			for _, watcher := range p.watchers {
				go watcher(config)
			}

		case <-p.stopChan:
			return
		}
	}
}

// Close closes the provider
func (p *Provider) Close() error {
	close(p.stopChan)
	return nil
}

// Enhanced helper methods for type conversion
func (p *Provider) getString(configMap map[string]interface{}, key string, defaultValue string) string {
	if value, ok := configMap[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
		// Try to convert other types to string
		return fmt.Sprintf("%v", value)
	}
	return defaultValue
}

func (p *Provider) getInt(configMap map[string]interface{}, key string, defaultValue int) int {
	if value, ok := configMap[key]; ok {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if intValue, err := strconv.Atoi(v); err == nil {
				return intValue
			}
		}
	}
	return defaultValue
}

func (p *Provider) getBool(configMap map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := configMap[key]; ok {
		switch v := value.(type) {
		case bool:
			return v
		case string:
			if boolValue, err := strconv.ParseBool(v); err == nil {
				return boolValue
			}
		}
	}
	return defaultValue
}

func (p *Provider) getStringSlice(configMap map[string]interface{}, key string, defaultValue []string) []string {
	if value, ok := configMap[key]; ok {
		switch v := value.(type) {
		case []string:
			return v
		case []interface{}:
			result := make([]string, len(v))
			for i, item := range v {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					result[i] = fmt.Sprintf("%v", item)
				}
			}
			return result
		case string:
			return strings.Split(v, ",")
		}
	}
	return defaultValue
}

func (p *Provider) getFloat64(configMap map[string]interface{}, key string, defaultValue float64) float64 {
	if value, ok := configMap[key]; ok {
		switch v := value.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case string:
			if floatValue, err := strconv.ParseFloat(v, 64); err == nil {
				return floatValue
			}
		}
	}
	return defaultValue
}

// Map helper
func (p *Provider) getMap(configMap map[string]interface{}, key string) map[string]interface{} {
	if value, ok := configMap[key]; ok {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return map[string]interface{}{}
}

// Minimal configuration parsing helpers (provide sane defaults; extend as needed)
func (p *Provider) getConfigurationConfig(configMap map[string]interface{}, prefix string) types.ConfigurationConfig {
	return types.ConfigurationConfig{
		Provider: p.getString(configMap, prefix+"/provider", "file"),
		File: types.FileConfigProvider{
			Path: p.getString(configMap, prefix+"/file/path", ""),
			Type: p.getString(configMap, prefix+"/file/type", "yaml"),
		},
		Env: types.EnvConfigProvider{
			Prefix: p.getString(configMap, prefix+"/env/prefix", ""),
		},
		Consul: types.ConsulConfig{
			Address: p.getString(configMap, prefix+"/consul/address", ""),
			Token:   p.getString(configMap, prefix+"/consul/token", ""),
		},
		Vault: types.VaultConfig{
			Address: p.getString(configMap, prefix+"/vault/address", ""),
			Token:   p.getString(configMap, prefix+"/vault/token", ""),
			Path:    p.getString(configMap, prefix+"/vault/path", ""),
		},
	}
}

func (p *Provider) getPostgreSQLConfig(configMap map[string]interface{}, prefix string) types.PostgreSQLConfig {
	return types.PostgreSQLConfig{
		Host:                        p.getString(configMap, prefix+"/host", "localhost"),
		Port:                        p.getInt(configMap, prefix+"/port", 5432),
		User:                        p.getString(configMap, prefix+"/user", ""),
		Password:                    p.getString(configMap, prefix+"/password", ""),
		DBName:                      p.getString(configMap, prefix+"/dbname", ""),
		SSLMode:                     p.getString(configMap, prefix+"/sslmode", "disable"),
		MaxOpenConns:                p.getInt(configMap, prefix+"/max_open_conns", 25),
		MaxIdleConns:                p.getInt(configMap, prefix+"/max_idle_conns", 5),
		MinOpenConns:                p.getInt(configMap, prefix+"/min_open_conns", 5),
		ConnMaxLifetime:             p.getInt(configMap, prefix+"/conn_max_lifetime", 3600),
		ConnMaxIdleTime:             p.getInt(configMap, prefix+"/conn_max_idle_time", 1800),
		ConnectTimeout:              p.getInt(configMap, prefix+"/connect_timeout", 30),
		QueryTimeout:                p.getInt(configMap, prefix+"/query_timeout", 30),
		StatementTimeout:            p.getInt(configMap, prefix+"/statement_timeout", 30000),
		ApplicationName:             p.getString(configMap, prefix+"/application_name", ""),
		Timezone:                    p.getString(configMap, prefix+"/timezone", "UTC"),
		SearchPath:                  p.getString(configMap, prefix+"/search_path", ""),
		DefaultTransactionIsolation: p.getString(configMap, prefix+"/default_transaction_isolation", ""),
		ReplicationMode:             p.getString(configMap, prefix+"/replication_mode", ""),
		StandbyMode:                 p.getString(configMap, prefix+"/standby_mode", ""),
		HealthCheckInterval:         p.getInt(configMap, prefix+"/health_check_interval", 30),
		EnableMetrics:               p.getBool(configMap, prefix+"/enable_metrics", false),
		LogLevel:                    p.getString(configMap, prefix+"/log_level", "info"),
		EnableWALArchiving:          p.getBool(configMap, prefix+"/enable_wal_archiving", false),
		ArchiveCommand:              p.getString(configMap, prefix+"/archive_command", ""),
		RestoreCommand:              p.getString(configMap, prefix+"/restore_command", ""),
		Custom:                      p.getMap(configMap, prefix+"/custom"),
	}
}

func (p *Provider) getLoggingConfig(configMap map[string]interface{}, prefix string) types.LoggingConfig {
	return types.LoggingConfig{
		Level:  p.getString(configMap, prefix+"/level", "info"),
		Format: p.getString(configMap, prefix+"/format", "json"),
		Output: p.getString(configMap, prefix+"/output", "stdout"),
	}
}

func (p *Provider) getMonitoringConfig(configMap map[string]interface{}, prefix string) types.MonitoringConfig {
	return types.MonitoringConfig{
		Prometheus: types.PrometheusConfig{
			Enabled: p.getBool(configMap, prefix+"/prometheus/enabled", true),
			Port:    p.getString(configMap, prefix+"/prometheus/port", "9090"),
			Path:    p.getString(configMap, prefix+"/prometheus/path", "/metrics"),
		},
		Jaeger: types.JaegerConfig{
			Enabled:  p.getBool(configMap, prefix+"/jaeger/enabled", false),
			Endpoint: p.getString(configMap, prefix+"/jaeger/endpoint", ""),
			Service:  p.getString(configMap, prefix+"/jaeger/service", ""),
		},
	}
}

func (p *Provider) getStorageConfig(configMap map[string]interface{}, prefix string) types.StorageConfig {
	return types.StorageConfig{}
}

func (p *Provider) getAuthConfig(configMap map[string]interface{}, prefix string) types.AuthConfig {
	return types.AuthConfig{}
}

// Minimal stubs for remaining sections; extend parsing as needed
func (p *Provider) getAPIConfig(configMap map[string]interface{}, prefix string) types.APIConfig {
	return types.APIConfig{}
}
func (p *Provider) getCommunicationConfig(configMap map[string]interface{}, prefix string) types.CommunicationConfig {
	return types.CommunicationConfig{}
}
func (p *Provider) getCacheConfig(configMap map[string]interface{}, prefix string) types.CacheConfig {
	return types.CacheConfig{}
}
func (p *Provider) getMessagingConfig(configMap map[string]interface{}, prefix string) types.MessagingConfig {
	return types.MessagingConfig{}
}
func (p *Provider) getEmailConfig(configMap map[string]interface{}, prefix string) types.EmailConfig {
	return types.EmailConfig{}
}
func (p *Provider) getPaymentConfig(configMap map[string]interface{}, prefix string) types.PaymentConfig {
	return types.PaymentConfig{}
}
func (p *Provider) getDiscoveryConfig(configMap map[string]interface{}, prefix string) types.DiscoveryConfig {
	return types.DiscoveryConfig{}
}
func (p *Provider) getFailoverConfig(configMap map[string]interface{}, prefix string) types.FailoverConfig {
	return types.FailoverConfig{}
}
func (p *Provider) getEdgeConfig(configMap map[string]interface{}, prefix string) types.EdgeConfig {
	return types.EdgeConfig{}
}
func (p *Provider) getCircuitBreakerConfig(configMap map[string]interface{}, prefix string) types.CircuitBreakerLibConfig {
	return types.CircuitBreakerLibConfig{}
}
func (p *Provider) getEventConfig(configMap map[string]interface{}, prefix string) types.EventConfig {
	return types.EventConfig{}
}
func (p *Provider) getRateLimitConfig(configMap map[string]interface{}, prefix string) types.RateLimitConfig {
	return types.RateLimitConfig{}
}
func (p *Provider) getSchedulingConfig(configMap map[string]interface{}, prefix string) types.SchedulingConfig {
	return types.SchedulingConfig{}
}
func (p *Provider) getZeroTrustConfig(configMap map[string]interface{}, prefix string) types.ZeroTrustConfig {
	return types.ZeroTrustConfig{}
}
func (p *Provider) getBackupConfig(configMap map[string]interface{}, prefix string) types.BackupConfig {
	return types.BackupConfig{}
}
func (p *Provider) getChaosConfig(configMap map[string]interface{}, prefix string) types.ChaosConfig {
	return types.ChaosConfig{}
}
func (p *Provider) getAIConfig(configMap map[string]interface{}, prefix string) types.AIConfig {
	return types.AIConfig{}
}
func (p *Provider) getMiddlewareConfig(configMap map[string]interface{}, prefix string) types.MiddlewareConfig {
	return types.MiddlewareConfig{}
}
func (p *Provider) getFileGenConfig(configMap map[string]interface{}, prefix string) types.FileGenConfig {
	return types.FileGenConfig{}
}
func (p *Provider) getServicesConfig(configMap map[string]interface{}, prefix string) types.ServicesConfig {
	return types.ServicesConfig{}
}
func (p *Provider) getCustomConfig(configMap map[string]interface{}) map[string]interface{} {
	return p.getMap(configMap, "custom")
}
