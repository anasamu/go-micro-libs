package types

// ProviderConfig holds dynamic provider-specific settings for server-level concerns
// Kept here to separate provider concerns from library-level config structures.
type ProviderConfig struct {
	Settings map[string]interface{} `mapstructure:",remain"`
}

// ConfigurationConfig represents config library providers and options
type ConfigurationConfig struct {
	Provider string             `mapstructure:"provider"` // file, env, consul, vault
	File     FileConfigProvider `mapstructure:"file"`
	Env      EnvConfigProvider  `mapstructure:"env"`
	Consul   ConsulConfig       `mapstructure:"consul"`
	Vault    VaultConfig        `mapstructure:"vault"`
}

type FileConfigProvider struct {
	Path string `mapstructure:"path"`
	Type string `mapstructure:"type"` // yaml,json,toml,env
}

type EnvConfigProvider struct {
	Prefix string `mapstructure:"prefix"`
}

// CircuitBreakerLibConfig holds circuit breaker library configuration
type CircuitBreakerLibConfig struct {
	Provider  string              `mapstructure:"provider"`
	Gobreaker GobreakerConfig     `mapstructure:"gobreaker"`
	Custom    CustomCircuitConfig `mapstructure:"custom"`
}

type GobreakerConfig struct {
	Name                  string  `mapstructure:"name"`
	IntervalSeconds       int     `mapstructure:"interval_seconds"`
	TimeoutSeconds        int     `mapstructure:"timeout_seconds"`
	ReadyToTripFailures   int     `mapstructure:"ready_to_trip_failures"`
	ErrorPercentThreshold float64 `mapstructure:"error_percent_threshold"`
}

type CustomCircuitConfig struct {
	Params map[string]interface{} `mapstructure:",remain"`
}
