package types

import (
	"context"
	"time"
)

// DatabaseFeature represents a database feature
type DatabaseFeature string

const (
	FeatureTransactions   DatabaseFeature = "transactions"
	FeaturePreparedStmts  DatabaseFeature = "prepared_statements"
	FeatureConnectionPool DatabaseFeature = "connection_pool"
	FeatureReadReplicas   DatabaseFeature = "read_replicas"
	FeatureClustering     DatabaseFeature = "clustering"
	FeatureSharding       DatabaseFeature = "sharding"
	FeatureFullTextSearch DatabaseFeature = "full_text_search"
	FeatureJSONSupport    DatabaseFeature = "json_support"
	FeatureGeoSpatial     DatabaseFeature = "geo_spatial"
	FeatureTimeSeries     DatabaseFeature = "time_series"
	FeatureGraphDB        DatabaseFeature = "graph_db"
	FeatureKeyValue       DatabaseFeature = "key_value"
	FeatureDocumentStore  DatabaseFeature = "document_store"
	FeatureColumnFamily   DatabaseFeature = "column_family"
	FeatureInMemory       DatabaseFeature = "in_memory"
	FeaturePersistent     DatabaseFeature = "persistent"
)

// ConnectionInfo represents database connection information
type ConnectionInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Driver   string `json:"driver"`
	Version  string `json:"version"`
}

// Transaction represents a database transaction
type Transaction interface {
	Commit() error
	Rollback() error
	Query(ctx context.Context, query string, args ...interface{}) (QueryResult, error)
	QueryRow(ctx context.Context, query string, args ...interface{}) (Row, error)
	Exec(ctx context.Context, query string, args ...interface{}) (ExecResult, error)
	Prepare(ctx context.Context, query string) (PreparedStatement, error)
}

// QueryResult represents the result of a query
type QueryResult interface {
	Close() error
	Next() bool
	Scan(dest ...interface{}) error
	Columns() ([]string, error)
	Err() error
}

// Row represents a single row from a query
type Row interface {
	Scan(dest ...interface{}) error
	Err() error
}

// ExecResult represents the result of an execution
type ExecResult interface {
	LastInsertId() (int64, error)
	RowsAffected() (int64, error)
}

// PreparedStatement represents a prepared statement
type PreparedStatement interface {
	Close() error
	Query(ctx context.Context, args ...interface{}) (QueryResult, error)
	QueryRow(ctx context.Context, args ...interface{}) (Row, error)
	Exec(ctx context.Context, args ...interface{}) (ExecResult, error)
}

// DatabaseStats represents database statistics
type DatabaseStats struct {
	ActiveConnections int                    `json:"active_connections"`
	IdleConnections   int                    `json:"idle_connections"`
	MaxConnections    int                    `json:"max_connections"`
	WaitCount         int64                  `json:"wait_count"`
	WaitDuration      time.Duration          `json:"wait_duration"`
	MaxIdleClosed     int64                  `json:"max_idle_closed"`
	MaxIdleTimeClosed int64                  `json:"max_idle_time_closed"`
	MaxLifetimeClosed int64                  `json:"max_lifetime_closed"`
	ProviderData      map[string]interface{} `json:"provider_data"`
}
