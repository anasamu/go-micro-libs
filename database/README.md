# Database Library

The Database library provides a unified interface for database operations across multiple providers including PostgreSQL, MySQL, MongoDB, Redis, and more. It offers comprehensive database management with connection pooling, transaction support, prepared statements, and advanced query capabilities.

## Features

- **Multi-Provider Support**: PostgreSQL, MySQL, MongoDB, Redis, SQLite, and more
- **Connection Management**: Robust connection pooling and management
- **Transaction Support**: Full ACID transaction support with rollback capabilities
- **Prepared Statements**: Optimized prepared statement support
- **Query Operations**: Comprehensive query, queryRow, and exec operations
- **Health Monitoring**: Database health checks and connection monitoring
- **Statistics**: Detailed database statistics and performance metrics
- **Retry Logic**: Built-in retry mechanisms for resilience
- **Migration Support**: Database migration and schema management

## Supported Providers

- **PostgreSQL**: Full-featured PostgreSQL support
- **MySQL**: MySQL and MariaDB support
- **MongoDB**: Document database support
- **Redis**: Key-value store support
- **SQLite**: Embedded database support
- **Cassandra**: NoSQL database support
- **Elasticsearch**: Search and analytics engine
- **InfluxDB**: Time-series database
- **CockroachDB**: Distributed SQL database

## Installation

```bash
go get github.com/anasamu/go-micro-libs/database
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/database"
    "github.com/anasamu/go-micro-libs/database/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create database manager with default config
    config := database.DefaultManagerConfig()
    manager := database.NewDatabaseManager(config, logger)

    // Register PostgreSQL provider (example)
    // postgresProvider := postgresql.NewPostgreSQLProvider("postgres://user:pass@localhost/db")
    // manager.RegisterProvider(postgresProvider)

    // Connect to database
    ctx := context.Background()
    err := manager.Connect(ctx, "postgresql")
    if err != nil {
        log.Fatal(err)
    }

    // Execute a query
    result, err := manager.Query(ctx, "postgresql", "SELECT * FROM users WHERE active = $1", true)
    if err != nil {
        log.Fatal(err)
    }
    defer result.Close()

    // Process results
    for result.Next() {
        var id int
        var name string
        var email string
        
        err := result.Scan(&id, &name, &email)
        if err != nil {
            log.Fatal(err)
        }
        
        fmt.Printf("User: %d, %s, %s\n", id, name, email)
    }
}
```

## API Reference

### DatabaseManager

The main manager for handling database operations across multiple providers.

#### Methods

##### `NewDatabaseManager(config *ManagerConfig, logger *logrus.Logger) *DatabaseManager`
Creates a new database manager with the given configuration and logger.

##### `RegisterProvider(provider DatabaseProvider) error`
Registers a new database provider.

**Parameters:**
- `provider`: The database provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (DatabaseProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (DatabaseProvider, error)`
Returns the default database provider.

##### `Connect(ctx context.Context, providerName string) error`
Connects to a database using the specified provider.

##### `Disconnect(ctx context.Context, providerName string) error`
Disconnects from a database using the specified provider.

##### `Ping(ctx context.Context, providerName string) error`
Pings a database to check connectivity.

##### `Query(ctx context.Context, providerName, query string, args ...interface{}) (types.QueryResult, error)`
Executes a query that returns multiple rows.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `query`: SQL query string
- `args`: Query parameters

**Returns:**
- `types.QueryResult`: Query result with rows
- `error`: Any error that occurred

##### `QueryRow(ctx context.Context, providerName, query string, args ...interface{}) (types.Row, error)`
Executes a query that returns a single row.

##### `Exec(ctx context.Context, providerName, query string, args ...interface{}) (types.ExecResult, error)`
Executes a query without returning rows (INSERT, UPDATE, DELETE).

##### `BeginTransaction(ctx context.Context, providerName string) (types.Transaction, error)`
Begins a new transaction.

##### `WithTransaction(ctx context.Context, providerName string, fn func(types.Transaction) error) error`
Executes a function within a transaction with automatic commit/rollback.

##### `Prepare(ctx context.Context, providerName, query string) (types.PreparedStatement, error)`
Prepares a statement for repeated execution.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*types.DatabaseStats, error)`
Gets statistics from a specific provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.DatabaseFeature, *types.ConnectionInfo, error)`
Returns capabilities of a specific provider.

##### `Close() error`
Closes all database connections.

### Types

#### ManagerConfig
Configuration for the database manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxConnections  int               `json:"max_connections"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### QueryResult
Represents the result of a query.

```go
type QueryResult interface {
    Close() error
    Next() bool
    Scan(dest ...interface{}) error
    Columns() ([]string, error)
    Err() error
}
```

#### Row
Represents a single row from a query.

```go
type Row interface {
    Scan(dest ...interface{}) error
    Err() error
}
```

#### ExecResult
Represents the result of an execution.

```go
type ExecResult interface {
    LastInsertId() (int64, error)
    RowsAffected() (int64, error)
}
```

#### Transaction
Represents a database transaction.

```go
type Transaction interface {
    Commit() error
    Rollback() error
    Query(ctx context.Context, query string, args ...interface{}) (QueryResult, error)
    QueryRow(ctx context.Context, query string, args ...interface{}) (Row, error)
    Exec(ctx context.Context, query string, args ...interface{}) (ExecResult, error)
    Prepare(ctx context.Context, query string) (PreparedStatement, error)
}
```

#### PreparedStatement
Represents a prepared statement.

```go
type PreparedStatement interface {
    Close() error
    Query(ctx context.Context, args ...interface{}) (QueryResult, error)
    QueryRow(ctx context.Context, args ...interface{}) (Row, error)
    Exec(ctx context.Context, args ...interface{}) (ExecResult, error)
}
```

#### DatabaseStats
Database statistics.

```go
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
```

#### ConnectionInfo
Database connection information.

```go
type ConnectionInfo struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Database string `json:"database"`
    User     string `json:"user"`
    Driver   string `json:"driver"`
    Version  string `json:"version"`
}
```

## Advanced Usage

### Basic Query Operations

```go
// Query multiple rows
result, err := manager.Query(ctx, "postgresql", 
    "SELECT id, name, email FROM users WHERE active = $1", true)
if err != nil {
    log.Fatal(err)
}
defer result.Close()

for result.Next() {
    var user User
    err := result.Scan(&user.ID, &user.Name, &user.Email)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("User: %+v\n", user)
}

// Query single row
row, err := manager.QueryRow(ctx, "postgresql", 
    "SELECT id, name, email FROM users WHERE id = $1", userID)
if err != nil {
    log.Fatal(err)
}

var user User
err = row.Scan(&user.ID, &user.Name, &user.Email)
if err != nil {
    log.Fatal(err)
}

// Execute query (INSERT, UPDATE, DELETE)
result, err := manager.Exec(ctx, "postgresql", 
    "INSERT INTO users (name, email) VALUES ($1, $2)", "John Doe", "john@example.com")
if err != nil {
    log.Fatal(err)
}

lastID, _ := result.LastInsertId()
rowsAffected, _ := result.RowsAffected()
fmt.Printf("Inserted user with ID: %d, Rows affected: %d\n", lastID, rowsAffected)
```

### Transaction Management

```go
// Using WithTransaction (recommended)
err := manager.WithTransaction(ctx, "postgresql", func(tx types.Transaction) error {
    // Insert user
    _, err := tx.Exec(ctx, "INSERT INTO users (name, email) VALUES ($1, $2)", 
        "John Doe", "john@example.com")
    if err != nil {
        return err // Transaction will be rolled back
    }
    
    // Insert user profile
    _, err = tx.Exec(ctx, "INSERT INTO user_profiles (user_id, bio) VALUES ($1, $2)", 
        userID, "Software developer")
    if err != nil {
        return err // Transaction will be rolled back
    }
    
    return nil // Transaction will be committed
})

// Manual transaction management
tx, err := manager.BeginTransaction(ctx, "postgresql")
if err != nil {
    log.Fatal(err)
}

defer func() {
    if err != nil {
        tx.Rollback()
    } else {
        tx.Commit()
    }
}()

_, err = tx.Exec(ctx, "INSERT INTO users (name, email) VALUES ($1, $2)", 
    "John Doe", "john@example.com")
if err != nil {
    return err
}

_, err = tx.Exec(ctx, "INSERT INTO user_profiles (user_id, bio) VALUES ($1, $2)", 
    userID, "Software developer")
if err != nil {
    return err
}
```

### Prepared Statements

```go
// Prepare statement for repeated use
stmt, err := manager.Prepare(ctx, "postgresql", 
    "INSERT INTO users (name, email) VALUES ($1, $2)")
if err != nil {
    log.Fatal(err)
}
defer stmt.Close()

// Execute prepared statement multiple times
users := []User{
    {Name: "John Doe", Email: "john@example.com"},
    {Name: "Jane Smith", Email: "jane@example.com"},
    {Name: "Bob Johnson", Email: "bob@example.com"},
}

for _, user := range users {
    _, err := stmt.Exec(ctx, user.Name, user.Email)
    if err != nil {
        log.Printf("Failed to insert user %s: %v", user.Name, err)
    }
}
```

### Complex Queries with Joins

```go
// Complex query with joins
query := `
    SELECT u.id, u.name, u.email, p.bio, p.avatar_url
    FROM users u
    LEFT JOIN user_profiles p ON u.id = p.user_id
    WHERE u.active = $1 AND u.created_at > $2
    ORDER BY u.created_at DESC
    LIMIT $3
`

result, err := manager.Query(ctx, "postgresql", query, true, 
    time.Now().AddDate(0, -1, 0), 100)
if err != nil {
    log.Fatal(err)
}
defer result.Close()

for result.Next() {
    var user UserWithProfile
    var bio, avatarURL sql.NullString
    
    err := result.Scan(&user.ID, &user.Name, &user.Email, &bio, &avatarURL)
    if err != nil {
        log.Fatal(err)
    }
    
    if bio.Valid {
        user.Bio = bio.String
    }
    if avatarURL.Valid {
        user.AvatarURL = avatarURL.String
    }
    
    fmt.Printf("User: %+v\n", user)
}
```

### Pagination

```go
func getUsersPaginated(manager *database.DatabaseManager, page, limit int) ([]User, error) {
    ctx := context.Background()
    offset := (page - 1) * limit
    
    query := `
        SELECT id, name, email, created_at
        FROM users
        WHERE active = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `
    
    result, err := manager.Query(ctx, "postgresql", query, true, limit, offset)
    if err != nil {
        return nil, err
    }
    defer result.Close()
    
    var users []User
    for result.Next() {
        var user User
        err := result.Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }
    
    return users, nil
}
```

### Database Statistics

```go
// Get database statistics
stats, err := manager.GetStats(ctx, "postgresql")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Active connections: %d\n", stats.ActiveConnections)
fmt.Printf("Idle connections: %d\n", stats.IdleConnections)
fmt.Printf("Max connections: %d\n", stats.MaxConnections)
fmt.Printf("Wait count: %d\n", stats.WaitCount)
fmt.Printf("Wait duration: %v\n", stats.WaitDuration)
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

// Ping specific provider
err := manager.Ping(ctx, "postgresql")
if err != nil {
    fmt.Printf("PostgreSQL is not responding: %v\n", err)
}
```

### Connection Management

```go
// Connect to multiple providers
providers := []string{"postgresql", "mysql", "mongodb"}

for _, provider := range providers {
    err := manager.Connect(ctx, provider)
    if err != nil {
        log.Printf("Failed to connect to %s: %v", provider, err)
    } else {
        log.Printf("Connected to %s successfully", provider)
    }
}

// Check connected providers
connectedProviders := manager.GetConnectedProviders()
fmt.Printf("Connected providers: %v\n", connectedProviders)

// Check if specific provider is connected
isConnected := manager.IsProviderConnected("postgresql")
fmt.Printf("PostgreSQL connected: %v\n", isConnected)
```

### Error Handling

```go
result, err := manager.Query(ctx, "postgresql", "SELECT * FROM users")
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Database connection error: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Query timeout: %v", err)
    case strings.Contains(err.Error(), "syntax"):
        log.Printf("SQL syntax error: %v", err)
    case strings.Contains(err.Error(), "permission"):
        log.Printf("Permission denied: %v", err)
    default:
        log.Printf("Database error: %v", err)
    }
    return
}
defer result.Close()

// Handle query execution errors
for result.Next() {
    var user User
    err := result.Scan(&user.ID, &user.Name, &user.Email)
    if err != nil {
        log.Printf("Error scanning row: %v", err)
        continue
    }
    // Process user
}
```

### Multi-Database Operations

```go
// Write to PostgreSQL, read from MySQL
func syncData(manager *database.DatabaseManager) error {
    ctx := context.Background()
    
    // Read from MySQL
    result, err := manager.Query(ctx, "mysql", "SELECT * FROM source_table")
    if err != nil {
        return err
    }
    defer result.Close()
    
    // Write to PostgreSQL in transaction
    return manager.WithTransaction(ctx, "postgresql", func(tx types.Transaction) error {
        for result.Next() {
            var data DataRow
            err := result.Scan(&data.ID, &data.Name, &data.Value)
            if err != nil {
                return err
            }
            
            // Insert into PostgreSQL
            _, err = tx.Exec(ctx, "INSERT INTO target_table (id, name, value) VALUES ($1, $2, $3)",
                data.ID, data.Name, data.Value)
            if err != nil {
                return err
            }
        }
        return nil
    })
}
```

## Best Practices

1. **Connection Management**: Use connection pooling and proper connection lifecycle management
2. **Transaction Usage**: Use transactions for data consistency and atomicity
3. **Prepared Statements**: Use prepared statements for repeated queries
4. **Error Handling**: Implement comprehensive error handling and logging
5. **Query Optimization**: Optimize queries for performance and resource usage
6. **Security**: Use parameterized queries to prevent SQL injection
7. **Monitoring**: Monitor database performance and connection health
8. **Resource Cleanup**: Always close connections, transactions, and prepared statements
9. **Timeout Management**: Set appropriate timeouts for database operations
10. **Retry Logic**: Implement retry logic for transient failures

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
