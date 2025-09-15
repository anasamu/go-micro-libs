package migrations

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/database"
	"github.com/anasamu/go-micro-libs/database/types"
	"github.com/sirupsen/logrus"
)

// Migration represents a database migration
type Migration struct {
	Version     string     `json:"version"`
	Description string     `json:"description"`
	UpSQL       string     `json:"up_sql"`
	DownSQL     string     `json:"down_sql"`
	CreatedAt   time.Time  `json:"created_at"`
	AppliedAt   *time.Time `json:"applied_at,omitempty"`
	Checksum    string     `json:"checksum"`
}

// MigrationManager manages database migrations
type MigrationManager struct {
	provider database.DatabaseProvider
	logger   *logrus.Logger
	table    string
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(provider database.DatabaseProvider, logger *logrus.Logger) *MigrationManager {
	return &MigrationManager{
		provider: provider,
		logger:   logger,
		table:    "schema_migrations",
	}
}

// validateTableName validates and sanitizes table name to prevent SQL injection
func validateTableName(tableName string) (string, error) {
	if tableName == "" {
		return "", fmt.Errorf("table name cannot be empty")
	}

	// Remove any whitespace
	tableName = strings.TrimSpace(tableName)

	// Check for dangerous patterns
	dangerousPatterns := []string{
		"DROP", "DELETE", "TRUNCATE", "ALTER", "CREATE", "INSERT", "UPDATE",
		"SELECT", "UNION", "EXEC", "EXECUTE", "SCRIPT", "--", "/*", "*/",
		"<", ">", "'", "\"", ";", "\\", "/", "*", "?", "[", "]", "{", "}",
	}

	upperTableName := strings.ToUpper(tableName)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(upperTableName, pattern) {
			return "", fmt.Errorf("table name contains dangerous pattern: %s", pattern)
		}
	}

	// Validate table name format (alphanumeric and underscore only, must start with letter or underscore)
	matched, err := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, tableName)
	if err != nil {
		return "", fmt.Errorf("failed to validate table name: %w", err)
	}

	if !matched {
		return "", fmt.Errorf("invalid table name format: %s (must start with letter or underscore, contain only alphanumeric characters and underscores)", tableName)
	}

	// Check length limits
	if len(tableName) > 63 {
		return "", fmt.Errorf("table name too long: %s (maximum 63 characters)", tableName)
	}

	if len(tableName) < 2 {
		return "", fmt.Errorf("table name too short: %s (minimum 2 characters)", tableName)
	}

	return tableName, nil
}

// sanitizeTableName sanitizes table name by removing dangerous characters
func sanitizeTableName(tableName string) string {
	// Remove any non-alphanumeric characters except underscore
	sanitized := regexp.MustCompile(`[^a-zA-Z0-9_]`).ReplaceAllString(tableName, "")

	// Ensure it starts with letter or underscore
	if len(sanitized) > 0 && !regexp.MustCompile(`^[a-zA-Z_]`).MatchString(sanitized) {
		sanitized = "t_" + sanitized
	}

	// Ensure minimum length
	if len(sanitized) < 2 {
		sanitized = "table_" + sanitized
	}

	// Truncate if too long
	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
	}

	return sanitized
}

// buildSafeQuery builds a safe SQL query with validated table name
func (mm *MigrationManager) buildSafeQuery(queryTemplate string) (string, error) {
	// Validate table name
	if _, err := validateTableName(mm.table); err != nil {
		return "", fmt.Errorf("invalid table name for query: %w", err)
	}

	// Build query with validated table name
	return fmt.Sprintf(queryTemplate, mm.table), nil
}

// SetTableName sets the migration table name with validation
func (mm *MigrationManager) SetTableName(table string) error {
	validatedTable, err := validateTableName(table)
	if err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	mm.table = validatedTable
	return nil
}

// Initialize creates the migration table if it doesn't exist
func (mm *MigrationManager) Initialize(ctx context.Context) error {
	// Validate table name before proceeding
	if _, err := validateTableName(mm.table); err != nil {
		return fmt.Errorf("invalid table name for initialization: %w", err)
	}

	// Create migration table based on provider type
	var createTableSQL string

	switch mm.provider.GetName() {
	case "postgresql", "mysql", "mariadb", "cockroachdb":
		createTableSQL = fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				version VARCHAR(255) PRIMARY KEY,
				description TEXT,
				up_sql TEXT,
				down_sql TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				applied_at TIMESTAMP,
				checksum VARCHAR(255)
			)`, mm.table)
	case "sqlite":
		createTableSQL = fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				version TEXT PRIMARY KEY,
				description TEXT,
				up_sql TEXT,
				down_sql TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				applied_at DATETIME,
				checksum TEXT
			)`, mm.table)
	case "cassandra":
		createTableSQL = fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				version TEXT PRIMARY KEY,
				description TEXT,
				up_sql TEXT,
				down_sql TEXT,
				created_at TIMESTAMP,
				applied_at TIMESTAMP,
				checksum TEXT
			)`, mm.table)
	case "mongodb":
		// MongoDB doesn't need a table, we'll use a collection
		mm.logger.Info("MongoDB migration table initialization skipped")
		return nil
	case "redis":
		// Redis doesn't need a table, we'll use keys
		mm.logger.Info("Redis migration table initialization skipped")
		return nil
	case "influxdb":
		// InfluxDB doesn't need a table, we'll use a measurement
		mm.logger.Info("InfluxDB migration table initialization skipped")
		return nil
	default:
		return fmt.Errorf("unsupported provider for migrations: %s", mm.provider.GetName())
	}

	_, err := mm.provider.Exec(ctx, createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	mm.logger.Info("Migration table initialized successfully")
	return nil
}

// GetAppliedMigrations returns a list of applied migrations
func (mm *MigrationManager) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	var migrations []Migration

	switch mm.provider.GetName() {
	case "postgresql", "mysql", "mariadb", "cockroachdb", "sqlite":
		query, err := mm.buildSafeQuery("SELECT version, description, up_sql, down_sql, created_at, applied_at, checksum FROM %s ORDER BY version")
		if err != nil {
			return nil, err
		}
		rows, err := mm.provider.Query(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to query applied migrations: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var migration Migration
			var appliedAt *time.Time

			err := rows.Scan(
				&migration.Version,
				&migration.Description,
				&migration.UpSQL,
				&migration.DownSQL,
				&migration.CreatedAt,
				&appliedAt,
				&migration.Checksum,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan migration: %w", err)
			}

			migration.AppliedAt = appliedAt
			migrations = append(migrations, migration)
		}

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating migrations: %w", err)
		}

	case "cassandra":
		query, err := mm.buildSafeQuery("SELECT version, description, up_sql, down_sql, created_at, applied_at, checksum FROM %s")
		if err != nil {
			return nil, err
		}
		rows, err := mm.provider.Query(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to query applied migrations: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var migration Migration
			var appliedAt *time.Time

			err := rows.Scan(
				&migration.Version,
				&migration.Description,
				&migration.UpSQL,
				&migration.DownSQL,
				&migration.CreatedAt,
				&appliedAt,
				&migration.Checksum,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan migration: %w", err)
			}

			migration.AppliedAt = appliedAt
			migrations = append(migrations, migration)
		}

	case "mongodb", "redis", "influxdb":
		// For NoSQL databases, we'll return empty list for now
		// In a real implementation, you'd query the appropriate storage
		mm.logger.Info("Applied migrations query not implemented for NoSQL providers")
	}

	return migrations, nil
}

// ApplyMigration applies a migration
func (mm *MigrationManager) ApplyMigration(ctx context.Context, migration Migration) error {
	// Check if migration is already applied
	applied, err := mm.IsMigrationApplied(ctx, migration.Version)
	if err != nil {
		return fmt.Errorf("failed to check if migration is applied: %w", err)
	}

	if applied {
		mm.logger.WithField("version", migration.Version).Info("Migration already applied, skipping")
		return nil
	}

	// Execute the migration
	err = mm.provider.WithTransaction(ctx, func(tx types.Transaction) error {
		// Execute the up SQL
		if migration.UpSQL != "" {
			_, err := tx.Exec(ctx, migration.UpSQL)
			if err != nil {
				return fmt.Errorf("failed to execute up migration: %w", err)
			}
		}

		// Record the migration
		return mm.recordMigration(ctx, tx, migration, true)
	})

	if err != nil {
		return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
	}

	mm.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Info("Migration applied successfully")

	return nil
}

// RollbackMigration rolls back a migration
func (mm *MigrationManager) RollbackMigration(ctx context.Context, migration Migration) error {
	// Check if migration is applied
	applied, err := mm.IsMigrationApplied(ctx, migration.Version)
	if err != nil {
		return fmt.Errorf("failed to check if migration is applied: %w", err)
	}

	if !applied {
		mm.logger.WithField("version", migration.Version).Info("Migration not applied, skipping rollback")
		return nil
	}

	// Execute the rollback
	err = mm.provider.WithTransaction(ctx, func(tx types.Transaction) error {
		// Execute the down SQL
		if migration.DownSQL != "" {
			_, err := tx.Exec(ctx, migration.DownSQL)
			if err != nil {
				return fmt.Errorf("failed to execute down migration: %w", err)
			}
		}

		// Remove the migration record
		return mm.removeMigration(ctx, tx, migration.Version)
	})

	if err != nil {
		return fmt.Errorf("failed to rollback migration %s: %w", migration.Version, err)
	}

	mm.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Info("Migration rolled back successfully")

	return nil
}

// IsMigrationApplied checks if a migration is already applied
func (mm *MigrationManager) IsMigrationApplied(ctx context.Context, version string) (bool, error) {
	switch mm.provider.GetName() {
	case "postgresql", "mysql", "mariadb", "cockroachdb", "sqlite":
		query, err := mm.buildSafeQuery("SELECT COUNT(*) FROM %s WHERE version = ?")
		if err != nil {
			return false, err
		}
		row, err := mm.provider.QueryRow(ctx, query, version)
		if err != nil {
			return false, fmt.Errorf("failed to check migration status: %w", err)
		}

		var count int
		if err := row.Scan(&count); err != nil {
			return false, fmt.Errorf("failed to scan migration count: %w", err)
		}

		return count > 0, nil

	case "cassandra":
		query, err := mm.buildSafeQuery("SELECT COUNT(*) FROM %s WHERE version = ?")
		if err != nil {
			return false, err
		}
		row, err := mm.provider.QueryRow(ctx, query, version)
		if err != nil {
			return false, fmt.Errorf("failed to check migration status: %w", err)
		}

		var count int
		if err := row.Scan(&count); err != nil {
			return false, fmt.Errorf("failed to scan migration count: %w", err)
		}

		return count > 0, nil

	case "mongodb", "redis", "influxdb":
		// For NoSQL databases, we'll return false for now
		// In a real implementation, you'd check the appropriate storage
		mm.logger.Info("Migration status check not implemented for NoSQL providers")
		return false, nil

	default:
		return false, fmt.Errorf("unsupported provider for migration status check: %s", mm.provider.GetName())
	}
}

// recordMigration records a migration in the database
func (mm *MigrationManager) recordMigration(ctx context.Context, tx types.Transaction, migration Migration, applied bool) error {
	now := time.Now()
	migration.AppliedAt = &now

	switch mm.provider.GetName() {
	case "postgresql", "mysql", "mariadb", "cockroachdb", "sqlite":
		query, err := mm.buildSafeQuery(`
			INSERT INTO %s (version, description, up_sql, down_sql, created_at, applied_at, checksum)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, query,
			migration.Version,
			migration.Description,
			migration.UpSQL,
			migration.DownSQL,
			migration.CreatedAt,
			migration.AppliedAt,
			migration.Checksum,
		)
		return err

	case "cassandra":
		query, err := mm.buildSafeQuery(`
			INSERT INTO %s (version, description, up_sql, down_sql, created_at, applied_at, checksum)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, query,
			migration.Version,
			migration.Description,
			migration.UpSQL,
			migration.DownSQL,
			migration.CreatedAt,
			migration.AppliedAt,
			migration.Checksum,
		)
		return err

	case "mongodb", "redis", "influxdb":
		// For NoSQL databases, we'll skip recording for now
		// In a real implementation, you'd store in the appropriate format
		mm.logger.Info("Migration recording not implemented for NoSQL providers")
		return nil

	default:
		return fmt.Errorf("unsupported provider for migration recording: %s", mm.provider.GetName())
	}
}

// removeMigration removes a migration record from the database
func (mm *MigrationManager) removeMigration(ctx context.Context, tx types.Transaction, version string) error {
	switch mm.provider.GetName() {
	case "postgresql", "mysql", "mariadb", "cockroachdb", "sqlite":
		query, err := mm.buildSafeQuery("DELETE FROM %s WHERE version = ?")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, query, version)
		return err

	case "cassandra":
		query, err := mm.buildSafeQuery("DELETE FROM %s WHERE version = ?")
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, query, version)
		return err

	case "mongodb", "redis", "influxdb":
		// For NoSQL databases, we'll skip removal for now
		// In a real implementation, you'd remove from the appropriate storage
		mm.logger.Info("Migration removal not implemented for NoSQL providers")
		return nil

	default:
		return fmt.Errorf("unsupported provider for migration removal: %s", mm.provider.GetName())
	}
}

// GetMigrationStatus returns the status of all migrations
func (mm *MigrationManager) GetMigrationStatus(ctx context.Context, availableMigrations []Migration) ([]MigrationStatus, error) {
	appliedMigrations, err := mm.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedMap := make(map[string]Migration)
	for _, migration := range appliedMigrations {
		appliedMap[migration.Version] = migration
	}

	var statuses []MigrationStatus
	for _, migration := range availableMigrations {
		status := MigrationStatus{
			Migration: migration,
			Applied:   false,
		}

		if applied, exists := appliedMap[migration.Version]; exists {
			status.Applied = true
			status.AppliedAt = applied.AppliedAt
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	Migration Migration  `json:"migration"`
	Applied   bool       `json:"applied"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}
