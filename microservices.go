// Package microservices provides a comprehensive library for microservices development
// with support for AI, Authentication, Storage, Database, Cache, Messaging, and more.
//
// This package provides a unified interface for all microservices components,
// allowing you to import everything from a single module:
//
//	import "github.com/anasamu/go-micro-libs"
//
// Version: v1.0.0
package microservices

// Re-export main services for unified access
import (
	// AI Services
	"github.com/anasamu/go-micro-libs/ai"

	// API Services
	"github.com/anasamu/go-micro-libs/api"

	// Authentication Services
	"github.com/anasamu/go-micro-libs/auth"

	// Backup Services
	"github.com/anasamu/go-micro-libs/backup"

	// Cache Services
	"github.com/anasamu/go-micro-libs/cache"

	// Chaos Engineering
	"github.com/anasamu/go-micro-libs/chaos"

	// Circuit Breaker
	"github.com/anasamu/go-micro-libs/circuitbreaker"

	// Communication
	"github.com/anasamu/go-micro-libs/communication"

	// Configuration
	"github.com/anasamu/go-micro-libs/config"

	// Database Services
	"github.com/anasamu/go-micro-libs/database"

	// Discovery Services
	"github.com/anasamu/go-micro-libs/discovery"

	// Email Services
	"github.com/anasamu/go-micro-libs/email"

	// Event Sourcing
	"github.com/anasamu/go-micro-libs/event"

	// File Generation
	"github.com/anasamu/go-micro-libs/filegen"

	// Failover
	"github.com/anasamu/go-micro-libs/failover"

	// Logging
	"github.com/anasamu/go-micro-libs/logging"

	// Messaging Services
	"github.com/anasamu/go-micro-libs/messaging"

	// Middleware
	"github.com/anasamu/go-micro-libs/middleware"

	// Monitoring
	"github.com/anasamu/go-micro-libs/monitoring"

	// Payment
	"github.com/anasamu/go-micro-libs/payment"

	// Rate Limiting
	"github.com/anasamu/go-micro-libs/ratelimit"

	// Scheduling
	"github.com/anasamu/go-micro-libs/scheduling"

	// Storage Services
	"github.com/anasamu/go-micro-libs/storage"

	// Utils
	"github.com/anasamu/go-micro-libs/utils"
)

// AI Services
type AIManager = ai.AIManager

// API Services
type APIManager = api.APIManager

// Authentication Services
type AuthManager = auth.AuthManager

// Backup Services
type BackupManager = backup.BackupManager

// Cache Services
type CacheManager = cache.CacheManager

// Chaos Engineering
type ChaosManager = chaos.Manager

// Circuit Breaker
type CircuitBreakerManager = circuitbreaker.CircuitBreakerManager

// Communication
type CommunicationManager = communication.CommunicationManager

// Configuration
type ConfigManager = config.Manager

// Database Services
type DatabaseManager = database.DatabaseManager

// Discovery Services
type DiscoveryManager = discovery.DiscoveryManager

// Email Services
type EmailManager = email.EmailManager

// Event Sourcing
type EventManager = event.EventSourcingManager

// File Generation
type FileGenManager = filegen.Manager

// Failover
type FailoverManager = failover.FailoverManager

// Logging
type LoggingManager = logging.LoggingManager

// Messaging Services
type MessagingManager = messaging.MessagingManager

// Middleware
type MiddlewareManager = middleware.MiddlewareManager

// Monitoring
type MonitoringManager = monitoring.MonitoringManager

// Payment
type PaymentManager = payment.PaymentManager

// Rate Limiting
type RateLimitManager = ratelimit.RateLimitManager

// Scheduling
type SchedulingManager = scheduling.SchedulingManager

// Storage Services
type StorageManager = storage.StorageManager

// Manager Constructor Functions
var NewAIManager = ai.NewAIManager
var NewAPIManager = api.NewAPIManager
var NewAuthManager = auth.NewAuthManager
var NewBackupManager = backup.NewBackupManager
var NewCacheManager = cache.NewCacheManager
var NewChaosManager = chaos.NewManager
var NewCircuitBreakerManager = circuitbreaker.NewCircuitBreakerManager
var NewCommunicationManager = communication.NewCommunicationManager
var NewConfigManager = config.NewManager
var NewDatabaseManager = database.NewDatabaseManager
var NewDiscoveryManager = discovery.NewDiscoveryManager
var NewEmailManager = email.NewEmailManager
var NewEventManager = event.NewEventSourcingManager
var NewFileGenManager = filegen.NewManager
var NewFailoverManager = failover.NewFailoverManager
var NewLoggingManager = logging.NewLoggingManager
var NewMessagingManager = messaging.NewMessagingManager
var NewMiddlewareManager = middleware.NewMiddlewareManager
var NewMonitoringManager = monitoring.NewMonitoringManager
var NewPaymentManager = payment.NewPaymentManager
var NewRateLimitManager = ratelimit.NewRateLimitManager
var NewSchedulingManager = scheduling.NewSchedulingManager
var NewStorageManager = storage.NewStorageManager

// Configuration Functions (only for services that have them)
var DefaultAPIManagerConfig = api.DefaultManagerConfig
var DefaultAuthManagerConfig = auth.DefaultManagerConfig
var DefaultStorageManagerConfig = storage.DefaultManagerConfig
var DefaultDatabaseManagerConfig = database.DefaultManagerConfig
var DefaultEmailManagerConfig = email.DefaultManagerConfig
var DefaultMessagingManagerConfig = messaging.DefaultManagerConfig

// Utility Functions
var GenerateUUID = utils.GenerateUUID
var GenerateUUIDString = utils.GenerateUUIDString
var HashPassword = utils.HashPassword
var VerifyPassword = utils.VerifyPassword
var GenerateHash = utils.GenerateHash
var IsValidEmail = utils.IsValidEmail
var IsValidPhone = utils.IsValidPhone
var IsValidURL = utils.IsValidURL
var IsValidUUID = utils.IsValidUUID
var IsValidPassword = utils.IsValidPassword
var IsEmpty = utils.IsEmpty
var IsNotEmpty = utils.IsNotEmpty
var Now = utils.Now
var NowUTC = utils.NowUTC
