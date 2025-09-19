# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.2] - 2025-09-19

### Added
- Examples: Added new examples and expanded usage in `examples/` including `services-users`

### Fixed
- Config Types: Fixed bugs in `config/types` improving type definitions and validation

## [v1.1.1] - 2025-09-17

### Fixed
- **Memory Cache Provider**: Fixed goroutine leak in cleanup mechanism by adding proper stop channel
- **MySQL Database Provider**: Improved connection pool configuration and transaction rollback error handling
- **S3 Storage Provider**: Fixed object existence error handling with proper AWS error type checking
- **JWT Authentication Provider**: Generate secure random keys when no environment variable is set and improved error logging security
- **Redis Rate Limiter Provider**: Added graceful disconnect with timeout handling to prevent connection issues
- **Password Validation**: Strengthened password requirements (minimum 12 characters, mixed case, numbers, special characters)
- **File Cleanup**: Removed unnecessary build files (event/Makefile, event/tidy.sh)

### Added
- **Comprehensive Documentation**: Added detailed README files for all 23 modules with examples and usage guides
- **Enhanced Password Validation**: Added `ValidatePasswordWithDetails` function for detailed error messages
- **Improved Error Handling**: Better error handling across all providers with proper context and timeouts

### Enhanced
- **Connection Management**: Improved connection lifecycle management across database and cache providers
- **Security Practices**: Enhanced security with stronger password validation and secure key generation
- **Transaction Handling**: More robust transaction handling with proper rollback error management
- **Documentation Quality**: Significantly improved documentation coverage and examples

## [v1.1.0] - 2025-09-15

### Added
- **New Modules**:
  - API Library - Unified interface for third-party API integrations (HTTP, GraphQL, gRPC, WebSocket)
  - Email Library - Email services with SMTP, IMAP, and POP3 support
  - Edge Computing Library - Edge deployment support for Cloudflare Workers, Fastly, Akamai, and WASM
  - ZeroTrust Library - Zero Trust security implementation with SPIFFE/SPIRE, Istio, and mTLS

- **New Storage Providers**:
  - Cloudflare R2 - Object storage with S3-compatible API

- **New Authentication Providers**:
  - Auth0 - Enterprise identity and access management
  - Keycloak - Open source identity and access management
  - Okta - Cloud-based identity management

- **New Database Providers**:
  - Cassandra - Distributed NoSQL database
  - CockroachDB - Distributed SQL database
  - Elasticsearch - Search and analytics engine
  - InfluxDB - Time series database
  - MariaDB - MySQL-compatible database

### Enhanced
- Improved API integration capabilities with dynamic headers and authentication
- Edge computing support with WASM compilation for lightweight execution
- Zero Trust security implementation with service identity management
- Email services integration with multiple protocols
- Enhanced documentation with comprehensive examples
- Optimized provider implementations for better performance

### Changed
- Updated module structure for better organization
- Enhanced error handling across all providers
- Improved configuration management

### Fixed
- Various bug fixes and stability improvements
- Enhanced connection management
- Improved error messages and logging

## [v1.0.0] - 2025-08-04

### Added
- Initial release of microservices library
- Support for 20+ microservices modules
- 50+ provider implementations
- Comprehensive documentation
- Full test coverage

### Modules Included
- AI Services (OpenAI, Anthropic, XAI, DeepSeek, Google)
- Authentication & Authorization (JWT, OAuth2, 2FA, RBAC, ABAC, ACL)
- Database (PostgreSQL, MySQL, MongoDB, Redis, SQLite, etc.)
- Cache (Redis, Memcache, Memory)
- Storage (S3, GCS, Azure, MinIO)
- Messaging (Kafka, NATS, RabbitMQ, SQS)
- Monitoring (Prometheus, Jaeger, Elasticsearch)
- Payment (Stripe, PayPal, Midtrans, Xendit)
- And many more...

[v1.1.1]: https://github.com/anasamu/go-micro-libs/releases/tag/v1.1.1
[v1.1.0]: https://github.com/anasamu/go-micro-libs/releases/tag/v1.1.0
[v1.0.0]: https://github.com/anasamu/go-micro-libs/releases/tag/v1.0.0
