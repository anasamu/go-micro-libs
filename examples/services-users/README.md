# services-users (example)

Contoh service users menggunakan go-micro-libs berarsitektur DDD + bootstrap modular:

- Config (file provider + watcher)
- Logging (console/logrus)
- Communication HTTP provider (tanpa mux custom)
- Discovery (Consul)
- Messaging (Kafka) publish/subscribe
- Monitoring (Prometheus)
- Database (PostgreSQL) via DatabaseManager
- Rate Limit (in-memory) token bucket
- Circuit Breaker (gobreaker)
- Failover (Consul provider)

## Menjalankan

1) Set konfigurasi di `examples/services-users/config.yaml` atau environment variables:

```bash
export CONFIG_PATH=./examples/services-users/config.yaml
export CONSUL_ADDR=localhost:8500
export PROM_HOST=localhost
export SERVICE_ID=user-service-1
# Postgres
export PGHOST=localhost
export PGPORT=5432
export PGUSER=postgres
export PGPASSWORD=postgres
export PGDATABASE=users
```

2) Jalankan contoh:

```bash
go run ./examples/services-users
```

Service akan:
- Start HTTP di port dari `server.port`
- Register ke Consul
- Connect ke Kafka
- Connect ke Prometheus (mock connect)
- Connect ke PostgreSQL
- Subscribe topic Kafka (`kafka.topic`) dan handle event `user.upsert`/`user.created`
- Terapkan rate limit dan circuit breaker di endpoint Users

Hentikan dengan Ctrl+C. Service akan deregister dari Consul dan menutup koneksi.

## Catatan
- Pastikan Kafka dan Consul berjalan secara lokal atau update env/config sesuai environment.
- Anda bisa menambahkan provider lain (file logging, elasticsearch logging, jaeger, dll) sesuai kebutuhan.
- Untuk database, buat tabel:

```sql
CREATE TABLE IF NOT EXISTS users (
  id         text PRIMARY KEY,
  email      text UNIQUE NOT NULL,
  name       text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
```

- Failover: bootstrap tersedia di `internal/bootstrap/failover.go`. Daftarkan endpoint ke Consul agar failover dapat memilih endpoint sehat.
