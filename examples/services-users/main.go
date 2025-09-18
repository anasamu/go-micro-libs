package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	micro "github.com/anasamu/go-micro-libs"
	cfgtypes "github.com/anasamu/go-micro-libs/config/types"
	discconsul "github.com/anasamu/go-micro-libs/discovery/providers/consul"
	disctypes "github.com/anasamu/go-micro-libs/discovery/types"
	app "github.com/anasamu/go-micro-libs/examples/services-users/internal/application"
	"github.com/anasamu/go-micro-libs/examples/services-users/internal/bootstrap"
	"github.com/anasamu/go-micro-libs/examples/services-users/internal/infrastructure"
	uihttp "github.com/anasamu/go-micro-libs/examples/services-users/internal/interfaces/http"
	msgt "github.com/anasamu/go-micro-libs/messaging"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// trap signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// 1) Load configuration via bootstrap
	configPath := env("CONFIG_PATH", "./examples/services-users/config.yaml")
	cfgMgr, cfg, err := bootstrap.LoadConfig(configPath)
	must(err)

	// 2) Logging via bootstrap
	lb := bootstrap.InitLogging(orDefault(cfg.Server.ServiceName, "user-service"), cfg.Server.Version, cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output, cfg.Logging.Index)
	core := lb.Core
	logMgr := lb.LogMgr

	// 3) HTTP via bootstrap
	commMgr, httpProv := bootstrap.InitHTTP(core,
		orDefault(cfg.Server.Host, "0.0.0.0"),
		toInt(orDefault(cfg.Server.Port, "8080")),
		cfg.Server.ReadTimeout,
		cfg.Server.WriteTimeout,
		cfg.Server.IdleTimeout,
	)

	// 5) Discovery (Consul)
	discMgr := micro.NewDiscoveryManager(nil, core)
	consulProv, err := discconsul.NewConsulProvider(&discconsul.ConsulConfig{
		Address: env("CONSUL_ADDR", "localhost:8500"),
		Token:   os.Getenv("CONSUL_TOKEN"),
		Timeout: 30 * time.Second,
	}, core)
	must(err)
	must(discMgr.RegisterProvider(consulProv))
	// Connect/ping where applicable
	must(consulProv.Connect(ctx))

	// Register this service in discovery
	reg := &disctypes.ServiceRegistration{
		ID:       orDefault(os.Getenv("SERVICE_ID"), "user-service-1"),
		Name:     orDefault(cfg.Server.ServiceName, "user-service"),
		Address:  orDefault(cfg.Server.Host, "127.0.0.1"),
		Port:     toInt(orDefault(cfg.Server.Port, "8080")),
		Protocol: orDefault(cfg.Services.UserService.Protocol, "http"),
		Tags:     []string{"users", cfg.Server.Environment},
		Metadata: map[string]string{"version": cfg.Server.Version},
		TTL:      30 * time.Second,
	}
	must(discMgr.RegisterService(ctx, reg))

	// 6) Messaging (Kafka) via bootstrap
	msgMgr, err := bootstrap.InitMessaging(core, cfg.Kafka.Brokers, cfg.Kafka.GroupID)
	must(err)

	// 7) Monitoring (Prometheus) via bootstrap
	monMgr, err := bootstrap.InitMonitoring(core,
		env("PROM_HOST", "localhost"),
		toInt(orDefault(cfg.Monitoring.Prometheus.Port, cfgtypes.PrometheusConfig{Port: "9090"}.Port)),
		cfg.Server.ServiceName,
		cfg.Server.Environment,
	)
	must(err)

	// 7b) Database (PostgreSQL) via bootstrap
	dbMgr, err := bootstrap.InitPostgres(core,
		cfg.Database.PostgreSQL.Host,
		cfg.Database.PostgreSQL.Port,
		cfg.Database.PostgreSQL.User,
		cfg.Database.PostgreSQL.Password,
		cfg.Database.PostgreSQL.DBName,
		cfg.Database.PostgreSQL.SSLMode,
		cfg.Database.PostgreSQL.MaxConns,
		cfg.Database.PostgreSQL.MinConns,
	)
	must(err)

	// 8) Cross-cutting tools: rate limit, circuit breaker, failover
	rl, err := bootstrap.InitRateLimit(core, "users")
	must(err)
	cb, err := bootstrap.InitCircuitBreaker(core, "users-db")
	must(err)
	fo, err := bootstrap.InitFailover(core, env("CONSUL_ADDR", "localhost:8500"), os.Getenv("CONSUL_TOKEN"))
	must(err)

	// 9) Start HTTP server using communication provider routing
	repo := infrastructure.NewSQLUserRepository(dbMgr, "postgresql")
	service := app.NewUserService(repo)
	handlers := uihttp.NewUserHandlers(service)
	handlers.RateLimiter = rl.Manager
	handlers.RateLimit = rl.Limit
	handlers.Circuit = cb.Manager
	handlers.CircuitName = cb.Name
	httpProv.RegisterHandler("/users", handlers.HandleUsers)
	httpProv.RegisterHandler("/users/", handlers.HandleUserByID)
	must(commMgr.Start(ctx, "http", map[string]interface{}{}))

	// 8b) Messaging subscription handler (consume events from other services)
	must(msgMgr.SubscribeToTopic(ctx, "kafka", &msgt.SubscribeRequest{
		Topic:   cfg.Kafka.Topic,
		GroupID: cfg.Kafka.GroupID,
		AutoAck: true,
	}, func(c context.Context, m *msgt.Message) error {
		switch m.Type {
		case "user.upsert", "user.created":
			email, _ := m.Payload["email"].(string)
			name, _ := m.Payload["name"].(string)
			if email == "" || name == "" {
				core.WithField("message_id", m.ID).Warn("invalid user payload")
				return nil
			}
			_, err := service.CreateUser(app.CreateUserCommand{Email: email, Name: name})
			if err != nil {
				core.WithError(err).WithField("message_id", m.ID).Error("failed to handle user.upsert")
				return err
			}
			core.WithFields(logrus.Fields{"message_id": m.ID, "type": m.Type}).Info("message handled")
			return nil
		default:
			// ignore other event types
			return nil
		}
	}))

	// 9) Watch config changes to sync logging
	_ = cfgMgr.Watch(func(newCfg *cfgtypes.Config) {
		core.SetLevel(parseLevel(newCfg.Logging.Level))
		_ = logMgr.Info(ctx, "config reloaded")
	})

	core.WithField("service", reg.Name).Info("service started")
	<-sig

	// graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = commMgr.Stop(shutdownCtx, "http")
	_ = discMgr.DeregisterService(shutdownCtx, reg.ID)
	_ = msgMgr.Disconnect(shutdownCtx, "kafka")
	_ = monMgr.Disconnect(shutdownCtx, "prometheus")
	_ = fo.Manager.Close()
	_ = logMgr.Info(context.Background(), "service stopped")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(lvl string) logrus.Level {
	l, err := logrus.ParseLevel(lvl)
	if err != nil {
		return logrus.InfoLevel
	}
	return l
}

func toInt(s string) int {
	// very small helper; ignore error -> default 0
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// no custom mux; routing handled by communication provider
