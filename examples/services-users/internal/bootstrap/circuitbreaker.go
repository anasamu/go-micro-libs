package bootstrap

import (
	"time"

	micro "github.com/anasamu/go-micro-libs"
	cbg "github.com/anasamu/go-micro-libs/circuitbreaker/providers/gobreaker"
	cbtypes "github.com/anasamu/go-micro-libs/circuitbreaker/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type CircuitBundle struct {
	Manager *micro.CircuitBreakerManager
	Name    string
}

func InitCircuitBreaker(core *logrus.Logger, name string) (*CircuitBundle, error) {
	cm := micro.NewCircuitBreakerManager(nil, core)
	prov := cbg.NewGobreakerProvider(nil, core)
	if err := cm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := prov.Connect(context.Background()); err != nil {
		return nil, err
	}
	cfg := &cbtypes.CircuitBreakerConfig{
		Name:                name,
		MaxRequests:         5,
		Interval:            10 * time.Second,
		Timeout:             30 * time.Second,
		FailureThreshold:    50.0,
		MaxConsecutiveFails: 3,
	}
	if err := cm.Configure(context.Background(), name, cfg); err != nil {
		return nil, err
	}
	return &CircuitBundle{Manager: cm, Name: name}, nil
}
