package bootstrap

import (
	"time"

	micro "github.com/anasamu/go-micro-libs"
	fconsul "github.com/anasamu/go-micro-libs/failover/providers/consul"
	ftypes "github.com/anasamu/go-micro-libs/failover/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type FailoverBundle struct {
	Manager *micro.FailoverManager
	Config  *ftypes.FailoverConfig
}

func InitFailover(core *logrus.Logger, consulAddr, token string) (*FailoverBundle, error) {
	fm := micro.NewFailoverManager(nil, core)
	prov, err := fconsul.NewProvider(&fconsul.Config{Address: consulAddr, Token: token, Timeout: 30 * time.Second}, core)
	if err != nil {
		return nil, err
	}
	if err := fm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := prov.Connect(context.Background()); err != nil {
		return nil, err
	}
	cfg := &ftypes.FailoverConfig{
		Name:          "external-api",
		Strategy:      ftypes.StrategyRoundRobin,
		RetryAttempts: 3,
		RetryDelay:    500 * time.Millisecond,
		Timeout:       3 * time.Second,
	}
	if err := fm.Configure(context.Background(), cfg); err != nil {
		return nil, err
	}
	return &FailoverBundle{Manager: fm, Config: cfg}, nil
}
