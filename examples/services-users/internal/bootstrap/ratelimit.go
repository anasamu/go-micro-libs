package bootstrap

import (
	"time"

	micro "github.com/anasamu/go-micro-libs"
	rlmem "github.com/anasamu/go-micro-libs/ratelimit/providers/inmemory"
	rltypes "github.com/anasamu/go-micro-libs/ratelimit/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type RateLimitBundle struct {
	Manager *micro.RateLimitManager
	Limit   *rltypes.RateLimit
}

func InitRateLimit(core *logrus.Logger, keyPrefix string) (*RateLimitBundle, error) {
	rm := micro.NewRateLimitManager(nil, core)
	prov, err := rlmem.NewProvider(&rlmem.Config{CleanupInterval: time.Minute, MaxBuckets: 10000})
	if err != nil {
		return nil, err
	}
	if err := rm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := prov.Connect(context.Background()); err != nil {
		return nil, err
	}
	// Note: RateLimit struct does not support KeyPrefix; use your own key composition at call site
	limit := &rltypes.RateLimit{Algorithm: rltypes.AlgorithmTokenBucket, Limit: 10, Window: time.Second * 1}
	return &RateLimitBundle{Manager: rm, Limit: limit}, nil
}
