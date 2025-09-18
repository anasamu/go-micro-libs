package bootstrap

import (
	micro "github.com/anasamu/go-micro-libs"
	monprom "github.com/anasamu/go-micro-libs/monitoring/providers/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

func InitMonitoring(core *logrus.Logger, host string, port int, namespace, env string) (*micro.MonitoringManager, error) {
	mm := micro.NewMonitoringManager(nil, core)
	prov := monprom.NewPrometheusProvider(&monprom.PrometheusConfig{
		Host:        host,
		Port:        port,
		Protocol:    "http",
		Path:        "/api/v1",
		Namespace:   namespace,
		Environment: env,
	}, core)
	if err := mm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := mm.Connect(context.Background(), "prometheus"); err != nil {
		return nil, err
	}
	return mm, nil
}
