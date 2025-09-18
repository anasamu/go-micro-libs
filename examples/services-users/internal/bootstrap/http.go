package bootstrap

import (
	"time"

	micro "github.com/anasamu/go-micro-libs"
	commhttp "github.com/anasamu/go-micro-libs/communication/providers/http"
	"github.com/sirupsen/logrus"
)

func InitHTTP(core *logrus.Logger, host string, port int, read, write, idle int) (*micro.CommunicationManager, *commhttp.Provider) {
	cm := micro.NewCommunicationManager(nil, core)
	prov := commhttp.NewProvider(core)
	_ = cm.RegisterProvider(prov)
	_ = prov.Configure(map[string]interface{}{
		"host":          host,
		"port":          port,
		"read_timeout":  time.Duration(read) * time.Second,
		"write_timeout": time.Duration(write) * time.Second,
		"idle_timeout":  time.Duration(idle) * time.Second,
	})
	return cm, prov
}
