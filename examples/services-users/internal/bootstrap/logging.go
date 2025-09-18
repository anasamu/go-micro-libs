package bootstrap

import (
	"time"

	micro "github.com/anasamu/go-micro-libs"
	logconsole "github.com/anasamu/go-micro-libs/logging/providers/console"
	logtypes "github.com/anasamu/go-micro-libs/logging/types"
	"github.com/sirupsen/logrus"
)

type LogBundle struct {
	Core   *logrus.Logger
	LogMgr *micro.LoggingManager
}

func InitLogging(service, version, level, format, output, index string) *LogBundle {
	core := logrus.New()
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	core.SetLevel(lvl)
	core.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	lm := micro.NewLoggingManager(nil, core)
	cfg := &logtypes.LoggingConfig{
		Level:   logtypes.LogLevel(level),
		Format:  logtypes.LogFormat(format),
		Output:  logtypes.LogOutput(output),
		Service: service,
		Version: version,
		Index:   index,
	}
	_ = lm.RegisterProvider(logconsole.NewConsoleProvider(cfg))
	return &LogBundle{Core: core, LogMgr: lm}
}
