package logging

import (
	"github.com/anasamu/go-micro-libs/logx"
	"github.com/sirupsen/logrus"
)

// Core returns the underlying core logger if available for backward compatibility
func (lm *LoggingManager) Core() *logrus.Logger { return lm.logger }

// Facade returns a facade Logger for standardized usage without changing public API
func (lm *LoggingManager) Facade() logx.Logger { return logx.NewLogrusAdapter(lm.logger) }
