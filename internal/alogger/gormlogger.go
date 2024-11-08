package alogger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/est"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

// GormLogger wraps the Logger to implement GORM's logger.Interface
type GormLogger struct {
	logger                    est.Logger
	logLevel                  logger.LogLevel
	slowThreshold             time.Duration
	ignoreRecordNotFoundError bool
}

// NewGormLogger creates a new GormLogger using the provided est.Logger
func NewGormLogger(estLogger est.Logger) *GormLogger {
	return &GormLogger{
		logger:                    estLogger,
		logLevel:                  logger.Warn,
		slowThreshold:             200 * time.Millisecond,
		ignoreRecordNotFoundError: true,
	}
}

func (gl *GormLogger) LogMode(level logger.LogLevel) logger.Interface {
	newLogger := *gl
	newLogger.logLevel = level
	return &newLogger
}

func (gl *GormLogger) Info(ctx context.Context, msg string, args ...interface{}) {
	if gl.logLevel < logger.Info {
		return
	}
	gl.logger.Infof(msg, args...)
}

func (gl *GormLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	if gl.logLevel < logger.Warn {
		return
	}
	gl.logger.Infof(msg, args...)
}

func (gl *GormLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	if gl.logLevel < logger.Error {
		return
	}
	gl.logger.Errorf(msg, args...)
}

func (gl *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if gl.logLevel <= logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	switch {
	case err != nil && (!errors.Is(err, logger.ErrRecordNotFound) || !gl.ignoreRecordNotFoundError):
		if gl.logLevel >= logger.Error {
			gl.logger.Errorw("database error",
				"err", err,
				"elapsed", elapsed,
				"rows", rows,
				"sql", sql,
				"file", utils.FileWithLineNum(),
			)
		}
	case elapsed > gl.slowThreshold && gl.slowThreshold != 0:
		if gl.logLevel >= logger.Warn {
			slowLog := fmt.Sprintf("SLOW SQL >= %v", gl.slowThreshold)
			gl.logger.Infow(slowLog,
				"elapsed", elapsed,
				"rows", rows,
				"sql", sql,
				"file", utils.FileWithLineNum(),
			)
		}
	default:
		if gl.logLevel >= logger.Info {
			gl.logger.Debugw("database query",
				"elapsed", elapsed,
				"rows", rows,
				"sql", sql,
				"file", utils.FileWithLineNum(),
			)
		}
	}
}
