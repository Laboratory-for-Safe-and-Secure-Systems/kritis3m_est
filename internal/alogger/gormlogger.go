package alogger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

// GormLogger implements the gorm.io/gorm/logger.Interface
type GormLogger struct {
	LogLevel                  gormlogger.LogLevel
	SlowThreshold             time.Duration
	IgnoreRecordNotFoundError bool
	Logger                    common.Logger
}

// NewGormLogger creates a new GormLogger using the provided common.Logger
func NewGormLogger(logger common.Logger) *GormLogger {
	return &GormLogger{
		LogLevel:                  gormlogger.Warn,
		SlowThreshold:             time.Second,
		IgnoreRecordNotFoundError: true,
		Logger:                    logger,
	}
}

// LogMode sets the log level and returns a new logger instance
func (gl *GormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	newLogger := *gl
	newLogger.LogLevel = level
	return &newLogger
}

// Info logs info messages
func (gl *GormLogger) Info(ctx context.Context, msg string, args ...interface{}) {
	if gl.LogLevel < gormlogger.Info {
		return
	}
	gl.Logger.Infof(msg, args...)
}

// Warn logs warning messages
func (gl *GormLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	if gl.LogLevel < gormlogger.Warn {
		return
	}
	gl.Logger.Infof("WARNING: "+msg, args...) // Using Info level since Logger may not have Warn
}

// Error logs error messages
func (gl *GormLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	if gl.LogLevel < gormlogger.Error {
		return
	}
	gl.Logger.Errorf(msg, args...)
}

// Trace logs database operations
func (gl *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if gl.LogLevel <= gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()
	sqlWithRows := fmt.Sprintf("[rows:%v] %s", rows, sql)

	switch {
	case err != nil && (!errors.Is(err, gormlogger.ErrRecordNotFound) || !gl.IgnoreRecordNotFoundError):
		if gl.LogLevel >= gormlogger.Error {
			gl.Logger.Errorw("database error",
				"error", err,
				"elapsed", elapsed,
				"sql", sqlWithRows,
				"caller", utils.FileWithLineNum(),
			)
		}
	case elapsed > gl.SlowThreshold && gl.SlowThreshold != 0:
		if gl.LogLevel >= gormlogger.Warn {
			slowLog := fmt.Sprintf("SLOW SQL >= %v", gl.SlowThreshold)
			gl.Logger.Infow(slowLog,
				"elapsed", elapsed,
				"sql", sqlWithRows,
				"caller", utils.FileWithLineNum(),
			)
		}
	default:
		if gl.LogLevel >= gormlogger.Info {
			gl.Logger.Debugf("database query [%s] %s", elapsed, sqlWithRows)
		}
	}
}
