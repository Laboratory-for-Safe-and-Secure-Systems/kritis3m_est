/*
Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package alogger

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
	"github.com/rs/zerolog"
)

// Logger is a zerolog-based logger implementing common.Logger interface.
type Logger struct {
	logger zerolog.Logger
	fields []keyValue
}

// keyValue is a loosely-typed key-value pair.
type keyValue struct {
	key   string
	value interface{}
}

// LogEvent wraps a zerolog.Event to implement the common.LogEvent interface
type LogEvent struct {
	event *zerolog.Event
}

// Msg sends the event with the given message
func (e *LogEvent) Msg(msg string) {
	e.event.Msg(msg)
}

// Msgf sends the event with the formatted message
func (e *LogEvent) Msgf(format string, args ...interface{}) {
	e.event.Msgf(format, args...)
}

// Err adds the given error to the event
func (e *LogEvent) Err(err error) common.LogEvent {
	e.event.Err(err)
	return e
}

// Str adds a string field to the event
func (e *LogEvent) Str(key, val string) common.LogEvent {
	e.event.Str(key, val)
	return e
}

// New creates a new zerolog-based logger which writes to the specified writer.
func New(w io.Writer, level zerolog.Level) common.Logger {
	// Use zerolog.ConsoleWriter for human-readable output with colors
	consoleWriter := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: time.RFC3339Nano,
		NoColor:    false, // Enable colors
	}

	// Initialize zerolog with the console writer
	logger := zerolog.New(consoleWriter).With().Timestamp().Logger()

	// Set the global level to debug to include all log levels
	zerolog.SetGlobalLevel(level)

	return &Logger{
		logger: logger,
	}
}

// Debug uses fmt.Sprint to construct and log a message.
func (l *Logger) Debug(v ...interface{}) {
	msg := fmt.Sprint(v...)
	l.logw(zerolog.DebugLevel, msg)
}

// Debugf uses fmt.Sprintf to log a formatted message.
func (l *Logger) Debugf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.logw(zerolog.DebugLevel, msg)
}

// Debugw logs a message with some additional context.
func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	l.logw(zerolog.DebugLevel, msg, keysAndValues...)
}

// Error uses fmt.Sprint to construct and log a message.
func (l *Logger) Error(v ...interface{}) {
	msg := fmt.Sprint(v...)
	l.logw(zerolog.ErrorLevel, msg)
}

// Errorf uses fmt.Sprintf to log a formatted message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.logw(zerolog.ErrorLevel, msg)
}

// Errorw logs a message with some additional context.
func (l *Logger) Errorw(msg string, keysAndValues ...interface{}) {
	l.logw(zerolog.ErrorLevel, msg, keysAndValues...)
}

// Info returns a logger with info level
func (l *Logger) Info() common.LogEvent {
	return &LogEvent{event: l.logger.Info()}
}

// InfoPrint uses fmt.Sprint to construct and log a message.
// This replaces the old Info method to avoid conflicts
func (l *Logger) InfoPrint(v ...interface{}) {
	msg := fmt.Sprint(v...)
	l.logw(zerolog.InfoLevel, msg)
}

// Infof uses fmt.Sprintf to log a formatted message.
func (l *Logger) Infof(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.logw(zerolog.InfoLevel, msg)
}

// Infow logs a message with some additional context.
func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
	l.logw(zerolog.InfoLevel, msg, keysAndValues...)
}

// Fatal returns a logger with fatal level
func (l *Logger) Fatal() common.LogEvent {
	return &LogEvent{event: l.logger.Fatal()}
}

// With adds a variadic number of fields to the logging context.
func (l *Logger) With(args ...interface{}) common.Logger {
	// If the number of args is odd, the last field will be discarded.
	// This is consistent with zerolog's behavior.
	if len(args)%2 != 0 {
		args = args[:len(args)-1]
	}

	// Create a new logger with the same underlying logger but different fields.
	newFields := make([]keyValue, len(l.fields), len(l.fields)+len(args)/2)
	copy(newFields, l.fields)

	// Add new fields
	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		newFields = append(newFields, keyValue{key: key, value: args[i+1]})
	}

	newLogger := &Logger{
		logger: l.logger,
		fields: newFields,
	}

	return newLogger
}

// logw is the common logging implementation for various levels.
func (l *Logger) logw(level zerolog.Level, msg string, keysAndValues ...interface{}) {
	var event *zerolog.Event

	switch level {
	case zerolog.DebugLevel:
		event = l.logger.Debug()
	case zerolog.InfoLevel:
		event = l.logger.Info()
	case zerolog.WarnLevel:
		event = l.logger.Warn()
	case zerolog.ErrorLevel:
		event = l.logger.Error()
	case zerolog.FatalLevel:
		event = l.logger.Fatal()
	case zerolog.PanicLevel:
		event = l.logger.Panic()
	default:
		event = l.logger.Log()
	}

	// Add caller information
	_, file, line, ok := runtime.Caller(2)
	if ok {
		event = event.Str("caller", fmt.Sprintf("%s:%d", filepath.Base(file), line))
	}

	// Add pre-existing fields
	for _, field := range l.fields {
		event = addField(event, field.key, field.value)
	}

	// Add the key-value pairs from this specific log entry
	keysAndValues = cleanKeysAndValues(keysAndValues)
	for i := 0; i < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			continue
		}

		if i+1 < len(keysAndValues) {
			event = addField(event, key, keysAndValues[i+1])
		}
	}

	event.Msg(msg)
}

// cleanKeysAndValues ensures that keysAndValues has an even length
func cleanKeysAndValues(keysAndValues []interface{}) []interface{} {
	if len(keysAndValues)%2 != 0 {
		return keysAndValues[:len(keysAndValues)-1]
	}
	return keysAndValues
}

// addField adds a field to the zerolog.Event based on the value's type
func addField(event *zerolog.Event, key string, value interface{}) *zerolog.Event {
	if value == nil {
		return event.Interface(key, nil)
	}

	switch v := value.(type) {
	case string:
		return event.Str(key, v)
	case bool:
		return event.Bool(key, v)
	case int:
		return event.Int(key, v)
	case int64:
		return event.Int64(key, v)
	case float64:
		return event.Float64(key, v)
	case error:
		return event.Err(v).Str(key, v.Error())
	default:
		return event.Interface(key, v)
	}
}
