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

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
	"github.com/rs/zerolog"
)

// Logger is a zerolog-based logger implementing est.Logger.
type Logger struct {
	logger zerolog.Logger
	fields []keyValue
}

// keyValue is a loosely-typed key-value pair.
type keyValue struct {
	key   string
	value interface{}
}

// New creates a new zerolog-based logger which writes to the specified writer.
func New(w io.Writer) est.Logger {
	// Use zerolog.ConsoleWriter for human-readable output with colors
	consoleWriter := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: time.RFC3339Nano,
		NoColor:    false, // Enable colors
	}

	// Initialize zerolog with the console writer
	logger := zerolog.New(consoleWriter).With().Timestamp().Logger()

	// Set the global level to debug to include all log levels
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

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

// Info uses fmt.Sprint to construct and log a message.
func (l *Logger) Info(v ...interface{}) {
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

// With adds a variadic number of key-values pairs to the logging context. The
// first element of the pair is used as the field key and should be a string.
// Passing a non-string key or passing an orphaned key panics.
func (l *Logger) With(args ...interface{}) est.Logger {
	if len(args)%2 != 0 {
		panic("number of arguments is not a multiple of 2")
	}

	newLogger := &Logger{
		logger: l.logger,
		fields: l.fields,
	}

	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			panic(fmt.Sprintf("argument %d is not a string", i))
		}

		newLogger.fields = append(newLogger.fields, keyValue{key: key, value: args[i+1]})
	}

	return newLogger
}

// logw is the common implementation for all logging methods.
func (l *Logger) logw(level zerolog.Level, msg string, keysAndValues ...interface{}) {
	// Start a new event at the specified level
	event := l.logger.WithLevel(level)

	// Get the caller information
	_, file, line, ok := runtime.Caller(2) // Adjust skip level if needed
	if ok {
		shortFile := fmt.Sprintf("%s/%s:%d", filepath.Base(filepath.Dir(file)), filepath.Base(file), line)
		// Add the caller info to the event
		event = event.Str("caller", shortFile)
	}

	// Add the stored fields
	for _, kv := range l.fields {
		event = event.Interface(kv.key, kv.value)
	}

	// Process keysAndValues
	if len(keysAndValues)%2 != 0 {
		panic("number of arguments is not a multiple of 2")
	}

	for i := 0; i < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			panic(fmt.Sprintf("argument %d is not a string", i))
		}
		value := keysAndValues[i+1]
		event = event.Interface(key, value)
	}

	// Log the message
	event.Msg(msg)
}
