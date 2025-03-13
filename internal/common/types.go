package common

// Logger is an interface for logging operations
type Logger interface {
	// Errorf uses fmt.Sprintf to log a formatted message.
	Errorf(format string, args ...interface{})

	// Errorw logs a message with some additional context. The variadic
	// key-value pairs are treated as they are in With.
	Errorw(format string, keysAndValues ...interface{})

	// Infof uses fmt.Sprintf to log a formatted message.
	Infof(format string, args ...interface{})

	// Infow logs a message with some additional context. The variadic
	// key-value pairs are treated as they are in With.
	Infow(format string, keysAndValues ...interface{})

	// Debugf uses fmt.Sprintf to log a formatted message.
	Debugf(format string, args ...interface{})

	// Debugw logs a message with some additional context. The variadic
	// key-value pairs are treated as they are in With.
	Debugw(format string, keysAndValues ...interface{})

	// With adds a variadic number of key-values pairs to the logging context.
	With(keysAndValues ...interface{}) Logger

	// Info returns a logger with info level
	Info() LogEvent

	// Fatal returns a logger with fatal level
	Fatal() LogEvent
}

// LogEvent is an interface for logging events
type LogEvent interface {
	// Msg logs a message
	Msg(msg string)

	// Msgf logs a formatted message
	Msgf(format string, args ...interface{})

	// Err adds an error to the log event
	Err(err error) LogEvent

	// Str adds a string field to the log event
	Str(key, val string) LogEvent
}

type ContextKey string

const TLSStateKey ContextKey = "tlsState"
