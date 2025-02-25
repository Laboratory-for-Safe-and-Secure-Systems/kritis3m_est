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
}

type ContextKey string

const TLSStateKey ContextKey = "tlsState"
