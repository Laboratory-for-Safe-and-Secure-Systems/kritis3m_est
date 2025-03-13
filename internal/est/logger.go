/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est

import "github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"

// Logger is an interface for an EST server logger.
type Logger = common.Logger

// nopLogger is a do-nothing logger which can be used if no logger is
// provided to the EST server.
type nopLogger struct{}

// nopLogEvent is a do-nothing log event.
type nopLogEvent struct{}

func (l *nopLogger) Errorf(format string, args ...interface{}) {}

func (l *nopLogger) Errorw(msg string, keysAndValues ...interface{}) {}

func (l *nopLogger) Infof(format string, args ...interface{}) {}

func (l *nopLogger) Infow(msg string, keysAndValues ...interface{}) {}

func (l *nopLogger) Debugf(format string, args ...interface{}) {}

func (l *nopLogger) Debugw(msg string, keysAndValues ...interface{}) {}

func (l *nopLogger) With(keysAndValues ...interface{}) common.Logger {
	return l
}

// Info returns a new no-op log event
func (l *nopLogger) Info() common.LogEvent {
	return &nopLogEvent{}
}

// Fatal returns a new no-op log event
func (l *nopLogger) Fatal() common.LogEvent {
	return &nopLogEvent{}
}

// Msg implements the LogEvent interface
func (e *nopLogEvent) Msg(msg string) {}

// Msgf implements the LogEvent interface
func (e *nopLogEvent) Msgf(format string, args ...interface{}) {}

// Err implements the LogEvent interface
func (e *nopLogEvent) Err(err error) common.LogEvent {
	return e
}

// Str implements the LogEvent interface
func (e *nopLogEvent) Str(key, val string) common.LogEvent {
	return e
}

func newNOPLogger() common.Logger {
	return &nopLogger{}
}
