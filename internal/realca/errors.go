package realca

// caError is an internal error structure implementing est.Error.
type caError struct {
	status     int
	desc       string
	retryAfter int
}

// StatusCode returns the HTTP status code.
func (e caError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e caError) Error() string {
	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e caError) RetryAfter() int {
	return e.retryAfter
}

