package cryptoprov

// markedError is an error with a sentinel as an additional identity.
type markedError struct {
	err      error
	sentinel error
}

func (e *markedError) Error() string { return e.err.Error() }

// Unwrap returns the marked error, so errors.As still finds its causes.
func (e *markedError) Unwrap() error { return e.err }

// Is reports whether target is the sentinel.
func (e *markedError) Is(target error) bool { return target == e.sentinel }

// MarkError returns err with sentinel as an additional identity:
// errors.Is(result, sentinel) is true, with the standard library as with
// cockroachdb/errors, the message is that of err, and errors.As still finds
// the causes of err. A provider uses it to report a backend error, such as
// the "not found" of a KMS, as ErrKeyNotFound without losing the service
// error. A nil err stays nil.
func MarkError(err, sentinel error) error {
	if err == nil {
		return nil
	}
	return &markedError{
		err:      err,
		sentinel: sentinel,
	}
}
