package dataprotection

import "context"

// Provider interface for data protection
type Provider interface {
	// Protect returns protected blob
	Protect(ctx context.Context, data []byte) ([]byte, error)
	// Unprotect returns unprotected data
	Unprotect(ctx context.Context, protected []byte) ([]byte, error)
	// IsReady returns true when provider has encryption keys
	IsReady() bool
}
