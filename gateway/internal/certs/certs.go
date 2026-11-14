// Package certs loads the server's TLS certificate for the HTTPS listener.
package certs

import (
	"crypto/tls"
	"fmt"
)

// ServerConfig loads the server certificate and key (PEM files).
func ServerConfig(certFile, keyFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}
