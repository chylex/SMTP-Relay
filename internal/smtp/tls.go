package smtp

import (
	"crypto/tls"
	"fmt"
)

func GetTlsConfig(certFile *string, keyFile *string) (*tls.Config, error) {
	// Ciphersuites as defined in stock Go but without 3DES and RC4
	// https://golang.org/src/crypto/tls/cipher_suites.go
	var tlsCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
	}

	if *certFile == "" || *keyFile == "" {
		return nil, fmt.Errorf("TLS certificate/key file not defined in config")
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load X509 keypair: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: tlsCipherSuites,
		Certificates: []tls.Certificate{cert},
	}, nil
}
