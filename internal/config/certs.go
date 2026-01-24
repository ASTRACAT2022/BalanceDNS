package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func (c *Config) WriteCertFilesFromEnv() (bool, error) {
	if c.CertContent == "" && c.KeyContent == "" {
		return false, nil
	}
	if c.CertContent == "" || c.KeyContent == "" {
		return false, fmt.Errorf("both SSL_CERT_CONTENT and SSL_KEY_CONTENT must be set")
	}

	certContent, err := normalizePEM(c.CertContent, "certificate")
	if err != nil {
		return false, err
	}
	keyContent, err := normalizePEM(c.KeyContent, "private key")
	if err != nil {
		return false, err
	}

	certPath := c.CertFile
	if certPath == "" {
		certPath = "cert.pem"
	}
	keyPath := c.KeyFile
	if keyPath == "" {
		keyPath = "key.pem"
	}

	if err := os.WriteFile(certPath, []byte(certContent), 0644); err != nil {
		return false, fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		return false, fmt.Errorf("write key file: %w", err)
	}

	c.CertFile = certPath
	c.KeyFile = keyPath
	return true, nil
}

func normalizePEM(value string, label string) (string, error) {
	normalized := strings.TrimSpace(value)
	if strings.Contains(normalized, "\\n") && !strings.Contains(normalized, "\n") {
		normalized = strings.ReplaceAll(normalized, "\\n", "\n")
	}
	if !strings.Contains(normalized, "BEGIN ") {
		compact := strings.ReplaceAll(normalized, "\n", "")
		compact = strings.ReplaceAll(compact, "\r", "")
		compact = strings.ReplaceAll(compact, " ", "")
		decoded, err := base64.StdEncoding.DecodeString(compact)
		if err == nil {
			normalized = strings.TrimSpace(string(decoded))
		}
	}
	if !strings.Contains(normalized, "BEGIN ") {
		return "", fmt.Errorf("%s content is not valid PEM", label)
	}
	return normalized, nil
}
