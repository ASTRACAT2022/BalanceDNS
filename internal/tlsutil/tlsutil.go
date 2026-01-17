package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedCert generates a self-signed certificate and key.
func GenerateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Astracat DNS Self-Signed"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add localhost and all found interface IPs
	template.DNSNames = []string{"localhost"}
	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP("0.0.0.0")}

	// Collect all network interface IP addresses
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if !ipNet.IP.IsLoopback() {
					template.IPAddresses = append(template.IPAddresses, ipNet.IP)
				}
			}
		}
	} else {
		log.Printf("Warning: Failed to list network interfaces: %v. Certificate will only support localhost.", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write cert
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert.pem: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing cert.pem: %w", err)
	}

	// Write key
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to key.pem: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing key.pem: %w", err)
	}

	log.Printf("Successfully generated self-signed certificate at %s and key at %s", certPath, keyPath)
	return nil
}

// EnsureCerts checks if the provided cert/key exist. If not, it generates self-signed ones in a local ./certs dir.
// Returns the final paths to be used.
func EnsureCerts(configCert, configKey string) (string, string, error) {
	// If config provides paths and they exist, use them.
	if configCert != "" && configKey != "" {
		_, certErr := os.Stat(configCert)
		_, keyErr := os.Stat(configKey)
		if certErr == nil && keyErr == nil {
			return configCert, configKey, nil
		}
		log.Printf("Configured certificates not found (Cert: %v, Key: %v). Falling back to self-signed generation.", certErr, keyErr)
	}

	// Default fallback paths
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current working directory: %w", err)
	}

	certDir := filepath.Join(cwd, "certs")
	certFile := filepath.Join(certDir, "selfsigned.crt")
	keyFile := filepath.Join(certDir, "selfsigned.key")

	// Check if already generated
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if certErr == nil && keyErr == nil {
		log.Println("Using existing self-signed certificates.")
		return certFile, keyFile, nil
	}

	log.Println("Generating new self-signed certificates...")
	if err := GenerateSelfSignedCert(certFile, keyFile); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}
