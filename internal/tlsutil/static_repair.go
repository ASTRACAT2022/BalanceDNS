package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dns-resolver/internal/config"
)

type tlsPairCandidate struct {
	CertPath string
	KeyPath  string
}

var discoverStaticTLSCandidates = defaultDiscoverStaticTLSCandidates

func loadBestStaticTLSPair(cfg *config.Config, configuredCertFile, configuredKeyFile, preferredDomain string) (tls.Certificate, tlsPairCandidate, error) {
	candidates := discoverStaticTLSCandidates(cfg, configuredCertFile, configuredKeyFile)
	now := time.Now()

	bestScore := -1
	var bestCert tls.Certificate
	var bestCandidate tlsPairCandidate
	var lastErr error

	for _, candidate := range candidates {
		cert, leaf, err := loadAndValidateTLSPair(candidate.CertPath, candidate.KeyPath)
		if err != nil {
			lastErr = err
			continue
		}
		if leaf.NotAfter.Before(now) {
			lastErr = fmt.Errorf("certificate expired for %s", candidate.CertPath)
			continue
		}

		score := 0
		if candidate.CertPath == configuredCertFile && candidate.KeyPath == configuredKeyFile {
			score += 30
		}
		if strings.Contains(candidate.CertPath, "/etc/letsencrypt/live/") {
			score += 20
		}
		if leaf.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
			score += 10
		}
		if preferredDomain != "" {
			if err := leaf.VerifyHostname(preferredDomain); err == nil {
				score += 100
			}
		}

		if score > bestScore {
			bestScore = score
			bestCert = cert
			bestCandidate = candidate
		}
	}

	if bestScore < 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no candidate pairs available")
		}
		return tls.Certificate{}, tlsPairCandidate{}, lastErr
	}
	return bestCert, bestCandidate, nil
}

func defaultDiscoverStaticTLSCandidates(cfg *config.Config, configuredCertFile, configuredKeyFile string) []tlsPairCandidate {
	seen := map[string]struct{}{}
	out := make([]tlsPairCandidate, 0, 8)

	add := func(certPath, keyPath string) {
		if certPath == "" || keyPath == "" {
			return
		}
		key := certPath + "\x00" + keyPath
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, tlsPairCandidate{CertPath: certPath, KeyPath: keyPath})
	}

	add(configuredCertFile, configuredKeyFile)
	add("/opt/astracatdns/certs/fullchain.pem", "/opt/astracatdns/certs/privkey.pem")

	for _, domain := range cfg.AcmeDomains {
		d := strings.TrimSpace(domain)
		if d == "" {
			continue
		}
		add(filepath.Join("/etc/letsencrypt/live", d, "fullchain.pem"), filepath.Join("/etc/letsencrypt/live", d, "privkey.pem"))
	}

	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem")
	for _, certPath := range matches {
		keyPath := filepath.Join(filepath.Dir(certPath), "privkey.pem")
		add(certPath, keyPath)
	}

	return out
}

func loadAndValidateTLSPair(certPath, keyPath string) (tls.Certificate, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, nil, fmt.Errorf("empty certificate chain in %s", certPath)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert.Leaf = leaf
	return cert, leaf, nil
}

func syncStaticTLSPair(targetCert, targetKey, sourceCert, sourceKey string) error {
	certPEM, err := os.ReadFile(sourceCert)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(sourceKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(targetCert), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetKey), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(targetCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(targetKey, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}
