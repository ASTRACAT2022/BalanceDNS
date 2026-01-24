package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/tlsutil"

	"gopkg.in/yaml.v3"
)

const (
	defaultCertPath = "cert.pem"
	defaultKeyPath  = "key.pem"
)

type syncResponse struct {
	ConfigYAML string `json:"config_yaml"`
	CertPEM    string `json:"cert_pem"`
	KeyPEM     string `json:"key_pem"`
}

// SyncFromAdmin fetches config/certs from the admin server and returns a merged config.
func SyncFromAdmin(cfg *config.Config, configPath string) (*config.Config, error) {
	if cfg.ClusterAdminURL == "" {
		return cfg, nil
	}

	endpoint := strings.TrimRight(cfg.ClusterAdminURL, "/") + "/api/cluster/sync"
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return cfg, fmt.Errorf("build sync request: %w", err)
	}
	if cfg.ClusterToken != "" {
		req.Header.Set("X-Cluster-Token", cfg.ClusterToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return cfg, fmt.Errorf("cluster sync request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return cfg, fmt.Errorf("cluster sync failed: %s (%s)", resp.Status, bytes.TrimSpace(body))
	}

	var payload syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return cfg, fmt.Errorf("decode cluster response: %w", err)
	}

	if payload.ConfigYAML == "" {
		return cfg, fmt.Errorf("cluster response missing config")
	}

	newCfg := config.NewConfig()
	if err := yaml.Unmarshal([]byte(payload.ConfigYAML), newCfg); err != nil {
		return cfg, fmt.Errorf("unmarshal cluster config: %w", err)
	}

	// Preserve local cluster settings so nodes keep their role/admin URL/token.
	newCfg.ClusterRole = cfg.ClusterRole
	newCfg.ClusterAdminURL = cfg.ClusterAdminURL
	newCfg.ClusterToken = cfg.ClusterToken
	newCfg.ClusterSyncInterval = cfg.ClusterSyncInterval

	if configPath != "" {
		if err := os.WriteFile(configPath, []byte(payload.ConfigYAML), 0644); err != nil {
			return cfg, fmt.Errorf("write cluster config: %w", err)
		}
	}

	if payload.CertPEM != "" && payload.KeyPEM != "" {
		certPath := newCfg.CertFile
		keyPath := newCfg.KeyFile
		if certPath == "" {
			certPath = defaultCertPath
		}
		if keyPath == "" {
			keyPath = defaultKeyPath
		}

		if err := os.WriteFile(certPath, []byte(payload.CertPEM), 0644); err != nil {
			return cfg, fmt.Errorf("write cluster cert: %w", err)
		}
		if err := os.WriteFile(keyPath, []byte(payload.KeyPEM), 0600); err != nil {
			return cfg, fmt.Errorf("write cluster key: %w", err)
		}

		newCfg.CertFile = certPath
		newCfg.KeyFile = keyPath
	}

	if newCfg.ClusterRole == "node" {
		newCfg.AdminAddr = ""
		newCfg.AcmeEnabled = false
	}

	log.Printf("Cluster sync completed from %s", endpoint)
	return newCfg, nil
}

// EnsureAdminCertificates creates self-signed certs for cluster distribution when missing.
func EnsureAdminCertificates(cfg *config.Config) (string, string, error) {
	certPath := cfg.CertFile
	keyPath := cfg.KeyFile
	if certPath == "" {
		certPath = defaultCertPath
	}
	if keyPath == "" {
		keyPath = defaultKeyPath
	}

	hosts := []string{"astracat.dns", "localhost", "127.0.0.1", "::1"}
	if err := tlsutil.EnsureCertificate(certPath, keyPath, hosts); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}
