package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the structure of the config.yaml file.
// We only map the fields we need for the proxy.
type Config struct {
	ListenAddr string `yaml:"listen_addr"` // Upstream DNS (e.g., 0.0.0.0:53)

	DoH struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
		CertFile   string `yaml:"cert_file"`
		KeyFile    string `yaml:"key_file"`
	} `yaml:"doh"`

	DoT struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
		CertFile   string `yaml:"cert_file"`
		KeyFile    string `yaml:"key_file"`
	} `yaml:"dot"`
}

// LoadConfig reads the configuration from the specified path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
