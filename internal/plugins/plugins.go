package plugins

import (
	"log"

	"github.com/miekg/dns"
)

// PluginContext holds context for a plugin's execution.
type PluginContext struct {
	// You can add more context fields here if needed,
	// for example, the original dns.ResponseWriter.
	ResponseWriter dns.ResponseWriter
}

// ConfigField defines a configurable field for a plugin.
type ConfigField struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // e.g., "text", "number", "boolean"
	Value       any    `json:"value"`
}

// Plugin is the interface that all plugins must implement.
type Plugin interface {
	Name() string
	// Execute processes a DNS message. It returns true if it has handled the
	// message and no further processing should be done.
	Execute(ctx *PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error)
	GetConfig() map[string]any
	SetConfig(config map[string]any) error
	GetConfigFields() []ConfigField
}

// PluginManager manages the lifecycle of plugins.
type PluginManager struct {
	plugins []Plugin
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make([]Plugin, 0),
	}
}

// Register adds a new plugin to the manager.
func (pm *PluginManager) Register(p Plugin) {
	log.Printf("Registering plugin: %s", p.Name())
	pm.plugins = append(pm.plugins, p)
}

// ExecutePlugins runs all registered plugins.
func (pm *PluginManager) ExecutePlugins(ctx *PluginContext, w dns.ResponseWriter, r *dns.Msg) bool {
	for _, p := range pm.plugins {
		handled, err := p.Execute(ctx, w, r)
		if err != nil {
			log.Printf("Error executing plugin %s: %v", p.Name(), err)
		}
		if handled {
			return true
		}
	}
	return false
}

// GetPlugins returns all registered plugins.
func (pm *PluginManager) GetPlugins() []Plugin {
	return pm.plugins
}

// GetPlugin returns a plugin by name.
func (pm *PluginManager) GetPlugin(name string) Plugin {
	for _, p := range pm.plugins {
		if p.Name() == name {
			return p
		}
	}
	return nil
}