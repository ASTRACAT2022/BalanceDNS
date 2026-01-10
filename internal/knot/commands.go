package knot

import (
	"strings"
)

// ClearCache clears the Knot Resolver cache.
func (a *Adapter) ClearCache() error {
	// Lua: cache.clear()
	_, err := a.Execute("cache.clear()")
	return err
}

// Reload reloads the configuration.
// In kresd, strict "reload" usually means restarting or re-reading config.
// Since we are running under systemd usually, we might just trigger systemd reload?
// Or we can simple re-execute the config file via `dofile`.
// Assuming `dofile('/etc/kresd/kresd.conf')` works or similar.
// Better yet, if we are the control plane, we might just update the file and tell kresd to reload.
// But mostly `kresd` doesn't support full hot reload of everything without restart, but `policy` can be swapped.
// For now, we'll try to use a standardized reload command or just a log message if not fully supported.
func (a *Adapter) Reload() error {
	// There isn't a single 'reload' command in kresd that re-reads everything safely.
	// Often it's better to restart the service via systemctl (controlled by Go app exec).
	// However, clearing cache or updating policy modules can be done.
	// We'll leave this as a placeholder or implement specific policy reload.
	return nil
}

// GetStats retrieves statistics from Knot Resolver.
func (a *Adapter) GetStats() (map[string]interface{}, error) {
	// Lua: stats.list()
	// Output is usually a table. We need to parse it.
	// Or we can use `stats.list()` and parse the text output.
	// Kresd default output for stats.list() is key value pairs.
	resp, err := a.Execute("stats.list()")
	if err != nil {
		return nil, err
	}

	// Parse response
	stats := make(map[string]interface{})
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			// value is usually number, but simplistic parsing here
			stats[key] = strings.TrimSpace(parts[1])
		}
	}
	return stats, nil
}
