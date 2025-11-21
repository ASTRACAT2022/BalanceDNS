package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/hosts"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Server provides an admin web interface.
type Server struct {
	addr         string
	metrics      *metrics.Metrics
	hosts        *hosts.HostsPlugin
	adblock      *adblock.AdBlockPlugin
	pm           *plugins.PluginManager
	username     string
	passwordHash []byte
	sessionToken string
	sessionExpiry time.Time
	configPath   string  // Path to config file
}

// New creates a new admin server.
func New(addr string, m *metrics.Metrics, h *hosts.HostsPlugin, ab *adblock.AdBlockPlugin, pm *plugins.PluginManager) *Server {
	// In a real application, load this from config
	username := "astracat"
	password := "astracat"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	return &Server{
		addr:         addr,
		metrics:      m,
		hosts:        h,
		adblock:      ab,
		pm:           pm,
		username:     username,
		passwordHash: hash,
		configPath:   "config.yaml", // Default config path
	}
}

// Start runs the admin server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// Protected routes
	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/plugins", s.authMiddleware(http.HandlerFunc(s.handlePlugins)))
	mux.Handle("/api/plugins/config", s.authMiddleware(http.HandlerFunc(s.handlePluginConfigUpdate)))
	mux.Handle("/api/metrics", s.authMiddleware(http.HandlerFunc(s.handleApiMetrics)))
	mux.Handle("/change-password", s.authMiddleware(http.HandlerFunc(s.handleChangePassword)))
	mux.Handle("/api/hosts/reload", s.authMiddleware(http.HandlerFunc(s.handleHostsReload)))
	mux.Handle("/api/hosts/content", s.authMiddleware(http.HandlerFunc(s.handleHostsContent)))
	mux.Handle("/hosts/update", s.authMiddleware(http.HandlerFunc(s.handleHostsUpdate)))
	mux.Handle("/adblock/add", s.authMiddleware(http.HandlerFunc(s.handleAddBlocklist)))
	mux.Handle("/adblock/remove", s.authMiddleware(http.HandlerFunc(s.handleRemoveBlocklist)))
	mux.Handle("/adblock/reload", s.authMiddleware(http.HandlerFunc(s.handleAdBlockReload)))

	log.Printf("Starting admin server on %s", s.addr)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		log.Fatalf("Failed to start admin server: %v", err)
	}
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		if cookie.Value != s.sessionToken || time.Now().After(s.sessionExpiry) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	errorMessage := ""
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == s.username && bcrypt.CompareHashAndPassword(s.passwordHash, []byte(password)) == nil {
			token := make([]byte, 32)
			rand.Read(token)
			s.sessionToken = base64.StdEncoding.EncodeToString(token)
			s.sessionExpiry = time.Now().Add(12 * time.Hour)

			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   s.sessionToken,
				Expires: s.sessionExpiry,
				Path:    "/",
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		errorMessage = "Invalid username or password"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("login").Parse(loginPage)
	tpl.Execute(w, map[string]string{"Error": errorMessage})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionToken = ""
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	newPassword := r.FormValue("new_password")
	if len(newPassword) < 8 {
		// In a real app, you'd render this error nicely on the page
		http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}
	s.passwordHash = hash
	// Redirect with a success message
	http.Redirect(w, r, "/?message=Password+changed+successfully", http.StatusFound)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	data := struct {
		Queries    int64
		Message    string
		Blocklists []string
	}{
		Queries:    s.metrics.GetQueries(),
		Message:    message,
		Blocklists: s.adblock.GetBlocklists(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("stats").Parse(statsPage)
	tpl.Execute(w, data)
}

func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL cannot be empty", http.StatusBadRequest)
		return
	}
	s.adblock.AddBlocklist(url)
	
	// Save updated blocklists to config
	if err := s.saveConfig(); err != nil {
		log.Printf("Failed to save config: %v", err)
		// Continue anyway, as the plugin still has the updated list
	}
	
	http.Redirect(w, r, "/?message=Blocklist+added", http.StatusFound)
}

func (s *Server) handleRemoveBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL cannot be empty", http.StatusBadRequest)
		return
	}
	s.adblock.RemoveBlocklist(url)
	
	// Save updated blocklists to config
	if err := s.saveConfig(); err != nil {
		log.Printf("Failed to save config: %v", err)
		// Continue anyway, as the plugin still has the updated list
	}
	
	http.Redirect(w, r, "/?message=Blocklist+removed", http.StatusFound)
}

func (s *Server) handleAdBlockReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	go s.adblock.UpdateBlocklists() // Run in background
	http.Redirect(w, r, "/?message=Blocklist+update+started", http.StatusFound)
}


func (s *Server) handleHostsContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.hosts.ReadFileContent()
	if err != nil {
		log.Printf("Failed to read hosts file: %v", err)
		// Return an empty response if file doesn't exist
		content = "# Hosts file not found or empty\n"
	}
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(content))
}

func (s *Server) handleHostsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	
	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Hosts content cannot be empty", http.StatusBadRequest)
		return
	}
	
	// Write the new content to the hosts file
	if err := os.WriteFile(s.hosts.GetFilePath(), []byte(content), 0644); err != nil {
		log.Printf("Failed to write hosts file: %v", err)
		http.Error(w, fmt.Sprintf("Failed to update hosts file: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Reload the hosts plugin to use the new content
	if err := s.hosts.Reload(); err != nil {
		log.Printf("Failed to reload hosts after update: %v", err)
		http.Error(w, fmt.Sprintf("Updated hosts file but failed to reload: %v", err), http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/?message=Hosts+file+updated+and+reloaded", http.StatusFound)
}

func (s *Server) handleHostsReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.hosts.Reload(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload hosts file: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Hosts file reloaded successfully"})
}

func (s *Server) handleApiMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.metrics.RLock()
	defer s.metrics.RUnlock()

	var topNXDomains []metrics.DomainCount
	s.metrics.TopNXDomains.Range(func(key, value interface{}) bool {
		topNXDomains = append(topNXDomains, metrics.DomainCount{Domain: key.(string), Count: value.(int64)})
		return true
	})

	var topLatencyDomains []metrics.DomainLatency
	s.metrics.TopLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(metrics.LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count)
			topLatencyDomains = append(topLatencyDomains, metrics.DomainLatency{Domain: key.(string), AvgLatency: avgLatency})
		}
		return true
	})

	var queryTypes []metrics.TypeCount
	s.metrics.QueryTypes.Range(func(key, value interface{}) bool {
		queryTypes = append(queryTypes, metrics.TypeCount{Type: key.(string), Count: value.(int64)})
		return true
	})

	var responseCodes []metrics.CodeCount
	s.metrics.ResponseCodes.Range(func(key, value interface{}) bool {
		responseCodes = append(responseCodes, metrics.CodeCount{Code: key.(string), Count: value.(int64)})
		return true
	})

	var cacheHitRate float64
	if s.metrics.CacheHits+s.metrics.CacheMisses > 0 {
		cacheHitRate = float64(s.metrics.CacheHits) / float64(s.metrics.CacheHits+s.metrics.CacheMisses) * 100
	}

	data := metrics.DashboardMetrics{
		QPS:               s.metrics.QPS,
		TotalQueries:      s.metrics.GetQueries(),
		BlockedDomains:    s.metrics.BlockedDomains,
		CPUUsage:          s.metrics.CPUUsage,
		MemoryUsage:       s.metrics.MemoryUsage,
		Goroutines:        s.metrics.Goroutines,
		CacheHits:         s.metrics.CacheHits,
		CacheMisses:       s.metrics.CacheMisses,
		CacheHitRate:      cacheHitRate,
		TopNXDomains:      topNXDomains,
		TopLatencyDomains: topLatencyDomains,
		QueryTypes:        queryTypes,
		ResponseCodes:     responseCodes,
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding metrics to JSON: %v", err)
	}
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	data := struct {
		Message string
		Plugins []plugins.Plugin
	}{
		Message: message,
		Plugins: s.pm.GetPlugins(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("plugins").Parse(pluginsPage)
	tpl.Execute(w, data)
}

func (s *Server) saveConfig() error {
	// Get current config values from plugins
	cfg := config.NewConfig() // This gets defaults, we need to load the actual config file if it exists
	
	// Read existing config file if it exists
	var existingConfigData []byte
	var configExists bool
	if data, err := os.ReadFile(s.configPath); err == nil {
		existingConfigData = data
		configExists = true
	}
	
	// If config file exists, unmarshal it to preserve all other settings
	if configExists {
		if err := yaml.Unmarshal(existingConfigData, cfg); err != nil {
			return fmt.Errorf("failed to unmarshal existing config: %v", err)
		}
	}

	// Update only the adblock list URLs
	cfg.AdblockListURLs = s.adblock.GetBlocklists()

	// Write the updated config back to file
	if err := cfg.Save(s.configPath); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}
	
	return nil
}

func (s *Server) handlePluginConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	pluginName := r.FormValue("pluginName")
	plugin := s.pm.GetPlugin(pluginName)
	if plugin == nil {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	config := make(map[string]any)
	for _, field := range plugin.GetConfigFields() {
		config[field.Name] = r.FormValue(field.Name)
	}

	if err := plugin.SetConfig(config); err != nil {
		http.Redirect(w, r, "/plugins?message=Error+updating+config: "+err.Error(), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/plugins?message=Configuration+updated+successfully", http.StatusFound)
}

const loginPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
        .login-container { background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { text-align: center; color: #333; }
        .input-group { margin-bottom: 1rem; }
        .input-group label { display: block; margin-bottom: 0.5rem; color: #555; }
        .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { width: 100%; padding: 0.75rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
        .error { color: #d93025; text-align: center; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>ASTRACAT DNS</h2>
        <form method="post">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        {{if .Error}}
        <p class="error">{{.Error}}</p>
        {{end}}
    </div>
</body>
</html>
`

const pluginsPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Plugins</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
        .navbar { background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar .logo { font-size: 1.5rem; font-weight: bold; }
        .navbar a { text-decoration: none; color: #007bff; }
		.navbar a:hover { text-decoration: underline; }
        .container { padding: 2rem; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 1.5rem; padding: 1.5rem; }
        h1, h2 { color: #333; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input, .form-group textarea { width: 100%; max-width: 400px; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
		.message { padding: 1rem; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">ASTRACAT DNS</div>
        <div>
            <a href="/" style="margin-right: 1rem;">Dashboard</a>
            <a href="/logout">Logout</a>
        </div>
    </div>
    <div class="container">
        <h1>Plugin Management</h1>
		{{if .Message}}
		<div class="message">{{.Message}}</div>
		{{end}}
        {{range .Plugins}}
        <div class="card">
            <h2>{{.Name}}</h2>
            <form action="/api/plugins/config" method="post">
                <input type="hidden" name="pluginName" value="{{.Name}}">
                {{range .GetConfigFields}}
                <div class="form-group">
                    <label for="{{.Name}}">{{.Description}}</label>
                    {{if eq .Type "textarea"}}
                    <textarea id="{{.Name}}" name="{{.Name}}" rows="5">{{.Value}}</textarea>
                    {{else}}
                    <input type="{{.Type}}" id="{{.Name}}" name="{{.Name}}" value="{{.Value}}">
                    {{end}}
                </div>
                {{end}}
                <button type="submit" class="btn">Save Configuration</button>
            </form>
        </div>
        {{end}}
    </div>
</body>
</html>
`

const statsPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
        .navbar { background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar .logo { font-size: 1.5rem; font-weight: bold; }
        .navbar a { text-decoration: none; color: #007bff; }
		.navbar a:hover { text-decoration: underline; }
        .container { padding: 2rem; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 1.5rem; padding: 1.5rem; }
        h1, h2 { color: #333; }
		.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .stat-item { text-align: center; }
        .stat-item .value { font-size: 2.5rem; font-weight: bold; }
        .stat-item .label { color: #666; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; max-width: 400px; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
		.message { padding: 1rem; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">ASTRACAT DNS</div>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <h1>Dashboard</h1>
		{{if .Message}}
		<div class="message">{{.Message}}</div>
		{{end}}
        <div class="card">
            <h2>Statistics</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="value" id="total-queries">{{.Queries}}</div>
                    <div class="label">Total Queries</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="qps">0</div>
                    <div class="label">QPS</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="blocked-domains">0</div>
                    <div class="label">Blocked Domains</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cache-hit-rate">0%</div>
                    <div class="label">Cache Hit Rate</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cpu-usage">0%</div>
                    <div class="label">CPU Usage</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="memory-usage">0%</div>
                    <div class="label">Memory Usage</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="goroutines">0</div>
                    <div class="label">Goroutines</div>
                </div>
            </div>
            <div style="width: 100%; margin-top: 2rem;">
                <canvas id="qpsChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h2>Detailed Statistics</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
                <div>
                    <h3>Top Queried Domains</h3>
                    <ul id="top-queried-domains" style="max-height: 300px; overflow-y: auto;">
                        <li>Loading...</li>
                    </ul>
                </div>
                <div>
                    <h3>Top NXDOMAIN Queries</h3>
                    <ul id="top-nx-domains" style="max-height: 300px; overflow-y: auto;">
                        <li>Loading...</li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="card">
            <h2>Settings</h2>
            <form action="/change-password" method="post">
                <div class="form-group">
                    <label for="new_password">Change Admin Password</label>
                    <input type="password" id="new_password" name="new_password" minlength="8" required>
                </div>
                <button type="submit" class="btn">Change Password</button>
            </form>
        </div>
		<div class="card">
			<h2>AdBlock Management</h2>
			<div class="form-group">
				<form action="/adblock/add" method="post" style="display: flex; gap: 10px;">
					<input type="url" name="url" placeholder="https://example.com/blocklist.txt" required style="flex-grow: 1;">
					<button type="submit" class="btn">Add Blocklist</button>
				</form>
			</div>
			<div class="form-group">
				<form action="/adblock/reload" method="post">
					<button type="submit" class="btn">Update All Blocklists Now</button>
				</form>
			</div>
			<h4>Current Blocklists:</h4>
			<ul>
				{{range .Blocklists}}
				<li style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
					<span>{{.}}</span>
					<form action="/adblock/remove" method="post">
						<input type="hidden" name="url" value="{{.}}">
						<button type="submit" class="btn" style="background-color: #dc3545;">Remove</button>
					</form>
				</li>
				{{end}}
			</ul>
		</div>
		<div class="card">
			<h2>Hosts Management</h2>
			<form action="/hosts/update" method="post">
				<div class="form-group">
					<label for="content">Hosts File Content</label>
					<textarea id="content" name="content" rows="10" style="width: 100%; font-family: monospace;" placeholder="Example:
127.0.0.1 localhost
127.0.0.1 example.com">127.0.0.1 localhost
127.0.0.1 example.com</textarea>
				</div>
				<button type="submit" class="btn">Update Hosts File</button>
			</form>
			<div class="form-group" style="margin-top: 1rem;">
				<form action="/api/hosts/reload" method="post">
					<button type="submit" class="btn">Reload Hosts File from Disk</button>
				</form>
			</div>
		</div>
    </div>
    <script>
        const qpsData = {
            labels: [],
            datasets: [{
                label: 'QPS',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1,
                fill: false
            }]
        };

        const qpsChart = new Chart(document.getElementById('qpsChart'), {
            type: 'line',
            data: qpsData,
            options: {
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'second'
                        }
                    }
                }
            }
        });

        function updateMetrics() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-queries').innerText = data.total_queries;
                    document.getElementById('qps').innerText = data.qps.toFixed(2);
                    document.getElementById('blocked-domains').innerText = data.blocked_domains;
                    document.getElementById('cache-hit-rate').innerText = data.cache_hit_rate.toFixed(2) + '%';
                    document.getElementById('cpu-usage').innerText = data.cpu_usage.toFixed(2) + '%';
                    document.getElementById('memory-usage').innerText = data.memory_usage.toFixed(2) + '%';
                    document.getElementById('goroutines').innerText = data.goroutines;

                    // Update top queried domains
                    const topQueriedList = document.getElementById('top-queried-domains');
                    topQueriedList.innerHTML = '';
                    if (data.top_queried_domains && data.top_queried_domains.length > 0) {
                        data.top_queried_domains.forEach(item => {
                            const li = document.createElement('li');
                            li.textContent = item.domain + ': ' + item.count;
                            topQueriedList.appendChild(li);
                        });
                    } else {
                        topQueriedList.innerHTML = '<li>No data available</li>';
                    }

                    // Update top NX domains
                    const topNxList = document.getElementById('top-nx-domains');
                    topNxList.innerHTML = '';
                    if (data.top_nx_domains && data.top_nx_domains.length > 0) {
                        data.top_nx_domains.forEach(item => {
                            const li = document.createElement('li');
                            li.textContent = item.domain + ': ' + item.count;
                            topNxList.appendChild(li);
                        });
                    } else {
                        topNxList.innerHTML = '<li>No data available</li>';
                    }

                    const now = new Date();
                    qpsData.labels.push(now);
                    qpsData.datasets[0].data.push(data.qps);

                    if (qpsData.labels.length > 60) {
                        qpsData.labels.shift();
                        qpsData.datasets[0].data.shift();
                    }

                    qpsChart.update();
                })
                .catch(error => {
                    console.error('Error fetching metrics:', error);
                    // Keep the old values in case of error
                });
        }

        setInterval(updateMetrics, 2000);
        updateMetrics(); // Initial call
    </script>
    <script>
        // Load current hosts file content on page load
        window.onload = function() {
            fetch('/api/hosts/content')
            .then(response => {
                if (response.ok) {
                    return response.text();
                }
                return "# Failed to load hosts content";
            })
            .then(content => {
                const contentElement = document.getElementById('content');
                if (contentElement) {
                    contentElement.value = content;
                }
            })
            .catch(error => {
                console.error('Error loading hosts content:', error);
            });
        };
    </script>
</body>
</html>
`
